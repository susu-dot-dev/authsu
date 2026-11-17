package session

import (
	"context"
	"crypto"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/susu-dot-dev/japikey_go"
)

// Errors Verify returns. A token that fails for any reason about the token or
// its key is ErrUnauthorized, and the cause is for logs only: telling a caller
// whether a key exists, was revoked or expired would be an oracle.
var (
	// ErrUnauthorized means the token is not a currently valid session.
	ErrUnauthorized = errors.New("not a valid session")
	// ErrUnavailable means the store could not be read, which says nothing
	// about the token.
	ErrUnavailable = errors.New("session store unavailable")
)

var errStoredKey = errors.New("stored key is not a valid public key")

// Verifier checks session tokens.
type Verifier struct {
	reader Reader
	issuer Issuer
	now    func() time.Time
}

// NewVerifier returns a Verifier that reads keys from reader.
func NewVerifier(reader Reader, issuer Issuer, now func() time.Time) *Verifier {
	return &Verifier{reader: reader, issuer: issuer, now: now}
}

// Verify checks token and returns who it speaks for.
//
// japikey checks the token itself (format, algorithm pinned from the signed
// version, issuer equal to "<base>/<kid>", expiry, and the audience, which is
// the session audience here, so an API key cannot be presented as a session).
// The lookup callback adds what only the database knows: the key must exist and
// must not be revoked at now. Revocation can be scheduled for a moment ahead, so
// a key whose revocation is still in the future verifies.
//
// japikey reads the wall clock itself for the token's own claims; now is used
// for the revocation comparison.
func (v *Verifier) Verify(ctx context.Context, token string) (Principal, error) {
	var (
		found ActiveKey
		// storeErr is why the lookup failed, if it did. japikey reduces any
		// failure of the callback to a fixed message, so the cause is kept here
		// and reattached: it is what the log needs.
		storeErr error
	)

	lookup := func(ctx context.Context, kid uuid.UUID) (crypto.PublicKey, error) {
		key, ok, err := v.reader.ActiveKey(ctx, kid.String(), v.now())
		if err != nil {
			storeErr = fmt.Errorf("%w: %w", ErrUnavailable, err)

			return nil, storeErr
		}

		if !ok {
			return nil, sql.ErrNoRows
		}

		found = key

		public, err := parseStoredKey(key.JWK, kid)
		if err != nil {
			storeErr = fmt.Errorf("%w: %w", ErrUnavailable, err)

			return nil, storeErr
		}

		return public, nil
	}

	result, err := japikey.Verify(ctx, token, japikey.VerifyConfig{
		BaseIssuerURL:     v.issuer.Base,
		AllowInsecureHTTP: v.issuer.Insecure,
		Timeout:           0,
		Audience:          Audience(KindSession),
	}, lookup)
	if err != nil {
		return Principal{}, classify(err, storeErr)
	}

	subject, _ := result.Claims["sub"].(string)
	if subject != found.UserID {
		// The signed subject must be the account the row belongs to.
		return Principal{}, fmt.Errorf("%w: subject is not the key's owner", ErrUnauthorized)
	}

	return Principal{
		UserID:       found.UserID,
		KeyID:        result.KeyID.String(),
		ExpiresAt:    found.ExpiresAt,
		CredentialID: found.CredentialID,
		Role:         found.Role,
	}, nil
}

// classify maps a japikey failure to ours. Anything that is a verdict on the
// token is ErrUnauthorized; a failure of the store, or of the stored key, is
// ErrUnavailable so the caller can answer 503 and not 401. storeErr is the
// callback's own error when it failed, which japikey's wrapping would hide.
func classify(err, storeErr error) error {
	if storeErr != nil {
		return fmt.Errorf("%w: %w", storeErr, err)
	}

	if _, internal := errors.AsType[*japikey.InternalError](err); internal {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}

	if _, timeout := errors.AsType[*japikey.DatabaseTimeoutError](err); timeout {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}

	return fmt.Errorf("%w: %w", ErrUnauthorized, err)
}

// parseStoredKey reads the public key out of the stored JWK document. The
// document is the {"keys":[...]} form japikey writes; japikey's parser is
// strict about its members, and the key id in it must be the row's. Any failure
// is the stored row being wrong, which the caller reports as the store being
// unavailable: it says nothing about the token.
func parseStoredKey(document []byte, kid uuid.UUID) (crypto.PublicKey, error) {
	var parsed japikey.JWKS

	err := json.Unmarshal(document, &parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errStoredKey, err)
	}

	key, err := parsed.GetPublicKey(kid)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errStoredKey, err)
	}

	return key, nil
}
