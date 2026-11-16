package webauthn

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxClientDataJSON caps clientDataJSON before it is parsed. A real one is
// about 150 bytes plus the challenge; it is client-supplied, so it is bounded.
const MaxClientDataJSON = 2048

// createType is the clientData type of a registration ceremony.
const createType = "webauthn.create"

var (
	errNotObject    = errors.New("not a JSON object")
	errDuplicateKey = errors.New("duplicate key")
	errTrailingData = errors.New("trailing data")
	errNotString    = errors.New("not a string")
	errMissing      = errors.New("missing member")
	errNotBool      = errors.New("not a boolean")
)

// ParseClientData verifies clientDataJSON for a registration at rp and returns
// the challenge bytes the browser echoed, plus the SHA-256 of the JSON (the
// client data hash, which an attestation signature would cover).
//
// The challenge is not compared here: the caller owns challenge semantics (our
// challenges are signed, not stored). It is returned decoded, from the browser
// as it ran the ceremony, which is the only copy of the challenge that is bound
// to the authenticator's response.
//
// The document is read strictly. encoding/json would match member names
// case-insensitively and keep the last of a repeated name, so a document could
// mean one thing to the browser and another to us. Instead names are matched
// exactly and a repeated name is an error.
func ParseClientData(raw []byte, rp RelyingParty) ([]byte, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte

	if len(raw) == 0 || len(raw) > MaxClientDataJSON {
		return nil, zero, fmt.Errorf("%w: size %d", ErrClientData, len(raw))
	}

	members, err := strictObject(raw)
	if err != nil {
		return nil, zero, fmt.Errorf("%w: %w", ErrClientData, err)
	}

	err = checkCeremony(members, rp)
	if err != nil {
		return nil, zero, fmt.Errorf("%w: %w", ErrClientData, err)
	}

	challenge, err := echoedChallenge(members)
	if err != nil {
		return nil, zero, fmt.Errorf("%w: %w", ErrClientData, err)
	}

	return challenge, sha256.Sum256(raw), nil
}

var (
	errWrongType   = errors.New("wrong ceremony type")
	errWrongOrigin = errors.New("origin is not the relying party's")
	errEmptyChal   = errors.New("empty challenge")
)

// checkCeremony requires a registration ceremony from exactly our origin, made
// outside any cross-origin context.
func checkCeremony(members map[string]json.RawMessage, rp RelyingParty) error {
	typ, err := requiredString(members, "type")
	if err != nil {
		return err
	}

	if typ != createType {
		return fmt.Errorf("%w: %q", errWrongType, typ)
	}

	origin, err := requiredString(members, "origin")
	if err != nil {
		return err
	}

	// Origin is compared exactly, as a whole string: the browser writes the
	// serialized origin, so there is nothing to normalise, and a looser match
	// (prefix, suffix, parsed host) is how origin checks get bypassed.
	if subtle.ConstantTimeCompare([]byte(origin), []byte(rp.Origin)) != 1 {
		return fmt.Errorf("%w: %q", errWrongOrigin, origin)
	}

	return rejectCrossOrigin(members)
}

// echoedChallenge returns the decoded challenge the browser echoed.
func echoedChallenge(members map[string]json.RawMessage) ([]byte, error) {
	encoded, err := requiredString(members, "challenge")
	if err != nil {
		return nil, err
	}

	// Section 7.1 step 8 compares C.challenge with the base64url encoding of
	// the challenge; strict decoding gives that encoding exactly one
	// spelling, so comparing the decoded bytes is the same comparison.
	challenge, err := decodeBase64URL(encoded)
	if err != nil {
		return nil, fmt.Errorf("challenge: %w", err)
	}

	if len(challenge) == 0 {
		return nil, errEmptyChal
	}

	return challenge, nil
}

// strictObject decodes a JSON object into its members, left undecoded. It
// rejects a repeated member name and anything after the object.
func strictObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))

	open, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	if delim, ok := open.(json.Delim); !ok || delim != '{' {
		return nil, errNotObject
	}

	members := make(map[string]json.RawMessage)

	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("read key: %w", err)
		}

		// The decoder yields a string here: a non-string key is a syntax
		// error it has already reported.
		name, _ := key.(string)

		var value json.RawMessage

		err = decoder.Decode(&value)
		if err != nil {
			return nil, fmt.Errorf("read value of %q: %w", name, err)
		}

		if _, seen := members[name]; seen {
			return nil, fmt.Errorf("%w: %q", errDuplicateKey, name)
		}

		members[name] = value
	}

	// Consume the closing brace, then require the input to end.
	_, err = decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("read close: %w", err)
	}

	_, err = decoder.Token()
	if !errors.Is(err, io.EOF) {
		return nil, errTrailingData
	}

	return members, nil
}

// requiredString returns the string member name. null is not a string:
// encoding/json would decode it as a no-op and leave "".
func requiredString(members map[string]json.RawMessage, name string) (string, error) {
	value, ok := members[name]
	if !ok {
		return "", fmt.Errorf("%w: %q", errMissing, name)
	}

	var out *string

	err := json.Unmarshal(value, &out)
	if err != nil || out == nil {
		return "", fmt.Errorf("%q: %w", name, errNotString)
	}

	return *out, nil
}

// rejectCrossOrigin refuses a registration made from a cross-origin context.
// crossOrigin is optional, and false means same-origin, so only true is
// refused; but when present it must be a boolean, and null is not one
// (encoding/json would read it as false). topOrigin only accompanies a
// cross-origin context and is refused whenever present.
func rejectCrossOrigin(members map[string]json.RawMessage) error {
	if value, ok := members["crossOrigin"]; ok {
		var cross *bool

		err := json.Unmarshal(value, &cross)
		if err != nil || cross == nil {
			return fmt.Errorf("crossOrigin: %w", errNotBool)
		}

		if *cross {
			return errCrossOrigin
		}
	}

	if _, ok := members["topOrigin"]; ok {
		return errCrossOrigin
	}

	return nil
}

var errCrossOrigin = errors.New("cross-origin registration is not accepted")
