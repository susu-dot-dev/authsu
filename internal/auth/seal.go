package auth

import (
	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/result"
)

// Sealer encrypts a secret to a recipient (internal/seal.Seal in production). It
// is a dependency of the routes that return a secret, so a test can make it
// fail, which no valid recipient does.
type Sealer func(recipient []byte, plaintext string) (string, error)

// CodePublicKeyRequired is a request for a secret from a credential that may
// only be sent one sealed, that carried no public key.
const CodePublicKeyRequired = "public_key_required"

// Recipient decides who a secret in a response is sealed to, from the request's
// publicKey member (nil when it was absent or null) and the credential.
//
// A response that carries a secret may be routed through inference, whose logs
// keep it, when the caller is software a model drives. A session is a browser's:
// it comes from a passkey sign-in and not from anything a model holds, so a
// session may omit the key and be sent the secret as it is. Every other
// credential must send one, or is refused before anything is written. A key sent
// by anyone is used.
//
// The result is the zero PublicKey when the secret is to be sent in plaintext.
func Recipient(who Principal, raw *string) result.Result[input.PublicKey] {
	if raw != nil {
		return result.Of(input.ParsePublicKey(*raw))
	}

	if who.Kind == KindSession {
		return result.Ok(input.PublicKey{})
	}

	return result.Fail[input.PublicKey](
		apierr.New(apierr.BadRequest, CodePublicKeyRequired,
			"publicKey is required: a secret is only sent to this credential sealed to a key"))
}

// SealTo is the secret as the response carries it: sealed to the recipient with
// seal, or "" when there is no recipient and the secret is to be sent as it is.
// A recipient that cannot be sealed to (a key of low order) is the client's
// mistake and a 400, and as the secret is sealed before the write that creates
// it, nothing has been created.
func SealTo(seal Sealer, to input.PublicKey, secret string) result.Result[string] {
	if !to.Present() {
		return result.Ok("")
	}

	sealed, err := seal(to.Recipient(), secret)
	if err != nil {
		return result.Fail[string](
			apierr.New(apierr.BadRequest, input.CodeInvalidPublicKey, "publicKey cannot be sealed to").WithCause(err))
	}

	return result.Ok(sealed)
}
