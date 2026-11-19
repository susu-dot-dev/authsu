// Package jws signs a JSON Web Token as an RS256 JWS in compact form
// (RFC 7515, RFC 7518 section 3.3) and does nothing else.
//
// authsu only signs JWTs, and every byte is server-controlled. If authsu ever
// has to read or verify a JWT, replace this whole package with a vetted crypto
// library; do not extend it to parse.
//
// That is why it is small enough to read at once, and why there is deliberately
// no JWT library: the header is one fixed shape, {"alg":"RS256","kid":...,
// "typ":"JWT"}, written here rather than chosen by a caller, so there is no
// "alg" for anyone to confuse. The one thing read back is the claims this
// package has just encoded itself, to refuse a number a JavaScript client would
// silently round (see Sign); that is a check of its own output, not a parser of
// anything received.
//
// The signature is RSASSA-PKCS1-v1_5 with SHA-256, which is deterministic: the
// same key and claims always give the same token, and no entropy is read. The
// standard library is all it uses.
package jws

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	// maxSafeInteger is 2^53-1, the largest integer a JSON number can carry
	// through a JavaScript client unchanged. A claim beyond it is refused.
	maxSafeInteger = 1<<53 - 1
	// maxKeyIDLen bounds a key ID. The ones authsu uses are 11 characters.
	maxKeyIDLen = 64
)

// Reasons a token is not signed. They describe the server's own input, never a
// request, so a caller treats every one as an internal error.
var (
	errKey    = errors.New("jws: no signing key")
	errKeyID  = errors.New("jws: the key ID must be 1 to 64 base64url characters")
	errClaims = errors.New("jws: the claims must be a JSON object")
	errNumber = errors.New("jws: a claim is a number that is not an integer within 2^53-1")
)

// Sign returns the compact JWS of claims, signed with key and carrying kid in
// its header: base64url(header) "." base64url(claims) "." base64url(signature),
// without padding.
//
// claims is any value encoding/json writes as a JSON object, typically a struct
// with json tags. Every number in it must be an integer within 2^53-1 in
// magnitude, as the NumericDate claims (iat, exp, auth_time) are: a fraction, an
// exponent form or a larger integer is refused, so no client reads back a value
// other than the one signed. kid must be 1 to 64 characters of the base64url
// alphabet. The key's size is the caller's to judge.
//
// Nothing is returned for a token that is not signed in full.
func Sign(key *rsa.PrivateKey, kid string, claims any) (string, error) {
	if key == nil {
		return "", errKey
	}

	if !validKeyID(kid) {
		return "", errKeyID
	}

	payload, err := encodeClaims(claims)
	if err != nil {
		return "", err
	}

	// kid is only base64url characters, so it needs no JSON escaping.
	header := `{"alg":"RS256","kid":"` + kid + `","typ":"JWT"}`
	signingInput := b64([]byte(header)) + "." + b64(payload)
	digest := sha256.Sum256([]byte(signingInput))

	// PKCS #1 v1.5 signing is deterministic, so no random source is passed.
	signature, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("jws: sign: %w", err)
	}

	return signingInput + "." + b64(signature), nil
}

// b64 is base64url without padding.
func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

// validKeyID reports whether kid is 1 to maxKeyIDLen characters of the base64url
// alphabet.
func validKeyID(kid string) bool {
	return kid != "" && len(kid) <= maxKeyIDLen &&
		strings.Trim(kid, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") == ""
}

// encodeClaims is the JSON of claims, which must be an object with only safe
// integers as numbers.
func encodeClaims(claims any) ([]byte, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("jws: encode claims: %w", err)
	}

	if !bytes.HasPrefix(payload, []byte("{")) {
		return nil, errClaims
	}

	err = checkNumbers(payload)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

// checkNumbers refuses the first number in payload that is not an integer
// within 2^53-1. payload is what encoding/json just produced from the claims,
// so it is well formed and the scan cannot fail on syntax.
func checkNumbers(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}

		// coverage:ignore: encoding/json emitted these bytes a moment ago, so they are well formed
		if err != nil {
			return fmt.Errorf("jws: scan claims: %w", err)
		}

		number, isNumber := token.(json.Number)
		if isNumber && !safeInteger(number) {
			return errNumber
		}
	}
}

// safeInteger reports whether n is written as a plain decimal integer whose
// magnitude is at most 2^53-1.
func safeInteger(n json.Number) bool {
	value, err := strconv.ParseInt(string(n), 10, 64)

	return err == nil && value >= -maxSafeInteger && value <= maxSafeInteger
}
