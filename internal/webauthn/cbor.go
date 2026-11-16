package webauthn

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const (
	// maxNestedLevels bounds CBOR nesting. Everything we accept is at most two
	// levels deep (the attestation object's attStmt map inside the object).
	maxNestedLevels = 4
	// maxCBORCollection bounds the elements of any array or map before
	// decoding allocates for them. Ours have at most five members.
	maxCBORCollection = 16
)

// errNotCanonical means an item decoded but was not written in CTAP2 canonical
// form: map keys out of order, or an integer or length not in its shortest
// encoding.
var errNotCanonical = errors.New("not in CTAP2 canonical CBOR form")

// strictOptions is the strict decoding profile used for every CBOR item we
// accept. WebAuthn requires authenticators to emit CTAP2 canonical CBOR and
// says decoders SHOULD reject anything else (section 2.4):
//
//   - a repeated map key is an error (a duplicate could mean different things
//     to different parsers);
//   - indefinite-length items and tags are refused;
//   - a key the destination struct does not name exactly is an error, so a
//     field we were not written to understand, or one spelled in another
//     case, is rejected, not skipped or folded;
//   - nesting and collection sizes are bounded.
//
// The decoder cannot check canonical form itself; decoder.requireCanonical
// does, by re-encoding.
func strictOptions() cbor.DecOptions {
	return cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
		MaxNestedLevels:   maxNestedLevels,
		MaxArrayElements:  maxCBORCollection,
		MaxMapPairs:       maxCBORCollection,
	}
}

// decoder decodes CBOR under the strict profile, and re-encodes it under the
// CTAP2 canonical one to check canonical form.
type decoder struct {
	mode      cbor.DecMode
	canonical cbor.EncMode
}

// newDecoder builds a decoder from opts and the canonical encoding options
// enc. It fails only for an invalid option set, which strictOptions and
// cbor.CTAP2EncOptions never are; taking both as parameters keeps those
// failures reachable from a test.
func newDecoder(opts cbor.DecOptions, enc cbor.EncOptions) (decoder, error) {
	mode, err := opts.DecMode()
	if err != nil {
		return decoder{}, fmt.Errorf("build CBOR decoder: %w", err)
	}

	canonical, err := enc.EncMode()
	if err != nil {
		return decoder{}, fmt.Errorf("build CBOR encoder: %w", err)
	}

	return decoder{mode: mode, canonical: canonical}, nil
}

// unmarshal decodes data, which must hold exactly one CBOR item, into v. Bytes
// after the item are an error.
func (d decoder) unmarshal(data []byte, v any) error {
	return d.mode.Unmarshal(data, v) //nolint:wrapcheck // callers wrap it with their sentinel
}

// unmarshalFirst decodes the first CBOR item in data into v and returns the
// bytes after it, for an item embedded in a longer byte string.
func (d decoder) unmarshalFirst(data []byte, v any) ([]byte, error) {
	return d.mode.UnmarshalFirst(data, v) //nolint:wrapcheck // callers wrap it with their sentinel
}

// requireCanonical checks that data, which must hold exactly one CBOR item, is
// in CTAP2 canonical form. It decodes the item into generic values and
// re-encodes them canonically: canonical form is unique, so the bytes are
// canonical exactly when the two agree.
func (d decoder) requireCanonical(data []byte) error {
	var value any

	err := d.unmarshal(data, &value)
	if err != nil {
		return err
	}

	again, err := d.canonical.Marshal(value)
	// coverage:ignore: every value the decoder produces (maps, strings, integers, simple values) encodes
	if err != nil {
		return fmt.Errorf("re-encode: %w", err)
	}

	if !bytes.Equal(again, data) {
		return errNotCanonical
	}

	return nil
}
