package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// Strictness failures, classified by decodeError.
var (
	errUnknownMember   = errors.New("unknown member")
	errDuplicateMember = errors.New("repeated member")
	errInvalidText     = errors.New("text is not valid UTF-8")
)

// checkStrict reads one JSON value from dec and checks it against t, the Go
// type it will be decoded into. encoding/json matches member names
// case-insensitively, keeps the last of a repeated name, and replaces invalid
// UTF-8 with U+FFFD, so one body could mean one thing to another parser (a
// proxy, a log pipeline) and another to us. checkStrict refuses all three:
//
//   - a member of a struct must be named exactly as its json tag (or field
//     name) says;
//   - a name may appear once per object;
//   - no name or string may contain U+FFFD. Invalid UTF-8 and lone surrogate
//     escapes both decode to it, and no honest client sends it.
//
// Where t gives no structure (an interface, json.RawMessage, a scalar given an
// object) only the last two rules apply, and decoding reports any type error.
// Embedded structs are not promoted: a type decoded here must name its members
// directly.
func checkStrict(dec *json.Decoder, t reflect.Type) error {
	token, err := dec.Token()
	if err != nil {
		// io.EOF here means the body is empty.
		return err //nolint:wrapcheck // decodeError classifies the decoder's errors
	}

	return truncated(checkToken(dec, token, t))
}

// truncated reports input that ends after the first token as a truncated
// body (io.ErrUnexpectedEOF, as encoding/json does), not an empty one.
func truncated(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}

	return err
}

// checkValue reads and checks the next value.
func checkValue(dec *json.Decoder, t reflect.Type) error {
	token, err := dec.Token()
	if err != nil {
		return err //nolint:wrapcheck // decodeError classifies the decoder's errors
	}

	return checkToken(dec, token, t)
}

// checkToken checks the value that starts with token.
func checkToken(dec *json.Decoder, token json.Token, t reflect.Type) error {
	t = indirect(t)

	switch value := token.(type) {
	case string:
		return checkText(value)
	case json.Delim:
		var err error

		if value == '[' {
			err = checkArray(dec, elemType(t))
		} else {
			err = checkObject(dec, t)
		}

		if err != nil {
			return err
		}

		// The closing bracket or brace.
		_, err = dec.Token()

		return err //nolint:wrapcheck // decodeError classifies the decoder's errors
	default:
		return nil
	}
}

func checkArray(dec *json.Decoder, elem reflect.Type) error {
	for dec.More() {
		err := checkValue(dec, elem)
		if err != nil {
			return err
		}
	}

	return nil
}

func checkObject(dec *json.Decoder, t reflect.Type) error {
	seen := make(map[string]struct{})

	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return err //nolint:wrapcheck // decodeError classifies the decoder's errors
		}

		// The decoder yields a string here: a non-string key is a syntax
		// error it has already reported.
		name, _ := token.(string)

		err = checkText(name)
		if err != nil {
			return err
		}

		if _, repeated := seen[name]; repeated {
			return fmt.Errorf("%w: %q", errDuplicateMember, name)
		}

		seen[name] = struct{}{}

		member, known := memberType(t, name)
		if !known {
			return fmt.Errorf("%w: %q", errUnknownMember, name)
		}

		err = checkValue(dec, member)
		if err != nil {
			return err
		}
	}

	return nil
}

func checkText(s string) error {
	if strings.ContainsRune(s, utf8.RuneError) {
		return errInvalidText
	}

	return nil
}

// memberType is the type of member name of an object decoded into t, and
// whether t has such a member. A nil type means no structure is known.
func memberType(t reflect.Type, name string) (reflect.Type, bool) {
	if t == nil {
		return nil, true
	}

	switch t.Kind() { //nolint:exhaustive // only structs and maps give members a type
	case reflect.Struct:
		for field := range t.Fields() {
			if jsonName(field) == name {
				return field.Type, true
			}
		}

		return nil, false
	case reflect.Map:
		return t.Elem(), true
	default:
		return nil, true
	}
}

// elemType is the element type of an array decoded into t, or nil.
func elemType(t reflect.Type) reflect.Type {
	if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
		return t.Elem()
	}

	return nil
}

func indirect(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	return t
}

// jsonName is the member name encoding/json uses for field.
func jsonName(field reflect.StructField) string {
	name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
	if name == "" {
		return field.Name
	}

	return name
}
