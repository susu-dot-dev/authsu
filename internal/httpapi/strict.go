package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Strictness failures, classified by decodeError.
var (
	errUnknownMember   = errors.New("unknown member")
	errDuplicateMember = errors.New("repeated member")
	errInvalidText     = errors.New("text is not valid UTF-8")
	errTooManyItems    = errors.New("array has too many items")
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
//     escapes both decode to it, and no honest client sends it;
//   - an array member whose field has a `maxitems:"N"` tag may hold at most N
//     items. The walk stops at item N+1, so an oversized array is refused
//     (never truncated) before the decoder allocates it.
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

	return truncated(checkToken(dec, token, t, noLimit))
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
//
// limit is the most items an array value may hold, or noLimit.
func checkValue(dec *json.Decoder, t reflect.Type, limit int) error {
	token, err := dec.Token()
	if err != nil {
		return err //nolint:wrapcheck // decodeError classifies the decoder's errors
	}

	return checkToken(dec, token, t, limit)
}

// noLimit means an array may hold any number of items (the body cap still
// bounds it).
const noLimit = -1

// checkToken checks the value that starts with token. limit applies only if
// the value is an array.
func checkToken(dec *json.Decoder, token json.Token, t reflect.Type, limit int) error {
	t = indirect(t)

	switch value := token.(type) {
	case string:
		return checkText(value)
	case json.Delim:
		var err error

		if value == '[' {
			err = checkArray(dec, elemType(t), limit)
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

func checkArray(dec *json.Decoder, elem reflect.Type, limit int) error {
	for count := 0; dec.More(); count++ {
		if limit != noLimit && count >= limit {
			return fmt.Errorf("%w: more than %d", errTooManyItems, limit)
		}

		err := checkValue(dec, elem, noLimit)
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

		member, limit, known := memberType(t, name)
		if !known {
			return fmt.Errorf("%w: %q", errUnknownMember, name)
		}

		err = checkValue(dec, member, limit)
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

// memberType is the type of member name of an object decoded into t, the most
// items it may hold if it is an array (noLimit if none is set), and whether t
// has such a member. A nil type means no structure is known.
func memberType(t reflect.Type, name string) (reflect.Type, int, bool) {
	if t == nil {
		return nil, noLimit, true
	}

	switch t.Kind() { //nolint:exhaustive // only structs and maps give members a type
	case reflect.Struct:
		for field := range t.Fields() {
			if jsonName(field) == name {
				return field.Type, maxItems(field), true
			}
		}

		return nil, noLimit, false
	case reflect.Map:
		return t.Elem(), noLimit, true
	default:
		return nil, noLimit, true
	}
}

// maxItems is the limit a field's `maxitems:"N"` tag sets, or noLimit. A tag
// that is not a non-negative integer is a programming error, so it panics: the
// handler's recover turns that into an Internal error rather than silently
// leaving the array unbounded.
func maxItems(field reflect.StructField) int {
	tag, ok := field.Tag.Lookup("maxitems")
	if !ok {
		return noLimit
	}

	limit, err := strconv.Atoi(tag)
	if err != nil || limit < 0 {
		panic(fmt.Sprintf("httpapi: field %s has an invalid maxitems tag %q", field.Name, tag))
	}

	return limit
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
