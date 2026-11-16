// Package result provides Result, a value that holds either a T or an error,
// so a sequence of fallible steps reads as one chain instead of a repeated
// `if err != nil { return ... }`.
//
// The first step to fail ends the chain: every later step is skipped and the
// error is carried through unchanged. Chains are ordinary values, so each step
// is a small named function that is tested on its own.
//
// Methods that change the value's type (Then, Map) are generic methods, which
// need Go 1.27.
package result

// Result is either a value or an error, never both. The zero Result is a
// successful zero value.
type Result[T any] struct {
	value T
	err   error
}

// Ok returns a successful Result holding value.
func Ok[T any](value T) Result[T] {
	return Result[T]{value: value, err: nil}
}

// Fail returns a failed Result holding err.
func Fail[T any](err error) Result[T] {
	var zero T

	return Result[T]{value: zero, err: err}
}

// Of adapts the (T, error) pair that Go functions return, so any such function
// can start or join a chain: Of(os.ReadFile(name)). When err is non-nil the
// value is discarded, so a Result never holds both: a failed Result always has
// the zero value.
func Of[T any](value T, err error) Result[T] {
	if err != nil {
		return Fail[T](err)
	}

	return Ok(value)
}

// Get returns the value and error, for handing back to ordinary Go code.
func (r Result[T]) Get() (T, error) {
	return r.value, r.err
}

// Err returns the error, or nil when the Result succeeded.
func (r Result[T]) Err() error {
	return r.err
}

// Then runs next on the value. It may return a different type, and may fail.
func (r Result[T]) Then[U any](next func(T) (U, error)) Result[U] {
	if r.err != nil {
		return Fail[U](r.err)
	}

	return Of(next(r.value))
}

// Map runs a step that cannot fail.
func (r Result[T]) Map[U any](next func(T) U) Result[U] {
	if r.err != nil {
		return Fail[U](r.err)
	}

	return Ok(next(r.value))
}

// Check runs a guard on the value. The value passes through unchanged when the
// guard returns nil; otherwise the Result fails with the guard's error.
func (r Result[T]) Check(guard func(T) error) Result[T] {
	if r.err == nil {
		r.err = guard(r.value)
	}

	return r
}

// MapErr transforms a failure, for example to classify or add context. It is
// not called when the Result succeeded.
func (r Result[T]) MapErr(next func(error) error) Result[T] {
	if r.err != nil {
		r.err = next(r.err)
	}

	return r
}
