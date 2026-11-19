package secret_test

import (
	"io"
	"sync"
)

// countingReader serves an endless, predictable stream (byte i of the stream
// is byte(i)) and records how much was read, so a test can tell that a caller
// took exactly what it needs and no more.
type countingReader struct {
	mu   sync.Mutex
	read int
}

func (r *countingReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i := range p {
		p[i] = byte((r.read + i) & 0xff)
	}

	r.read += len(p)

	return len(p), nil
}

// total is how many bytes have been read.
func (r *countingReader) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.read
}

// errBoom is a distinct error for failingReader to return.
type fixtureError string

func (e fixtureError) Error() string { return string(e) }

const errBoom = fixtureError("entropy source failed")

// failingReader returns data bytes and then fails with err (io.EOF when err is
// nil), so it models both a short read and a broken source. Each call returns
// at most one byte, which also exercises that Generate keeps reading.
type failingReader struct {
	data []byte
	err  error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 || len(p) == 0 {
		if r.err == nil {
			return 0, io.EOF
		}

		return 0, r.err
	}

	p[0] = r.data[0]
	r.data = r.data[1:]

	return 1, nil
}
