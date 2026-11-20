package fetch_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// errNetwork is what the fake Doer and the fake bodies fail with.
var errNetwork = errors.New("dial tcp 10.0.0.1:443: connect: connection refused")

// testURL is the document URL the tests fetch.
const testURL = "https://client.example/metadata.json"

// body is a response body that records how much was read and that it was
// closed. source is where the bytes come from.
type body struct {
	source io.Reader
	// ended, when set, is the Done channel of the request, and err reports why.
	// A read ends with err when it closes, as the platform's body does.
	ended <-chan struct{}
	err   func() error

	mu     sync.Mutex
	read   int
	closed chan struct{}
	once   sync.Once
}

func newBody(source io.Reader) *body {
	return &body{source: source, closed: make(chan struct{})}
}

func (b *body) Read(p []byte) (int, error) {
	if b.ended != nil {
		return b.readWithContext(p)
	}

	return b.readSource(p)
}

func (b *body) Close() error {
	b.once.Do(func() { close(b.closed) })

	return nil
}

// readWithContext reads from the source on a goroutine and gives up when the
// context ends, which is what the platform's body does for a stalled stream.
func (b *body) readWithContext(p []byte) (int, error) {
	type outcome struct {
		n   int
		err error
	}

	done := make(chan outcome, 1)
	buf := make([]byte, len(p))

	go func() {
		n, err := b.readSource(buf)
		done <- outcome{n, err}
	}()

	select {
	case got := <-done:
		copy(p, buf[:got.n])

		return got.n, got.err
	case <-b.ended:
		return 0, b.err()
	}
}

func (b *body) readSource(p []byte) (int, error) {
	n, err := b.source.Read(p)

	b.mu.Lock()
	b.read += n
	b.mu.Unlock()

	return n, err //nolint:wrapcheck // a test fake passes its source's outcome through unchanged
}

// bytesRead is how many bytes the client took from the body.
func (b *body) bytesRead() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.read
}

// isClosed reports whether Close was called.
func (b *body) isClosed() bool {
	select {
	case <-b.closed:
		return true
	case <-time.After(2 * time.Second):
		return false
	}
}

// blockedSource is a source that never produces a byte and never ends.
type blockedSource struct{}

func (blockedSource) Read([]byte) (int, error) { select {} }

// endless is a reader of an unbounded stream of 'a'.
type endless struct{}

func (endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}

	return len(p), nil
}

// brokenAfter serves data and then fails with errNetwork.
type brokenAfter struct{ data string }

func (b *brokenAfter) Read(p []byte) (int, error) {
	if b.data == "" {
		return 0, errNetwork
	}

	n := copy(p, b.data)
	b.data = b.data[n:]

	return n, nil
}

// reply is what the fake Doer answers with.
type reply struct {
	status        int
	contentTypes  []string
	contentLength int64
	source        io.Reader
}

// jsonReply is a well-formed 200 answer carrying payload.
func jsonReply(payload string) reply {
	return reply{
		status: http.StatusOK, contentTypes: []string{"application/json"},
		contentLength: int64(len(payload)), source: strings.NewReader(payload),
	}
}

// fakeDoer answers every request from one scripted behaviour and records the
// requests it saw and the body it handed out.
type fakeDoer struct {
	reply reply
	// respond, when set, replaces the scripted reply. It may block.
	respond func(*http.Request) (*http.Response, error)

	mu       sync.Mutex
	requests []*http.Request
	body     *body
}

func (d *fakeDoer) do(req *http.Request) (*http.Response, error) {
	d.mu.Lock()
	d.requests = append(d.requests, req)
	d.mu.Unlock()

	if d.respond != nil {
		return d.respond(req)
	}

	header := http.Header{}
	for _, value := range d.reply.contentTypes {
		header.Add("Content-Type", value)
	}

	b := newBody(d.reply.source)
	b.ended, b.err = req.Context().Done(), req.Context().Err

	d.mu.Lock()
	d.body = b
	d.mu.Unlock()

	return &http.Response{
		StatusCode: d.reply.status, Header: header, ContentLength: d.reply.contentLength, Body: b,
	}, nil
}

// seen returns the requests received so far.
func (d *fakeDoer) seen() []*http.Request {
	d.mu.Lock()
	defer d.mu.Unlock()

	return append([]*http.Request(nil), d.requests...)
}

// lastBody is the body of the last scripted reply.
func (d *fakeDoer) lastBody() *body {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.body
}

// blocked is a Doer behaviour that waits for the request's context to end, as
// the platform's fetch does for a server that never answers, and returns the
// context's error.
type blocked struct {
	answer reply
}

func newBlocked(answer reply) *blocked { return &blocked{answer: answer} }

func (b *blocked) respond(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()

	//nolint:wrapcheck // a test fake returns the context's own error, as the platform's fetch does
	return nil, req.Context().Err()
}

// background is the context every test starts from.
func background() context.Context { return context.Background() }
