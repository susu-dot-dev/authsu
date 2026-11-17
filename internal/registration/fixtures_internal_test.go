package registration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
)

var errDB = errors.New("database is on fire")

const (
	testSecret = "registration-secret-0123456789ABCDEFGHIJ"
	testRPID   = "example.com"
	testOrigin = "https://example.com"
	testAPI    = "https://auth.example.com"
	testCode   = "the-invitation-code-0123456789ABCDEFGHIJKL"
	testName   = "Alice"

	// Strings that recur across the tests.
	noneFormat = "none"
	emptyCase  = "empty"
	firstRun   = "first_run"
)

// testKey returns the challenge-signing key the tests use.
func testKey() []byte { return bytes.Repeat([]byte{0x42}, 32) }

// testNow is the fixed time the tests run at.
func testNow() time.Time { return time.Date(2026, time.November, 16, 12, 0, 0, 0, time.UTC) }

// counterEntropy is deterministic entropy: each byte is the previous plus one,
// starting at 1.
func counterEntropy() io.Reader {
	next := byte(1)

	return readerFunc(func(p []byte) (int, error) {
		for i := range p {
			p[i] = next
			next++
		}

		return len(p), nil
	})
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// fakeReader answers RedeemableInvitationType from a fixed table.
type fakeReader struct {
	// types maps a code hash (as a string) to the invitation type.
	types map[string]string
	err   error
}

func (f *fakeReader) RedeemableInvitationType(_ context.Context, hash []byte, _ time.Time) (string, bool, error) {
	if f.err != nil {
		return "", false, f.err
	}

	invitationType, ok := f.types[string(hash)]

	return invitationType, ok, nil
}

// fakeBatch records the batches it receives and returns a configured error.
type fakeBatch struct {
	err     error
	batches [][]atomic.Statement
}

func (f *fakeBatch) run(_ context.Context, statements ...atomic.Statement) ([]atomic.Result, error) {
	f.batches = append(f.batches, statements)

	return make([]atomic.Result, len(statements)), f.err
}

func getenv(overrides map[string]string) func(string) string {
	values := map[string]string{
		SecretHMAC:   testSecret,
		VarAPIOrigin: testAPI,
		VarUIOrigin:  testOrigin,
	}

	maps.Copy(values, overrides)

	return func(name string) string { return values[name] }
}

// fixture is a service wired to fakes, with a clock and ids we control.
type fixture struct {
	svc     *Service
	reader  *fakeReader
	batcher *fakeBatch
	ids     int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	fix := &fixture{
		reader:  &fakeReader{types: map[string]string{string(codeHash(testCode)): firstRun}, err: nil},
		batcher: &fakeBatch{err: nil, batches: nil},
		ids:     0,
		svc:     nil,
	}

	fix.svc = NewService(Deps{
		Reader:  fix.reader,
		Batch:   fix.batcher.run,
		Now:     testNow,
		Entropy: counterEntropy(),
		NewID: func() string {
			fix.ids++

			return fmt.Sprintf("00000000-0000-7000-8000-%012d", fix.ids)
		},
	})

	return fix
}

func request(t *testing.T, body any) httpapi.Request {
	t.Helper()

	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	return httpapi.Request{Method: http.MethodPost, Path: "/", Context: t.Context(), Query: nil, Body: data}
}

// failureOf returns the classified error of a handler result.
func failureOf(t *testing.T, err error) *apierr.Error {
	t.Helper()

	if err == nil {
		t.Fatal("handler succeeded, want an error")
	}

	return apierr.As(err)
}

// wantFailure checks the kind and code of a handler failure.
func wantFailure(t *testing.T, err error, kind apierr.Kind, code string) {
	t.Helper()

	failure := failureOf(t, err)
	if failure.Kind != kind || failure.Code != code {
		t.Errorf("error = (%d, %q), want (%d, %q)", failure.Kind, failure.Code, kind, code)
	}
}

// begin runs the begin handler and decodes its response.
func begin(t *testing.T, fix *fixture, env func(string) string, body any) (creationOptions, error) {
	t.Helper()

	resp, err := fix.svc.BeginHandler(env)(request(t, body)).Get()
	if err != nil {
		return creationOptions{}, fmt.Errorf("begin: %w", err)
	}

	if resp.Status != http.StatusOK {
		t.Fatalf("begin status = %d, want %d", resp.Status, http.StatusOK)
	}

	options, ok := resp.Body.(creationOptions)
	if !ok {
		t.Fatalf("begin body is %T", resp.Body)
	}

	return options, nil
}

// finish runs the finish handler.
func finish(t *testing.T, fix *fixture, env func(string) string, body FinishRequest) (FinishResponse, int, error) {
	t.Helper()

	resp, err := fix.svc.FinishHandler(env)(request(t, body)).Get()
	if err != nil {
		return FinishResponse{}, 0, fmt.Errorf("finish: %w", err)
	}

	out, ok := resp.Body.(FinishResponse)
	if !ok {
		t.Fatalf("finish body is %T", resp.Body)
	}

	return out, resp.Status, nil
}

// beginThenRespond runs a full begin and has the authenticator answer it.
func beginThenRespond(t *testing.T, fix *fixture, auth authenticator) FinishRequest {
	t.Helper()

	options, err := begin(t, fix, getenv(nil), BeginRequest{InvitationCode: testCode, Name: testName})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	return auth.respond(t, options)
}
