package apierr_test

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
)

const innerCode = "inner"

var errCause = errors.New("disk on fire")

func TestKindStatus(t *testing.T) {
	t.Parallel()

	tests := map[apierr.Kind]int{
		apierr.Internal:         http.StatusInternalServerError,
		apierr.BadRequest:       http.StatusBadRequest,
		apierr.Unauthorized:     http.StatusUnauthorized,
		apierr.Forbidden:        http.StatusForbidden,
		apierr.NotFound:         http.StatusNotFound,
		apierr.MethodNotAllowed: http.StatusMethodNotAllowed,
		apierr.Conflict:         http.StatusConflict,
		apierr.PayloadTooLarge:  http.StatusRequestEntityTooLarge,
		apierr.RateLimited:      http.StatusTooManyRequests,
		apierr.Unavailable:      http.StatusServiceUnavailable,
		apierr.Kind(200):        http.StatusInternalServerError, // unknown kinds fail closed
	}

	for kind, want := range tests {
		if got := kind.Status(); got != want {
			t.Errorf("Kind(%d).Status() = %d, want %d", kind, got, want)
		}
	}
}

func TestErrorString(t *testing.T) {
	t.Parallel()

	base := apierr.New(apierr.NotFound, "nope", "not here")

	if got, want := base.Error(), "nope: not here"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}

	withCause := base.WithCause(errCause)
	if got, want := withCause.Error(), "nope: not here: disk on fire"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}

	if !errors.Is(withCause, errCause) {
		t.Error("cause is not reachable with errors.Is")
	}
}

func TestWithHelpersDoNotMutate(t *testing.T) {
	t.Parallel()

	base := apierr.New(apierr.BadRequest, "bad", "bad input")
	withData := base.WithData(map[string]string{"field": "code"})
	withCause := base.WithCause(errCause)

	if base.Data != nil || errors.Unwrap(base) != nil {
		t.Error("base was mutated")
	}

	if withData.Data == nil || withCause.Unwrap() == nil {
		t.Error("copy is missing its data or cause")
	}
}

func TestWrap(t *testing.T) {
	t.Parallel()

	inner := apierr.New(apierr.NotFound, innerCode, innerCode)

	tests := map[string]struct {
		err      error
		wantNil  bool
		wantKind apierr.Kind
		wantCode string
	}{
		"nil stays nil":       {err: nil, wantNil: true},
		"plain error":         {err: errCause, wantKind: apierr.Conflict, wantCode: "outer"},
		"innermost wins":      {err: inner, wantKind: apierr.NotFound, wantCode: innerCode},
		"wins through %w":     {err: fmt.Errorf("ctx: %w", inner), wantKind: apierr.NotFound, wantCode: innerCode},
		"wins through joined": {err: errors.Join(errCause, inner), wantKind: apierr.NotFound, wantCode: innerCode},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := apierr.Wrap(tt.err, apierr.Conflict, "outer", "outer")
			if tt.wantNil {
				if err != nil {
					t.Fatalf("Wrap = %v, want nil", err)
				}

				return
			}

			got := apierr.As(err)
			if got.Kind != tt.wantKind || got.Code != tt.wantCode {
				t.Errorf("Wrap = (%d, %q), want (%d, %q)", got.Kind, got.Code, tt.wantKind, tt.wantCode)
			}
		})
	}
}

func TestAs(t *testing.T) {
	t.Parallel()

	classified := apierr.New(apierr.Forbidden, "no", "no")
	found := apierr.As(fmt.Errorf("ctx: %w", classified))
	if found != classified {
		t.Errorf("As did not find the wrapped *Error")
	}

	got := apierr.As(errCause)
	if got.Kind != apierr.Internal || got.Code != "internal" {
		t.Errorf("As(unclassified) = (%d, %q), want Internal", got.Kind, got.Code)
	}

	if !strings.Contains(got.Error(), "disk on fire") || !errors.Is(got, errCause) {
		t.Errorf("unclassified error lost its cause: %v", got)
	}
}
