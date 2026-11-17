package invitations

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/atomic"
)

func createCall(t *testing.T, fix *fixture, body any) (CreateResponse, error) {
	t.Helper()

	handler := fix.svc.Handlers(getenv).Collection[http.MethodPost]

	resp, err := handler(request(t, http.MethodPost, body, "")).Get()
	if err != nil {
		return CreateResponse{}, fmt.Errorf("handler: %w", err)
	}

	if resp.Status != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.Status)
	}

	created, ok := resp.Body.(CreateResponse)
	if !ok {
		t.Fatalf("body is a %T, want a CreateResponse", resp.Body)
	}

	return created, nil
}

func TestCreateReturnsTheInvitationAndItsCodeOnce(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	expires := testNow().Unix() + 3600

	created, err := createCall(t, fix, CreateRequest{
		Type: testType, NumInvites: 3, Label: "November workshop", ExpiresAt: &expires,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 32 bytes of 0xab, base64url without padding: 43 characters.
	want := CreateResponse{
		ID: testNewID, Type: testType, Label: "November workshop", NumInvites: 3, Uses: 0,
		Status: StatusActive, ExpiresAt: &expires, RevokedAt: nil, CreatedBy: new(testAdminID),
		CreatedAt: testNow().Unix(),
		Code:      "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s",
	}

	if !reflect.DeepEqual(created, want) {
		t.Errorf("created = %+v, want %+v", created, want)
	}

	if len(created.Code) != 43 {
		t.Errorf("code is %d characters, want 43", len(created.Code))
	}
}

// TestCreateStoresOnlyTheHashOfTheCode: the write binds the SHA-256 of the code
// and never the code, and records who created it.
func TestCreateStoresOnlyTheHashOfTheCode(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	created, err := createCall(t, fix, CreateRequest{Type: testType, NumInvites: 1})
	if err != nil {
		t.Fatal(err)
	}

	if len(fix.batcher.batches) != 1 || len(fix.batcher.batches[0]) != 1 {
		t.Fatalf("batches = %v, want one with one statement", fix.batcher.batches)
	}

	stmt := fix.batcher.batches[0][0]
	if stmt.Query != insertQuery || len(stmt.Args) != strings.Count(stmt.Query, "?") {
		t.Fatalf("statement = %q with %d args", stmt.Query, len(stmt.Args))
	}

	// id, code_hash, type, label, num_invites, expires_at (no expiry is NULL,
	// "never expires" in every query), created_by, created_at.
	want := []any{testNewID, codeHash(created.Code), testType, "", int64(1), nil, testAdminID, testNow().Unix()}
	if !reflect.DeepEqual(stmt.Args, want) {
		t.Errorf("args = %v, want %v", stmt.Args, want)
	}

	if slices.Contains(stmt.Args, any(created.Code)) {
		t.Error("the plaintext code was bound into the write")
	}
}

// TestCreateRefusesBadInput: each refusal is a 400 with its own code, comes
// before the store is touched, and writes nothing.
func TestCreateRefusesBadInput(t *testing.T) {
	t.Parallel()

	now := testNow().Unix()
	past := now - 1
	tooLong := strings.Repeat("é", MaxLabelChars+1)
	valid := func(mutate func(*CreateRequest)) CreateRequest {
		in := CreateRequest{Type: testType, NumInvites: 1, Label: "", ExpiresAt: nil}
		mutate(&in)

		return in
	}

	tests := map[string]struct {
		body any
		code string
	}{
		"no type":          {valid(func(in *CreateRequest) { in.Type = "" }), CodeInvalidType},
		"unknown type":     {valid(func(in *CreateRequest) { in.Type = "nonsense" }), CodeInvalidType},
		"first run":        {valid(func(in *CreateRequest) { in.Type = firstRunType }), CodeInvalidType},
		"zero invites":     {valid(func(in *CreateRequest) { in.NumInvites = 0 }), CodeInvalidNum},
		"negative invites": {valid(func(in *CreateRequest) { in.NumInvites = -1 }), CodeInvalidNum},
		"too many invites": {valid(func(in *CreateRequest) { in.NumInvites = MaxNumInvites + 1 }), CodeInvalidNum},
		"label too long":   {valid(func(in *CreateRequest) { in.Label = tooLong }), CodeInvalidLabel},
		"expired already":  {valid(func(in *CreateRequest) { in.ExpiresAt = &past }), CodeInvalidExpiry},
		"expires now":      {valid(func(in *CreateRequest) { in.ExpiresAt = &now }), CodeInvalidExpiry},
		"unknown field":    {`{"type":"workshop","numInvites":1,"role":"admin"}`, "unknown_field"},
		"invites string":   {`{"type":"workshop","numInvites":"3"}`, "invalid_field_type"},
		"invites fraction": {`{"type":"workshop","numInvites":1.5}`, "invalid_field_type"},
		"empty body":       {"", "empty_body"},
		"not json":         {"nope", "invalid_json"},
		"missing invites":  {`{"type":"workshop"}`, CodeInvalidNum},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)

			_, err := createCall(t, fix, tt.body)
			wantFailure(t, err, apierr.BadRequest, tt.code)

			if len(fix.batcher.batches) != 0 {
				t.Errorf("a refused request wrote: %v", fix.batcher.batches)
			}
		})
	}
}

// TestCreateRefusesEveryTypeWhileNoneIsCreatable is the state production is in:
// no invitation type exists to create, so POST can only refuse, and for first
// run it says where the invitation comes from.
func TestCreateRefusesEveryTypeWhileNoneIsCreatable(t *testing.T) {
	t.Parallel()

	if got := CreatableTypes(); len(got) != 0 {
		t.Fatalf("CreatableTypes = %v; give a new type a role in registration.RoleFor and cover it here", got)
	}

	fix := newFixture(t)
	svc := NewService(Deps{
		Sessions: fix.sessions, Reader: fix.reader, Batch: fix.batcher.run, Now: testNow,
		Entropy: fix.entropy, NewID: func() string { return testNewID }, Types: CreatableTypes(),
	})
	handler := svc.Handlers(getenv).Collection[http.MethodPost]

	for _, invitationType := range []string{firstRunType, testType, ""} {
		_, err := handler(request(t, http.MethodPost, CreateRequest{Type: invitationType, NumInvites: 1}, "")).Get()
		wantFailure(t, err, apierr.BadRequest, CodeInvalidType)
	}

	_, err := handler(request(t, http.MethodPost, CreateRequest{Type: firstRunType, NumInvites: 1}, "")).Get()
	if got := apierr.As(err).Description; !strings.Contains(got, "/api/first-run") {
		t.Errorf("first-run refusal %q does not point at /api/first-run", got)
	}
}

func TestCreateFailures(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		setup func(*fixture)
		kind  apierr.Kind
		code  string
	}{
		"entropy fails": {
			setup: func(f *fixture) { f.svc.entropy = failingReader{} },
			kind:  apierr.Internal, code: CodeCodeFailed,
		},
		dbUnavailable: {
			setup: func(f *fixture) { f.batcher.err = errDB },
			kind:  apierr.Unavailable, code: CodeCreateFailed,
		},
		"conflict": {
			setup: func(f *fixture) { f.batcher.err = errors.Join(atomic.ErrConflict, errDB) },
			kind:  apierr.Conflict, code: CodeCreateFailed,
		},
		schemaRejects: {
			setup: func(f *fixture) { f.batcher.err = errors.Join(atomic.ErrRejected, errDB) },
			kind:  apierr.Internal, code: CodeCreateRejected,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			tt.setup(fix)

			_, err := createCall(t, fix, CreateRequest{Type: testType, NumInvites: 1})
			wantFailure(t, err, tt.kind, tt.code)
		})
	}
}
