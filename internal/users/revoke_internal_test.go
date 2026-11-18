package users

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/atomic"
)

func revokeCall(t *testing.T, fix *fixture, id string) (User, error) {
	t.Helper()

	resp, err := fix.svc.Handlers(getenv).Item[http.MethodDelete](request(t, http.MethodDelete, id)).Get()
	if err != nil {
		return User{}, fmt.Errorf("handler: %w", err)
	}

	got, ok := resp.Body.(User)
	if !ok || resp.Status != http.StatusOK {
		t.Fatalf("response = %d %T, want 200 and a User", resp.Status, resp.Body)
	}

	return got, nil
}

// TestRevokeRevokesTheAccountAndItsKeys: one batch, the account first and its
// keys second, both at the same time, and the response is the row the write
// returned.
func TestRevokeRevokesTheAccountAndItsKeys(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	revoked := row(testUserID)
	revoked.RevokedAt = new(testNow().Unix())
	fix.batcher.rows = [][]any{columns(revoked)}

	got, err := revokeCall(t, fix, testUserID)
	if err != nil {
		t.Fatal(err)
	}

	if want := present(revoked); !reflect.DeepEqual(got, want) || got.Status != StatusRevoked {
		t.Errorf("revoked = %+v, want %+v", got, want)
	}

	if len(fix.batcher.batches) != 1 {
		t.Fatalf("ran %d batches, want 1", len(fix.batcher.batches))
	}

	batch := fix.batcher.batches[0]
	now := testNow().Unix()
	want := []atomic.Statement{
		{Query: revokeQuery, Args: []any{now, testUserID, roleAdmin}},
		{Query: revokeKeysQuery, Args: []any{now, testUserID}},
		{Query: revokeAgentsQuery, Args: []any{now, testUserID}},
	}

	if !reflect.DeepEqual(batch, want) {
		t.Errorf("batch = %v, want %v", batch, want)
	}

	// The row comes from the write itself: nothing is read afterwards.
	if fix.reader.gets != 0 {
		t.Errorf("revoke read the row %d times, want 0", fix.reader.gets)
	}
}

// TestRevokeIsIdempotent: revoking a revoked account succeeds and reports the
// original time, which the COALESCE in the write keeps.
func TestRevokeIsIdempotent(t *testing.T) {
	t.Parallel()

	earlier := testNow().Unix() - 500
	already := row(testUserID)
	already.RevokedAt = &earlier

	fix := newFixture(t)
	fix.batcher.rows = [][]any{columns(already)}

	got, err := revokeCall(t, fix, testUserID)
	if err != nil {
		t.Fatal(err)
	}

	if got.RevokedAt == nil || *got.RevokedAt != earlier {
		t.Errorf("revoked again = %+v, want the original time %d", got, earlier)
	}
}

// TestRevokeRefusesTheLastAdmin: when the guard in the write refuses, the row
// comes back with revoked_at still NULL, and that is a 409.
func TestRevokeRefusesTheLastAdmin(t *testing.T) {
	t.Parallel()

	last := row(testAdminID)
	last.Role = roleAdmin

	fix := newFixture(t)
	fix.batcher.rows = [][]any{columns(last)}

	_, err := revokeCall(t, fix, testAdminID)
	wantFailure(t, err, apierr.Conflict, CodeLastAdmin)
}

func TestRevokeFailures(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		setup func(*fixture)
		id    string
		kind  apierr.Kind
		code  string
	}{
		"no such user": {func(*fixture) {}, testUserID, apierr.NotFound, CodeNotFound},
		"bad id":       {func(*fixture) {}, "nope", apierr.BadRequest, CodeInvalidID},
		"database unavailable": {
			func(f *fixture) { f.batcher.err = errDB }, testUserID, apierr.Unavailable, CodeRevokeFailed,
		},
		"schema rejects it": {
			func(f *fixture) { f.batcher.err = errors.Join(atomic.ErrRejected, errDB) },
			testUserID, apierr.Internal, CodeRevokeRejected,
		},
		"a constraint conflicts": {
			func(f *fixture) { f.batcher.err = errors.Join(atomic.ErrConflict, errDB) },
			testUserID, apierr.Internal, CodeRevokeRejected,
		},
		"batch returns one result for two statements": {
			func(f *fixture) { f.batcher.results = []atomic.Result{{}} }, testUserID, apierr.Internal, CodeRevokeRejected,
		},
		"more than one row returned": {
			func(f *fixture) { f.batcher.rows = [][]any{columns(row(testUserID)), columns(row(testUserID))} },
			testUserID, apierr.Internal, CodeRevokeRejected,
		},
		"a row of the wrong width": {
			func(f *fixture) { f.batcher.rows = [][]any{{int64(1)}} }, testUserID, apierr.Internal, CodeRevokeRejected,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			tt.setup(fix)

			_, err := revokeCall(t, fix, tt.id)
			wantFailure(t, err, tt.kind, tt.code)
		})
	}
}
