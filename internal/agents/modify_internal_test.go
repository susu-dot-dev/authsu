package agents

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/atomic"
)

func (f *fixture) rename(t *testing.T, id, body string) (Agent, error) {
	t.Helper()

	resp, err := f.call(t, pathItem, http.MethodPatch, id, body)
	if err != nil {
		return Agent{}, err
	}

	out, _ := resp.Body.(Agent)

	return out, nil
}

func (f *fixture) revoke(t *testing.T, id string) (Agent, error) {
	t.Helper()

	resp, err := f.call(t, pathItem, http.MethodDelete, id, "")
	if err != nil {
		return Agent{}, err
	}

	out, _ := resp.Body.(Agent)

	return out, nil
}

func TestRenameWritesOneStatementScopedToTheOwner(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	renamed := row(testAgentID)
	renamed.Name = "scheduler"
	fix.batcher.rows = [][]any{columns(renamed)}

	got, err := fix.rename(t, testAgentID, `{"name":"scheduler"}`)
	if err != nil {
		t.Fatal(err)
	}

	if want := present(renamed); !reflect.DeepEqual(got, want) {
		t.Errorf("renamed = %+v, want %+v", got, want)
	}

	want := [][]atomic.Statement{{{Query: renameQuery, Args: []any{"scheduler", testAgentID, testUserID}}}}
	if !reflect.DeepEqual(fix.batcher.batches, want) {
		t.Errorf("batches = %v, want %v", fix.batcher.batches, want)
	}

	if fix.reader.gets != 0 {
		t.Errorf("rename read the row %d times, want 0", fix.reader.gets)
	}
}

func TestRenameOfARevokedAgentIsRefused(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	revoked := row(testAgentID)
	revoked.RevokedAt = new(int64(12345))
	fix.batcher.rows = [][]any{columns(revoked)}

	_, err := fix.rename(t, testAgentID, `{"name":"x"}`)
	wantFailure(t, err, apierr.Conflict, CodeRevoked)
}

func TestRenameValidatesBeforeAuthenticating(t *testing.T) {
	t.Parallel()

	tests := map[string]struct{ body, code string }{
		"no body":        {"", "empty_body"},
		"no name":        {`{}`, CodeMissingName},
		"null name":      {`{"name":null}`, CodeMissingName},
		"empty name":     {`{"name":""}`, CodeInvalidName},
		"unknown member": {`{"name":"a","scopes":"x"}`, "unknown_field"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)

			_, err := fix.rename(t, testAgentID, tt.body)
			wantFailure(t, err, apierr.BadRequest, tt.code)

			if fix.sessions.calls != 0 {
				t.Error("an invalid request was authenticated")
			}
		})
	}
}

func TestRenameRejectsABadID(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	_, err := fix.rename(t, badID, `{"name":"a"}`)
	wantFailure(t, err, apierr.BadRequest, CodeInvalidID)

	if len(fix.batcher.batches) != 0 {
		t.Error("wrote for a malformed id")
	}
}

func TestRevokeRevokesTheAgentThenItsKeysInOneBatch(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	revoked := row(testAgentID)
	revoked.RevokedAt = new(testNow().Unix())
	fix.batcher.rows = [][]any{columns(revoked)}

	got, err := fix.revoke(t, testAgentID)
	if err != nil {
		t.Fatal(err)
	}

	if want := present(revoked); !reflect.DeepEqual(got, want) || got.Status != StatusRevoked {
		t.Errorf("revoked = %+v, want %+v", got, want)
	}

	now := testNow().Unix()
	want := [][]atomic.Statement{{
		{Query: revokeQuery, Args: []any{now, testAgentID, testUserID}},
		{Query: revokeKeysQuery, Args: []any{now, testAgentID, testUserID}},
	}}

	if !reflect.DeepEqual(fix.batcher.batches, want) {
		t.Errorf("batches = %v, want %v", fix.batcher.batches, want)
	}

	if fix.reader.gets != 0 {
		t.Errorf("revoke read the row %d times, want 0", fix.reader.gets)
	}
}

// TestRevokeIsIdempotent: revoking a revoked agent succeeds and reports the
// original time, which the COALESCE in the write keeps.
func TestRevokeIsIdempotent(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	revoked := row(testAgentID)
	revoked.RevokedAt = new(int64(12345))
	fix.batcher.rows = [][]any{columns(revoked)}

	got, err := fix.revoke(t, testAgentID)
	if err != nil {
		t.Fatal(err)
	}

	if got.RevokedAt == nil || *got.RevokedAt != 12345 {
		t.Errorf("revokedAt = %v, want the earlier time 12345", got.RevokedAt)
	}
}

func TestRevokeFailures(t *testing.T) {
	t.Parallel()

	valid := columns(row(testAgentID))

	tests := map[string]struct {
		id       string
		batchErr error
		rows     [][]any
		results  []atomic.Result
		kind     apierr.Kind
		code     string
	}{
		"no such agent, or not the caller's": {id: testAgentID, rows: nil, kind: apierr.NotFound, code: CodeNotFound},
		"bad id":                             {id: badID, kind: apierr.BadRequest, code: CodeInvalidID},
		caseDBDown: {
			id: testAgentID, batchErr: errDB, kind: apierr.Unavailable, code: CodeRevokeFailed,
		},
		caseRejects: {
			id: testAgentID, batchErr: atomic.ErrRejected, kind: apierr.Internal, code: CodeRevokeRejected,
		},
		"a conflict is a defect here": {
			id: testAgentID, batchErr: atomic.ErrConflict, kind: apierr.Internal, code: CodeRevokeRejected,
		},
		"batch misreports": {
			id: testAgentID, results: []atomic.Result{{}}, kind: apierr.Internal, code: CodeRevokeRejected,
		},
		"two rows": {
			id: testAgentID, rows: [][]any{valid, valid}, kind: apierr.Internal, code: CodeRevokeRejected,
		},
		"row too narrow": {
			id: testAgentID, rows: [][]any{{testAgentID}}, kind: apierr.Internal, code: CodeRevokeRejected,
		},
		"row of the wrong type": {
			id: testAgentID, rows: [][]any{{testAgentID, "n", "s", nil, "not a time"}},
			kind: apierr.Internal, code: CodeRevokeRejected,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			fix.batcher.err = tt.batchErr
			fix.batcher.rows = tt.rows
			fix.batcher.results = tt.results

			_, err := fix.revoke(t, tt.id)
			wantFailure(t, err, tt.kind, tt.code)
		})
	}
}

func TestRenameFailures(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		batchErr error
		rows     [][]any
		kind     apierr.Kind
		code     string
	}{
		"no such agent, or not the caller's": {kind: apierr.NotFound, code: CodeNotFound},
		caseDBDown:                           {batchErr: errDB, kind: apierr.Unavailable, code: CodeUpdateFailed},
		caseRejects:                          {batchErr: atomic.ErrRejected, kind: apierr.Internal, code: CodeUpdateRejected},
		"row too narrow":                     {rows: [][]any{{"x"}}, kind: apierr.Internal, code: CodeUpdateRejected},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			fix.batcher.err = tt.batchErr
			fix.batcher.rows = tt.rows

			_, err := fix.rename(t, testAgentID, `{"name":"a"}`)
			wantFailure(t, err, tt.kind, tt.code)
		})
	}
}
