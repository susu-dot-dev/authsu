package invitations

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/atomic"

	"errors"
)

func updateCall(t *testing.T, fix *fixture, body any, id string) (Invitation, error) {
	t.Helper()

	handler := fix.svc.Handlers(getenv).Item[http.MethodPatch]

	resp, err := handler(request(t, http.MethodPatch, body, id)).Get()
	if err != nil {
		return Invitation{}, fmt.Errorf("handler: %w", err)
	}

	got, ok := resp.Body.(Invitation)
	if !ok || resp.Status != http.StatusOK {
		t.Fatalf("response = %d %T, want 200 and an Invitation", resp.Status, resp.Body)
	}

	return got, nil
}

func revokeCall(t *testing.T, fix *fixture, id string) (Invitation, error) {
	t.Helper()

	handler := fix.svc.Handlers(getenv).Item[http.MethodDelete]

	resp, err := handler(request(t, http.MethodDelete, nil, id)).Get()
	if err != nil {
		return Invitation{}, fmt.Errorf("handler: %w", err)
	}

	got, ok := resp.Body.(Invitation)
	if !ok || resp.Status != http.StatusOK {
		t.Fatalf("response = %d %T, want 200 and an Invitation", resp.Status, resp.Body)
	}

	return got, nil
}

func TestUpdateChangesTheCap(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	// The statement returns the row as it left it, with the new cap.
	updated := row(testInvID)
	updated.NumInvites = 9
	fix.batcher.rows = [][]any{returned(1, updated)}

	got, err := updateCall(t, fix, UpdateRequest{NumInvites: new(int64(9))}, testInvID)
	if err != nil {
		t.Fatal(err)
	}

	if want := present(updated, StatusActive); !reflect.DeepEqual(got, want) || got.NumInvites != 9 {
		t.Errorf("updated = %+v, want %+v", got, want)
	}

	stmt := fix.batcher.batches[0][0]
	if stmt.Query != updateNumInvitesQuery {
		t.Fatalf("statement = %q", stmt.Query)
	}

	// The new cap twice (set, and compared with the accounts), then the id.
	if want := []any{int64(9), int64(9), testInvID}; !reflect.DeepEqual(stmt.Args, want) {
		t.Errorf("args = %v, want %v", stmt.Args, want)
	}

	// The row comes from the write itself: nothing is read afterwards.
	if fix.reader.gets != 0 {
		t.Errorf("update read the row %d times, want 0", fix.reader.gets)
	}
}

// TestUpdateReportsWhyItDidNotApply: a conditional write that changes nothing
// is not an error, so the statement returns the row with a verdict, and the
// refusal is read off that row. No second read is involved.
func TestUpdateReportsWhyItDidNotApply(t *testing.T) {
	t.Parallel()

	revoked := row(testInvID)
	revoked.RevokedAt = new(testNow().Unix() - 5)

	// Two accounts exist and the caller asked for a cap of 1.
	tests := map[string]struct {
		rows [][]any
		kind apierr.Kind
		code string
		uses int64
	}{
		"no such invitation": {rows: nil, kind: apierr.NotFound, code: CodeNotFound, uses: 0},
		"revoked":            {rows: [][]any{returned(0, revoked)}, kind: apierr.Conflict, code: CodeRevoked, uses: 0},
		"below the accounts it has created": {
			rows: [][]any{returned(0, row(testInvID))}, kind: apierr.Conflict, code: CodeBelowUses, uses: 2,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			fix.batcher.rows = tt.rows

			_, err := updateCall(t, fix, UpdateRequest{NumInvites: new(int64(1))}, testInvID)
			wantFailure(t, err, tt.kind, tt.code)

			data, hasData := apierr.As(err).Data.(map[string]int64)
			if tt.uses != 0 && (!hasData || data["uses"] != tt.uses) {
				t.Errorf("data = %v, want the %d accounts it has", data, tt.uses)
			}

			if fix.reader.gets != 0 {
				t.Errorf("update read the row %d times, want 0", fix.reader.gets)
			}
		})
	}
}

// TestUpdateAppliedIsWhatTheWriteSaid: whether the write applied is the
// verdict the statement returned, and the response is the row it returned, even
// when the stored row has since moved on.
func TestUpdateAppliedIsWhatTheWriteSaid(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	// Applied, with the new cap. Another request then revokes the stored row.
	updated := row(testInvID)
	updated.NumInvites = 9
	fix.batcher.rows = [][]any{returned(1, updated)}

	revoked := updated
	revoked.RevokedAt = new(testNow().Unix())
	fix.store(revoked)

	got, err := updateCall(t, fix, UpdateRequest{NumInvites: new(int64(9))}, testInvID)
	if err != nil {
		t.Fatalf("an applied write was reported as %v", err)
	}

	if got.NumInvites != 9 || got.Status != StatusActive {
		t.Errorf("updated = %+v, want the invitation as the write left it", got)
	}
}

func TestUpdateRefusesBadInput(t *testing.T) {
	t.Parallel()

	two := UpdateRequest{NumInvites: new(int64(2))}

	tests := map[string]struct {
		body any
		id   string
		code string
	}{
		"no fields":     {`{}`, testInvID, CodeMissingNumInvite},
		"null":          {`{"numInvites":null}`, testInvID, CodeMissingNumInvite},
		"zero":          {UpdateRequest{NumInvites: new(int64(0))}, testInvID, CodeInvalidNum},
		"negative":      {UpdateRequest{NumInvites: new(int64(-2))}, testInvID, CodeInvalidNum},
		"too many":      {UpdateRequest{NumInvites: new(int64(MaxNumInvites + 1))}, testInvID, CodeInvalidNum},
		"unknown field": {`{"numInvites":2,"type":"x"}`, testInvID, "unknown_field"},
		"empty body":    {"", testInvID, "empty_body"},
		"no id":         {two, "", CodeInvalidID},
		"id too short":  {two, "abc", CodeInvalidID},
		"id not hex":    {two, strings.Repeat("g", 36), CodeInvalidID},
		"id has quote":  {two, "' OR 1=1 --" + strings.Repeat("0", 25), CodeInvalidID},
		"id upper case": {two, strings.ToUpper(testInvID), CodeInvalidID},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)

			_, err := updateCall(t, fix, tt.body, tt.id)
			wantFailure(t, err, apierr.BadRequest, tt.code)

			if len(fix.batcher.batches) != 0 {
				t.Errorf("a refused request wrote: %v", fix.batcher.batches)
			}
		})
	}
}

func TestUpdateFailures(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		setup func(*fixture)
		kind  apierr.Kind
		code  string
	}{
		dbUnavailable: {
			setup: func(f *fixture) { f.batcher.err = errDB },
			kind:  apierr.Unavailable, code: CodeUpdateFailed,
		},
		schemaRejects: {
			setup: func(f *fixture) { f.batcher.err = errors.Join(atomic.ErrRejected, errDB) },
			kind:  apierr.Internal, code: CodeUpdateRejected,
		},
		"batch returns no result": {
			setup: func(f *fixture) { f.batcher.results = []atomic.Result{} },
			kind:  apierr.Internal, code: CodeUpdateRejected,
		},
		"more than one row returned": {
			setup: func(f *fixture) {
				f.batcher.rows = [][]any{returned(1, row(testInvID)), returned(1, row(testInvID))}
			},
			kind: apierr.Internal, code: CodeUpdateRejected,
		},
		"a row of the wrong width": {
			setup: func(f *fixture) { f.batcher.rows = [][]any{{int64(1)}} },
			kind:  apierr.Internal, code: CodeUpdateRejected,
		},
		"a row of the wrong type": {
			setup: func(f *fixture) {
				bad := returned(1, row(testInvID))
				bad[1] = int64(7)
				f.batcher.rows = [][]any{bad}
			},
			kind: apierr.Internal, code: CodeUpdateRejected,
		},
		"a verdict that is not a number": {
			setup: func(f *fixture) {
				bad := returned(1, row(testInvID))
				bad[0] = "yes"
				f.batcher.rows = [][]any{bad}
			},
			kind: apierr.Internal, code: CodeUpdateRejected,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			fix.store(row(testInvID))
			tt.setup(fix)

			_, err := updateCall(t, fix, UpdateRequest{NumInvites: new(int64(9))}, testInvID)
			wantFailure(t, err, tt.kind, tt.code)
		})
	}
}

func TestRevokeRevokesNow(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	// The statement returns the row as it left it: revoked now.
	revoked := row(testInvID)
	revoked.RevokedAt = new(testNow().Unix())
	fix.batcher.rows = [][]any{invitationColumns(revoked)}

	got, err := revokeCall(t, fix, testInvID)
	if err != nil {
		t.Fatal(err)
	}

	if got.ID != testInvID || got.Status != StatusRevoked || got.RevokedAt == nil || *got.RevokedAt != testNow().Unix() {
		t.Errorf("revoked = %+v", got)
	}

	// The row comes from the write itself: nothing is read afterwards.
	if fix.reader.gets != 0 {
		t.Errorf("revoke read the row %d times, want 0", fix.reader.gets)
	}
}

func TestRevokeWritesTheTimeAndTheID(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	fix.batcher.rows = [][]any{invitationColumns(row(testInvID))}

	_, err := revokeCall(t, fix, testInvID)
	if err != nil {
		t.Fatal(err)
	}

	stmt := fix.batcher.batches[0][0]
	if want := []any{testNow().Unix(), testInvID}; stmt.Query != revokeQuery || !reflect.DeepEqual(stmt.Args, want) {
		t.Errorf("statement = %q %v, want %v", stmt.Query, stmt.Args, want)
	}
}

// TestRevokeIsIdempotent: revoking a revoked invitation succeeds and reports
// the original revocation time. The COALESCE in the write is what keeps that
// time; here the statement returns the row with the earlier time it kept, as
// the database would.
func TestRevokeIsIdempotent(t *testing.T) {
	t.Parallel()

	earlier := testNow().Unix() - 500
	already := row(testInvID)
	already.RevokedAt = &earlier

	fix := newFixture(t)
	fix.batcher.rows = [][]any{invitationColumns(already)}

	got, err := revokeCall(t, fix, testInvID)
	if err != nil {
		t.Fatal(err)
	}

	if got.RevokedAt == nil || *got.RevokedAt != earlier || got.Status != StatusRevoked {
		t.Errorf("revoked again = %+v, want the original time %d", got, earlier)
	}
}

func TestRevokeFailures(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		setup func(*fixture)
		id    string
		kind  apierr.Kind
		code  string
	}{
		"no such invitation": {func(*fixture) {}, testInvID, apierr.NotFound, CodeNotFound},
		"bad id":             {func(*fixture) {}, "nope", apierr.BadRequest, CodeInvalidID},
		dbUnavailable:        {func(f *fixture) { f.batcher.err = errDB }, testInvID, apierr.Unavailable, CodeRevokeFailed},
		schemaRejects: {
			func(f *fixture) { f.batcher.err = errors.Join(atomic.ErrRejected, errDB) },
			testInvID, apierr.Internal, CodeRevokeRejected,
		},
		"batch returns no result": {
			func(f *fixture) { f.batcher.results = []atomic.Result{} }, testInvID, apierr.Internal, CodeRevokeRejected,
		},
		"more than one row returned": {
			func(f *fixture) {
				f.batcher.rows = [][]any{invitationColumns(row(testInvID)), invitationColumns(row(testInvID))}
			},
			testInvID, apierr.Internal, CodeRevokeRejected,
		},
		"a row of the wrong width": {
			func(f *fixture) { f.batcher.rows = [][]any{{int64(1)}} }, testInvID, apierr.Internal, CodeRevokeRejected,
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

func TestStatusOf(t *testing.T) {
	t.Parallel()

	now := testNow()
	unix := now.Unix()
	past, future := unix-1, unix+1

	tests := map[string]struct {
		row  Row
		want Status
	}{
		"active":              {Row{NumInvites: 2, Uses: 1}, StatusActive},
		"unused":              {Row{NumInvites: 1, Uses: 0}, StatusActive},
		"exhausted":           {Row{NumInvites: 2, Uses: 2}, StatusExhausted},
		"over its cap":        {Row{NumInvites: 1, Uses: 2}, StatusExhausted},
		"revoked":             {Row{NumInvites: 2, RevokedAt: &past}, StatusRevoked},
		"revoked in future":   {Row{NumInvites: 2, RevokedAt: &future}, StatusRevoked},
		"expires later":       {Row{NumInvites: 2, ExpiresAt: &future}, StatusActive},
		"expires exactly now": {Row{NumInvites: 2, ExpiresAt: &unix}, StatusExpired},
		"expired":             {Row{NumInvites: 2, ExpiresAt: &past}, StatusExpired},
		"expired, exhausted":  {Row{NumInvites: 1, Uses: 1, ExpiresAt: &past}, StatusExpired},
		"all three":           {Row{NumInvites: 1, Uses: 1, ExpiresAt: &past, RevokedAt: &past}, StatusRevoked},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := StatusOf(tt.row, now); got != tt.want {
				t.Errorf("StatusOf = %q, want %q", got, tt.want)
			}
		})
	}
}
