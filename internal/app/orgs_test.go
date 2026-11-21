package app_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/store"
)

// TestOrgsActForTheCaller: the organization routes act for the signed-in user.
// Through the real stack, the caller in each statement is the token's account and
// never anything in the request, the platform administrator role is bound as an
// argument (and is the same whatever role the caller has: the write decides), and
// a mutation is one batch of exactly the statements the store declares.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestOrgsActForTheCaller(t *testing.T) {
	t.Parallel()

	const (
		orgRow = "00000000-0000-7000-8000-0000000000c1"
		admin  = "admin"
	)

	tests := []struct {
		name         string
		role         string
		method, path string
		body         string
		// results is the answer to the route's one batch.
		results []store.Result
		status  int
		// statements is how many statements the batch has, and args the
		// arguments of the first.
		statements int
		args       []any
	}{
		{name: "a member lists organizations", role: roleMember, method: http.MethodGet, path: "/api/org?limit=5",
			results: []store.Result{{}}, status: http.StatusOK, statements: 1,
			args: []any{memberID, "g", int64(6), admin}},
		{name: "a platform administrator lists with the same arguments", role: roleAdmin, method: http.MethodGet,
			path: "/api/org?limit=5&caller=" + adminID, results: []store.Result{{}}, status: http.StatusOK,
			statements: 1, args: []any{memberID, "g", int64(6), admin}},
		{name: "reading one organization", role: roleMember, method: http.MethodGet, path: "/api/org/" + someID,
			results: []store.Result{{}}, status: http.StatusNotFound, statements: 1,
			args: []any{someID, memberID, admin}},
		{name: "leaving is one batch of three statements", role: roleMember, method: http.MethodDelete,
			path:    "/api/member/" + memberID,
			results: []store.Result{{}, {}, {}}, status: http.StatusNotFound, statements: 3,
			args: []any{memberID, memberID, admin}},
		{name: "accepting an offer is one batch of four", role: roleMember, method: http.MethodPost,
			path:    "/api/offer/" + someID + "/accept",
			results: []store.Result{{}, {}, {}, {}}, status: http.StatusNotFound, statements: 4,
			args: []any{someID, memberID}},
		{name: "withdrawing an offer is one statement", role: roleAdmin, method: http.MethodDelete,
			path:    "/api/offer/" + someID,
			results: []store.Result{{}}, status: http.StatusNotFound, statements: 1,
			args: []any{someID, memberID, admin}},
		{name: "revoking an organization is one batch of six", role: roleMember, method: http.MethodDelete,
			path:    "/api/org/" + someID,
			results: []store.Result{{}, {}, {}, {}, {}, {}}, status: http.StatusNotFound, statements: 6,
			args: []any{someID, memberID, admin}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			signedIn := newSession(t, memberID)

			script := []step{signedIn.activeSessionStep(tt.role)}
			if tt.statements > 0 {
				script = append(script, step{match: "", results: tt.results, err: nil})
			}

			h := newHarness(t, fullEnv(), script...)

			rec := h.do(request{method: tt.method, path: tt.path, body: tt.body, cookies: []*http.Cookie{signedIn.cookie}})
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.status, rec.Body)
			}

			if tt.statements == 0 {
				return
			}

			batch := h.exec.calls[1]
			if len(batch) != tt.statements {
				t.Fatalf("batch has %d statements, want %d", len(batch), tt.statements)
			}

			got := batch[0].Args
			if len(got) < len(tt.args) || !sameArgs(got[:len(tt.args)], tt.args) {
				t.Errorf("first statement args = %v, want it to start with %v", got, tt.args)
			}

			if strings.Contains(describe(batch), memberID) || strings.Contains(describe(batch), adminID) {
				t.Errorf("a caller's id is written into the SQL text: %s", describe(batch))
			}
		})
	}
}

// sameArgs reports whether two argument lists are equal.
func sameArgs(got, want []any) bool {
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}

	return true
}
