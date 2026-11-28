//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package users_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/store"
)

// TestRevoke is DELETE /api/user/{id}: every outcome of the store's revocation,
// and that it is called once with the signed-in administrator as the caller, the
// admin role and the injected time.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestRevoke(t *testing.T) {
	t.Parallel()

	calls := []storeCall{revokeCall(targetID)}

	// what the store returns for a revocation made at clockAt
	justNow := userRow(targetID)
	justNow.RevokedAt = new(clockAt.Unix())

	// an account revoked earlier keeps its earlier time
	earlier := userRow(targetID)
	earlier.RevokedAt = new(clockAt.Unix() - 500)

	badProfile := justNow
	badProfile.Profile = "{"

	cases := []outcomeCase{
		{
			name:    "revokes the account and returns it as the write left it",
			program: func(f *fakeStore) { f.revoked = justNow },
			status:  http.StatusOK,
			body:    userJSON(targetID, roleMember, profileAda, "revoked", justNow.RevokedAt, "1700000000") + "\n",
			logged:  "", calls: calls,
		},
		{
			name:    "revoking twice succeeds and reports the first time",
			program: func(f *fakeStore) { f.revoked = earlier },
			status:  http.StatusOK,
			body:    userJSON(targetID, roleMember, profileAda, "revoked", earlier.RevokedAt, "1700000000") + "\n",
			logged:  "", calls: calls,
		},
		{
			name:    "the last active administrator is refused",
			program: func(f *fakeStore) { f.revokeErr = store.ErrLastAdmin },
			status:  http.StatusConflict, body: bodyLastAdmin, logged: "user_last_admin", calls: calls,
		},
		{
			name:    "the last administrator, however the store wraps the outcome",
			program: func(f *fakeStore) { f.revokeErr = fmt.Errorf("revoke: %w", store.ErrLastAdmin) },
			status:  http.StatusConflict, body: bodyLastAdmin, logged: "user_last_admin", calls: calls,
		},
		{
			name:    "no such account",
			program: func(f *fakeStore) { f.revokeErr = store.ErrNotFound },
			status:  http.StatusNotFound, body: bodyNotFound, logged: "user_not_found", calls: calls,
		},
		{
			name:    "no such account, however the store wraps the outcome",
			program: func(f *fakeStore) { f.revokeErr = fmt.Errorf("revoke: %w", store.ErrNotFound) },
			status:  http.StatusNotFound, body: bodyNotFound, logged: "user_not_found", calls: calls,
		},
		{
			name:    "the caller was revoked while the request ran",
			program: func(f *fakeStore) { f.revokeErr = store.ErrAccountRevoked },
			status:  http.StatusUnauthorized, body: bodyUnauthenticated, logged: "unauthenticated", calls: calls,
		},
		{
			name:    "the caller was revoked, however the store wraps the outcome",
			program: func(f *fakeStore) { f.revokeErr = fmt.Errorf("revoke: %w", store.ErrAccountRevoked) },
			status:  http.StatusUnauthorized, body: bodyUnauthenticated, logged: "unauthenticated", calls: calls,
		},
		{
			name:    "the database is unavailable",
			program: func(f *fakeStore) { f.revokeErr = unavailable(store.CodeUserRevokeFailed) },
			status:  http.StatusServiceUnavailable, body: bodyUnavailable(store.CodeUserRevokeFailed),
			logged: store.CodeUserRevokeFailed, calls: calls,
		},
		{
			name:    "the store reports a defect",
			program: func(f *fakeStore) { f.revokeErr = rejected(store.CodeUserRevokeRejected) },
			status:  http.StatusInternalServerError, body: internalBody,
			logged: store.CodeUserRevokeRejected, calls: calls,
		},
		{
			name:    "an unclassified failure is a bare 500",
			program: func(f *fakeStore) { f.revokeErr = errIO },
			status:  http.StatusInternalServerError, body: internalBody, logged: "internal", calls: calls,
		},
		{
			name:    "a malformed profile on the revoked row is logged, and the revocation is still reported as done",
			program: func(f *fakeStore) { f.revoked = badProfile },
			status:  http.StatusOK,
			body:    userJSON(targetID, roleMember, `{}`, "revoked", badProfile.RevokedAt, "1700000000") + "\n",
			logged:  "user_profile_invalid", calls: calls,
		},
	}

	runOutcomes(t, routeNamed(opRevoke), cases)
}

// TestRevokeYourself: nothing in the route treats the caller's own account
// differently (docs/users_design.md): an administrator may revoke themself
// while another active administrator remains, and is refused as the last one.
// The refusal is the store's, so the route must pass the caller's own id on.
func TestRevokeYourself(t *testing.T) {
	t.Parallel()

	self := userRow(adminID)
	self.Role = roleAdmin
	self.RevokedAt = new(clockAt.Unix())

	rt := routeNamed(opRevoke)
	rt.target = itemPrefix + adminID

	runOutcomes(t, rt, []outcomeCase{
		{
			name:    "another active administrator remains",
			program: func(f *fakeStore) { f.revoked = self },
			status:  http.StatusOK,
			body:    userJSON(adminID, roleAdmin, profileAda, "revoked", self.RevokedAt, "1700000000") + "\n",
			logged:  "", calls: []storeCall{revokeCall(adminID)},
		},
		{
			name:    "the caller is the last active administrator",
			program: func(f *fakeStore) { f.revokeErr = store.ErrLastAdmin },
			status:  http.StatusConflict, body: bodyLastAdmin, logged: "user_last_admin",
			calls: []storeCall{revokeCall(adminID)},
		},
	})
}

// TestRevokeReadsTheClockOncePerRequest: each revocation is stamped with the
// clock as it is at that request, unchanged, and a read never asks the clock
// or passes a role.
func TestRevokeReadsTheClockOncePerRequest(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	cookie := rg.signIn(adminID, roleAdmin)
	rg.store.revoked = userRow(targetID)
	rg.store.revoked.RevokedAt = new(int64(1))

	first, second := clockAt, clockAt.AddDate(0, 0, 1).Add(1)

	rg.now = first
	rg.as(cookie, http.MethodDelete, itemPrefix+targetID)

	rg.now = second
	rg.as(cookie, http.MethodDelete, itemPrefix+targetID)

	rg.as(cookie, http.MethodGet, itemPrefix+targetID)

	want := []storeCall{
		{op: opRevoke, id: targetID, caller: adminID, role: roleAdmin, now: first},
		{op: opRevoke, id: targetID, caller: adminID, role: roleAdmin, now: second},
		getCall(targetID),
	}

	wantCalls(t, rg.store.calls, want)
}
