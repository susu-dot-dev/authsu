//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package users_test

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/store"
)

// maxSafeInteger is 2^53-1, the largest integer D1 moves exactly.
const maxSafeInteger = 1<<53 - 1

// TestList is GET /api/user: every store outcome and the exact body it becomes.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestList(t *testing.T) {
	t.Parallel()

	listCalls := []storeCall{readCall(opList, "")}

	admin := userRow(adminID)
	admin.Role = roleAdmin

	revoked := userRow("01890000-0000-7000-8000-000000000003")
	revoked.RevokedAt = new(int64(1_700_000_050))

	revokedAtEpoch := userRow("01890000-0000-7000-8000-000000000004")
	revokedAtEpoch.RevokedAt = new(int64(0))

	extreme := userRow("01890000-0000-7000-8000-000000000005")
	extreme.CreatedAt = maxSafeInteger
	extreme.RevokedAt = new(int64(maxSafeInteger))

	nested := userRow("01890000-0000-7000-8000-000000000006")
	nested.Profile = `{"name":"Ada","tags":[1,2,{"a":null}],"nested":{"b":"c"}}`

	badProfile := userRow("01890000-0000-7000-8000-000000000007")
	badProfile.Profile = `{"name":`

	cases := []outcomeCase{
		{
			name:    "no accounts is an empty array, never null",
			program: func(f *fakeStore) { f.users = nil },
			status:  http.StatusOK, body: `{"users":[]}` + "\n", logged: "", calls: listCalls,
		},
		{
			name:    "an empty, non-nil list is an empty array",
			program: func(f *fakeStore) { f.users = []store.User{} },
			status:  http.StatusOK, body: `{"users":[]}` + "\n", logged: "", calls: listCalls,
		},
		{
			name:    "every account with its status, in the store's order",
			program: func(f *fakeStore) { f.users = []store.User{revoked, userRow(targetID), admin} },
			status:  http.StatusOK,
			body: `{"users":[` +
				userJSON(revoked.ID, roleMember, profileAda, "revoked", revoked.RevokedAt, "1700000000") + "," +
				userJSON(targetID, roleMember, profileAda, "active", nil, "1700000000") + "," +
				userJSON(adminID, roleAdmin, profileAda, "active", nil, "1700000000") + `]}` + "\n",
			logged: "", calls: listCalls,
		},
		{
			name:    "revoked at the epoch is still revoked and still shown",
			program: func(f *fakeStore) { f.users = []store.User{revokedAtEpoch} },
			status:  http.StatusOK,
			body: `{"users":[` +
				userJSON(revokedAtEpoch.ID, roleMember, profileAda, "revoked", revokedAtEpoch.RevokedAt, "1700000000") +
				`]}` + "\n",
			logged: "", calls: listCalls,
		},
		{
			name:    "integers at 2^53-1 are written exactly",
			program: func(f *fakeStore) { f.users = []store.User{extreme} },
			status:  http.StatusOK,
			body: `{"users":[` +
				userJSON(extreme.ID, roleMember, profileAda, "revoked", extreme.RevokedAt, "9007199254740991") +
				`]}` + "\n",
			logged: "", calls: listCalls,
		},
		{
			name:    "the profile is a JSON object in the response, not text",
			program: func(f *fakeStore) { f.users = []store.User{nested} },
			status:  http.StatusOK,
			body: `{"users":[` +
				userJSON(nested.ID, roleMember, nested.Profile, "active", nil, "1700000000") + `]}` + "\n",
			logged: "", calls: listCalls,
		},
		{
			name:    "one account with a malformed profile is logged and listed with {}, and the rest are unaffected",
			program: func(f *fakeStore) { f.users = []store.User{userRow(targetID), badProfile} },
			status:  http.StatusOK,
			body: `{"users":[` +
				userJSON(targetID, roleMember, profileAda, "active", nil, "1700000000") + "," +
				userJSON(badProfile.ID, roleMember, `{}`, "active", nil, "1700000000") + `]}` + "\n",
			logged: "user_profile_invalid", calls: listCalls,
		},
		{
			name:    "the database is unavailable",
			program: func(f *fakeStore) { f.listErr = unavailable(store.CodeUserListFailed) },
			status:  http.StatusServiceUnavailable, body: bodyUnavailable(store.CodeUserListFailed),
			logged: store.CodeUserListFailed, calls: listCalls,
		},
		{
			name:    "the store reports a defect",
			program: func(f *fakeStore) { f.listErr = rejected(store.CodeUserListRejected) },
			status:  http.StatusInternalServerError, body: internalBody,
			logged: store.CodeUserListRejected, calls: listCalls,
		},
		{
			name:    "an unclassified failure is a bare 500",
			program: func(f *fakeStore) { f.listErr = errIO },
			status:  http.StatusInternalServerError, body: internalBody, logged: "internal", calls: listCalls,
		},
		{
			name:    "a failure keeps no rows the store also returned",
			program: func(f *fakeStore) { f.users = []store.User{admin}; f.listErr = fmt.Errorf("partial: %w", errIO) },
			status:  http.StatusInternalServerError, body: internalBody, logged: "internal", calls: listCalls,
		},
	}

	runOutcomes(t, routes()[0], cases)
}

// TestListFailureCauseIsLoggedNotSent: the response says what failed and never
// why; the cause is in the log.
func TestListFailureCauseIsLoggedNotSent(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	cookie := rg.signIn(adminID, roleAdmin)
	rg.store.listErr = unavailable(store.CodeUserListFailed)

	rec := rg.as(cookie, http.MethodGet, collection)

	if len(rg.logged) != 1 || !errors.Is(rg.logged[0], errDB) {
		t.Errorf("logged = %v, want one error wrapping the database failure", rg.logged)
	}

	if body := rec.Body.String(); body != bodyUnavailable(store.CodeUserListFailed) {
		t.Errorf("body = %q leaks or changed the failure", body)
	}
}
