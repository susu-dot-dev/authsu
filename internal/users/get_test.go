//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package users_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/store"
)

// TestGet is GET /api/user/{id}.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestGet(t *testing.T) {
	t.Parallel()

	calls := []storeCall{getCall(targetID)}

	revoked := userRow(targetID)
	revoked.RevokedAt = new(int64(1_700_000_050))

	admin := userRow(targetID)
	admin.Role = roleAdmin

	badProfile := userRow(targetID)
	badProfile.Profile = "not json"

	cases := []outcomeCase{
		{
			name:    "an active account",
			program: func(f *fakeStore) { f.got = userRow(targetID) },
			status:  http.StatusOK, body: userJSON(targetID, roleMember, profileAda, "active", nil, "1700000000") + "\n",
			logged: "", calls: calls,
		},
		{
			name:    "an administrator",
			program: func(f *fakeStore) { f.got = admin },
			status:  http.StatusOK, body: userJSON(targetID, roleAdmin, profileAda, "active", nil, "1700000000") + "\n",
			logged: "", calls: calls,
		},
		{
			name:    "a revoked account is shown, with its time",
			program: func(f *fakeStore) { f.got = revoked },
			status:  http.StatusOK,
			body:    userJSON(targetID, roleMember, profileAda, "revoked", revoked.RevokedAt, "1700000000") + "\n",
			logged:  "", calls: calls,
		},
		{
			name:    "no such account",
			program: func(f *fakeStore) { f.getErr = store.ErrNotFound },
			status:  http.StatusNotFound, body: bodyNotFound, logged: "user_not_found", calls: calls,
		},
		{
			name:    "no such account, however the store wraps the outcome",
			program: func(f *fakeStore) { f.getErr = fmt.Errorf("lookup: %w", store.ErrNotFound) },
			status:  http.StatusNotFound, body: bodyNotFound, logged: "user_not_found", calls: calls,
		},
		{
			name:    "the database is unavailable",
			program: func(f *fakeStore) { f.getErr = unavailable(store.CodeUserLookupFailed) },
			status:  http.StatusServiceUnavailable, body: bodyUnavailable(store.CodeUserLookupFailed),
			logged: store.CodeUserLookupFailed, calls: calls,
		},
		{
			name:    "the store reports a defect",
			program: func(f *fakeStore) { f.getErr = rejected(store.CodeUserLookupRejected) },
			status:  http.StatusInternalServerError, body: internalBody,
			logged: store.CodeUserLookupRejected, calls: calls,
		},
		{
			name:    "an unclassified failure is a bare 500",
			program: func(f *fakeStore) { f.getErr = errIO },
			status:  http.StatusInternalServerError, body: internalBody, logged: "internal", calls: calls,
		},
		{
			name:    "a malformed profile is logged and served as an empty object",
			program: func(f *fakeStore) { f.got = badProfile },
			status:  http.StatusOK, body: userJSON(targetID, roleMember, `{}`, "active", nil, "1700000000") + "\n",
			logged: "user_profile_invalid", calls: calls,
		},
	}

	runOutcomes(t, routeNamed(opGet), cases)
}

// TestSelf is GET /api/user/me: the caller's own account, read by the id the
// credential resolved to, and shown as any other. The store is asked for the
// signed-in administrator and nobody else.
func TestSelf(t *testing.T) {
	t.Parallel()

	calls := []storeCall{getCall(adminID)}

	admin := userRow(adminID)
	admin.Role = roleAdmin

	badProfile := admin
	badProfile.Profile = "not json"

	cases := []outcomeCase{
		{
			name:    "the caller's own account",
			program: func(f *fakeStore) { f.got = admin },
			status:  http.StatusOK, body: userJSON(adminID, roleAdmin, profileAda, "active", nil, "1700000000") + "\n",
			logged: "", calls: calls,
		},
		{
			name:    "an account that is gone by the time it is read",
			program: func(f *fakeStore) { f.getErr = store.ErrNotFound },
			status:  http.StatusNotFound, body: bodyNotFound, logged: "user_not_found", calls: calls,
		},
		{
			name:    "the database is unavailable",
			program: func(f *fakeStore) { f.getErr = unavailable(store.CodeUserLookupFailed) },
			status:  http.StatusServiceUnavailable, body: bodyUnavailable(store.CodeUserLookupFailed),
			logged: store.CodeUserLookupFailed, calls: calls,
		},
		{
			name:    "an unclassified failure is a bare 500",
			program: func(f *fakeStore) { f.getErr = errIO },
			status:  http.StatusInternalServerError, body: internalBody, logged: "internal", calls: calls,
		},
		{
			name:    "a malformed profile is logged and served as an empty object",
			program: func(f *fakeStore) { f.got = badProfile },
			status:  http.StatusOK, body: userJSON(adminID, roleAdmin, `{}`, "active", nil, "1700000000") + "\n",
			logged: "user_profile_invalid", calls: calls,
		},
	}

	runOutcomes(t, routeNamed(opSelf), cases)
}

// TestSelfIsNotAnotherAccount: "me" is a route of its own and is never read as
// an id, and the account asked for is the caller's whoever the caller is: there
// is nothing in the request that names another.
func TestSelfIsNotAnotherAccount(t *testing.T) {
	t.Parallel()

	for _, caller := range []string{adminID, targetID} {
		t.Run(caller, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			cookie := rg.signIn(caller, roleAdmin)
			rg.store.got = userRow(caller)

			rec := rg.do(request{
				method: http.MethodGet, target: selfTarget + "?id=" + otherID, body: "", contentType: "",
				cookies: []*http.Cookie{cookie},
			})

			wantCalls(t, rg.store.calls, []storeCall{getCall(caller)})

			if rec.Code != http.StatusOK {
				t.Errorf("response = %d %q", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestSelfWithAnIDThatIsNotOne: a credential whose user id is not an id (the
// schema forbids it, so this is a defect of the stored data) is a failure that
// never reaches the store, and is not a 404 that would read as a real account.
func TestSelfWithAnIDThatIsNotOne(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	cookie := rg.signIn("not-an-id", roleAdmin)

	rec := rg.as(cookie, http.MethodGet, selfTarget)

	wantResponse(t, rg, rec, http.StatusBadRequest, bodyInvalidID, "invalid_id")
	wantCalls(t, rg.store.calls, nil)
}

// TestProfile is every shape a stored profile can have, on the routes that show
// it. The schema does not constrain the column to an object, so the response is
// where a malformed one is dealt with: a profile that is not one valid JSON
// object is a defect of the stored data. It is logged, naming the account, and
// served as {}: the request succeeds, and the response is never malformed.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestProfile(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		profile string
		// want is the profile as the response carries it, or "" when it is logged
		// and replaced by {}.
		want string
	}{
		{name: "an empty object", profile: `{}`, want: `{}`},
		{name: "a name", profile: profileAda, want: profileAda},
		{name: "nested values", profile: `{"a":[1,{"b":null}],"c":{"d":"e"}}`, want: `{"a":[1,{"b":null}],"c":{"d":"e"}}`},
		{name: "whitespace around the object is dropped", profile: " \n{ \"a\" : 1 }\t\n", want: `{"a":1}`},
		{name: "non-ASCII text", profile: `{"name":"Ада 🙂"}`, want: `{"name":"Ада 🙂"}`},
		{name: "empty text", profile: ``, want: ""},
		{name: "blank text", profile: ` `, want: ""},
		{name: "null", profile: `null`, want: ""},
		{name: "an array", profile: `[]`, want: ""},
		{name: "a string", profile: `"Ada"`, want: ""},
		{name: "a number", profile: `1`, want: ""},
		{name: "a boolean", profile: `true`, want: ""},
		{name: "text that is not JSON", profile: `Ada`, want: ""},
		{name: "a truncated object", profile: `{"name":`, want: ""},
		{name: "an unterminated string", profile: `{"name":"Ada`, want: ""},
		{name: "single quotes", profile: `{'name':'Ada'}`, want: ""},
		{name: "a trailing comma", profile: `{"name":"Ada",}`, want: ""},
		{name: "two objects", profile: `{} {}`, want: ""},
		{name: "an extra closing brace", profile: `{"a":1}}`, want: ""},
		{name: "text after the object", profile: `{"a":1} x`, want: ""},
		{name: "a leading BOM", profile: "\ufeff{}", want: ""},
		{name: "invalid UTF-8", profile: "{\"name\":\"\xff\"}", want: ""},
	}

	for _, rt := range routes() {
		t.Run(rt.name, func(t *testing.T) {
			t.Parallel()

			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()

					rg := newRig(t)
					cookie := rg.signIn(adminID, roleAdmin)

					stored := userRow(targetID)
					stored.Profile = tc.profile
					rg.store.users, rg.store.got, rg.store.revoked = store.UserPage{Users: []store.User{stored}}, stored, stored
					rg.store.revoked.RevokedAt = new(int64(1_700_000_050))

					rec := rg.as(cookie, rt.method, rt.target)

					logged, want := "", tc.want
					if want == "" {
						logged, want = "user_profile_invalid", `{}`
					}

					body := userJSON(targetID, roleMember, want, "active", nil, "1700000000")

					switch rt.op {
					case opList:
						body = `{"users":[` + body + `]}`
					case opRevoke:
						body = userJSON(targetID, roleMember, want, "revoked", new(int64(1_700_000_050)), "1700000000")
					}

					wantResponse(t, rg, rec, http.StatusOK, body+"\n", logged)
				})
			}
		})
	}
}
