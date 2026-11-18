//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package auth_test

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// TestPrincipalIsTheStoredRow: who the caller is comes from the row the store
// returned, read now, and the clock the boundary was given.
func TestPrincipalIsTheStoredRow(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	key := r.sessionFor(userID, roleMember)

	rec := r.get(pathMe, sessionCookie(key))
	if rec.Code != http.StatusOK || len(r.handled) != 1 {
		t.Fatalf("status = %d, ran %d times", rec.Code, len(r.handled))
	}

	checkSessionPrincipal(t, r.handled[0].Principal, key)

	if len(r.keys.calls) != 1 || r.keys.calls[0].kid != key.ID.String() {
		t.Errorf("store read = %v, want one read of %s", r.keys.calls, key.ID)
	}
}

// checkSessionPrincipal checks who a member's session speaks for.
func checkSessionPrincipal(t *testing.T, got auth.Principal, key auth.Key) {
	t.Helper()

	if got.UserID != userID || got.Role != roleMember || got.KeyID != key.ID.String() ||
		got.CredentialID != credentialID || got.Kind != auth.KindSession || !got.ExpiresAt.Equal(key.ExpiresAt) ||
		got.AgentID != "" {
		t.Errorf("principal = %+v", got)
	}

	checkSessionScopes(t, got)
}

// checkSessionScopes checks that a session is signed with default:session and
// has no agent, so its effective scopes are all of them.
func checkSessionScopes(t *testing.T, got auth.Principal) {
	t.Helper()

	if !slices.Equal([]string(got.KeyScope), []string{scope.DefaultSession}) || len(got.AgentScope) != 0 {
		t.Errorf("scope lists = key %v, agent %v", got.KeyScope, got.AgentScope)
	}

	if want := len(scope.Scopes()); got.Effective.Len() != want {
		t.Errorf("effective scopes = %v, want all %d", got.Effective.Sorted(), want)
	}
}

// TestRoleIsNeverATokenClaim: a token that claims to be an administrator, even
// a correctly signed one that names every scope, has the role of its account's
// row. The role is read from the database on every request, so a demotion takes
// effect at once and no token can promote itself: an admin scope on a member's
// token grants nothing, and the same token works the moment the account is
// promoted.
func TestRoleIsNeverATokenClaim(t *testing.T) {
	t.Parallel()

	r := newRig(t)

	key, err := auth.CreateKey(r.issuer, auth.KeySpec{
		Kind: auth.KindSession, Subject: userID, Expires: r.now.Add(time.Hour),
		Scope:  scope.List{scope.DefaultSession},
		Claims: map[string]any{"role": auth.RoleAdmin, "is_admin": true},
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	r.keys.rows[rowKey{kid: key.ID.String(), kind: auth.KindSession}] = r.row(key, userID, roleMember)

	rec := r.serve(r.standardRoutes(), request{target: pathAdmin, cookies: []*http.Cookie{sessionCookie(key)}})
	wantFailure(t, r, rec, http.StatusForbidden, bodyForbidden, auth.CodeForbidden, nil)

	// The same token, when the account is later promoted, is an administrator
	// without a new token.
	r.setRow(key, func(row *store.ActiveKey) { row.Role = auth.RoleAdmin })

	rec = r.serve(r.standardRoutes(), request{target: pathAdmin, cookies: []*http.Cookie{sessionCookie(key)}})
	if rec.Code != http.StatusOK {
		t.Errorf("after promotion: status = %d, want 200", rec.Code)
	}
}

// TestNoneRoutesNeverTouchTheSession: a None route does not read the cookie,
// the configuration or the store, and its caller has no principal.
func TestNoneRoutesNeverTouchTheSession(t *testing.T) {
	t.Parallel()

	r := newRig(t)

	rec := r.get(pathPublic, sessionCookie(r.session()))
	if rec.Code != http.StatusOK || rec.Body.String() != bodyOK {
		t.Fatalf("response = %d %q", rec.Code, rec.Body)
	}

	if len(r.keys.calls) != 0 || r.envReads != 0 {
		t.Errorf("store read %d times and configuration %d times, want neither", len(r.keys.calls), r.envReads)
	}

	got := r.handled[0].Principal
	if got.UserID != "" || got.KeyID != "" || got.Effective.Len() != 0 || got.KeyScope != nil {
		t.Errorf("principal = %+v, want none", got)
	}
}

// TestRefusalsLeakNothingAboutTheKey: whatever was wrong with the token, the
// client gets the same status and the same bytes, so a response is not an oracle
// for whether a key exists, was revoked, or belongs to someone else.
func TestRefusalsLeakNothingAboutTheKey(t *testing.T) {
	t.Parallel()

	foreign := auth.Issuer{Base: "https://other.example.com/keys", Insecure: false}

	reasons := map[string]cookieFn{
		nameNoCookie:     nil,
		"garbage":        sessionValue("garbage"),
		"unknown key":    afterStoring(revoked),
		"another owner":  ownedBy(otherUserID),
		"two cookies":    twice(valid),
		nameEmpty:        sessionValue(""),
		"oversized":      sessionValue(strings.Repeat("a", 5000)),
		"another issuer": foreignIssuer(foreign),
		"never stored":   neverStored,
	}

	for name, reason := range reasons {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)

			var cookies []*http.Cookie
			if reason != nil {
				cookies = reason(r)
			}

			rec := r.get(pathMe, cookies...)
			if rec.Code != http.StatusUnauthorized || rec.Body.String() != bodyUnauthenticated {
				t.Errorf("response = %d %q, want 401 %q", rec.Code, rec.Body, bodyUnauthenticated)
			}

			if rec.Header().Get("Set-Cookie") != "" || rec.Header().Get("WWW-Authenticate") != "" {
				t.Errorf("headers = %v: a refusal says nothing but the body", rec.Header())
			}
		})
	}
}

// TestUnauthenticatedIsTheOneAnswer is the exported answer features use when
// they learn mid-request that the session is gone.
func TestUnauthenticatedIsTheOneAnswer(t *testing.T) {
	t.Parallel()

	for name, in := range map[string]error{"with a cause": errRevoked, "without one": nil} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			failure, found := errors.AsType[*apierr.Error](auth.Unauthenticated(in))
			if !found {
				t.Fatal("not an *apierr.Error")
			}

			if failure.Kind != apierr.Unauthorized || failure.Code != "unauthenticated" ||
				failure.Description != "not signed in" || failure.Data != nil {
				t.Errorf("error = %+v, want Unauthorized unauthenticated %q", failure, "not signed in")
			}

			if failure.Kind.Status() != http.StatusUnauthorized {
				t.Errorf("status = %d", failure.Kind.Status())
			}

			if in != nil && !errors.Is(failure, in) {
				t.Error("the cause is not kept for the log")
			}
		})
	}
}
