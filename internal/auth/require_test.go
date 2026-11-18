//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package auth_test

import (
	"net/http"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/store"
)

func TestAdmin(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		role string
		want bool
	}{
		"the constant":           {role: auth.RoleAdmin, want: true},
		"member":                 {role: roleMember, want: false},
		"no role":                {role: "", want: false},
		nameUpper:                {role: "ADMIN", want: false},
		"capitalised":            {role: "Admin", want: false},
		"trailing space":         {role: "admin ", want: false},
		"leading space":          {role: " admin", want: false},
		"a longer name":          {role: "administrator", want: false},
		"a shortened name":       {role: "adm", want: false},
		"superadmin":             {role: "superadmin", want: false},
		"admin with a NUL":       {role: "admin\x00", want: false},
		"admin with a lookalike": {role: "аdmin", want: false}, // a Cyrillic "а"
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := auth.Admin(auth.Principal{Role: tt.role, UserID: userID})
			if (err == nil) != tt.want {
				t.Fatalf("Admin(%q) = %v, want allowed = %v", tt.role, err, tt.want)
			}

			if err == nil {
				return
			}

			failure := apierr.As(err)
			if failure.Kind != apierr.Forbidden || failure.Code != "forbidden" {
				t.Errorf("error = %+v, want Forbidden forbidden", failure)
			}

			if failure.Description != "administrator access is required" {
				t.Errorf("description = %q", failure.Description)
			}
		})
	}

	if got := auth.RoleAdmin; got != adminText {
		t.Errorf("RoleAdmin = %q, want the stored spelling %q", got, adminText)
	}
}

func TestRoleForInvitation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		invitationType string
		wantRole       string
		wantOK         bool
	}{
		"first run":        {invitationType: store.InvitationFirstRun, wantRole: auth.RoleAdmin, wantOK: true},
		"first_run":        {invitationType: "first_run", wantRole: auth.RoleAdmin, wantOK: true},
		nameEmpty:          {invitationType: "", wantOK: false},
		"admin":            {invitationType: "admin", wantRole: auth.RoleAdmin, wantOK: true},
		"member":           {invitationType: "member", wantRole: auth.RoleMember, wantOK: true},
		"user":             {invitationType: "user", wantOK: false},
		"upper admin":      {invitationType: "ADMIN", wantOK: false},
		nameUpper:          {invitationType: "FIRST_RUN", wantOK: false},
		"trailing space":   {invitationType: "first_run ", wantOK: false},
		"another spelling": {invitationType: "first-run", wantOK: false},
		"a shortened type": {invitationType: "first", wantOK: false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			role, ok := auth.RoleForInvitation(tt.invitationType)
			if role != tt.wantRole || ok != tt.wantOK {
				t.Errorf("RoleForInvitation(%q) = %q, %v; want %q, %v", tt.invitationType, role, ok, tt.wantRole, tt.wantOK)
			}
		})
	}
}

// TestCreatableInvitationType: every type with a role is creatable except first
// run, so a creatable type never lacks a role.
func TestCreatableInvitationType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		invitationType string
		want           bool
	}{
		{"member", auth.InvitationMember, true},
		{"admin", auth.InvitationAdmin, true},
		{"first run is never creatable", store.InvitationFirstRun, false},
		{"empty", "", false},
		{"another case", "Member", false},
		{"a trailing space", "member ", false},
		{"a type with no role", "owner", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := auth.CreatableInvitationType(tt.invitationType); got != tt.want {
				t.Errorf("CreatableInvitationType(%q) = %v, want %v", tt.invitationType, got, tt.want)
			}

			if _, hasRole := auth.RoleForInvitation(tt.invitationType); tt.want && !hasRole {
				t.Errorf("creatable type %q has no role", tt.invitationType)
			}
		})
	}
}

// requireCase is a requirement and the request it is applied to.
type requireCase struct {
	target     string
	require    func(auth.Principal) error
	cookies    cookieFn
	wantStatus int
	wantBody   string
	// wantAsked is whether the requirement should have been asked.
	wantAsked bool
	wantCalls int
}

func allow(auth.Principal) error { return nil }

func classifiedRefusal(auth.Principal) error { return refusal() }

func refusal() *apierr.Error { return apierr.New(apierr.Forbidden, "nope", "not for you") }

func plainRefusal(auth.Principal) error { return errPlain }

func requireCases() map[string]requireCase {
	item := pathItems + itemID

	return map[string]requireCase{
		"allowed":            {item, allow, valid, 200, bodyOK, true, 1},
		"classified":         {item, classifiedRefusal, valid, 403, errorBody("nope", "not for you"), true, 1},
		"not classified":     {item, plainRefusal, valid, 500, bodyInternal, true, 1},
		"no session":         {item, allow, nil, 401, bodyUnauthenticated, false, 0},
		"bad id":             {pathItems + "NOPE", allow, valid, 400, bodyInvalidID, true, 1},
		"bad id, no session": {pathItems + "NOPE", allow, nil, 401, bodyUnauthenticated, false, 0},
		"bad id, refused":    {pathItems + "NOPE", classifiedRefusal, valid, 403, errorBody("nope", "not for you"), true, 1},
		"revoked":            {item, allow, afterStoring(revoked), 401, bodyUnauthenticated, false, 1},
	}
}

// TestRequireRunsOnlyForAVerifiedCaller: a requirement is a function of the
// Principal alone, runs once, after authentication and before the id is parsed,
// and never for a request
// that failed an earlier check. What it returns is what the client gets.
func TestRequireRunsOnlyForAVerifiedCaller(t *testing.T) {
	t.Parallel()

	for name, tt := range requireCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)

			var asked []auth.Principal

			guarded := r.getRoute(patternItem, auth.Session, func(p auth.Principal) error {
				asked = append(asked, p)

				return tt.require(p)
			})

			var cookies []*http.Cookie
			if tt.cookies != nil {
				cookies = tt.cookies(r)
			}

			rec := r.serve([]auth.Route{guarded}, request{target: tt.target, cookies: cookies})
			if rec.Code != tt.wantStatus || rec.Body.String() != tt.wantBody {
				t.Errorf("response = %d %q, want %d %q", rec.Code, rec.Body, tt.wantStatus, tt.wantBody)
			}

			if len(r.keys.calls) != tt.wantCalls {
				t.Errorf("store read %d times, want %d", len(r.keys.calls), tt.wantCalls)
			}

			if ran := len(r.handled) == 1; ran != (tt.wantStatus == http.StatusOK) {
				t.Errorf("route ran %d times for status %d", len(r.handled), rec.Code)
			}

			tt.checkAsked(t, asked)
		})
	}
}

// checkAsked checks that the requirement was asked about the verified
// principal, once, or not at all.
func (tt requireCase) checkAsked(t *testing.T, asked []auth.Principal) {
	t.Helper()

	if !tt.wantAsked {
		if len(asked) != 0 {
			t.Errorf("requirement was asked about %+v, want never", asked)
		}

		return
	}

	if len(asked) != 1 || asked[0].UserID != userID || asked[0].Kind != auth.KindSession {
		t.Errorf("requirement saw %+v, want the session's principal once", asked)
	}
}
