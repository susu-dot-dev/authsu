//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package auth_test

import (
	"testing"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/store"
)

func TestRoleAdminIsTheStoredSpelling(t *testing.T) {
	t.Parallel()

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
