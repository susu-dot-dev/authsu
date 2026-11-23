package invitations_test

import (
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/invitations"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

const (
	// namedOrg is an organization id as a client spells it.
	namedOrg = "00000000-0000-7000-8000-0000000000f1"

	codeInvalidID      = "invalid_id"
	codeInvalidOrgRole = "invalid_org_role"
)

// orgBody is a create body of one account with the organization fields as given. A
// part that is empty is left out, and one that is given is JSON written
// verbatim, so a field can be missing, null or of any type.
func orgBody(orgID, orgRole string) string {
	body := `{"type":"member","numInvites":1`

	if orgID != "" {
		body += `,"orgId":` + orgID
	}

	if orgRole != "" {
		body += `,"orgRole":` + orgRole
	}

	return body + "}"
}

// TestCreateRefusesInvalidOrgs: every refusal of the organization is a 400 that comes
// before anything is generated or stored, with the code of the value at fault.
// Both fields are needed together, and nothing is assumed for a missing one.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestCreateRefusesInvalidOrgs(t *testing.T) {
	t.Parallel()

	tests := []invalidCase{
		// One without the other.
		{"a role with no organization", orgBody("", text("member")), input.CodeMissingOrgID},
		{"a role with a null organization", orgBody("null", text("member")), input.CodeMissingOrgID},
		{"an organization with no role", orgBody(text(namedOrg), ""), input.CodeMissingOrgRole},
		{"an organization with a null role", orgBody(text(namedOrg), "null"), input.CodeMissingOrgRole},

		// The organization: a canonical id, exactly as the parser says.
		{"an empty organization", orgBody(`""`, text("member")), codeInvalidID},
		{"an organization that is not an id", orgBody(text("acme"), text("member")), codeInvalidID},
		{"an organization id in upper case", orgBody(text(strings.ToUpper(namedOrg)), text("member")), codeInvalidID},
		{"an organization id with a space", orgBody(text(namedOrg+" "), text("member")), codeInvalidID},
		{"an organization id too short", orgBody(text(namedOrg[1:]), text("member")), codeInvalidID},
		{"an organization id too long", orgBody(text(namedOrg+"0"), text("member")), codeInvalidID},
		{"an organization id with a NUL", orgBody(text(namedOrg[:35]+`\u0000`), text("member")), codeInvalidID},
		{"an organization id of 3000 characters", orgBody(text(strings.Repeat("a", 3000)), text("member")), codeInvalidID},
		{"an organization that is a number", orgBody("1", text("member")), codeInvalidFieldType},
		{"an organization that is an object", orgBody(`{"id":"`+namedOrg+`"}`, text("member")), codeInvalidFieldType},
		{"an organization that is a list", orgBody(`["`+namedOrg+`"]`, text("member")), codeInvalidFieldType},

		// The role: exactly member or admin.
		{"an empty role", orgBody(text(namedOrg), `""`), codeInvalidOrgRole},
		{"a role in another case", orgBody(text(namedOrg), text("Admin")), codeInvalidOrgRole},
		{"a role with a space", orgBody(text(namedOrg), text("admin ")), codeInvalidOrgRole},
		{"a role with a NUL", orgBody(text(namedOrg), text(`admin\u0000`)), codeInvalidOrgRole},
		{"a role the code does not know", orgBody(text(namedOrg), text("owner")), codeInvalidOrgRole},
		{"the platform's own role", orgBody(text(namedOrg), text("e2e_member")), codeInvalidOrgRole},
		{"a prefix of a role", orgBody(text(namedOrg), text("adm")), codeInvalidOrgRole},
		{"a role of 3000 characters", orgBody(text(namedOrg), text(strings.Repeat("a", 3000))), codeInvalidOrgRole},
		{"a role that is a number", orgBody(text(namedOrg), "1"), codeInvalidFieldType},
		{"a role that is a boolean", orgBody(text(namedOrg), "true"), codeInvalidFieldType},

		// Which is reported first: the id before the role, and every value of
		// the invitation before the organization.
		{"the organization before the role", orgBody(text("acme"), text("owner")), codeInvalidID},
		{"the invitation's expiry before the organization",
			`{"type":"member","numInvites":1,"expiresAt":0,"orgId":"acme","orgRole":"owner"}`, input.CodeInvalidExpiresAt},
		{"the invitation's type before the organization",
			`{"type":"nonsense","numInvites":1,"orgId":"acme","orgRole":"owner"}`, invitations.CodeInvalidType},

		// Names that are not the fields.
		{"the organization under another name",
			`{"type":"member","numInvites":1,"org":"` + namedOrg + `","orgRole":"member"}`, codeUnknownField},
		{"the role under another name", `{"type":"member","numInvites":1,"orgId":"` + namedOrg + `","role":"member"}`,
			codeUnknownField},
		{"the fields in another case", `{"type":"member","numInvites":1,"OrgID":"` + namedOrg + `","OrgRole":"member"}`,
			codeUnknownField},
		{"the organization twice",
			`{"type":"member","numInvites":1,"orgId":"` + namedOrg + `","orgId":"` + namedOrg + `","orgRole":"member"}`,
			codeDuplicateField},
		{"the organization as an object",
			`{"type":"member","numInvites":1,"org":{"id":"` + namedOrg + `","role":"member"}}`, codeUnknownField},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)

			rec := harn.asAdmin(http.MethodPost, collectionPath, tt.body)

			wantError(t, harn, rec, http.StatusBadRequest, tt.code, tt.code)

			if len(harn.store.calls) != 0 || harn.entropy.taken != 0 || harn.idCalls != 0 {
				t.Errorf("a refused request did work: store %v, entropy %d bytes, %d ids",
					harn.opsCalled(), harn.entropy.taken, harn.idCalls)
			}
		})
	}
}

// TestCreateRefusesAnOversizedOrg: an organization or a role too large for the
// route's body limit is refused by the boundary before it is read, so a value
// that could only be an attempt to make the route read more never reaches a
// parser, an id or the store.
func TestCreateRefusesAnOversizedOrg(t *testing.T) {
	t.Parallel()

	huge := text(strings.Repeat("a", invitations.MaxBody))

	for name, body := range map[string]string{
		"the organization": orgBody(huge, text("member")),
		"the role":         orgBody(text(namedOrg), huge),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)

			rec := harn.asAdmin(http.MethodPost, collectionPath, body)

			wantError(t, harn, rec, http.StatusRequestEntityTooLarge, "body_too_large", "body_too_large")

			if len(harn.store.calls) != 0 || harn.entropy.taken != 0 || harn.idCalls != 0 {
				t.Errorf("a refused request did work: store %v", harn.opsCalled())
			}
		})
	}
}

// TestCreateNamesAnOrganization: each role reaches the store with the
// organization, written with the invitation (one create call, one id issued);
// the response says what the database stored.
func TestCreateNamesAnOrganization(t *testing.T) {
	t.Parallel()

	for _, role := range input.OrgRoles() {
		t.Run(role, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)

			rec := harn.asAdmin(http.MethodPost, collectionPath, orgBody(text(namedOrg), text(role)))
			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}

			if len(harn.store.calls) != 1 || harn.store.calls[0].op != opCreate {
				t.Fatalf("store calls = %v, want one create", harn.opsCalled())
			}

			expectOrgWritten(t, harn, role)

			got := decode[wireCreated](t, rec)
			if got.OrgID == nil || *got.OrgID != namedOrg || got.OrgRole == nil || *got.OrgRole != role {
				t.Errorf("response organization = %v %v, want %s %s", got.OrgID, got.OrgRole, namedOrg, role)
			}

			if harn.clock.calls != 1 {
				t.Errorf("the clock was read %d times, want once", harn.clock.calls)
			}
		})
	}
}

// expectOrgWritten checks what the one create the store received carries: the
// organization namedOrg as role, and the invitation's creator and time.
func expectOrgWritten(t *testing.T, harn *harness, role string) {
	t.Helper()

	created := harn.store.calls[0].created

	if want := wantOrg(t, role); !reflect.DeepEqual(created.Org, want) {
		t.Errorf("organization = %+v, want %+v", created.Org, want)
	}

	if created.ID != newInvID || harn.idCalls != 1 {
		t.Errorf("invitation id %q after %d ids, want %q after 1", created.ID, harn.idCalls, newInvID)
	}

	if created.CreatedBy != adminID || !created.CreatedAt.Equal(fixedNow()) {
		t.Errorf("invitation is made by %q at %v, want the creator and time of the request",
			created.CreatedBy, created.CreatedAt)
	}
}

// wantOrg is the organization namedOrg as role that a create must hand the
// store, made by the same parsers the package uses.
func wantOrg(t *testing.T, role string) *store.NewInvitationOrg {
	t.Helper()

	orgID, err := input.ParseID(namedOrg)
	if err != nil {
		t.Fatal(err)
	}

	parsedRole, err := input.ParseOrgRole(role)
	if err != nil {
		t.Fatal(err)
	}

	return &store.NewInvitationOrg{OrgID: orgID, Role: parsedRole}
}

// TestCreateWithoutAnOrgSendsNone: a create that names no organization (or
// nulls) hands the store no organization, issues one id, and its response has neither
// field.
func TestCreateWithoutAnOrgSendsNone(t *testing.T) {
	t.Parallel()

	for name, body := range map[string]string{
		"neither field": orgBody("", ""),
		"both null":     orgBody("null", "null"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)

			rec := harn.asAdmin(http.MethodPost, collectionPath, body)
			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}

			if harn.store.calls[0].created.Org != nil || harn.idCalls != 1 {
				t.Errorf("organization %+v after %d ids, want none after 1", harn.store.calls[0].created.Org, harn.idCalls)
			}

			if strings.Contains(rec.Body.String(), "org") {
				t.Errorf("an invitation with no organization shows one: %s", rec.Body.String())
			}
		})
	}
}

// TestCreateResponseShowsTheOrg pins the whole body of a create that carries
// an organization, as a client reads it: the two fields follow createdAt.
func TestCreateResponseShowsTheOrg(t *testing.T) {
	t.Parallel()

	harn := newHarness(t)
	now := fixedNow().Unix()

	rec := harn.asAdmin(http.MethodPost, collectionPath,
		`{"type":"member","numInvites":3,"expiresAt":`+secs(now+3600)+`,"orgId":"`+namedOrg+`","orgRole":"admin"}`)

	want := `{"id":"` + newInvID + `","type":"member","label":"","numInvites":3,"uses":0,` +
		`"status":"active","expiresAt":` + secs(now+3600) + `,"createdBy":"` + adminID + `","createdAt":` + secs(now) + `,` +
		`"orgId":"` + namedOrg + `","orgRole":"admin",` +
		`"code":"` + codeOf(sequence(0, secret.BodyBytes)) + `"}` + "\n"

	if rec.Code != http.StatusCreated || rec.Body.String() != want {
		t.Errorf("response = %d\n%s\nwant\n%s", rec.Code, rec.Body.String(), want)
	}
}

// TestCreateResponseIsTheStoredOrg: the organization in the response is what the
// database returned and not what was asked for.
func TestCreateResponseIsTheStoredOrg(t *testing.T) {
	t.Parallel()

	stored := storedRow(func(r *store.Invitation) { r.OrgID, r.OrgRole = new("from-the-db"), new("member") })

	harn := newHarness(t)
	harn.store.created = &stored

	rec := harn.asAdmin(http.MethodPost, collectionPath, orgBody(text(namedOrg), text("admin")))

	got := decode[wireCreated](t, rec)
	if got.OrgID == nil || *got.OrgID != "from-the-db" || got.OrgRole == nil || *got.OrgRole != "member" {
		t.Errorf("response organization = %v %v, want what the database stored", got.OrgID, got.OrgRole)
	}
}

// TestCreateRefusesAnOrganizationThatCannotBeNamed: the store's refusal (the
// organization does not exist, is a sandbox, or is revoked at the write) is a
// 404 org_not_found with the cause only in the log, whatever the way, and no
// token is shown for the invitation that was not created.
func TestCreateRefusesAnOrganizationThatCannotBeNamed(t *testing.T) {
	t.Parallel()

	causes := map[string]error{
		"the bare sentinel":           store.ErrInvitationOrgUnavailable,
		"with the database's text":    errors.Join(store.ErrInvitationOrgUnavailable, errDB),
		"wrapped by another function": wrapped(store.ErrInvitationOrgUnavailable),
	}

	for name, cause := range causes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.store.err = cause

			rec := harn.asAdmin(http.MethodPost, collectionPath, orgBody(text(namedOrg), text("member")))

			wantError(t, harn, rec, http.StatusNotFound, invitations.CodeOrgNotFound, invitations.CodeOrgNotFound)

			if code := codeOf(sequence(0, secret.BodyBytes)); strings.Contains(rec.Body.String(), code) {
				t.Errorf("a refused create returned its token: %s", rec.Body.String())
			}

			if strings.Contains(rec.Body.String(), namedOrg) {
				t.Errorf("the refusal echoes the organization: %s", rec.Body.String())
			}
		})
	}
}

// TestCreateMapsTheStoresRefusals: the two ways the store refuses a create that
// the client can cause, each its own answer, with or without an organization and
// however the store wraps it: a creator who is revoked at the write is a 401 (the
// caller is no longer anyone), and an organization that cannot be named is a 404
// org_not_found. Neither returns a token or echoes anything the database said.
func TestCreateMapsTheStoresRefusals(t *testing.T) {
	t.Parallel()

	bodies := map[string]string{
		"without an organization": `{"type":"member","numInvites":1}`,
		"naming an organization":  orgBody(text(namedOrg), text("member")),
	}

	causes := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"a revoked creator", store.ErrAccountRevoked, http.StatusUnauthorized, auth.CodeUnauthenticated},
		{"a revoked creator, with the database's text", errors.Join(store.ErrAccountRevoked, errDB),
			http.StatusUnauthorized, auth.CodeUnauthenticated},
		{"a revoked creator, wrapped by another function", wrapped(store.ErrAccountRevoked),
			http.StatusUnauthorized, auth.CodeUnauthenticated},
		{"an organization that cannot be named", store.ErrInvitationOrgUnavailable,
			http.StatusNotFound, invitations.CodeOrgNotFound},
		{"an organization that cannot be named, with the database's text",
			errors.Join(store.ErrInvitationOrgUnavailable, errDB), http.StatusNotFound, invitations.CodeOrgNotFound},
	}

	for bodyName, body := range bodies {
		for _, cause := range causes {
			t.Run(bodyName+"/"+cause.name, func(t *testing.T) {
				t.Parallel()

				harn := newHarness(t)
				harn.store.err = cause.err

				rec := harn.asAdmin(http.MethodPost, collectionPath, body)

				wantError(t, harn, rec, cause.status, cause.code, cause.code)

				if code := codeOf(sequence(0, secret.BodyBytes)); strings.Contains(rec.Body.String(), code) {
					t.Errorf("a refused create returned its token: %s", rec.Body.String())
				}

				if len(harn.store.calls) != 1 {
					t.Errorf("store calls = %d, want 1", len(harn.store.calls))
				}
			})
		}
	}
}

// wrapped is err wrapped by a caller that says what it was doing.
func wrapped(err error) error { return errors.Join(errWrapper, err) }

// errWrapper is the context a caller adds around a store error.
var errWrapper = errors.New("create invitation")

// TestCreateWithAnOrgFailsWhenTheStoreDoes: the other failures of the write are
// the same as without an organization, and a bare conflict is still not a 409.
func TestCreateWithAnOrgFailsWhenTheStoreDoes(t *testing.T) {
	t.Parallel()

	failures := append(storeFailures(store.CodeInvitationCreateFailed, store.CodeInvitationCreateRejected),
		storeFailure{
			"an unclassified conflict", store.ErrConflict, http.StatusInternalServerError, codeInternal, codeInternal,
		})

	for _, tt := range failures {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.store.err = tt.err

			rec := harn.asAdmin(http.MethodPost, collectionPath, orgBody(text(namedOrg), text("member")))

			wantError(t, harn, rec, tt.status, tt.wireCode, tt.logCode)
		})
	}
}

// namedRow is a stored invitation that carries an organization of namedOrg as an
// administrator.
func namedRow() store.Invitation {
	return storedRow(func(r *store.Invitation) { r.OrgID, r.OrgRole = new(namedOrg), new("admin") })
}

// expectOrg fails the test unless the invitation shows the organization of namedOrg.
func expectOrg(t *testing.T, what string, got wireInvitation) {
	t.Helper()

	if got.OrgID == nil || *got.OrgID != namedOrg || got.OrgRole == nil || *got.OrgRole != "admin" {
		t.Errorf("%s shows %v %v, want the organization", what, got.OrgID, got.OrgRole)
	}
}

// TestListShowsTheOrgs: the list shows the organization of an invitation that has one,
// and neither field of one that has none.
func TestListShowsTheOrgs(t *testing.T) {
	t.Parallel()

	harn := newHarness(t)
	harn.store.list = []store.Invitation{namedRow(), storedRow(nil)}

	rec := harn.asAdmin(http.MethodGet, collectionPath, "")
	body := rec.Body.String()

	got := decode[wireList](t, rec).Invitations
	if len(got) != 2 {
		t.Fatalf("listed %d invitations, want 2", len(got))
	}

	expectOrg(t, "first", got[0])

	if got[1].OrgID != nil || got[1].OrgRole != nil {
		t.Errorf("second = %v %v, want none", got[1].OrgID, got[1].OrgRole)
	}

	if strings.Count(body, "orgId") != 1 || strings.Count(body, "orgRole") != 1 {
		t.Errorf("the body shows an organization that does not exist: %s", body)
	}
}

// TestUpdateAndRevokeShowTheOrg: an update and a revoke show the organization of the
// row the store returned, and a refused update shows no invitation at all.
func TestUpdateAndRevokeShowTheOrg(t *testing.T) {
	t.Parallel()

	t.Run("update", func(t *testing.T) {
		t.Parallel()

		harn := newHarness(t)
		harn.store.updated, harn.store.applied = namedRow(), true

		expectOrg(t, "update", decode[wireInvitation](t, harn.asAdmin(http.MethodPatch, itemPath, `{"numInvites":9}`)))
	})

	t.Run("update that did not apply", func(t *testing.T) {
		t.Parallel()

		harn := newHarness(t)
		harn.store.updated, harn.store.applied = namedRow(), false

		rec := harn.asAdmin(http.MethodPatch, itemPath, `{"numInvites":9}`)

		if rec.Code != http.StatusConflict || strings.Contains(rec.Body.String(), namedOrg) {
			t.Errorf("response = %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("revoke", func(t *testing.T) {
		t.Parallel()

		harn := newHarness(t)
		harn.store.revoked = namedRow()

		expectOrg(t, "revoke", decode[wireInvitation](t, harn.asAdmin(http.MethodDelete, itemPath, "")))
	})
}
