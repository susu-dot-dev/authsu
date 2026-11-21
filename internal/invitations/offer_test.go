package invitations_test

import (
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/invitations"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

const (
	// offeredOrg is an organization id as a client spells it.
	offeredOrg = "00000000-0000-7000-8000-0000000000f1"

	codeInvalidID      = "invalid_id"
	codeInvalidOrgRole = "invalid_org_role"
)

// offerBody is a create body of one account with the offer fields as given. A
// part that is empty is left out, and one that is given is JSON written
// verbatim, so a field can be missing, null or of any type.
func offerBody(orgID, orgRole string) string {
	body := `{"type":"member","numInvites":1`

	if orgID != "" {
		body += `,"orgId":` + orgID
	}

	if orgRole != "" {
		body += `,"orgRole":` + orgRole
	}

	return body + "}"
}

// TestCreateRefusesInvalidOffers: every refusal of the offer is a 400 that comes
// before anything is generated or stored, with the code of the value at fault.
// Both fields are needed together, and nothing is assumed for a missing one.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestCreateRefusesInvalidOffers(t *testing.T) {
	t.Parallel()

	tests := []invalidCase{
		// One without the other.
		{"a role with no organization", offerBody("", text("member")), input.CodeMissingOrgID},
		{"a role with a null organization", offerBody("null", text("member")), input.CodeMissingOrgID},
		{"an organization with no role", offerBody(text(offeredOrg), ""), input.CodeMissingOrgRole},
		{"an organization with a null role", offerBody(text(offeredOrg), "null"), input.CodeMissingOrgRole},

		// The organization: a canonical id, exactly as the parser says.
		{"an empty organization", offerBody(`""`, text("member")), codeInvalidID},
		{"an organization that is not an id", offerBody(text("acme"), text("member")), codeInvalidID},
		{"an organization id in upper case", offerBody(text(strings.ToUpper(offeredOrg)), text("member")), codeInvalidID},
		{"an organization id with a space", offerBody(text(offeredOrg+" "), text("member")), codeInvalidID},
		{"an organization id too short", offerBody(text(offeredOrg[1:]), text("member")), codeInvalidID},
		{"an organization id too long", offerBody(text(offeredOrg+"0"), text("member")), codeInvalidID},
		{"an organization id with a NUL", offerBody(text(offeredOrg[:35]+`\u0000`), text("member")), codeInvalidID},
		{"an organization id of 3000 characters", offerBody(text(strings.Repeat("a", 3000)), text("member")), codeInvalidID},
		{"an organization that is a number", offerBody("1", text("member")), codeInvalidFieldType},
		{"an organization that is an object", offerBody(`{"id":"`+offeredOrg+`"}`, text("member")), codeInvalidFieldType},
		{"an organization that is a list", offerBody(`["`+offeredOrg+`"]`, text("member")), codeInvalidFieldType},

		// The role: exactly member or admin.
		{"an empty role", offerBody(text(offeredOrg), `""`), codeInvalidOrgRole},
		{"a role in another case", offerBody(text(offeredOrg), text("Admin")), codeInvalidOrgRole},
		{"a role with a space", offerBody(text(offeredOrg), text("admin ")), codeInvalidOrgRole},
		{"a role with a NUL", offerBody(text(offeredOrg), text(`admin\u0000`)), codeInvalidOrgRole},
		{"a role the code does not know", offerBody(text(offeredOrg), text("owner")), codeInvalidOrgRole},
		{"the platform's own role", offerBody(text(offeredOrg), text("e2e_member")), codeInvalidOrgRole},
		{"a prefix of a role", offerBody(text(offeredOrg), text("adm")), codeInvalidOrgRole},
		{"a role of 3000 characters", offerBody(text(offeredOrg), text(strings.Repeat("a", 3000))), codeInvalidOrgRole},
		{"a role that is a number", offerBody(text(offeredOrg), "1"), codeInvalidFieldType},
		{"a role that is a boolean", offerBody(text(offeredOrg), "true"), codeInvalidFieldType},

		// Which is reported first: the id before the role, and every value of
		// the invitation before the offer.
		{"the organization before the role", offerBody(text("acme"), text("owner")), codeInvalidID},
		{"the invitation's expiry before the offer",
			`{"type":"member","numInvites":1,"expiresAt":0,"orgId":"acme","orgRole":"owner"}`, input.CodeInvalidExpiresAt},
		{"the invitation's type before the offer",
			`{"type":"nonsense","numInvites":1,"orgId":"acme","orgRole":"owner"}`, invitations.CodeInvalidType},

		// Names that are not the fields.
		{"the organization under another name",
			`{"type":"member","numInvites":1,"org":"` + offeredOrg + `","orgRole":"member"}`, codeUnknownField},
		{"the role under another name", `{"type":"member","numInvites":1,"orgId":"` + offeredOrg + `","role":"member"}`,
			codeUnknownField},
		{"the fields in another case", `{"type":"member","numInvites":1,"OrgID":"` + offeredOrg + `","OrgRole":"member"}`,
			codeUnknownField},
		{"the organization twice",
			`{"type":"member","numInvites":1,"orgId":"` + offeredOrg + `","orgId":"` + offeredOrg + `","orgRole":"member"}`,
			codeDuplicateField},
		{"the offer as an object",
			`{"type":"member","numInvites":1,"org":{"id":"` + offeredOrg + `","role":"member"}}`, codeUnknownField},
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

// TestCreateRefusesAnOversizedOffer: an organization or a role too large for the
// route's body limit is refused by the boundary before it is read, so a value
// that could only be an attempt to make the route read more never reaches a
// parser, an id or the store.
func TestCreateRefusesAnOversizedOffer(t *testing.T) {
	t.Parallel()

	huge := text(strings.Repeat("a", invitations.MaxBody))

	for name, body := range map[string]string{
		"the organization": offerBody(huge, text("member")),
		"the role":         offerBody(text(offeredOrg), huge),
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

// TestCreateOffersAnOrganization: each role reaches the store as the offer of the
// organization, written with the invitation (one create call) and with an id of
// its own after the invitation's; the response says what the database stored.
func TestCreateOffersAnOrganization(t *testing.T) {
	t.Parallel()

	for _, role := range input.OrgRoles() {
		t.Run(role, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)

			rec := harn.asAdmin(http.MethodPost, collectionPath, offerBody(text(offeredOrg), text(role)))
			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}

			if len(harn.store.calls) != 1 || harn.store.calls[0].op != opCreate {
				t.Fatalf("store calls = %v, want one create", harn.opsCalled())
			}

			expectOfferWritten(t, harn, role)

			got := decode[wireCreated](t, rec)
			if got.OrgID == nil || *got.OrgID != offeredOrg || got.OrgRole == nil || *got.OrgRole != role {
				t.Errorf("response offer = %v %v, want %s %s", got.OrgID, got.OrgRole, offeredOrg, role)
			}

			if harn.clock.calls != 1 {
				t.Errorf("the clock was read %d times, want once", harn.clock.calls)
			}
		})
	}
}

// expectOfferWritten checks what the one create the store received carries: the
// offer of offeredOrg as role, an id of its own issued after the invitation's,
// and the invitation's creator and time.
func expectOfferWritten(t *testing.T, harn *harness, role string) {
	t.Helper()

	created := harn.store.calls[0].created

	if want := wantOffer(t, role); !reflect.DeepEqual(created.Offer, want) {
		t.Errorf("offer = %+v, want %+v", created.Offer, want)
	}

	if created.ID != newInvID || harn.idCalls != 2 {
		t.Errorf("invitation id %q after %d ids, want %q after 2", created.ID, harn.idCalls, newInvID)
	}

	if created.CreatedBy != adminID || !created.CreatedAt.Equal(fixedNow()) {
		t.Errorf("offer is made by %q at %v, want the invitation's creator and time", created.CreatedBy, created.CreatedAt)
	}
}

// wantOffer is the offer of offeredOrg as role that a create must hand the store,
// made by the same parsers the package uses.
func wantOffer(t *testing.T, role string) *store.NewInvitationOffer {
	t.Helper()

	orgID, err := input.ParseID(offeredOrg)
	if err != nil {
		t.Fatal(err)
	}

	parsedRole, err := input.ParseOrgRole(role)
	if err != nil {
		t.Fatal(err)
	}

	return &store.NewInvitationOffer{ID: newOfferID, OrgID: orgID, Role: parsedRole}
}

// TestCreateWithoutAnOfferSendsNone: a create that names no organization (or
// nulls) hands the store no offer, issues one id, and its response has neither
// field.
func TestCreateWithoutAnOfferSendsNone(t *testing.T) {
	t.Parallel()

	for name, body := range map[string]string{
		"neither field": offerBody("", ""),
		"both null":     offerBody("null", "null"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)

			rec := harn.asAdmin(http.MethodPost, collectionPath, body)
			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}

			if harn.store.calls[0].created.Offer != nil || harn.idCalls != 1 {
				t.Errorf("offer %+v after %d ids, want none after 1", harn.store.calls[0].created.Offer, harn.idCalls)
			}

			if strings.Contains(rec.Body.String(), "org") {
				t.Errorf("an invitation with no offer shows one: %s", rec.Body.String())
			}
		})
	}
}

// TestCreateResponseShowsTheOffer pins the whole body of a create that carries
// an offer, as a client reads it: the offer's two fields follow createdAt.
func TestCreateResponseShowsTheOffer(t *testing.T) {
	t.Parallel()

	harn := newHarness(t)
	now := fixedNow().Unix()

	rec := harn.asAdmin(http.MethodPost, collectionPath,
		`{"type":"member","numInvites":3,"expiresAt":`+secs(now+3600)+`,"orgId":"`+offeredOrg+`","orgRole":"admin"}`)

	want := `{"id":"` + newInvID + `","type":"member","label":"","numInvites":3,"uses":0,` +
		`"status":"active","expiresAt":` + secs(now+3600) + `,"createdBy":"` + adminID + `","createdAt":` + secs(now) + `,` +
		`"orgId":"` + offeredOrg + `","orgRole":"admin",` +
		`"code":"` + codeOf(sequence(0, secret.BodyBytes)) + `"}` + "\n"

	if rec.Code != http.StatusCreated || rec.Body.String() != want {
		t.Errorf("response = %d\n%s\nwant\n%s", rec.Code, rec.Body.String(), want)
	}
}

// TestCreateResponseIsTheStoredOffer: the offer in the response is what the
// database returned and not what was asked for.
func TestCreateResponseIsTheStoredOffer(t *testing.T) {
	t.Parallel()

	stored := storedRow(func(r *store.Invitation) { r.OrgID, r.OrgRole = new("from-the-db"), new("member") })

	harn := newHarness(t)
	harn.store.created = &stored

	rec := harn.asAdmin(http.MethodPost, collectionPath, offerBody(text(offeredOrg), text("admin")))

	got := decode[wireCreated](t, rec)
	if got.OrgID == nil || *got.OrgID != "from-the-db" || got.OrgRole == nil || *got.OrgRole != "member" {
		t.Errorf("response offer = %v %v, want what the database stored", got.OrgID, got.OrgRole)
	}
}

// TestCreateRefusesAnOrganizationThatCannotBeOffered: the store's refusal (the
// organization does not exist, is a sandbox, or is revoked at the write) is a
// 404 org_not_found with the cause only in the log, whatever the way, and no
// token is shown for the invitation that was not created.
func TestCreateRefusesAnOrganizationThatCannotBeOffered(t *testing.T) {
	t.Parallel()

	causes := map[string]error{
		"the bare sentinel":           store.ErrOfferOrgUnavailable,
		"with the database's text":    errors.Join(store.ErrOfferOrgUnavailable, errDB),
		"wrapped by another function": wrapped(store.ErrOfferOrgUnavailable),
	}

	for name, cause := range causes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.store.err = cause

			rec := harn.asAdmin(http.MethodPost, collectionPath, offerBody(text(offeredOrg), text("member")))

			wantError(t, harn, rec, http.StatusNotFound, invitations.CodeOrgNotFound, invitations.CodeOrgNotFound)

			if code := codeOf(sequence(0, secret.BodyBytes)); strings.Contains(rec.Body.String(), code) {
				t.Errorf("a refused create returned its token: %s", rec.Body.String())
			}

			if strings.Contains(rec.Body.String(), offeredOrg) {
				t.Errorf("the refusal echoes the organization: %s", rec.Body.String())
			}
		})
	}
}

// wrapped is err wrapped by a caller that says what it was doing.
func wrapped(err error) error { return errors.Join(errWrapper, err) }

// errWrapper is the context a caller adds around a store error.
var errWrapper = errors.New("create invitation")

// TestCreateWithAnOfferFailsWhenTheStoreDoes: the other failures of the write are
// the same as without an offer, and a bare conflict is still not a 409.
func TestCreateWithAnOfferFailsWhenTheStoreDoes(t *testing.T) {
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

			rec := harn.asAdmin(http.MethodPost, collectionPath, offerBody(text(offeredOrg), text("member")))

			wantError(t, harn, rec, tt.status, tt.wireCode, tt.logCode)
		})
	}
}

// offeredRow is a stored invitation that carries an offer of offeredOrg as an
// administrator.
func offeredRow() store.Invitation {
	return storedRow(func(r *store.Invitation) { r.OrgID, r.OrgRole = new(offeredOrg), new("admin") })
}

// expectOffer fails the test unless the invitation shows the offer of offeredOrg.
func expectOffer(t *testing.T, what string, got wireInvitation) {
	t.Helper()

	if got.OrgID == nil || *got.OrgID != offeredOrg || got.OrgRole == nil || *got.OrgRole != "admin" {
		t.Errorf("%s shows %v %v, want the offer", what, got.OrgID, got.OrgRole)
	}
}

// TestListShowsTheOffers: the list shows the offer of an invitation that has one,
// and neither field of one that has none.
func TestListShowsTheOffers(t *testing.T) {
	t.Parallel()

	harn := newHarness(t)
	harn.store.list = []store.Invitation{offeredRow(), storedRow(nil)}

	rec := harn.asAdmin(http.MethodGet, collectionPath, "")
	body := rec.Body.String()

	got := decode[wireList](t, rec).Invitations
	if len(got) != 2 {
		t.Fatalf("listed %d invitations, want 2", len(got))
	}

	expectOffer(t, "first", got[0])

	if got[1].OrgID != nil || got[1].OrgRole != nil {
		t.Errorf("second = %v %v, want none", got[1].OrgID, got[1].OrgRole)
	}

	if strings.Count(body, "orgId") != 1 || strings.Count(body, "orgRole") != 1 {
		t.Errorf("the body shows an offer that does not exist: %s", body)
	}
}

// TestUpdateAndRevokeShowTheOffer: an update and a revoke show the offer of the
// row the store returned, and a refused update shows no invitation at all.
func TestUpdateAndRevokeShowTheOffer(t *testing.T) {
	t.Parallel()

	t.Run("update", func(t *testing.T) {
		t.Parallel()

		harn := newHarness(t)
		harn.store.updated, harn.store.applied = offeredRow(), true

		expectOffer(t, "update", decode[wireInvitation](t, harn.asAdmin(http.MethodPatch, itemPath, `{"numInvites":9}`)))
	})

	t.Run("update that did not apply", func(t *testing.T) {
		t.Parallel()

		harn := newHarness(t)
		harn.store.updated, harn.store.applied = offeredRow(), false

		rec := harn.asAdmin(http.MethodPatch, itemPath, `{"numInvites":9}`)

		if rec.Code != http.StatusConflict || strings.Contains(rec.Body.String(), offeredOrg) {
			t.Errorf("response = %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("revoke", func(t *testing.T) {
		t.Parallel()

		harn := newHarness(t)
		harn.store.revoked = offeredRow()

		expectOffer(t, "revoke", decode[wireInvitation](t, harn.asAdmin(http.MethodDelete, itemPath, "")))
	})
}
