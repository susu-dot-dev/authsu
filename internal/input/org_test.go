//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package input_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/input"
)

// The organization kind and offer role are closed sets that the parsers own:
// each table lists every spelling a client might try, and only the exact values
// are accepted. A refusal is the type's one fixed text, so it cannot echo the
// input.

// enumCases is the table for a parser of a closed set of lower-case words:
// every member accepted as written, and every near miss refused.
func enumCases(members ...string) []parseCase {
	cases := make([]parseCase, 0, 9+12*len(members))

	cases = append(cases,
		parseCase{"empty", "", false},
		parseCase{"NUL alone", "\x00", false},
		parseCase{"a space", " ", false},
		parseCase{"unknown word", "organization", false},
		parseCase{"unknown word with a NUL tail", "nope\x00", false},
		parseCase{"far too long", strings.Repeat("a", 4096), false},
		parseCase{"invalid UTF-8", "\xff", false},
		parseCase{"both members joined", strings.Join(members, ","), false},
		parseCase{"both members spaced", strings.Join(members, " "), false},
	)

	for _, member := range members {
		cases = append(cases,
			parseCase{"exactly " + member, member, true},
			parseCase{member + " upper-cased", strings.ToUpper(member), false},
			parseCase{member + " capitalised", strings.ToUpper(member[:1]) + member[1:], false},
			parseCase{member + " with a leading space", " " + member, false},
			parseCase{member + " with a trailing space", member + " ", false},
			parseCase{member + " with a trailing newline", member + "\n", false},
			parseCase{member + " with a trailing NUL", member + "\x00", false},
			parseCase{member + " with a NUL inside", member[:2] + "\x00" + member[2:], false},
			parseCase{member + " with a trailing letter", member + "s", false},
			parseCase{member + " truncated", member[:len(member)-1], false},
			parseCase{member + " with a zero-width space", member[:2] + "\u200b" + member[2:], false},
			parseCase{member + " in quotes", `"` + member + `"`, false},
		)
	}

	return cases
}

func parseOrgKind(raw string) (string, error) {
	return strAdapter(input.ParseOrgKind, input.OrgKind.String)(raw)
}

func parseOrgRole(raw string) (string, error) {
	return strAdapter(input.ParseOrgRole, input.OrgRole.String)(raw)
}

func TestParseOrgKind(t *testing.T) {
	t.Parallel()

	cases := append(enumCases(input.OrgKinds()...),
		// The other enumeration's words are not kinds.
		parseCase{"a role is not a kind", input.OrgRoleMember, false},
		parseCase{"the admin role is not a kind", input.OrgRoleAdmin, false},
	)

	runStringTable(t, cases, parseOrgKind, input.CodeInvalidOrgKind)
}

func TestParseOrgRole(t *testing.T) {
	t.Parallel()

	cases := append(enumCases(input.OrgRoles()...),
		parseCase{"a kind is not a role", input.OrgKindStandard, false},
		parseCase{"the sandbox kind is not a role", input.OrgKindSandbox, false},
		// The platform's own role spelling is a different thing.
		parseCase{"owner", "owner", false},
	)

	runStringTable(t, cases, parseOrgRole, input.CodeInvalidOrgRole)
}

// TestOrgEnumerationsAreStated holds the sets to what the constants say, so a
// value added to one place and not the other is noticed: every listed value
// parses, is distinct, and appears in the fixed refusal text a client reads.
func TestOrgEnumerationsAreStated(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []string
		parse  func(string) (string, error)
		code   string
		want   []string
	}{
		{"kind", input.OrgKinds(), parseOrgKind, input.CodeInvalidOrgKind, []string{"standard", "sandbox"}},
		{"role", input.OrgRoles(), parseOrgRole, input.CodeInvalidOrgRole, []string{"member", "admin"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if !slices.Equal(test.values, test.want) {
				t.Fatalf("values = %v, want %v", test.values, test.want)
			}

			_, err := test.parse("\x00")
			description := descriptionOf(t, err, test.code)

			for _, value := range test.values {
				got, parseErr := test.parse(value)
				if parseErr != nil || got != value {
					t.Errorf("parse(%q) = %q, %v", value, got, parseErr)
				}

				if !strings.Contains(description, `"`+value+`"`) {
					t.Errorf("description %q does not state %q", description, value)
				}
			}
		})
	}
}

// TestOrgEnumerationsReturnCopies holds that a caller cannot change the sets.
func TestOrgEnumerationsReturnCopies(t *testing.T) {
	t.Parallel()

	kinds := input.OrgKinds()
	kinds[0] = "tampered"

	roles := input.OrgRoles()
	roles[0] = "tampered"

	if input.OrgKinds()[0] != input.OrgKindStandard || input.OrgRoles()[0] != input.OrgRoleMember {
		t.Error("OrgKinds or OrgRoles returned a shared slice")
	}
}

// TestOrgPredicates holds Sandbox and Admin, and that the zero values are
// neither a kind nor a role.
func TestOrgPredicates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		kind      string
		role      string
		isSandbox bool
		isAdmin   bool
	}{
		{"standard member", input.OrgKindStandard, input.OrgRoleMember, false, false},
		{"sandbox admin", input.OrgKindSandbox, input.OrgRoleAdmin, true, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			kind, err := input.ParseOrgKind(test.kind)
			if err != nil || kind.Sandbox() != test.isSandbox {
				t.Errorf("kind %q: Sandbox() = %v, %v; want %v", test.kind, kind.Sandbox(), err, test.isSandbox)
			}

			role, err := input.ParseOrgRole(test.role)
			if err != nil || role.Admin() != test.isAdmin {
				t.Errorf("role %q: Admin() = %v, %v; want %v", test.role, role.Admin(), err, test.isAdmin)
			}
		})
	}

	var (
		kind input.OrgKind
		role input.OrgRole
	)

	if kind.String() != "" || kind.Sandbox() || role.String() != "" || role.Admin() {
		t.Error("the zero OrgKind or OrgRole is a value")
	}
}

// TestOrgEnumerationsFitTheSchema holds the longest value of each set inside
// the CHECK of the column it is stored in.
func TestOrgEnumerationsFitTheSchema(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		values  []string
		pattern string
	}{
		{"orgs.kind", input.OrgKinds(),
			`CREATE TABLE orgs \(.*? kind TEXT NOT NULL CHECK \(typeof\(kind\) = 'text' ` +
				`AND length\(kind\) BETWEEN \d+ AND (\d+)\)`},
		{"org_offers.role", input.OrgRoles(),
			`CREATE TABLE org_offers \(.*? role TEXT NOT NULL CHECK \(typeof\(role\) = 'text' ` +
				`AND length\(role\) BETWEEN \d+ AND (\d+)\)`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			limit := migrationNumbers(t, test.pattern)

			for _, value := range test.values {
				if len(value) < 1 || len(value) > limit[0] {
					t.Errorf("%q is %d bytes, outside the CHECK of 1 to %d", value, len(value), limit[0])
				}
			}
		})
	}
}

func orgSetOracle(members ...string) func(string) bool {
	return func(s string) bool { return slices.Contains(members, s) }
}

func FuzzParseOrgKind(f *testing.F) {
	fuzzString(f, seedsOf(enumCases(input.OrgKinds()...)), input.ParseOrgKind, input.OrgKind.String,
		input.CodeInvalidOrgKind, orgSetOracle(input.OrgKinds()...))
}

func FuzzParseOrgRole(f *testing.F) {
	fuzzString(f, seedsOf(enumCases(input.OrgRoles()...)), input.ParseOrgRole, input.OrgRole.String,
		input.CodeInvalidOrgRole, orgSetOracle(input.OrgRoles()...))
}

const offerTestOrg = "00000000-0000-7000-8000-0000000000f1"

// TestParseOrgOffer holds every combination of the two optional fields: neither
// is no offer, one without the other is refused naming the missing one (before
// the value given is looked at), and a value given is parsed as its own type
// parses it, the organization first.
func TestParseOrgOffer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		id      *string
		role    *string
		offered bool
		code    string
	}{
		{"neither", nil, nil, false, ""},
		{"a member offer", new(offerTestOrg), new("member"), true, ""},
		{"an admin offer", new(offerTestOrg), new("admin"), true, ""},
		{"a role with no organization", nil, new("member"), false, input.CodeMissingOrgID},
		{"an invalid role with no organization", nil, new("owner"), false, input.CodeMissingOrgID},
		{"an organization with no role", new(offerTestOrg), nil, false, input.CodeMissingOrgRole},
		{"an invalid organization with no role", new("nope"), nil, false, input.CodeMissingOrgRole},
		{"an empty role is a role", new(offerTestOrg), new(""), false, input.CodeInvalidOrgRole},
		{"an empty organization is an organization", new(""), new("member"), false, input.CodeInvalidID},
		{"an invalid organization", new("nope"), new("member"), false, input.CodeInvalidID},
		{"an invalid role", new(offerTestOrg), new("owner"), false, input.CodeInvalidOrgRole},
		{"a role in other case", new(offerTestOrg), new("Admin"), false, input.CodeInvalidOrgRole},
		{"both invalid: the organization is refused first", new("nope"), new("owner"), false, input.CodeInvalidID},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			offer, err := input.ParseOrgOffer(test.id, test.role)

			if test.code != "" {
				requireRefusal(t, err, test.code)
				requireOffer(t, offer, nil, nil, false)

				return
			}

			if err != nil {
				t.Fatalf("err = %v", err)
			}

			requireOffer(t, offer, test.id, test.role, test.offered)
		})
	}
}

// requireOffer checks an offer: what it reports, and that it carries the id and
// the role it was given, or nothing (the zero value) when it is none.
func requireOffer(t *testing.T, offer input.OrgOffer, id, role *string, offered bool) {
	t.Helper()

	wantID, wantRole := "", ""
	if offered {
		wantID, wantRole = *id, *role
	}

	if offer.Offered() != offered || offer.OrgID().String() != wantID || offer.Role().String() != wantRole {
		t.Errorf("offer = %v, %q, %q; want %v, %q, %q",
			offer.Offered(), offer.OrgID().String(), offer.Role().String(), offered, wantID, wantRole)
	}
}

// TestParseOrgOfferMissingDescriptions holds that each missing field has its own
// fixed text, which names the field.
func TestParseOrgOfferMissingDescriptions(t *testing.T) {
	t.Parallel()

	_, err := input.ParseOrgOffer(nil, new("member"))
	requireFixedRefusal(t, err, input.CodeMissingOrgID, "orgId is required with orgRole")

	_, err = input.ParseOrgOffer(new(offerTestOrg), nil)
	requireFixedRefusal(t, err, input.CodeMissingOrgRole, "orgRole is required with orgId")
}

// FuzzParseOrgOffer holds that an accepted offer is exactly what was given, and
// that anything refused carries one of the offer's codes.
func FuzzParseOrgOffer(f *testing.F) {
	for _, id := range []string{"", offerTestOrg, "nope"} {
		for _, role := range input.OrgRoles() {
			f.Add(id, role, true, true)
		}
	}

	f.Add("", "", false, true)
	f.Add("", "", true, false)

	f.Fuzz(func(t *testing.T, id, role string, hasID, hasRole bool) {
		var idp, rolep *string
		if hasID {
			idp = &id
		}

		if hasRole {
			rolep = &role
		}

		offer, err := input.ParseOrgOffer(idp, rolep)
		if err != nil {
			requireOfferCode(t, err)

			return
		}

		requireOffer(t, offer, idp, rolep, hasID || hasRole)
	})
}

// requireOfferCode fails the test unless err is a refusal with one of the
// offer's codes.
func requireOfferCode(t *testing.T, err error) {
	t.Helper()

	refusal, isClient := errors.AsType[*apierr.Error](err)
	if !isClient || !slices.Contains([]string{
		input.CodeMissingOrgID, input.CodeMissingOrgRole, input.CodeInvalidID, input.CodeInvalidOrgRole,
	}, refusal.Code) {
		t.Fatalf("refused with %v, which is not one of the offer's codes", err)
	}
}

// TestParseOrgAdmin holds that the flag must be given, and is then exactly what
// was given: leaving it out is never read as false.
func TestParseOrgAdmin(t *testing.T) {
	t.Parallel()

	yes, no := true, false

	tests := []struct {
		name  string
		raw   *bool
		admin bool
		code  string
	}{
		{"absent", nil, false, input.CodeMissingAdmin},
		{"true", &yes, true, ""},
		{"false", &no, false, ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := input.ParseOrgAdmin(test.raw)

			if test.code != "" {
				requireFixedRefusal(t, err, test.code, "admin is required")

				return
			}

			if err != nil || got.Admin() != test.admin {
				t.Errorf("ParseOrgAdmin = %v, %v; want %v", got.Admin(), err, test.admin)
			}
		})
	}

	if (input.OrgAdmin{}).Admin() {
		t.Error("the zero OrgAdmin is an administrator")
	}
}
