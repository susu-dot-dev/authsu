package users

import (
	"net/http"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
)

func TestListShowsEveryUserWithItsStatus(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	revoked := row("00000000-0000-7000-8000-000000000003")
	revoked.RevokedAt = new(testNow().Unix() - 5)

	admin := row(testAdminID)
	admin.Role = roleAdmin

	for _, r := range []Row{admin, row(testUserID), revoked} {
		fix.store(r)
	}

	resp, err := fix.svc.Handlers(getenv).Collection[http.MethodGet](request(t, http.MethodGet, "")).Get()
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.Status)
	}

	want := `{"users":[` +
		`{"id":"` + testAdminID + `","role":"admin","invitationId":"` + testInvID + `","profile":` + testProfile +
		`,"status":"active","createdAt":` + itoa(admin.CreatedAt) + `},` +
		`{"id":"` + testUserID + `","role":"member","invitationId":"` + testInvID + `","profile":` + testProfile +
		`,"status":"active","createdAt":` + itoa(admin.CreatedAt) + `},` +
		`{"id":"00000000-0000-7000-8000-000000000003","role":"member","invitationId":"` + testInvID +
		`","profile":` + testProfile + `,"status":"revoked","revokedAt":` + itoa(*revoked.RevokedAt) +
		`,"createdAt":` + itoa(admin.CreatedAt) + `}]}`

	if got := bodyOf(t, resp); got != want {
		t.Errorf("body =\n%s\nwant\n%s", got, want)
	}
}

// TestListWithNothingIsAnEmptyArray: the body is `[]`, never `null`.
func TestListWithNothingIsAnEmptyArray(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	resp, err := fix.svc.Handlers(getenv).Collection[http.MethodGet](request(t, http.MethodGet, "")).Get()
	if err != nil {
		t.Fatal(err)
	}

	if got := bodyOf(t, resp); got != `{"users":[]}` {
		t.Errorf("body = %s, want an empty array", got)
	}
}

func TestListFailsWhenTheStoreDoes(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	fix.reader.listErr = errDB

	_, err := fix.svc.Handlers(getenv).Collection[http.MethodGet](request(t, http.MethodGet, "")).Get()
	wantFailure(t, err, apierr.Unavailable, CodeListFailed)
}

func TestGetReturnsOneUser(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	fix.store(row(testUserID))

	resp, err := fix.svc.Handlers(getenv).Item[http.MethodGet](request(t, http.MethodGet, testUserID)).Get()
	if err != nil {
		t.Fatal(err)
	}

	got, ok := resp.Body.(User)
	if !ok || resp.Status != http.StatusOK || got.ID != testUserID || got.Status != StatusActive ||
		string(got.Profile) != testProfile {
		t.Errorf("response = %d %+v", resp.Status, resp.Body)
	}
}

func TestGetFailures(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		setup func(*fixture)
		id    string
		kind  apierr.Kind
		code  string
	}{
		"no such user":  {func(*fixture) {}, testUserID, apierr.NotFound, CodeNotFound},
		"store fails":   {func(f *fixture) { f.reader.getErr = errDB }, testUserID, apierr.Unavailable, CodeLookupFailed},
		"no id":         {func(*fixture) {}, "", apierr.BadRequest, CodeInvalidID},
		"id too short":  {func(*fixture) {}, "abc", apierr.BadRequest, CodeInvalidID},
		"id not hex":    {func(*fixture) {}, strings.Repeat("g", 36), apierr.BadRequest, CodeInvalidID},
		"id upper case": {func(*fixture) {}, strings.ToUpper(testUserID), apierr.BadRequest, CodeInvalidID},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			tt.setup(fix)

			_, err := fix.svc.Handlers(getenv).Item[http.MethodGet](request(t, http.MethodGet, tt.id)).Get()
			wantFailure(t, err, tt.kind, tt.code)
		})
	}
}

// TestReadsNeverReturnTheUserHandle: the WebAuthn user handle identifies the
// account to authenticators and has no use to an admin.
func TestReadsNeverReturnTheUserHandle(t *testing.T) {
	t.Parallel()

	for name, query := range map[string]string{"list": listQuery, "get": getQuery, "revoke statement": revokeQuery} {
		if strings.Contains(query, "user_handle") {
			t.Errorf("%s query selects user_handle:\n%s", name, query)
		}
	}
}

func TestStatusOf(t *testing.T) {
	t.Parallel()

	if got := StatusOf(Row{}); got != StatusActive {
		t.Errorf("StatusOf(not revoked) = %q", got)
	}

	if got := StatusOf(Row{RevokedAt: new(int64(1))}); got != StatusRevoked {
		t.Errorf("StatusOf(revoked) = %q", got)
	}
}
