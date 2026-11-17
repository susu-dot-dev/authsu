package invitations

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
)

func listCall(t *testing.T, fix *fixture) (ListResponse, error) {
	t.Helper()

	handler := fix.svc.Handlers(getenv).Collection[http.MethodGet]

	resp, err := handler(request(t, http.MethodGet, nil, "")).Get()
	if err != nil {
		return ListResponse{}, fmt.Errorf("handler: %w", err)
	}

	if resp.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.Status)
	}

	list, ok := resp.Body.(ListResponse)
	if !ok {
		t.Fatalf("body is a %T, want a ListResponse", resp.Body)
	}

	return list, nil
}

func TestListShowsEveryInvitationWithItsStatus(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	now := testNow().Unix()

	revoked := row("00000000-0000-7000-8000-000000000002")
	revoked.RevokedAt = new(now - 5)
	revoked.CreatedBy = new(testAdminID)

	expired := row("00000000-0000-7000-8000-000000000003")
	expired.ExpiresAt = new(now - 1)

	exhausted := row("00000000-0000-7000-8000-000000000004")
	exhausted.Uses = exhausted.NumInvites

	// Revoked wins over everything else.
	both := row("00000000-0000-7000-8000-000000000005")
	both.RevokedAt = new(now - 5)
	both.ExpiresAt = new(now - 1)

	for _, r := range []Row{row("00000000-0000-7000-8000-000000000001"), revoked, expired, exhausted, both} {
		fix.store(r)
	}

	list, err := listCall(t, fix)
	if err != nil {
		t.Fatal(err)
	}

	got := list.Invitations
	if len(got) != 5 {
		t.Fatalf("listed %d invitations, want all 5 (revoked ones included)", len(got))
	}

	want := []Status{StatusActive, StatusRevoked, StatusExpired, StatusExhausted, StatusRevoked}
	for i, status := range want {
		if got[i].Status != status {
			t.Errorf("invitation %d status = %q, want %q", i, got[i].Status, status)
		}
	}

	if got[1].RevokedAt == nil || got[1].CreatedBy == nil || got[0].RevokedAt != nil || got[0].CreatedBy != nil {
		t.Errorf("optional fields wrong: %+v / %+v", got[1], got[0])
	}
}

// TestListWithNothingIsAnEmptyArray: the body is `[]`, never `null`, so a client
// need not special-case it.
func TestListWithNothingIsAnEmptyArray(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	resp, err := fix.svc.Handlers(getenv).Collection[http.MethodGet](request(t, http.MethodGet, nil, "")).Get()
	if err != nil {
		t.Fatal(err)
	}

	if got := bodyOf(t, resp); got != `{"invitations":[]}` {
		t.Errorf("body = %s, want an empty array", got)
	}
}

func TestListFailsWhenTheStoreDoes(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	fix.reader.listErr = errDB

	_, err := listCall(t, fix)
	wantFailure(t, err, apierr.Unavailable, CodeListFailed)
}

// TestListNeverReturnsTheCode: no field of an invitation, in the JSON a client
// receives, can carry the code or its hash.
func TestListNeverReturnsTheCode(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	fix.store(row(testInvID))

	resp, err := fix.svc.Handlers(getenv).Collection[http.MethodGet](request(t, http.MethodGet, nil, "")).Get()
	if err != nil {
		t.Fatal(err)
	}

	body := strings.ToLower(bodyOf(t, resp))
	for _, banned := range []string{"code", "hash"} {
		if strings.Contains(body, banned) {
			t.Errorf("list body mentions %q: %s", banned, body)
		}
	}
}
