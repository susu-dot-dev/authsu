package invitations_test

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/store"
)

// statusCase is a stored row and the status a client must be told for it.
type statusCase struct {
	name   string
	mutate func(*store.Invitation)
	want   string
}

// statusCases are the rows of the status table, at the boundaries of the clock
// (fixedNow): the second before, of and after an expiry, and each way of
// combining the facts.
func statusCases() []statusCase {
	now := fixedNow().Unix()

	return []statusCase{
		{"active", func(*store.Invitation) {}, statusActive},
		{"unused", func(r *store.Invitation) { r.Uses = 0 }, statusActive},
		{"one use left", func(r *store.Invitation) { r.Uses = r.NumInvites - 1 }, statusActive},
		{"uses equal the cap", func(r *store.Invitation) { r.Uses = r.NumInvites }, statusExhausted},
		{"uses over the cap", func(r *store.Invitation) { r.Uses = r.NumInvites + 1 }, statusExhausted},
		{"expires one second from now", func(r *store.Invitation) { r.ExpiresAt = now + 1 }, statusActive},
		{"expires exactly now", func(r *store.Invitation) { r.ExpiresAt = now }, statusExpired},
		{"expired one second ago", func(r *store.Invitation) { r.ExpiresAt = now - 1 }, statusExpired},
		{"expiry at the epoch", func(r *store.Invitation) { r.ExpiresAt = 0 }, statusExpired},
		{"expired and exhausted", func(r *store.Invitation) {
			r.ExpiresAt, r.Uses = now-1, r.NumInvites
		}, statusExpired},
		{"exhausted with a future expiry", func(r *store.Invitation) {
			r.ExpiresAt, r.Uses = now+1, r.NumInvites
		}, statusExhausted},
		{"revoked", func(r *store.Invitation) { r.RevokedAt = new(now - 5) }, statusRevoked},
		{"revoked now", func(r *store.Invitation) { r.RevokedAt = new(now) }, statusRevoked},
		{"revoked one second ago", func(r *store.Invitation) { r.RevokedAt = new(now - 1) }, statusRevoked},
		{"revoked at the epoch", func(r *store.Invitation) { r.RevokedAt = new(int64(0)) }, statusRevoked},
		// A revocation set for later has not taken effect: the store's active
		// predicate is (revoked_at IS NULL OR revoked_at > now), so the
		// invitation is whatever else it is until then.
		{"revoked one second from now", func(r *store.Invitation) { r.RevokedAt = new(now + 1) }, statusActive},
		{"revoked in the future", func(r *store.Invitation) { r.RevokedAt = new(now + 5) }, statusActive},
		{"revoked in the future and exhausted", func(r *store.Invitation) {
			r.RevokedAt, r.Uses = new(now+5), r.NumInvites
		}, statusExhausted},
		{"revoked in the future and expired", func(r *store.Invitation) {
			r.RevokedAt, r.ExpiresAt = new(now+5), now-1
		}, statusExpired},
		{"revoked now and expired now", func(r *store.Invitation) {
			r.RevokedAt, r.ExpiresAt = new(now), now
		}, statusRevoked},
		{"revoked and expired", func(r *store.Invitation) {
			r.RevokedAt, r.ExpiresAt = new(now-5), now-1
		}, statusRevoked},
		{"revoked and exhausted", func(r *store.Invitation) {
			r.RevokedAt, r.Uses = new(now-5), r.NumInvites
		}, statusRevoked},
		{"revoked, expired and exhausted", func(r *store.Invitation) {
			r.RevokedAt, r.ExpiresAt, r.Uses = new(now-5), now-1, r.NumInvites
		}, statusRevoked},
	}
}

// TestListDerivesStatusAtTheClock: status is decided from the row and the clock,
// revoked then expired then exhausted then active, and the boundaries fall where
// the store's active predicate puts them: an invitation is revoked AT its
// revoked_at (a later one has not taken effect), expires AT its expires_at, and
// is exhausted once its uses reach its cap.
func TestListDerivesStatusAtTheClock(t *testing.T) {
	t.Parallel()

	for _, tt := range statusCases() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.store.list = []store.Invitation{storedRow(tt.mutate)}

			rec := harn.asAdmin(http.MethodGet, collectionPath, "")

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}

			got := decode[wireList](t, rec).Invitations
			if len(got) != 1 || got[0].Status != tt.want {
				t.Errorf("listed %+v, want one with status %q", got, tt.want)
			}

			if harn.clock.calls != 1 {
				t.Errorf("the clock was read %d times, want once", harn.clock.calls)
			}
		})
	}
}

// TestListIsTheStoresRowsInTheStoresOrder: the body is the wire shape exactly,
// every row is listed (revoked ones included), the order is the store's, expiresAt
// is always present, and the other optional fields are absent, not null, when
// they are not set.
func TestListIsTheStoresRowsInTheStoresOrder(t *testing.T) {
	t.Parallel()

	harn := newHarness(t)
	now := fixedNow().Unix()
	created := strconv.FormatInt(now-100, 10)
	expires := strconv.FormatInt(now+3600, 10)

	harn.store.list = []store.Invitation{
		storedRow(func(r *store.Invitation) {
			r.ID = "00000000-0000-7000-8000-000000000003"
			r.RevokedAt, r.CreatedBy, r.ExpiresAt = new(now-5), new(adminID), now+60
			r.Label = ""
		}),
		storedRow(func(r *store.Invitation) { r.ID = "00000000-0000-7000-8000-000000000002" }),
		storedRow(func(r *store.Invitation) {
			r.ID = "00000000-0000-7000-8000-000000000001"
			r.Uses = 0
		}),
	}

	rec := harn.asAdmin(http.MethodGet, collectionPath, "")

	want := `{"invitations":[` +
		`{"id":"00000000-0000-7000-8000-000000000003","type":"member","label":"","numInvites":5,"uses":2,` +
		`"status":"revoked","expiresAt":` + strconv.FormatInt(now+60, 10) +
		`,"revokedAt":` + strconv.FormatInt(now-5, 10) + `,` +
		`"createdBy":"` + adminID + `","createdAt":` + created + `},` +
		`{"id":"00000000-0000-7000-8000-000000000002","type":"member","label":"November workshop",` +
		`"numInvites":5,"uses":2,"status":"active","expiresAt":` + expires + `,"createdAt":` + created + `},` +
		`{"id":"00000000-0000-7000-8000-000000000001","type":"member","label":"November workshop",` +
		`"numInvites":5,"uses":0,"status":"active","expiresAt":` + expires + `,"createdAt":` + created + `}]}` + "\n"

	if rec.Code != http.StatusOK || rec.Body.String() != want {
		t.Errorf("response = %d\n%s\nwant\n%s", rec.Code, rec.Body.String(), want)
	}

	if got := harn.opsCalled(); len(got) != 1 || got[0] != opList {
		t.Errorf("store calls = %v, want one list", got)
	}
}

// TestListWithNothingIsAnEmptyArray: the body is `[]`, never `null`, so a client
// need not special-case it, for no rows and for a nil slice alike.
func TestListWithNothingIsAnEmptyArray(t *testing.T) {
	t.Parallel()

	for name, rows := range map[string][]store.Invitation{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.store.list = rows

			rec := harn.asAdmin(http.MethodGet, collectionPath, "")

			if got := rec.Body.String(); rec.Code != http.StatusOK || got != `{"invitations":[]}`+"\n" {
				t.Errorf("response = %d %q", rec.Code, got)
			}
		})
	}
}

// TestListFailsWhenTheStoreDoes: the store's classified failure is the response,
// unchanged, and an unclassified one is a bare internal error.
func TestListFailsWhenTheStoreDoes(t *testing.T) {
	t.Parallel()

	for _, tt := range storeFailures(store.CodeInvitationListFailed, store.CodeInvitationListRejected) {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.store.err = tt.err

			rec := harn.asAdmin(http.MethodGet, collectionPath, "")

			wantError(t, harn, rec, tt.status, tt.wireCode, tt.logCode)
		})
	}
}

// TestNoReadRouteReturnsTheCodeOrItsHash: no body the list, update or revoke
// route produces can mention a code or a hash. Only the create's own response
// has a code (see TestCreateShowsTheCodeOnce), and the store's rows have no
// field to put one in.
func TestNoReadRouteReturnsTheCodeOrItsHash(t *testing.T) {
	t.Parallel()

	for _, route := range allRoutes() {
		if route.method == http.MethodPost {
			continue
		}

		t.Run(route.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			programmed(harn)
			harn.store.list = []store.Invitation{storedRow(nil)}

			rec := harn.asAdmin(route.method, route.target, route.body)

			if rec.Code != route.success {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}

			body := strings.ToLower(rec.Body.String())
			for _, banned := range []string{"code", "hash"} {
				if strings.Contains(body, banned) {
					t.Errorf("body mentions %q: %s", banned, body)
				}
			}
		})
	}
}
