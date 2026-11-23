package invitations_test

import (
	"fmt"
	"net/http"
	"strconv"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/invitations"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// TestGetStatesWhereTheInvitationStands ranges the list's status table over the
// one-invitation route: it must derive the status, at the request's one clock
// reading, exactly as the list does, so an admin is told the same thing
// whichever route they asked.
func TestGetStatesWhereTheInvitationStands(t *testing.T) {
	t.Parallel()

	for _, tt := range statusCases() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.store.got = storedRow(tt.mutate)

			rec := harn.asAdmin(http.MethodGet, itemPath, "")

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}

			if got := decode[wireInvitation](t, rec); got.Status != tt.want {
				t.Errorf("status = %q, want %q", got.Status, tt.want)
			}

			if len(harn.store.calls) != 1 || harn.store.calls[0].op != opGet || harn.store.calls[0].id != invID {
				t.Errorf("store calls = %+v, want one get of %s", harn.store.calls, invID)
			}

			if harn.clock.calls != 1 {
				t.Errorf("the clock was read %d times, want once", harn.clock.calls)
			}
		})
	}
}

// TestGetResponseIsTheWireShape pins the whole body: the list's entry for the
// invitation, with its use count and no token.
func TestGetResponseIsTheWireShape(t *testing.T) {
	t.Parallel()

	harn := newHarness(t)
	now := fixedNow().Unix()
	harn.store.got = storedRow(func(r *store.Invitation) { r.CreatedBy = new(adminID) })

	rec := harn.asAdmin(http.MethodGet, itemPath, "")

	want := `{"id":"` + invID + `","type":"member","label":"November workshop","numInvites":5,"uses":2,` +
		`"status":"active","expiresAt":` + strconv.FormatInt(now+3600, 10) +
		`,"createdBy":"` + adminID + `","createdAt":` + strconv.FormatInt(now-100, 10) + `}` + "\n"

	if rec.Code != http.StatusOK || rec.Body.String() != want {
		t.Errorf("response = %d\n%s\nwant\n%s", rec.Code, rec.Body.String(), want)
	}
}

// TestGetOfAnUnknownInvitationIsNotFound: the store's absence is a 404 under
// the invitation's own code, however the error is wrapped.
func TestGetOfAnUnknownInvitationIsNotFound(t *testing.T) {
	t.Parallel()

	for name, err := range map[string]error{
		"the bare sentinel":       store.ErrNotFound,
		"the sentinel in a chain": fmt.Errorf("get: %w", store.ErrNotFound),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.store.err = err

			rec := harn.asAdmin(http.MethodGet, itemPath, "")

			wantError(t, harn, rec, http.StatusNotFound, invitations.CodeNotFound, invitations.CodeNotFound)
		})
	}
}

// TestGetFailsWhenTheStoreDoes: the store's classified failure is the response,
// unchanged.
func TestGetFailsWhenTheStoreDoes(t *testing.T) {
	t.Parallel()

	for _, tt := range storeFailures(store.CodeInvitationReadFailed, store.CodeInvitationReadRejected) {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.store.err = tt.err

			rec := harn.asAdmin(http.MethodGet, itemPath, "")

			wantError(t, harn, rec, tt.status, tt.wireCode, tt.logCode)
		})
	}
}
