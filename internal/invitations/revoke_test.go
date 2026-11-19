package invitations_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/invitations"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// TestRevokeReportsTheRowAsTheWriteLeftIt: the store records the revocation at
// the request's clock and the response is the row it returns. Revoking an
// already revoked invitation reports the earlier time the store kept, and never
// moves it later, so a retry is safe.
func TestRevokeReportsTheRowAsTheWriteLeftIt(t *testing.T) {
	t.Parallel()

	now := fixedNow().Unix()

	tests := []struct {
		name   string
		mutate func(*store.Invitation)
		// revokedAt is the revocation time the client must see.
		revokedAt int64
	}{
		{"a fresh revocation", func(r *store.Invitation) { r.RevokedAt = new(now) }, now},
		{"already revoked earlier", func(r *store.Invitation) { r.RevokedAt = new(now - 500) }, now - 500},
		{"already revoked a second ago", func(r *store.Invitation) { r.RevokedAt = new(now - 1) }, now - 1},
		{"revoked, expired and exhausted", func(r *store.Invitation) {
			r.RevokedAt, r.ExpiresAt, r.Uses = new(now-9), now-1, r.NumInvites
		}, now - 9},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.store.revoked = storedRow(tt.mutate)

			rec := harn.asAdmin(http.MethodDelete, itemPath, "")

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}

			wantRevoked(t, harn, rec, tt.revokedAt)
		})
	}
}

// wantRevoked checks a revoke's response and the one store call behind it.
func wantRevoked(t *testing.T, harn *harness, rec *httptest.ResponseRecorder, revokedAt int64) {
	t.Helper()

	got := decode[wireInvitation](t, rec)
	if got.ID != invID || got.Status != statusRevoked || got.RevokedAt == nil || *got.RevokedAt != revokedAt {
		t.Errorf("response = %+v, want revoked at %d", got, revokedAt)
	}

	if len(harn.store.calls) != 1 || harn.store.calls[0].op != opRevoke ||
		harn.store.calls[0].id != invID || !harn.store.calls[0].now.Equal(fixedNow()) {
		t.Errorf("store calls = %+v, want one revoke of %s at %v", harn.store.calls, invID, fixedNow())
	}

	if harn.clock.calls != 1 {
		t.Errorf("the clock was read %d times, want once", harn.clock.calls)
	}
}

// TestRevokeNamesTheInvitationInThePath: the id the store is asked about is the
// one in the URL, and a body on a DELETE is not read.
func TestRevokeNamesTheInvitationInThePath(t *testing.T) {
	t.Parallel()

	const other = "00000000-0000-7000-8000-0000000000ee"

	for name, body := range map[string]string{"no body": "", "a body": `{"id":"` + invID + `"}`, "invalid JSON": garbage} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.store.revoked = storedRow(func(r *store.Invitation) { r.ID, r.RevokedAt = other, new(fixedNow().Unix()) })

			rec := harn.asAdmin(http.MethodDelete, collectionPath+"/"+other, body)

			if rec.Code != http.StatusOK || len(harn.store.calls) != 1 || harn.store.calls[0].id != other {
				t.Errorf("response = %d, store calls = %+v, want one revoke of %s", rec.Code, harn.store.calls, other)
			}
		})
	}
}

// TestRevokeResponseIsTheWireShape pins the whole body of a revoke.
func TestRevokeResponseIsTheWireShape(t *testing.T) {
	t.Parallel()

	harn := newHarness(t)
	now := fixedNow().Unix()
	harn.store.revoked = storedRow(func(r *store.Invitation) { r.RevokedAt, r.CreatedBy = new(now-3), new(adminID) })

	rec := harn.asAdmin(http.MethodDelete, itemPath, "")

	want := `{"id":"` + invID + `","type":"member","label":"November workshop","numInvites":5,"uses":2,` +
		`"status":"revoked","expiresAt":` + strconv.FormatInt(now+3600, 10) +
		`,"revokedAt":` + strconv.FormatInt(now-3, 10) + `,"createdBy":"` + adminID + `",` +
		`"createdAt":` + strconv.FormatInt(now-100, 10) + `}` + "\n"

	if rec.Code != http.StatusOK || rec.Body.String() != want {
		t.Errorf("response = %d\n%s\nwant\n%s", rec.Code, rec.Body.String(), want)
	}
}

// TestRevokeOfAnUnknownInvitationIsNotFound: the store's absence is a 404 under
// the invitation's own code, however the error is wrapped.
func TestRevokeOfAnUnknownInvitationIsNotFound(t *testing.T) {
	t.Parallel()

	for name, err := range map[string]error{
		"as is":   store.ErrNotFound,
		"wrapped": fmt.Errorf("revoke: %w", store.ErrNotFound),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.store.err = err

			rec := harn.asAdmin(http.MethodDelete, itemPath, "")

			wantError(t, harn, rec, http.StatusNotFound, invitations.CodeNotFound, invitations.CodeNotFound)
		})
	}
}

// TestRevokeFailsWhenTheStoreDoes: the store's classified failure is the
// response, unchanged.
func TestRevokeFailsWhenTheStoreDoes(t *testing.T) {
	t.Parallel()

	for _, tt := range storeFailures(store.CodeInvitationRevokeFailed, store.CodeInvitationRevokeRejected) {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.store.err = tt.err

			rec := harn.asAdmin(http.MethodDelete, itemPath, "")

			wantError(t, harn, rec, tt.status, tt.wireCode, tt.logCode)
		})
	}
}
