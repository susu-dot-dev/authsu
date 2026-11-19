package invitations_test

import (
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/invitations"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// updateBody is a PATCH body with numInvites n.
func updateBody(n string) string { return `{"numInvites":` + n + `}` }

// TestUpdateRefusesInvalidInput: every refusal is a 400 before the store is
// called. A missing numInvites has its own code, so a client that sent nothing
// is told so and not that zero is out of range.
func TestUpdateRefusesInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		code string
	}{
		{"no fields", `{}`, invitations.CodeMissingNumInvites},
		{"null numInvites", `{"numInvites":null}`, invitations.CodeMissingNumInvites},
		{"zero", updateBody("0"), input.CodeInvalidNumInvites},
		{"negative", updateBody("-2"), input.CodeInvalidNumInvites},
		{"one over the most", updateBody("10001"), input.CodeInvalidNumInvites},
		{"2^53", updateBody("9007199254740992"), input.CodeInvalidNumInvites},
		{"the int64 maximum", updateBody("9223372036854775807"), input.CodeInvalidNumInvites},
		{"beyond int64", updateBody("9223372036854775808"), codeInvalidFieldType},
		{"a fraction", updateBody("1.5"), codeInvalidFieldType},
		{"whole in exponent form", updateBody("1e1"), codeInvalidFieldType},
		{"text", updateBody(`"3"`), codeInvalidFieldType},
		{"a boolean", updateBody("true"), codeInvalidFieldType},
		{"unknown field", `{"numInvites":2,"type":"first_run"}`, codeUnknownField},
		{"only an unknown field", `{"revoked":true}`, codeUnknownField},
		{"repeated field", `{"numInvites":2,"numInvites":3}`, "duplicate_field"},
		{"empty body", "", "empty_body"},
		{"not JSON", garbage, "invalid_json"},
		{"trailing data", updateBody("2") + `{}`, "trailing_data"},
		{"an array", `[2]`, codeInvalidFieldType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			programmed(harn)

			rec := harn.asAdmin(http.MethodPatch, itemPath, tt.body)

			wantError(t, harn, rec, http.StatusBadRequest, tt.code, tt.code)

			if len(harn.store.calls) != 0 {
				t.Errorf("a refused request reached the store: %v", harn.opsCalled())
			}
		})
	}
}

// TestUpdateAppliesTheCapOnTheNamedInvitation: the store receives the id of the
// path and the parsed cap, at both ends of the range, and the response is the
// row the write left.
func TestUpdateAppliesTheCapOnTheNamedInvitation(t *testing.T) {
	t.Parallel()

	const other = "00000000-0000-7000-8000-0000000000ee"

	tests := []struct {
		name string
		id   string
		n    int64
	}{
		{"the fewest", invID, 1},
		{"a middling cap", invID, 9},
		{"the most", invID, input.MaxNumInvites},
		{"another invitation", other, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.store.updated = storedRow(func(r *store.Invitation) { r.ID, r.NumInvites = tt.id, tt.n })
			harn.store.applied = true

			rec := harn.asAdmin(http.MethodPatch, collectionPath+"/"+tt.id, updateBody(strconv.FormatInt(tt.n, 10)))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}

			want := storeCall{op: opUpdate, id: tt.id, n: tt.n, now: fixedNow()}
			if len(harn.store.calls) != 1 || !reflect.DeepEqual(harn.store.calls[0], want) {
				t.Errorf("store calls = %+v, want one update %+v", harn.store.calls, want)
			}

			got := decode[wireInvitation](t, rec)
			if got.ID != tt.id || got.NumInvites != tt.n {
				t.Errorf("response = %+v", got)
			}

			if harn.clock.calls != 1 {
				t.Errorf("the clock was read %d times, want once", harn.clock.calls)
			}
		})
	}
}

// TestUpdateResponseIsTheWireShape pins the whole body of an applied update.
func TestUpdateResponseIsTheWireShape(t *testing.T) {
	t.Parallel()

	harn := newHarness(t)
	now := fixedNow().Unix()
	harn.store.updated = storedRow(func(r *store.Invitation) {
		r.NumInvites, r.ExpiresAt, r.CreatedBy = 9, now+60, new(adminID)
	})
	harn.store.applied = true

	rec := harn.asAdmin(http.MethodPatch, itemPath, updateBody("9"))

	want := `{"id":"` + invID + `","type":"member","label":"November workshop","numInvites":9,"uses":2,` +
		`"status":"active","expiresAt":` + strconv.FormatInt(now+60, 10) + `,"createdBy":"` + adminID + `",` +
		`"createdAt":` + strconv.FormatInt(now-100, 10) + `}` + "\n"

	if rec.Code != http.StatusOK || rec.Body.String() != want {
		t.Errorf("response = %d\n%s\nwant\n%s", rec.Code, rec.Body.String(), want)
	}
}

// TestUpdateAppliedIsWhatTheWriteSaid: the route does not second-guess the
// store's verdict from the row, and presents the row as the write returned it,
// with the status derived at now.
func TestUpdateAppliedIsWhatTheWriteSaid(t *testing.T) {
	t.Parallel()

	now := fixedNow().Unix()

	tests := []struct {
		name   string
		mutate func(*store.Invitation)
		status string
	}{
		{"active", func(r *store.Invitation) { r.NumInvites = 9 }, statusActive},
		{"now exhausted", func(r *store.Invitation) { r.NumInvites, r.Uses = 2, 2 }, statusExhausted},
		{"expiring this second", func(r *store.Invitation) { r.ExpiresAt = now }, statusExpired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.store.updated = storedRow(tt.mutate)
			harn.store.applied = true

			rec := harn.asAdmin(http.MethodPatch, itemPath, updateBody("2"))

			if got := decode[wireInvitation](t, rec); rec.Code != http.StatusOK || got.Status != tt.status {
				t.Errorf("response = %d %+v, want status %q", rec.Code, got, tt.status)
			}
		})
	}
}

// TestUpdateReportsWhyItDidNotApply: a conditional write that changes nothing is
// not an error to the store, so the row says why, as of the instant the write
// ran. A revoked invitation is reported as revoked whatever its uses.
func TestUpdateReportsWhyItDidNotApply(t *testing.T) {
	t.Parallel()

	now := fixedNow().Unix()

	tests := []struct {
		name   string
		mutate func(*store.Invitation)
		code   string
		// uses is the data the client is given, when it is given any.
		uses *float64
	}{
		{"revoked", func(r *store.Invitation) { r.RevokedAt = new(now - 5) }, invitations.CodeRevoked, nil},
		{"revoked exactly now", func(r *store.Invitation) { r.RevokedAt = new(now) }, invitations.CodeRevoked, nil},
		{"revocation scheduled for later is not yet a revocation", func(r *store.Invitation) {
			r.RevokedAt = new(now + 5)
		}, invitations.CodeBelowUses, new(2.0)},
		{"revoked with more uses than the cap", func(r *store.Invitation) {
			r.RevokedAt, r.Uses = new(now-5), 50
		}, invitations.CodeRevoked, nil},
		{"revoked and expired", func(r *store.Invitation) {
			r.RevokedAt, r.ExpiresAt = new(now-5), now-1
		}, invitations.CodeRevoked, nil},
		{"below the accounts it has created", func(*store.Invitation) {}, invitations.CodeBelowUses, new(2.0)},
		{"far below them", func(r *store.Invitation) { r.Uses = 10000 }, invitations.CodeBelowUses, new(10000.0)},
		{"below them, and expired", func(r *store.Invitation) {
			r.ExpiresAt, r.Uses = now-1, 7
		}, invitations.CodeBelowUses, new(7.0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.store.updated = storedRow(tt.mutate)
			harn.store.applied = false

			rec := harn.asAdmin(http.MethodPatch, itemPath, updateBody("1"))

			got := wantError(t, harn, rec, http.StatusConflict, tt.code, tt.code)

			switch {
			case tt.uses == nil && got.Error.Data != nil:
				t.Errorf("data = %v, want none", got.Error.Data)
			case tt.uses != nil && (len(got.Error.Data) != 1 || got.Error.Data["uses"] != *tt.uses):
				t.Errorf("data = %v, want uses %v", got.Error.Data, *tt.uses)
			}

			if len(harn.store.calls) != 1 {
				t.Errorf("store calls = %v, want exactly the one write and no read", harn.opsCalled())
			}
		})
	}
}

// TestUpdateOfAnUnknownInvitationIsNotFound: the store's absence is a 404 under
// the invitation's own code, however the error is wrapped.
func TestUpdateOfAnUnknownInvitationIsNotFound(t *testing.T) {
	t.Parallel()

	for name, err := range map[string]error{
		"as is":   store.ErrNotFound,
		"wrapped": fmt.Errorf("update: %w", store.ErrNotFound),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.store.err = err

			rec := harn.asAdmin(http.MethodPatch, itemPath, updateBody("2"))

			wantError(t, harn, rec, http.StatusNotFound, invitations.CodeNotFound, invitations.CodeNotFound)
		})
	}
}

// TestUpdateFailsWhenTheStoreDoes: the store's classified failure is the
// response, unchanged.
func TestUpdateFailsWhenTheStoreDoes(t *testing.T) {
	t.Parallel()

	for _, tt := range storeFailures(store.CodeInvitationUpdateFailed, store.CodeInvitationUpdateRejected) {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.store.err = tt.err

			rec := harn.asAdmin(http.MethodPatch, itemPath, updateBody("2"))

			wantError(t, harn, rec, tt.status, tt.wireCode, tt.logCode)
		})
	}
}
