package registration_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/registration"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// This file holds what registration does with the configured first-run secret
// (docs/first_run_design.md). Registration only passes it on: whether a token
// that equals it is redeemable, and the creation of the first-run invitation,
// are decisions of the store's SQL, which e2e proves against the real database.
// What is decided here, and held below, is which configured values count as a
// first-run token at all, that begin and finish offer exactly that to the store
// and that nothing is offered that is not a token.

// firstRunSecretOf is a canonical invitation token other than the test codes,
// used as the configured secret.
//
//nolint:gosec // a throwaway token that only the tests know
const firstRunSecretOf = "susu_inv_k3Jx9Qp-Zr2_LmN8vB5tYcD1fGhWaXeUoIiS7dTqA0E"

// TestFirstRunSecretIsOfferedToTheStoreOnlyAsAToken: begin and finish read
// FIRST_RUN_SECRET on the request and hand it to the store as an invitation
// token when it is exactly one, and as nothing otherwise. Nothing is trimmed or
// corrected, so a value that merely resembles a token is never offered.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestFirstRunSecretIsOfferedToTheStoreOnlyAsAToken(t *testing.T) {
	t.Parallel()

	body := strings.TrimPrefix(firstRunSecretOf, "susu_inv_")

	cases := []struct {
		name   string
		secret string
		// want is the first-run token the store must receive, "" for none.
		want string
	}{
		{"a token", firstRunSecretOf, firstRunSecretOf},
		{"the same token as the one presented", testCode, testCode},
		{"unset", "", ""},
		{"a bare random body", body, ""},
		{"an old-style random string", "k3Jx9Qp-Zr2_LmN8vB5tYcD1fGhWaX0e", ""},
		{"a session token", "susu_ses_" + body, ""},
		{"prefix only", "susu_inv_", ""},
		{"a body one character short", firstRunSecretOf[:len(firstRunSecretOf)-1], ""},
		{"a body one character long", firstRunSecretOf + "A", ""},
		{"a leading space", " " + firstRunSecretOf, ""},
		{"a trailing space", firstRunSecretOf + " ", ""},
		{"a trailing newline", firstRunSecretOf + "\n", ""},
		{"a non-canonical last character", firstRunSecretOf[:len(firstRunSecretOf)-1] + "F", ""},
		{"padding", firstRunSecretOf[:len(firstRunSecretOf)-1] + "=", ""},
		{"two tokens", firstRunSecretOf + firstRunSecretOf, ""},
		{"a NUL byte", firstRunSecretOf + "\x00", ""},
		{"a very long value", strings.Repeat("k", 1<<16), ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Begin offers it with the lookup.
			r := newRig(t).with(map[string]string{config.SecretFirstRun: tc.secret})

			rec := r.begin(testName)
			if rec.Code != http.StatusOK {
				t.Fatalf("begin = %d %s, want 200", rec.Code, rec.Body)
			}

			if want := []redeemCall{wantRedeemWith(testCode, tc.want, r.now)}; !slices.Equal(r.store.redeemed, want) {
				t.Errorf("begin's invitation lookups = %v, want %v", r.store.redeemed, want)
			}

			// Finish offers it with the lookup and with the write.
			r = newRig(t).with(map[string]string{config.SecretFirstRun: tc.secret})
			options := r.beginOK()
			before := len(r.store.redeemed)

			rec = r.finish(newAuthenticator(t).respond(t, options))
			if rec.Code != http.StatusCreated {
				t.Fatalf("finish = %d %s, want 201", rec.Code, rec.Body)
			}

			if got := r.store.redeemed[before:]; !slices.Equal(got, []redeemCall{wantRedeemWith(testCode, tc.want, r.now)}) {
				t.Errorf("finish's invitation lookups = %v, want one with first-run token %q", got, tc.want)
			}

			if len(r.store.created) != 1 {
				t.Fatalf("account writes = %d, want 1", len(r.store.created))
			}

			got := ""
			if r.store.created[0].FirstRun != nil {
				got = r.store.created[0].FirstRun.String()
			}

			if got != tc.want {
				t.Errorf("the write was offered first-run token %q, want %q", got, tc.want)
			}
		})
	}
}

// TestFirstRunInvitationIsDescribedToTheWrite: whatever the registration, the
// write is given everything it would need to create the first-run invitation:
// a fresh id of its own (distinct from the account's and the passkey's), the
// admin-facing label and an expiry exactly input.ExpiryHorizon after the clock.
// The write creates it only when its conditions hold, so offering it costs
// nothing, and Go never decides it.
func TestFirstRunInvitationIsDescribedToTheWrite(t *testing.T) {
	t.Parallel()

	r := newRig(t).with(map[string]string{config.SecretFirstRun: testCode})
	options := r.beginOK()

	rec := r.finish(newAuthenticator(t).respond(t, options))
	if rec.Code != http.StatusCreated {
		t.Fatalf("finish = %d %s, want 201", rec.Code, rec.Body)
	}

	if len(r.store.created) != 1 {
		t.Fatalf("account writes = %d, want 1", len(r.store.created))
	}

	got := r.store.created[0]

	if got.FirstRunID != firstRunID3 {
		t.Errorf("FirstRunID = %q, want the third id asked for, %q", got.FirstRunID, firstRunID3)
	}

	if got.FirstRunID == got.UserID || got.FirstRunID == got.CredentialRowID {
		t.Errorf("FirstRunID %q is shared with the account (%q) or the passkey (%q)",
			got.FirstRunID, got.UserID, got.CredentialRowID)
	}

	if got.FirstRunLabel != registration.FirstRunLabel {
		t.Errorf("FirstRunLabel = %q, want %q", got.FirstRunLabel, registration.FirstRunLabel)
	}

	if want := r.now.Add(input.ExpiryHorizon); !got.FirstRunExpiresAt.Equal(want) {
		t.Errorf("FirstRunExpiresAt = %v, want %v (ExpiryHorizon after the clock)", got.FirstRunExpiresAt, want)
	}
}

// TestFirstRunSecretIsNotInAnyResponse: the secret is an admin credential until
// the owner registers. Registration reads it only to hand it to the store, so it
// is in no body and no header, on success and on every failure, and not in
// anything logged.
func TestFirstRunSecretIsNotInAnyResponse(t *testing.T) {
	t.Parallel()

	r := newRig(t).with(map[string]string{config.SecretFirstRun: firstRunSecretOf})

	// A begin and a finish that succeed, and ones that are refused: a token that
	// is not redeemable, and a store that fails.
	options := r.beginOK()
	responses := make([]string, 0, 4)
	responses = append(responses,
		r.begin(testName).Body.String(),
		r.finish(newAuthenticator(t).respond(t, options)).Body.String(),
		r.post(registration.PathBegin, beginJSON(unknownCode, testName)).Body.String(),
	)

	r.store.redeemErr = errDB
	responses = append(responses, r.begin(testName).Body.String())

	secretBody := strings.TrimPrefix(firstRunSecretOf, "susu_inv_")

	for _, body := range responses {
		if strings.Contains(body, firstRunSecretOf) || strings.Contains(body, secretBody) {
			t.Errorf("a response contains the first-run secret: %s", body)
		}
	}
}

// TestFirstRunLabelIsOneTheSchemaAndTheParserAccept: the first-run label is
// written straight to invitations.label and shown in the admin's list, so it
// must fit the column's CHECK in bytes (read from the migrations' text) and be a
// label the invitation parser would accept from a person, which is what the rest
// of the system assumes every label is.
func TestFirstRunLabelIsOneTheSchemaAndTheParserAccept(t *testing.T) {
	t.Parallel()

	limit := migrationLimits(t, `length\(cast\(label AS BLOB\)\) <= (\d+)`)[0]

	if size := len(registration.FirstRunLabel); size == 0 || size > limit {
		t.Errorf("the label is %d bytes; the schema allows up to %d", size, limit)
	}

	parsed, err := input.ParseInvitationLabel(registration.FirstRunLabel)
	if err != nil || parsed.String() != registration.FirstRunLabel {
		t.Errorf("the parser does not accept the first-run label as it is: %v", err)
	}
}

// TestFirstRunTypeHasTheAdminRole: the first-run invitation's type is what makes
// its holder the administrator, and the store reports that type for the
// configured secret. Registration trusts the type the store read and maps it to
// a role, so this ties the two together from the outside.
func TestFirstRunTypeHasTheAdminRole(t *testing.T) {
	t.Parallel()

	r := newRig(t).with(map[string]string{config.SecretFirstRun: testCode})
	r.store.invitations = map[string]string{testCode: store.InvitationFirstRun}

	options := r.beginOK()

	rec := r.finish(newAuthenticator(t).respond(t, options))
	if rec.Code != http.StatusCreated {
		t.Fatalf("finish = %d %s, want 201", rec.Code, rec.Body)
	}

	got := r.store.created[0]
	if got.InvitationType != store.InvitationFirstRun || got.Role != "admin" {
		t.Errorf("account written with type %q and role %q, want %q and admin",
			got.InvitationType, got.Role, store.InvitationFirstRun)
	}
}
