package registration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/atomic"
)

// Positions of the bound arguments in the two statements, per the comments on
// insertUserQuery and insertCredentialQuery.
const (
	userArgID          = 0
	userArgHandle      = 1
	userArgRole        = 2
	userArgProfile     = 3
	userArgCodeHash    = 5
	userArgType        = 6
	credArgHandle      = 2
	credArgFlags       = 4
	credArgMetadata    = 5
	wantStoredUPUVMask = 0x01 | 0x04
)

// acceptedBatch runs a full successful registration and returns the user and
// credential statements it wrote, with the response.
func acceptedBatch(t *testing.T, fix *fixture) (atomic.Statement, atomic.Statement, FinishResponse) {
	t.Helper()

	req := beginThenRespond(t, fix, newAuthenticator())

	out, status, err := finish(t, fix, getenv(nil), req)
	if err != nil {
		t.Fatalf("finish: %v", err)
	}

	if status != http.StatusCreated {
		t.Errorf("status = %d, want %d", status, http.StatusCreated)
	}

	if len(fix.batcher.batches) != 1 || len(fix.batcher.batches[0]) != 2 {
		t.Fatalf("batches = %v, want one batch of two statements (user, credential)", fix.batcher.batches)
	}

	return fix.batcher.batches[0][0], fix.batcher.batches[0][1], out
}

func TestFinishWritesUserThenCredentialAtomically(t *testing.T) {
	t.Parallel()

	user, cred, out := acceptedBatch(t, newFixture(t))

	if user.Query != insertUserQuery || cred.Query != insertCredentialQuery {
		t.Error("batch is not (insert user, insert credential), in that order")
	}

	for name, statement := range map[string]atomic.Statement{"user": user, "credential": cred} {
		if got, want := len(statement.Args), strings.Count(statement.Query, "?"); got != want {
			t.Errorf("%s insert binds %d values for %d placeholders", name, got, want)
		}
	}

	if user.Args[userArgID] != out.UserID {
		t.Errorf("user id arg = %v, response says %q", user.Args[userArgID], out.UserID)
	}

	if out.Role != RoleAdmin {
		t.Errorf("role = %q, want %q (copied from the first_run invitation)", out.Role, RoleAdmin)
	}
}

func TestFinishLinksCredentialToUserByTheHandle(t *testing.T) {
	t.Parallel()

	user, cred, _ := acceptedBatch(t, newFixture(t))

	userHandle, _ := user.Args[userArgHandle].([]byte)
	credHandle, _ := cred.Args[credArgHandle].([]byte)

	if !bytes.Equal(userHandle, credHandle) || len(userHandle) != UserHandleLen {
		t.Errorf("handles differ or are the wrong size: user %x, credential %x", userHandle, credHandle)
	}
}

func TestFinishIdentifiesTheInvitationByHashOnly(t *testing.T) {
	t.Parallel()

	user, _, _ := acceptedBatch(t, newFixture(t))

	for _, arg := range user.Args {
		if s, ok := arg.(string); ok && s == testCode {
			t.Error("the raw invitation code was bound as a query argument")
		}
	}

	hash, _ := user.Args[userArgCodeHash].([]byte)
	if !bytes.Equal(hash, codeHash(testCode)) {
		t.Error("the invitation is not identified by the hash of the code")
	}

	if user.Args[userArgType] != firstRun {
		t.Errorf("invitation type arg = %v, want %q", user.Args[userArgType], firstRun)
	}
}

func TestFinishStoresProfileAndMetadata(t *testing.T) {
	t.Parallel()

	user, cred, _ := acceptedBatch(t, newFixture(t))

	var stored profile

	rawProfile, _ := user.Args[userArgProfile].(string)

	err := json.Unmarshal([]byte(rawProfile), &stored)
	if err != nil || stored.Name != testName {
		t.Errorf("profile = %q (%v), want the name %q", rawProfile, err, testName)
	}

	var meta credentialMetadata

	rawMeta, _ := cred.Args[credArgMetadata].(string)

	err = json.Unmarshal([]byte(rawMeta), &meta)
	if err != nil || meta.Format != noneFormat || len(meta.Transports) != 1 ||
		meta.AAGUID != "00000000-0000-0000-0000-000000000000" {
		t.Errorf("metadata = %q (%v)", rawMeta, err)
	}

	if cred.Args[credArgFlags] != int64(wantStoredUPUVMask) {
		t.Errorf("flags = %v, want UP|UV", cred.Args[credArgFlags])
	}
}

// TestFinishRoleComesFromTheServer proves the client has no say in the role:
// there is no request field for it, and the bound role is the one Go chose.
func TestFinishRoleComesFromTheServer(t *testing.T) {
	t.Parallel()

	user, _, _ := acceptedBatch(t, newFixture(t))

	if user.Args[userArgRole] != RoleAdmin {
		t.Errorf("bound role = %v, want %q", user.Args[userArgRole], RoleAdmin)
	}
}

// TestFinishStoresTheHandleFromTheChallenge: the handle written is the one begin
// issued, read from the signed challenge, so a client cannot choose it.
func TestFinishStoresTheHandleFromTheChallenge(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	options, err := begin(t, fix, getenv(nil), BeginRequest{InvitationCode: testCode, Name: testName})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	issued, _ := base64.RawURLEncoding.DecodeString(options.PublicKey.User.ID)

	_, _, err = finish(t, fix, getenv(nil), newAuthenticator().respond(t, options))
	if err != nil {
		t.Fatalf("finish: %v", err)
	}

	stored, _ := fix.batcher.batches[0][0].Args[userArgHandle].([]byte)
	if !bytes.Equal(stored, issued) {
		t.Errorf("stored handle = %x, want the issued %x", stored, issued)
	}
}

// TestFinishStoresNoTransportsAsAnEmptyList: a client that reports no
// transports must not be stored as JSON null, which a reader would have to
// special-case.
func TestFinishStoresNoTransportsAsAnEmptyList(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	req := beginThenRespond(t, fix, newAuthenticator())
	req.Credential.Response.Transports = nil

	_, _, err := finish(t, fix, getenv(nil), req)
	if err != nil {
		t.Fatalf("finish: %v", err)
	}

	raw, _ := fix.batcher.batches[0][1].Args[credArgMetadata].(string)
	if !strings.Contains(raw, `"transports":[]`) {
		t.Errorf("metadata = %s, want an empty transports list", raw)
	}
}

// refusal is a finish request that must be refused before any write.
type refusal struct {
	auth     func(*authenticator)
	request  func(*FinishRequest)
	env      map[string]string
	wantKind apierr.Kind
	wantCode string
}

func runRefusals(t *testing.T, tests map[string]refusal) {
	t.Helper()

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			auth := newAuthenticator()

			if tt.auth != nil {
				tt.auth(&auth)
			}

			req := beginThenRespond(t, fix, auth)

			if tt.request != nil {
				tt.request(&req)
			}

			_, _, err := finish(t, fix, getenv(tt.env), req)

			wantFailure(t, err, tt.wantKind, tt.wantCode)

			if len(fix.batcher.batches) != 0 {
				t.Errorf("a write was attempted for a request that should have been refused: %v", fix.batcher.batches)
			}
		})
	}
}

func TestFinishRefusesABadPasskey(t *testing.T) {
	t.Parallel()

	runRefusals(t, map[string]refusal{
		"credential type is not public-key": {
			request:  func(r *FinishRequest) { r.Credential.Type = "password" },
			wantKind: apierr.BadRequest, wantCode: CodeInvalidCredential,
		},
		"wrong origin": {
			auth:     func(a *authenticator) { a.origin = "https://evil.example.com" },
			wantKind: apierr.BadRequest, wantCode: CodeInvalidCredential,
		},
		"wrong rp id": {
			auth:     func(a *authenticator) { a.rpID = "evil.example.com" },
			wantKind: apierr.BadRequest, wantCode: CodeInvalidCredential,
		},
		"wrong ceremony type": {
			auth:     func(a *authenticator) { a.clientDataType = "webauthn.get" },
			wantKind: apierr.BadRequest, wantCode: CodeInvalidCredential,
		},
		"user verification missing": {
			auth:     func(a *authenticator) { a.flags = 0x01 | 0x40 },
			wantKind: apierr.BadRequest, wantCode: CodeInvalidCredential,
		},
	})
}

func TestFinishRefusesABadChallenge(t *testing.T) {
	t.Parallel()

	runRefusals(t, map[string]refusal{
		"challenge was never issued": {
			auth:     func(a *authenticator) { a.challenge = bytes.Repeat([]byte{7}, challengeLen) },
			wantKind: apierr.BadRequest, wantCode: CodeInvalidChallenge,
		},
		"challenge is too short": {
			auth:     func(a *authenticator) { a.challenge = []byte{1, 2, 3} },
			wantKind: apierr.BadRequest, wantCode: CodeInvalidChallenge,
		},
		"challenge minted for another code": {
			request:  func(r *FinishRequest) { r.InvitationCode = "a-different-code" },
			wantKind: apierr.BadRequest, wantCode: CodeInvalidChallenge,
		},
		"challenge minted for another name": {
			request:  func(r *FinishRequest) { r.Name = "Mallory" },
			wantKind: apierr.BadRequest, wantCode: CodeInvalidChallenge,
		},
		"signed with a different secret": {
			env:      map[string]string{SecretHMAC: strings.Repeat("z", MinSecretLen)},
			wantKind: apierr.BadRequest, wantCode: CodeInvalidChallenge,
		},
	})
}

func TestFinishRefusesBadRequests(t *testing.T) {
	t.Parallel()

	runRefusals(t, map[string]refusal{
		"empty name": {
			request:  func(r *FinishRequest) { r.Name = "" },
			wantKind: apierr.BadRequest, wantCode: CodeInvalidName,
		},
		"empty code": {
			request:  func(r *FinishRequest) { r.InvitationCode = "" },
			wantKind: apierr.BadRequest, wantCode: CodeInvalidInvitation,
		},
		"secret missing": {
			env:      map[string]string{SecretHMAC: ""},
			wantKind: apierr.Unavailable, wantCode: CodeNotConfigured,
		},
	})
}

func TestFinishRefusesAnExpiredChallenge(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	req := beginThenRespond(t, fix, newAuthenticator())

	late := testNow().Add(ChallengeTTL)
	fix.svc.now = func() time.Time { return late }

	_, _, err := finish(t, fix, getenv(nil), req)

	wantFailure(t, err, apierr.BadRequest, CodeInvalidChallenge)

	if len(fix.batcher.batches) != 0 {
		t.Error("a write was attempted with an expired challenge")
	}
}

func TestFinishInvitationChecks(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		reader   func(*fakeReader)
		wantKind apierr.Kind
		wantCode string
	}{
		"invitation no longer redeemable": {
			reader:   func(r *fakeReader) { clear(r.types) },
			wantKind: apierr.Forbidden, wantCode: CodeInvalidInvitation,
		},
		"invitation lookup fails": {
			reader:   func(r *fakeReader) { r.err = errDB },
			wantKind: apierr.Unavailable, wantCode: CodeInvitationCheck,
		},
		"invitation type has no role": {
			reader: func(r *fakeReader) {
				r.types = map[string]string{string(codeHash(testCode)): "mystery"}
			},
			wantKind: apierr.Internal, wantCode: CodeRegistrationFailed,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			req := beginThenRespond(t, fix, newAuthenticator())

			tt.reader(fix.reader)

			_, _, err := finish(t, fix, getenv(nil), req)

			wantFailure(t, err, tt.wantKind, tt.wantCode)

			if len(fix.batcher.batches) != 0 {
				t.Error("a write was attempted")
			}
		})
	}
}

func TestFinishClassifiesBatchFailures(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err      error
		wantKind apierr.Kind
	}{
		"refused by a constraint": {err: errors.Join(atomic.ErrConflict, errDB), wantKind: apierr.Conflict},
		"database unavailable":    {err: errDB, wantKind: apierr.Unavailable},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			req := beginThenRespond(t, fix, newAuthenticator())
			fix.batcher.err = tt.err

			_, _, err := finish(t, fix, getenv(nil), req)

			wantFailure(t, err, tt.wantKind, CodeAcceptFailed)

			if !errors.Is(err, errDB) {
				t.Errorf("error %v does not keep the cause for the log", err)
			}
		})
	}
}

func TestFinishFailsWhenAColumnCannotBeEncoded(t *testing.T) {
	t.Parallel()

	// The first column encoded is the profile, the second the metadata.
	for failAt := 1; failAt <= 2; failAt++ {
		fix := newFixture(t)
		req := beginThenRespond(t, fix, newAuthenticator())

		calls := 0
		fix.svc.marshal = func(v any) ([]byte, error) {
			calls++
			if calls == failAt {
				return nil, errDB
			}

			return json.Marshal(v)
		}

		_, _, err := finish(t, fix, getenv(nil), req)

		wantFailure(t, err, apierr.Internal, CodeRegistrationFailed)

		if len(fix.batcher.batches) != 0 {
			t.Errorf("encode %d failing: a write was attempted", failAt)
		}
	}
}

func TestFinishWithoutABatchIsNotConfigured(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	req := beginThenRespond(t, fix, newAuthenticator())
	fix.svc.batch = nil

	_, _, err := finish(t, fix, getenv(nil), req)

	wantFailure(t, err, apierr.Unavailable, CodeNotConfigured)
}

func TestRoleFor(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		invitationType string
		wantRole       string
		wantKnown      bool
	}{
		"first run": {invitationType: firstRun, wantRole: RoleAdmin, wantKnown: true},
		"unknown":   {invitationType: "mystery", wantRole: "", wantKnown: false},
		emptyCase:   {invitationType: "", wantRole: "", wantKnown: false},
		// The match is exact: a differently cased type is not first run.
		"different case": {invitationType: "FIRST_RUN", wantRole: "", wantKnown: false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			role, known := RoleFor(tt.invitationType)
			if role != tt.wantRole || known != tt.wantKnown {
				t.Errorf("RoleFor(%q) = (%q, %v), want (%q, %v)", tt.invitationType, role, known, tt.wantRole, tt.wantKnown)
			}
		})
	}
}

func TestFormatAAGUID(t *testing.T) {
	t.Parallel()

	id := [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}

	if got, want := formatAAGUID(id), "01234567-89ab-cdef-fedc-ba9876543210"; got != want {
		t.Errorf("formatAAGUID = %q, want %q", got, want)
	}
}

// TestSQLUsesBoundValues holds the statements to the repo's rule that values
// are bound, never concatenated: every statement has placeholders.
func TestSQLUsesBoundValues(t *testing.T) {
	t.Parallel()

	for name, query := range map[string]string{
		"invitation": invitationQuery,
		"user":       insertUserQuery,
		"credential": insertCredentialQuery,
	} {
		if strings.Count(query, "?") == 0 {
			t.Errorf("%s statement has no placeholders", name)
		}
	}
}
