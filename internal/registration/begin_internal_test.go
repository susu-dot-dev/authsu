package registration

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
)

func TestBeginReturnsCreationOptions(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	options, err := begin(t, fix, getenv(nil), BeginRequest{InvitationCode: testCode, Name: testName})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	pk := options.PublicKey

	if pk.RP.ID != testRPID || pk.RP.Name != testRPName {
		t.Errorf("rp = %+v", pk.RP)
	}

	if pk.User.Name != testName || pk.User.DisplayName != testName {
		t.Errorf("user = %+v, want the name as both name and displayName", pk.User)
	}

	if pk.Timeout != ChallengeTTL.Milliseconds() {
		t.Errorf("timeout = %d, want %d", pk.Timeout, ChallengeTTL.Milliseconds())
	}
}

// TestBeginAsksForExactlyWhatTheVerifierAccepts: the options must request only
// what internal/webauthn will accept, or no honest browser could register.
func TestBeginAsksForExactlyWhatTheVerifierAccepts(t *testing.T) {
	t.Parallel()

	options, err := begin(t, newFixture(t), getenv(nil), BeginRequest{InvitationCode: testCode, Name: testName})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	pk := options.PublicKey

	if len(pk.PubKeyCredParams) != 1 || pk.PubKeyCredParams[0].Alg != -7 || pk.PubKeyCredParams[0].Type != "public-key" {
		t.Errorf("pubKeyCredParams = %+v, want only ES256", pk.PubKeyCredParams)
	}

	if pk.Attestation != noneFormat {
		t.Errorf("attestation = %q, want %s", pk.Attestation, noneFormat)
	}

	if pk.AuthenticatorSelection.ResidentKey != "required" || pk.AuthenticatorSelection.UserVerification != "required" {
		t.Errorf("authenticatorSelection = %+v", pk.AuthenticatorSelection)
	}
}

// TestBeginChallengeCommitsToTheHandle checks the link finish depends on: the
// challenge verifies for this code and name, and commits to the handle that
// user.id told the authenticator to store.
func TestBeginChallengeCommitsToTheHandle(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	options, err := begin(t, fix, getenv(nil), BeginRequest{InvitationCode: testCode, Name: testName})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	handle, err := base64.RawURLEncoding.DecodeString(options.PublicKey.User.ID)
	if err != nil || len(handle) != UserHandleLen {
		t.Fatalf("user id %q is not a %d-byte base64url handle: %v", options.PublicKey.User.ID, UserHandleLen, err)
	}

	challenge, err := base64.RawURLEncoding.DecodeString(options.PublicKey.Challenge)
	if err != nil {
		t.Fatalf("challenge is not base64url: %v", err)
	}

	opened, err := open(deriveKey(testSecret), challenge, testNow(), testCode, testName)
	if err != nil {
		t.Fatalf("the challenge does not verify: %v", err)
	}

	if !bytes.Equal(opened, handle) {
		t.Error("the challenge commits to a different handle than user.id")
	}
}

// TestBeginWritesNothing is the central property of begin: it is stateless. The
// service has a batch function, and begin must never call it.
func TestBeginWritesNothing(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	for range 3 {
		_, err := begin(t, fix, getenv(nil), BeginRequest{InvitationCode: testCode, Name: testName})
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
	}

	if len(fix.batcher.batches) != 0 {
		t.Errorf("begin issued %d write batches, want 0", len(fix.batcher.batches))
	}

	if fix.ids != 0 {
		t.Errorf("begin allocated %d ids, want 0: nothing may exist before finish", fix.ids)
	}
}

func TestBeginRejectsBadInput(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		body     BeginRequest
		wantKind apierr.Kind
		wantCode string
	}{
		"unknown invitation": {
			body:     BeginRequest{InvitationCode: "no-such-code", Name: testName},
			wantKind: apierr.Forbidden, wantCode: CodeInvalidInvitation,
		},
		"empty code": {
			body:     BeginRequest{InvitationCode: "", Name: testName},
			wantKind: apierr.BadRequest, wantCode: CodeInvalidInvitation,
		},
		"code too long": {
			body:     BeginRequest{InvitationCode: strings.Repeat("a", maxCodeBytes+1), Name: testName},
			wantKind: apierr.BadRequest, wantCode: CodeInvalidInvitation,
		},
		"empty name": {
			body:     BeginRequest{InvitationCode: testCode, Name: ""},
			wantKind: apierr.BadRequest, wantCode: CodeInvalidName,
		},
		"name too long": {
			body:     BeginRequest{InvitationCode: testCode, Name: strings.Repeat("a", maxNameBytes+1)},
			wantKind: apierr.BadRequest, wantCode: CodeInvalidName,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := begin(t, newFixture(t), getenv(nil), tt.body)

			wantFailure(t, err, tt.wantKind, tt.wantCode)
		})
	}
}

func TestBeginRejectsMissingConfiguration(t *testing.T) {
	t.Parallel()

	tests := map[string]map[string]string{
		"secret missing":   {SecretHMAC: ""},
		"secret too short": {SecretHMAC: strings.Repeat("a", MinSecretLen-1)},
		"rp id missing":    {VarRPID: ""},
		"rp origin":        {VarRPOrigin: ""},
		"rp name missing":  {VarRPName: ""},
	}

	for name, env := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := begin(t, newFixture(t), getenv(env), BeginRequest{InvitationCode: testCode, Name: testName})

			wantFailure(t, err, apierr.Unavailable, CodeNotConfigured)
		})
	}
}

func TestBeginInvitationLookupFailure(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	fix.reader.err = errDB

	_, err := begin(t, fix, getenv(nil), BeginRequest{InvitationCode: testCode, Name: testName})

	wantFailure(t, err, apierr.Unavailable, CodeInvitationCheck)
}

// TestValidateCodeAndNameRejectsInvalidUTF8 calls the validator directly:
// json.Marshal would replace an invalid byte with U+FFFD before the server ever
// saw it, and a decoder does the same on the way in. The check is the backstop
// for any caller that bypasses decoding.
func TestValidateCodeAndNameRejectsInvalidUTF8(t *testing.T) {
	t.Parallel()

	failure := apierr.As(validateCodeAndName(testCode, "bad\xff"))
	if failure.Code != CodeInvalidName {
		t.Errorf("code = %q, want %q", failure.Code, CodeInvalidName)
	}
}

func TestBeginWithoutADatabaseIsNotConfigured(t *testing.T) {
	t.Parallel()

	svc := NewService(Deps{Reader: nil, Batch: nil, Now: time.Now, Entropy: counterEntropy(), NewID: nil})

	_, err := svc.BeginHandler(getenv(nil))(request(t, BeginRequest{InvitationCode: testCode, Name: testName})).Get()

	wantFailure(t, err, apierr.Unavailable, CodeNotConfigured)
}

func TestBeginEntropyFailure(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	fix.svc.entropy = bytes.NewReader(nil)

	_, err := begin(t, fix, getenv(nil), BeginRequest{InvitationCode: testCode, Name: testName})

	wantFailure(t, err, apierr.Internal, CodeChallengeFailed)
}

func TestDecodeRejectsBadBodies(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		emptyCase:       ``,
		"not json":      `x`,
		"unknown field": `{"invitationCode":"a","name":"b","role":"admin"}`,
		"wrong type":    `{"invitationCode":1,"name":"b"}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := newFixture(t).svc.BeginHandler(getenv(nil))(httpapi.Request{
				Method: http.MethodPost, Path: "/", Context: t.Context(), Query: nil, Body: []byte(body),
			}).Get()

			failure := failureOf(t, err)
			if failure.Kind != apierr.BadRequest {
				t.Errorf("kind = %d, want BadRequest", failure.Kind)
			}
		})
	}
}
