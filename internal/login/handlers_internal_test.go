package login

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
	"github.com/susu-dot-dev/authsu/internal/deploy"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/session"
)

// Positions of the bound arguments in the two statements, per the comments on
// updateFlagsQuery and session.InsertSessionQuery.
const (
	flagsArgFlags   = 0
	flagsArgCredRow = 1
	keyArgKID       = 0
	keyArgOwnerRow  = 1
	keyArgJWK       = 2
	keyArgExpires   = 3
	keyArgGrant     = 4
	keyArgCredRow   = 5
	keyArgCreated   = 6
)

func TestBeginReturnsRequestOptions(t *testing.T) {
	t.Parallel()

	options, err := begin(t, newFixture(t), getenv(nil))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	pk := options.PublicKey

	if pk.RPID != testRPID {
		t.Errorf("rpId = %q, want %q", pk.RPID, testRPID)
	}

	if pk.UserVerification != "required" {
		t.Errorf("userVerification = %q, want required", pk.UserVerification)
	}

	if pk.Timeout != ChallengeTTL.Milliseconds() {
		t.Errorf("timeout = %d, want %d", pk.Timeout, ChallengeTTL.Milliseconds())
	}

	// An empty list is what makes login usernameless: the browser offers any
	// discoverable passkey for the relying party.
	if pk.AllowCredentials == nil || len(pk.AllowCredentials) != 0 {
		t.Errorf("allowCredentials = %#v, want an empty (non-nil) list", pk.AllowCredentials)
	}

	raw, err := base64.RawURLEncoding.DecodeString(pk.Challenge)
	if err != nil || len(raw) != challengeLen {
		t.Errorf("challenge = %q (%d bytes), want %d base64url bytes", pk.Challenge, len(raw), challengeLen)
	}
}

func TestBeginIsStateless(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	_, err := begin(t, fix, getenv(nil))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	if len(fix.batcher.batches) != 0 || len(fix.reader.asked) != 0 {
		t.Errorf("begin touched the database: %d batches, %d reads", len(fix.batcher.batches), len(fix.reader.asked))
	}
}

func TestBeginWorksWithNoDatabaseConfigured(t *testing.T) {
	t.Parallel()

	// begin holds only a clock and entropy, so it needs neither reader nor
	// batch: the host stub (no database) can still serve it.
	svc := NewService(Deps{Reader: nil, Batch: nil, Now: testNow, Entropy: counterEntropy()})

	resp, err := svc.BeginHandler(getenv(nil))(httpapi.Request{Context: t.Context()}).Get()
	if err != nil || resp.Status != http.StatusOK {
		t.Errorf("begin = %d, %v, want 200", resp.Status, err)
	}
}

func TestTwoBeginsDiffer(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	first, err := begin(t, fix, getenv(nil))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	second, err := begin(t, fix, getenv(nil))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	if first.PublicKey.Challenge == second.PublicKey.Challenge {
		t.Error("two begins returned the same challenge")
	}
}

func TestBeginRefusesWithoutConfiguration(t *testing.T) {
	t.Parallel()

	tests := map[string]map[string]string{
		"secret missing":      {deploy.SecretHMAC: ""},
		"secret too short":    {deploy.SecretHMAC: strings.Repeat("a", deploy.MinSecretLen-1)},
		"api origin missing":  {deploy.VarAPIOrigin: ""},
		"ui origin missing":   {deploy.VarUIOrigin: ""},
		"ui origin not http":  {deploy.VarUIOrigin: "ftp://example.com"},
		"api origin not http": {deploy.VarAPIOrigin: "ftp://auth.example.com"},
	}

	for name, overrides := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := begin(t, newFixture(t), getenv(overrides))
			wantFailure(t, err, apierr.Unavailable, CodeNotConfigured)
		})
	}
}

func TestBeginFailsWhenEntropyFails(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	fix.svc.entropy = bytes.NewReader(nil)

	_, err := begin(t, fix, getenv(nil))
	wantFailure(t, err, apierr.Internal, CodeChallenge)
}

// acceptedBatch runs a full successful login and returns the statements it
// wrote, with the response.
func acceptedBatch(t *testing.T, fix *fixture) (atomic.Statement, atomic.Statement, httpapi.Response) {
	t.Helper()

	req := beginThenRespond(t, fix, newAuthenticator())

	resp, err := finish(t, fix, getenv(nil), req)
	if err != nil {
		t.Fatalf("finish: %v", err)
	}

	if resp.Status != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.Status, http.StatusOK)
	}

	if len(fix.batcher.batches) != 1 || len(fix.batcher.batches[0]) != 2 {
		t.Fatalf("batches = %v, want one batch of two statements (flags, session)", fix.batcher.batches)
	}

	return fix.batcher.batches[0][0], fix.batcher.batches[0][1], resp
}

func TestFinishWritesFlagsThenSessionAtomically(t *testing.T) {
	t.Parallel()

	flags, key, _ := acceptedBatch(t, newFixture(t))

	if flags.Query != updateFlagsQuery || key.Query != session.InsertSessionQuery {
		t.Error("batch is not (update flags, insert session), in that order")
	}

	for name, statement := range map[string]atomic.Statement{"flags": flags, "session": key} {
		if got, want := len(statement.Args), strings.Count(statement.Query, "?"); got != want {
			t.Errorf("%s statement binds %d values for %d placeholders", name, got, want)
		}
	}
}

func TestFinishIssuesASessionForTheCredentialsAccount(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	_, key, resp := acceptedBatch(t, fix)

	// The account is not bound: the insert reads it from the credential's row,
	// so the session's owner is the credential's by construction. What is bound
	// is the credential, twice: for that subselect and for the column.
	if key.Args[keyArgOwnerRow] != testCredRowID {
		t.Errorf("session owner is read from credential %v, want %q", key.Args[keyArgOwnerRow], testCredRowID)
	}

	if key.Args[keyArgCredRow] != testCredRowID {
		t.Errorf("session credential = %v, want %q", key.Args[keyArgCredRow], testCredRowID)
	}

	if want := fix.now.Add(session.Lifetime).Unix(); key.Args[keyArgExpires] != want {
		t.Errorf("expires_at = %v, want %d", key.Args[keyArgExpires], want)
	}

	if key.Args[keyArgCreated] != fix.now.Unix() {
		t.Errorf("created_at = %v, want %d", key.Args[keyArgCreated], fix.now.Unix())
	}

	body, ok := resp.Body.(FinishResponse)
	if !ok {
		t.Fatalf("body is %T", resp.Body)
	}

	if body.UserID != testUserID || body.Role != testRole {
		t.Errorf("body = %+v, want user %q role %q", body, testUserID, testRole)
	}
}

func TestFinishRecordsTheChallengeAsTheGrant(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	req := beginThenRespond(t, fix, newAuthenticator())

	challenge := echoedChallenge(t, req)

	_, err := finish(t, fix, getenv(nil), req)
	if err != nil {
		t.Fatalf("finish: %v", err)
	}

	got, ok := fix.batcher.batches[0][1].Args[keyArgGrant].([]byte)
	if !ok || !bytes.Equal(got, session.LoginGrant(challenge)) {
		t.Errorf("granted_from = %x, want the login grant of the challenge", got)
	}
}

func TestFinishStoresTheReportedFlags(t *testing.T) {
	t.Parallel()

	// A synced credential reports backup state once it has synced, and that is
	// what is stored. Eligibility must match what registration stored.
	fix := newFixture(t)
	fix.reader.cred.Flags = 0x01 | 0x04 | 0x08

	auth := newAuthenticator()
	auth.flags = 0x01 | 0x04 | 0x08 | 0x10

	req := beginThenRespond(t, fix, auth)

	_, err := finish(t, fix, getenv(nil), req)
	if err != nil {
		t.Fatalf("finish: %v", err)
	}

	flags := fix.batcher.batches[0][0]

	if flags.Args[flagsArgFlags] != int64(0x01|0x04|0x08|0x10) || flags.Args[flagsArgCredRow] != testCredRowID {
		t.Errorf("flags args = %v, want the reported flags for the credential row", flags.Args)
	}
}

func TestFinishSetsTheSessionCookie(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	_, key, resp := acceptedBatch(t, fix)

	if len(resp.Cookies) != 1 {
		t.Fatalf("cookies = %v, want exactly the session cookie", resp.Cookies)
	}

	cookie := resp.Cookies[0]

	wantCookieAttributes(t, cookie)

	// The cookie's token is the one whose public key was stored: the stored
	// document is the public half, so it never contains the token.
	jwk, ok := key.Args[keyArgJWK].(string)
	if !ok || jwk == "" || strings.Contains(jwk, cookie.Value) {
		t.Errorf("stored jwk = %q: want a public key that does not contain the token", jwk)
	}
}

// TestFinishNeverReturnsTheTokenInTheBody holds the rule that the token
// travels only in the HttpOnly cookie, where page script cannot read it.
func TestFinishNeverReturnsTheTokenInTheBody(t *testing.T) {
	t.Parallel()

	_, _, resp := acceptedBatch(t, newFixture(t))

	encoded, err := json.Marshal(resp.Body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	if strings.Contains(string(encoded), resp.Cookies[0].Value) {
		t.Errorf("body %s carries the session token", encoded)
	}
}

// wantCookieAttributes checks the attributes that make the cookie safe.
func wantCookieAttributes(t *testing.T, cookie *http.Cookie) {
	t.Helper()

	if cookie.Name != session.CookieName || !cookie.HttpOnly || !cookie.Secure {
		t.Errorf("cookie = %+v, want an HttpOnly Secure %s cookie", cookie, session.CookieName)
	}

	if cookie.Path != "/" || cookie.Domain != "" {
		t.Errorf("cookie = %+v, want Path=/ and no Domain (what __Host- requires)", cookie)
	}
}

// echoedChallenge decodes the challenge the response put in clientDataJSON.
func echoedChallenge(t *testing.T, req FinishRequest) []byte {
	t.Helper()

	client, err := base64.RawURLEncoding.DecodeString(req.Response.ClientDataJSON)
	if err != nil {
		t.Fatalf("clientDataJSON: %v", err)
	}

	const marker = `"challenge":"`

	_, after, found := bytes.Cut(client, []byte(marker))
	if !found {
		t.Fatalf("no challenge in %s", client)
	}

	encoded, _, _ := bytes.Cut(after, []byte(`"`))

	challenge, err := base64.RawURLEncoding.DecodeString(string(encoded))
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}

	return challenge
}

// TestFinishRefusesEverythingTheSameWay is the point of CodeInvalidLogin: an
// unknown credential, a wrong handle, a bad signature and a forged challenge
// are all one answer, so a failed login reveals nothing about which check
// failed. None of them may write.
func TestFinishRefusesEverythingTheSameWay(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		auth func(*authenticator)
		fix  func(*fixture)
		edit func(*FinishRequest)
	}{
		"wrong origin":    {auth: func(a *authenticator) { a.origin = "https://evil.example.com" }},
		"wrong rp":        {auth: func(a *authenticator) { a.rpID = "evil.example.com" }},
		"no UV":           {auth: func(a *authenticator) { a.flags = 0x01 }},
		"ceremony type":   {auth: func(a *authenticator) { a.clientDataType = "webauthn.create" }},
		"another handle":  {auth: func(a *authenticator) { a.handle = []byte("someone-else") }},
		"another key":     {auth: func(a *authenticator) { a.key = otherKey(t) }},
		"unknown id":      {auth: func(a *authenticator) { a.credID = []byte("not-a-credential") }},
		"forged":          {auth: func(a *authenticator) { a.challenge = bytes.Repeat([]byte{7}, challengeLen) }},
		"short challenge": {auth: func(a *authenticator) { a.challenge = []byte("short") }},
		"expired":         {fix: func(f *fixture) { f.now = f.now.Add(ChallengeTTL) }},
		"not public-key":  {edit: func(r *FinishRequest) { r.Type = "password" }},
		"extensions":      {edit: func(r *FinishRequest) { r.ClientExtensionResults = map[string]json.RawMessage{"x": nil} }},
		"rawId empty":     {edit: func(r *FinishRequest) { r.RawID = "" }},
		"credential gone": {fix: func(f *fixture) { f.reader.ok = false }},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			auth := newAuthenticator()

			if tt.auth != nil {
				tt.auth(&auth)
			}

			req := beginThenRespond(t, fix, auth)

			if tt.edit != nil {
				tt.edit(&req)
			}

			if tt.fix != nil {
				tt.fix(fix)
			}

			_, err := finish(t, fix, getenv(nil), req)
			wantFailure(t, err, apierr.Unauthorized, CodeInvalidLogin)

			if len(fix.batcher.batches) != 0 {
				t.Errorf("a refused login wrote: %v", fix.batcher.batches)
			}
		})
	}
}

func TestFinishRefusesAChallengeFromTheOtherCeremony(t *testing.T) {
	t.Parallel()

	// A challenge signed with another key (registration's, in production)
	// does not verify, whatever it carries.
	fix := newFixture(t)

	foreign, err := mint(bytes.Repeat([]byte{9}, 32), counterEntropy(), fix.now.Add(ChallengeTTL))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	auth := newAuthenticator()
	auth.challenge = foreign

	req := beginThenRespond(t, fix, auth)

	_, err = finish(t, fix, getenv(nil), req)
	wantFailure(t, err, apierr.Unauthorized, CodeInvalidLogin)
}

func TestFinishRefusesAChallengeExpiringBeyondTheTTL(t *testing.T) {
	t.Parallel()

	// Signed by the real key, so only the far-ahead bound can refuse it.
	fix := newFixture(t)

	far, err := mint(deploy.DeriveKey(testSecret, derivationContext), counterEntropy(), fix.now.Add(30*24*time.Hour))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	auth := newAuthenticator()
	auth.challenge = far

	req := beginThenRespond(t, fix, auth)

	_, err = finish(t, fix, getenv(nil), req)
	wantFailure(t, err, apierr.Unauthorized, CodeInvalidLogin)

	if len(fix.batcher.batches) != 0 {
		t.Error("a login with a forged long-lived challenge wrote")
	}
}

func TestFinishRefusesWithoutConfiguration(t *testing.T) {
	t.Parallel()

	req := beginThenRespond(t, newFixture(t), newAuthenticator())

	tests := map[string]struct {
		env  map[string]string
		edit func(*fixture)
	}{
		"secret missing": {env: map[string]string{deploy.SecretHMAC: ""}},
		"no reader":      {edit: func(f *fixture) { f.svc.reader = nil }},
		"no batch":       {edit: func(f *fixture) { f.svc.batch = nil }},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)

			if tt.edit != nil {
				tt.edit(fix)
			}

			_, err := finish(t, fix, getenv(tt.env), req)
			wantFailure(t, err, apierr.Unavailable, CodeNotConfigured)
		})
	}
}

func TestFinishReportsAFailingCredentialLookupAsUnavailable(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	fix.reader.err = errDB

	req := beginThenRespond(t, fix, newAuthenticator())

	_, err := finish(t, fix, getenv(nil), req)
	wantFailure(t, err, apierr.Unavailable, CodeCredentialRead)

	if !errors.Is(err, errDB) {
		t.Errorf("err = %v, want it to wrap the database error for the log", err)
	}
}

func TestFinishFailsWhenTheSessionCannotBeMinted(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	fix.svc.mint = func(session.Issuer, string, time.Time) (session.Key, error) {
		return session.Key{}, errDB
	}

	req := beginThenRespond(t, fix, newAuthenticator())

	_, err := finish(t, fix, getenv(nil), req)
	wantFailure(t, err, apierr.Internal, CodeMintFailed)
}

func TestFinishClassifiesAFailedBatch(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err      error
		wantKind apierr.Kind
		wantCode string
	}{
		// A replay collides on granted_from. It is reported as any failed
		// login: the client cannot act on being told the response was used.
		"replay (conflict)": {
			err: errors.Join(atomic.ErrConflict, errDB), wantKind: apierr.Unauthorized, wantCode: CodeInvalidLogin,
		},
		"schema rejection": {
			err: errors.Join(atomic.ErrRejected, errDB), wantKind: apierr.Internal, wantCode: CodeAcceptRejected,
		},
		"database down": {err: errDB, wantKind: apierr.Unavailable, wantCode: CodeAcceptFailed},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			fix.batcher.err = tt.err

			req := beginThenRespond(t, fix, newAuthenticator())

			_, err := finish(t, fix, getenv(nil), req)
			wantFailure(t, err, tt.wantKind, tt.wantCode)

			if !errors.Is(err, errDB) {
				t.Errorf("err = %v, want it to wrap the cause for the log", err)
			}
		})
	}
}

func TestFinishRejectsMalformedBodies(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"empty":          ``,
		"not json":       `nope`,
		"unknown member": `{"id":"x","rawId":"x","type":"public-key","response":{},"role":"admin"}`,
		"wrong type":     `{"id":1}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)

			resp, err := fix.svc.FinishHandler(getenv(nil))(httpapi.Request{
				Context: t.Context(), Body: []byte(body),
			}).Get()
			if err == nil {
				t.Fatalf("finish accepted %q: %+v", body, resp)
			}

			failure := apierr.As(err)
			if failure.Kind != apierr.BadRequest {
				t.Errorf("error = (%d, %q), want a 400", failure.Kind, failure.Code)
			}

			if len(fix.batcher.batches) != 0 {
				t.Error("a malformed body wrote")
			}
		})
	}
}

// TestFinishChecksTheChallengeBeforeTheDatabase requires what finish's comment
// promises: everything that can be refused without the database is refused
// first. A forged challenge, or client data from another origin, needs no
// stored credential to refuse, so it must not cost a D1 read, and the time a
// refusal takes must not depend on whether the credential id exists.
func TestFinishChecksTheChallengeBeforeTheDatabase(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*authenticator){
		"forged challenge": func(a *authenticator) { a.challenge = bytes.Repeat([]byte{7}, challengeLen) },
		"wrong origin":     func(a *authenticator) { a.origin = "https://evil.example.com" },
		"wrong rp":         func(a *authenticator) { a.rpID = "evil.example.com" },
		"ceremony type":    func(a *authenticator) { a.clientDataType = "webauthn.create" },
	}

	for name, edit := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			auth := newAuthenticator()
			edit(&auth)

			_, err := finish(t, fix, getenv(nil), beginThenRespond(t, fix, auth))
			wantFailure(t, err, apierr.Unauthorized, CodeInvalidLogin)

			if len(fix.reader.asked) != 0 {
				t.Errorf("credential reads = %d, want 0: a response refusable without the database read it",
					len(fix.reader.asked))
			}
		})
	}
}
