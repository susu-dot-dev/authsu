package login_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/challenge"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/login"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Where the parts of a challenge are (see package challenge).
const (
	offVersion = 0
	offExpiry  = 1
	offNonce   = 9
	offTag     = 41
)

// flipByte alters the byte at i of the genuine challenge.
func flipByte(i int) func(*testing.T, *rig, []byte) []byte {
	return func(_ *testing.T, _ *rig, genuine []byte) []byte {
		out := slices.Clone(genuine)
		out[i] ^= 0xff

		return out
	}
}

// madeAt is a challenge the login key made for the test's own choice of expiry
// (relative to the clock), as a leaked key would let an attacker make.
func madeAt(expires time.Duration) func(*testing.T, *rig, []byte) []byte {
	return func(t *testing.T, r *rig, _ []byte) []byte {
		t.Helper()

		return forgeChallenge(t, r.config().LoginKey, r.now.Add(expires))
	}
}

// finishCase is one way a finish is refused. Cases are built with refusal and
// refined by the methods below, so each states only what makes it different.
type finishCase struct {
	name string
	// raw replaces the whole request body.
	raw string
	// authn makes the authenticator misbehave.
	authn func(*authenticator)
	// challenge replaces the challenge the browser echoes, given the genuine one.
	challenge func(*testing.T, *rig, []byte) []byte
	// edit changes the request body after the authenticator has built it.
	edit func(jsonBody)
	// rewrite changes the request body's text, to make what a map cannot.
	rewrite func(string) string
	// between changes the world after begin and before finish.
	between func(*rig)
	// stranger has the assertion signed by another key.
	stranger bool

	status int
	body   string
	logged string
	// cause is an error the logged failure must wrap: the reason, which is in
	// the log and never in the response.
	cause error
	// lookups, keys and writes are what the finish itself did: credential
	// reads, session creations and session writes.
	lookups, keys, writes int
}

// refusal is a case answered with a client-visible code and message.
func refusal(name string, status int, code, message string) finishCase {
	return finishCase{
		name: name, raw: "", authn: nil, challenge: nil, edit: nil, rewrite: nil, between: nil, stranger: false,
		status: status, body: errorBody(code, message), logged: code, cause: nil,
		lookups: 0, keys: 0, writes: 0,
	}
}

// defective is a case answered with the opaque 500, logged under code.
func defective(name, code string) finishCase {
	c := refusal(name, http.StatusInternalServerError, "", "")
	c.body, c.logged = bodyInternal, code

	return c
}

// badRequest is a 400 about the request itself.
func badRequest(name, code, message string) finishCase {
	return refusal(name, http.StatusBadRequest, code, message)
}

// invalid is the one answer to every assertion that does not verify.
func invalid(name string) finishCase {
	return refusal(name, http.StatusUnauthorized, codeInvalidLogin, msgInvalidLogin)
}

func (c finishCase) rawBody(text string) finishCase { c.raw = text; return c }

func (c finishCase) withAuthenticator(f func(*authenticator)) finishCase { c.authn = f; return c }

func (c finishCase) echoing(f func(*testing.T, *rig, []byte) []byte) finishCase {
	c.challenge = f
	return c
}

func (c finishCase) editing(f func(jsonBody)) finishCase { c.edit = f; return c }

func (c finishCase) rewriting(f func(string) string) finishCase { c.rewrite = f; return c }

func (c finishCase) afterBegin(f func(*rig)) finishCase { c.between = f; return c }

func (c finishCase) because(cause error) finishCase { c.cause = cause; return c }

// readCredential says the finish got as far as reading the credential.
func (c finishCase) readCredential() finishCase { c.lookups = 1; return c }

// createdKey says the finish got as far as creating the session key.
func (c finishCase) createdKey() finishCase { c.keys = 1; return c }

// wroteSession says the finish got as far as writing the session.
func (c finishCase) wroteSession() finishCase { c.writes = 1; return c }

// signedByAStranger has the assertion signed by a passkey the store does not hold.
func (c finishCase) signedByAStranger() finishCase { c.stranger = true; return c }

// shapeFailures are requests the decoder refuses, or a deployment that cannot
// answer: these are the only refusals that are not the one 401.
func shapeFailures() []finishCase {
	return []finishCase{
		badRequest("not JSON", "invalid_json", "request body is not valid JSON").rawBody("{"),
		badRequest("empty body", "empty_body", "request body is empty").rawBody(" "),
		badRequest("unknown member", "unknown_field", "request body has an unknown field").
			editing(func(b jsonBody) { b.set("role", "admin") }),
		badRequest("unknown member of the response", "unknown_field", "request body has an unknown field").
			editing(func(b jsonBody) { b.set("response.extra", 1) }),
		badRequest("a member of the wrong type", "invalid_field_type", "a field has the wrong type").
			editing(func(b jsonBody) { b.set("id", 7) }),
		badRequest("a repeated member", "duplicate_field", "request body repeats a field").
			rewriting(func(text string) string {
				return strings.Replace(text, `"type":"public-key"`, `"type":"public-key","type":"public-key"`, 1)
			}),
		refusal("no configuration", http.StatusServiceUnavailable, codeNotConfigured, msgNotConfigured).
			afterBegin(func(r *rig) { r.with(map[string]string{config.SecretHMAC: ""}) }),
	}
}

// envelopeFailures are credentials whose envelope is wrong.
func envelopeFailures() []finishCase {
	return []finishCase{
		invalid("credential type missing").editing(func(b jsonBody) { b.remove("type") }),
		invalid("credential type is not public-key").editing(func(b jsonBody) { b.set("type", "password") }),
		invalid("unsolicited client extension results").editing(func(b jsonBody) {
			b.set("clientExtensionResults", jsonBody{"credProps": jsonBody{"rk": true}})
		}),
	}
}

// assertionFailures are assertions the verifier refuses before the credential
// is read.
func assertionFailures() []finishCase {
	flags := func(f byte) func(*authenticator) { return func(a *authenticator) { a.flags = f } }

	return []finishCase{
		invalid("another origin").withAuthenticator(func(a *authenticator) { a.origin = "https://evil.example" }),
		invalid("another relying party").withAuthenticator(func(a *authenticator) { a.rpID = "evil.example" }),
		invalid("a registration ceremony").
			withAuthenticator(func(a *authenticator) { a.clientDataType = "webauthn.create" }),
		invalid("user presence missing").withAuthenticator(flags(flagUV)),
		invalid("user verification missing").withAuthenticator(flags(flagUP)),
		invalid("attested credential data announced").withAuthenticator(flags(flagUP | flagUV | flagAT)),
		invalid("extension data announced").withAuthenticator(flags(flagUP | flagUV | flagED)),
		invalid("backup state without backup eligibility").withAuthenticator(flags(flagUP | flagUV | flagBS)),
		invalid("authenticator data longer than 37 bytes").
			withAuthenticator(func(a *authenticator) { a.trailing = []byte{0} }),
		invalid("rawId is not the credential's id").
			editing(func(b jsonBody) { b.set("rawId", b64([]byte("another-credential-id"))) }),
		invalid("rawId empty").editing(func(b jsonBody) { b.set("rawId", "") }),
		invalid("no user handle").editing(func(b jsonBody) { b.remove("response.userHandle") }),
		invalid("user handle is not base64url").editing(func(b jsonBody) { b.set("response.userHandle", "not base64!") }),
		invalid("signature is not base64url").editing(func(b jsonBody) { b.set("response.signature", "not base64!") }),
		invalid("signature is too long").
			editing(func(b jsonBody) { b.set("response.signature", b64(make([]byte, 81))) }),
		invalid("client data is not base64url").
			editing(func(b jsonBody) { b.set("response.clientDataJSON", "not base64!") }),
	}
}

// challengeFailures are valid assertions answering a challenge that is forged,
// altered, stale, or made for another ceremony.
func challengeFailures() []finishCase {
	return []finishCase{
		invalid("version byte flipped").echoing(flipByte(offVersion)),
		invalid("expiry byte flipped").echoing(flipByte(offExpiry + 7)),
		invalid("nonce byte flipped").echoing(flipByte(offNonce)),
		invalid("tag byte flipped").echoing(flipByte(offTag + 31)),
		invalid("challenge truncated").echoing(
			func(_ *testing.T, _ *rig, c []byte) []byte { return c[:challenge.Len-1] }),
		invalid("challenge extended").echoing(
			func(_ *testing.T, _ *rig, c []byte) []byte { return append(slices.Clone(c), 0) }),
		invalid("challenge is a few bytes").echoing(
			func(*testing.T, *rig, []byte) []byte { return []byte("short") }),
		invalid("challenge is not ours at all").echoing(
			func(*testing.T, *rig, []byte) []byte { return make([]byte, challenge.Len) }),
		invalid("made by the registration key").echoing(func(t *testing.T, r *rig, _ []byte) []byte {
			t.Helper()

			return forgeChallenge(t, r.config().RegistrationKey, r.now.Add(ttl))
		}),
		invalid("the secret changed since begin").
			afterBegin(func(r *rig) { r.with(map[string]string{config.SecretHMAC: strings.Repeat("z", 40)}) }),
		invalid("expired exactly at its expiry").afterBegin(func(r *rig) { r.now = r.now.Add(ttl) }),
		invalid("expired long ago").afterBegin(func(r *rig) { r.now = r.now.Add(24 * time.Hour) }),
		invalid("signed with a far-future expiry").echoing(madeAt(ttl + time.Second)),
		invalid("signed to last for years").echoing(madeAt(10 * 365 * 24 * time.Hour)),
		invalid("the clock stepped back, so the expiry is further away than a TTL").
			afterBegin(func(r *rig) { r.now = r.now.Add(-time.Second) }),
	}
}

// credentialFailures are assertions refused once the credential was read.
func credentialFailures() []finishCase {
	read := finishCase.readCredential
	stored := func(change func(*store.Credential)) func(*rig) {
		return func(r *rig) { r.setCredential(change) }
	}

	return []finishCase{
		read(invalid("the credential is unknown").afterBegin(func(r *rig) { clear(r.store.credentials) })),
		read(invalid("another credential id that is unknown").
			withAuthenticator(func(a *authenticator) { a.credID = []byte("never-registered") })),
		read(invalid("the user handle is not the account's").
			withAuthenticator(func(a *authenticator) { a.handle = []byte("another-account-handle") })),
		read(invalid("the account's handle changed").
			afterBegin(stored(func(c *store.Credential) { c.UserHandle = []byte("another-account-handle") }))),
		read(invalid("backup eligibility appeared").
			withAuthenticator(func(a *authenticator) { a.flags = flagUP | flagUV | flagBE })),
		read(invalid("backup eligibility disappeared").
			afterBegin(stored(func(c *store.Credential) { c.Flags = flagUP | flagUV | flagBE }))),
		read(invalid("signed by another key").signedByAStranger()),
		read(invalid("the signature is not one").
			editing(func(b jsonBody) { b.set("response.signature", b64(make([]byte, 70))) })),
	}
}

// corruptStoredKeys are stored public keys that registration would have refused
// (see publicKeyFailures in the registration package), so
// finding one is the database no longer holding what was written: a 500 that
// pages someone, never the 401 a bad signature gets.
func corruptStoredKeys() []finishCase {
	stored := func(key []byte) func(*rig) {
		return func(r *rig) { r.setCredential(func(c *store.Credential) { c.PublicKey = key }) }
	}

	return []finishCase{
		defective("the stored key is not CBOR", login.CodeStoredCredentialInvalid).
			readCredential().afterBegin(stored([]byte("not a COSE key"))),
		defective("the stored key is empty", login.CodeStoredCredentialInvalid).
			readCredential().afterBegin(stored([]byte{})),
		defective("the stored key is nil", login.CodeStoredCredentialInvalid).
			readCredential().afterBegin(stored(nil)),
		defective("the stored key is truncated", login.CodeStoredCredentialInvalid).
			readCredential().afterBegin(func(r *rig) {
			r.setCredential(func(c *store.Credential) { c.PublicKey = c.PublicKey[:len(c.PublicKey)/2] })
		}),
		defective("the stored key has bytes after it", login.CodeStoredCredentialInvalid).
			readCredential().afterBegin(func(r *rig) {
			r.setCredential(func(c *store.Credential) { c.PublicKey = append(bytes.Clone(c.PublicKey), 0) })
		}),
		defective("the stored key's point is not on the curve", login.CodeStoredCredentialInvalid).
			readCredential().afterBegin(func(r *rig) {
			r.setCredential(func(c *store.Credential) {
				flipped := bytes.Clone(c.PublicKey)
				flipped[len(flipped)-1] ^= 0xff
				c.PublicKey = flipped
			})
		}),
	}
}

// databaseFailures are failures of the database or of key creation. They are
// the service's own fault, so each is answered as such, and none is the 401.
func databaseFailures() []finishCase {
	lookup := func(c finishCase, outcome error) finishCase {
		return c.because(errDB).readCredential().afterBegin(func(r *rig) { r.store.lookupErr = outcome })
	}
	write := func(c finishCase, outcome error) finishCase {
		return c.because(errDB).readCredential().createdKey().wroteSession().
			afterBegin(func(r *rig) { r.store.createErrs = []error{outcome} })
	}

	return []finishCase{
		lookup(refusal("the credential lookup is unavailable", http.StatusServiceUnavailable,
			store.CodeCredentialLookupFailed, msgUnavailable),
			classified(apierr.Unavailable, store.CodeCredentialLookupFailed)),
		lookup(defective("the credential lookup is a defect", store.CodeCredentialLookupRejected),
			classified(apierr.Internal, store.CodeCredentialLookupRejected)),
		lookup(defective("the credential lookup fails without being classified", codeInternal), errDB),
		defective("a session key cannot be created", "session_create_failed").
			because(errCreate).readCredential().createdKey().
			afterBegin(func(r *rig) { r.createErr = errCreate }),
		write(refusal("the session write is unavailable", http.StatusServiceUnavailable,
			store.CodeLoginAcceptFailed, msgUnavailable),
			classified(apierr.Unavailable, store.CodeLoginAcceptFailed)),
		write(defective("the session write is a defect", store.CodeLoginAcceptRejected),
			classified(apierr.Internal, store.CodeLoginAcceptRejected)),
		write(defective("the session write fails without being classified", codeInternal), errDB),
		write(invalid("the session write is refused as a conflict: a replay, a deleted passkey, a revoked account"),
			errors.Join(store.ErrConflict, errDB)),
	}
}

// allFailures is every way a finish is refused.
func allFailures() []finishCase {
	return slices.Concat(
		shapeFailures(), envelopeFailures(), assertionFailures(), challengeFailures(),
		credentialFailures(), corruptStoredKeys(), databaseFailures())
}

// request builds the finish request the case sends, after begin has run.
func (c finishCase) request(t *testing.T, r *rig) string {
	t.Helper()

	a := r.newAuthenticator()

	if c.authn != nil {
		c.authn(&a)
	}

	if c.stranger {
		a.key = newPrivateKey(t)
	}

	options := r.beginOK()

	if c.challenge != nil {
		a.challenge = c.challenge(t, r, unb64(t, options.PublicKey.Challenge))
	}

	body := a.respond(t, options)

	if c.edit != nil {
		c.edit(body)
	}

	if c.between != nil {
		c.between(r)
	}

	text := mustJSON(body)

	if c.rewrite != nil {
		text = c.rewrite(text)
	}

	if c.raw != "" {
		text = c.raw
	}

	return text
}

// TestFinishFailures: every way a finish is refused, with the exact answer and
// proof of which store calls it made. Everything that can be refused without the
// database is refused before it, and a key is created only for an assertion that
// verified.
func TestFinishFailures(t *testing.T) {
	t.Parallel()

	for _, tc := range allFailures() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			text := tc.request(t, r)
			rec := r.post(login.PathFinish, text)

			wantFailure(t, r, rec, tc.status, tc.body, tc.logged)

			if tc.cause != nil && !errors.Is(r.logged[0], tc.cause) {
				t.Errorf("logged error %v does not wrap the cause %v", r.logged[0], tc.cause)
			}

			if len(r.store.looked) != tc.lookups || len(r.sessions) != tc.keys || len(r.store.created) != tc.writes {
				t.Errorf("credential reads, session creations, session writes = %d, %d, %d; want %d, %d, %d",
					len(r.store.looked), len(r.sessions), len(r.store.created), tc.lookups, tc.keys, tc.writes)
			}
		})
	}
}

// snapshot is everything a client can observe of a response.
func snapshot(rec *httptest.ResponseRecorder) string {
	return fmt.Sprintf("%d %v %q", rec.Code, rec.Header(), rec.Body.String())
}

// TestFinishVerificationFailuresAreIndistinguishable: a failed login must reveal
// nothing about which check failed, so every refusal of an assertion is the same
// response down to the byte: status, headers and body, whether the credential is
// unknown, the signature bad, the challenge forged or a replay.
func TestFinishVerificationFailuresAreIndistinguishable(t *testing.T) {
	t.Parallel()

	var reference string

	count := 0

	for _, tc := range allFailures() {
		if tc.status != http.StatusUnauthorized {
			continue
		}

		r := newRig(t)
		got := snapshot(r.post(login.PathFinish, tc.request(t, r)))

		if reference == "" {
			reference = got
		}

		count++

		if got != reference {
			t.Errorf("%s: response differs from the first refusal:\n got  %s\n want %s", tc.name, got, reference)
		}
	}

	want := fmt.Sprintf("401 map[Cache-Control:[no-store] Content-Type:[application/json]] %q", bodyInvalidLogin())
	if reference != want {
		t.Errorf("the one answer = %s, want %s", reference, want)
	}

	if count < 40 {
		t.Errorf("only %d refusals compared: the table lost cases", count)
	}
}

// success is a finish that is accepted, and what must then be written.
type success struct {
	name  string
	authn func(*authenticator)
	edit  func(jsonBody)
	// stored changes the passkey the store holds.
	stored func(*store.Credential)
	// flags are what the store must be told the credential now has, and role
	// and user the account the response must name.
	flags uint8
	role  string
	user  string
}

func accepted(name string) success {
	return success{
		name: name, authn: nil, edit: nil, stored: nil, flags: flagUP | flagUV, role: testRole, user: testUserID,
	}
}

func (c success) withAuthenticator(f func(*authenticator)) success { c.authn = f; return c }

func (c success) editing(f func(jsonBody)) success { c.edit = f; return c }

func (c success) holding(f func(*store.Credential)) success { c.stored = f; return c }

func (c success) learning(flags uint8) success { c.flags = flags; return c }

func (c success) as(user, role string) success { c.user, c.role = user, role; return c }

func successes() []success {
	const otherUser = "00000000-0000-7000-8000-0000000000ff"

	return []success{
		accepted("a device-bound passkey"),
		accepted("a synced passkey that became backed up").
			holding(func(c *store.Credential) { c.Flags = flagUP | flagUV | flagBE }).
			withAuthenticator(func(a *authenticator) { a.flags = flagUP | flagUV | flagBE | flagBS }).
			learning(flagUP | flagUV | flagBE | flagBS),
		accepted("a synced passkey that stopped being backed up").
			holding(func(c *store.Credential) { c.Flags = flagUP | flagUV | flagBE | flagBS }).
			withAuthenticator(func(a *authenticator) { a.flags = flagUP | flagUV | flagBE }).
			learning(flagUP | flagUV | flagBE),
		accepted("a passkey whose first use verified the user").
			holding(func(c *store.Credential) { c.Flags = flagUP }).
			learning(flagUP | flagUV),
		accepted("the role is the account's, not a default").
			holding(func(c *store.Credential) { c.Role = "member" }).as(testUserID, "member"),
		accepted("the account is the passkey's owner").
			holding(func(c *store.Credential) { c.UserID = otherUser }).as(otherUser, testRole),
		accepted("an attachment the browser reports is ignored").
			editing(func(b jsonBody) { b.set("authenticatorAttachment", "platform") }),
		accepted("a user handle of the longest length").
			withAuthenticator(func(a *authenticator) { a.handle = make([]byte, 64) }).
			holding(func(c *store.Credential) { c.UserHandle = make([]byte, 64) }),
	}
}

// TestFinishSucceeds pins the whole of a successful finish: the response, the
// session cookie, and exactly what is written, for each shape of passkey.
func TestFinishSucceeds(t *testing.T) {
	t.Parallel()

	for _, tc := range successes() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			a := r.newAuthenticator()

			if tc.authn != nil {
				tc.authn(&a)
			}

			if tc.stored != nil {
				r.setCredential(tc.stored)
			}

			options := r.beginOK()
			body := a.respond(t, options)

			if tc.edit != nil {
				tc.edit(body)
			}

			rec := r.post(login.PathFinish, mustJSON(body))

			checkLoggedIn(t, r, rec, tc.user, tc.role)
			checkSessionWrite(t, r, unb64(t, options.PublicKey.Challenge), tc.user, tc.flags)
		})
	}
}

// apiOrigin is the configured API origin, which the session's issuer is made from.
func apiOrigin(t *testing.T) config.Origin {
	t.Helper()

	origin, err := config.ParseOrigin(testAPI)
	if err != nil {
		t.Fatalf("origin: %v", err)
	}

	return origin
}

// checkLoggedIn checks the response of a login that was accepted: the body, the
// headers, and the one cookie that carries the session.
func checkLoggedIn(t *testing.T, r *rig, rec *httptest.ResponseRecorder, user, role string) {
	t.Helper()

	if len(r.keys) != 1 {
		t.Fatalf("keys created = %d (response %d %s), want 1", len(r.keys), rec.Code, rec.Body)
	}

	key := r.keys[0]
	expires := r.now.Add(auth.SessionLifetime).Unix()
	wantBody := fmt.Sprintf(`{"userId":%q,"role":%q,"expiresAt":%d}`+"\n", user, role, expires)

	if rec.Code != http.StatusOK || rec.Body.String() != wantBody {
		t.Fatalf("response = %d %q, want 200 %q", rec.Code, rec.Body.String(), wantBody)
	}

	if strings.Contains(rec.Body.String(), key.JWT) {
		t.Error("the session token is in the response body: it belongs in the cookie alone")
	}

	if got := rec.Header().Get("Content-Type"); got != jsonType {
		t.Errorf("Content-Type = %q, want %q", got, jsonType)
	}

	if got := rec.Header().Get("Cache-Control"); got != cacheNoStore {
		t.Errorf("Cache-Control = %q, want %s", got, cacheNoStore)
	}

	if len(r.logged) != 0 {
		t.Errorf("logged %v, want nothing", r.logged)
	}

	checkSessionCookie(t, rec, key)
}

// checkSessionCookie checks the cookie by its attributes and by its exact wire
// form: a session cookie that loses HttpOnly, Secure or the __Host- rules would
// be a vulnerability, not a style choice.
func checkSessionCookie(t *testing.T, rec *httptest.ResponseRecorder, key auth.Key) {
	t.Helper()

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %v, want exactly one", cookies)
	}

	if !isSessionCookie(cookies[0], key) {
		t.Errorf("cookie = %+v, want the __Host- session cookie for the key, HttpOnly, Secure, Lax, to %v",
			cookies[0], key.ExpiresAt)
	}

	wantHeader := "__Host-session=" + key.JWT + "; Path=/; Expires=" + key.ExpiresAt.UTC().Format(http.TimeFormat) +
		"; HttpOnly; Secure; SameSite=Lax"
	if got := rec.Header().Get("Set-Cookie"); got != wantHeader {
		t.Errorf("Set-Cookie = %q, want %q", got, wantHeader)
	}
}

// checkSessionWrite checks what the login did with the store and with key
// creation: one lookup by the credential id, one key for the account, and one
// write carrying exactly what makes the login single use and auditable.
func checkSessionWrite(t *testing.T, r *rig, challengeBytes []byte, user string, flags uint8) {
	t.Helper()

	if len(r.store.looked) != 1 || string(r.store.looked[0]) != string(testCredID()) {
		t.Errorf("credential lookups = %q, want one for the credential id", r.store.looked)
	}

	expires := r.now.Add(auth.SessionLifetime)
	wantCall := sessionCall{issuer: auth.IssuerFor(apiOrigin(t)), userID: user, expires: expires}

	if len(r.sessions) != 1 || r.sessions[0] != wantCall {
		t.Errorf("session creations = %+v, want %+v", r.sessions, wantCall)
	}

	grant := sha256.Sum256(challengeBytes)
	key := r.keys[0]
	want := store.NewSession{
		KeyID:           key.ID.String(),
		CredentialRowID: testCredRowID,
		JWK:             key.JWK,
		ExpiresAt:       expires,
		GrantedFrom:     grant[:],
		Flags:           flags,
		CreatedAt:       r.now,
	}

	if len(r.store.created) != 1 || !reflect.DeepEqual(r.store.created[0], want) {
		t.Errorf("session written = %+v\nwant              %+v", r.store.created, want)
	}
}

// TestFinishChallengeClockBoundaries: the challenge is good from the second it
// is issued until the second before its expiry, and an expiry further ahead
// than one TTL is refused even when its tag is valid. The session starts, and
// lasts two weeks, from the time of the finish.
func TestFinishChallengeClockBoundaries(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// shift moves the clock between begin and finish.
		shift  time.Duration
		status int
	}{
		{"the clock a second behind begin", -time.Second, http.StatusUnauthorized},
		{"the same instant", 0, http.StatusOK},
		{"a second after begin", time.Second, http.StatusOK},
		{"one second before expiry", ttl - time.Second, http.StatusOK},
		{"exactly at expiry", ttl, http.StatusUnauthorized},
		{"one second after expiry", ttl + time.Second, http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			body := r.ceremony()

			r.now = r.now.Add(tc.shift)

			rec := r.finish(body)
			if rec.Code != tc.status {
				t.Fatalf("finish at %v = %d %s, want %d", tc.shift, rec.Code, rec.Body, tc.status)
			}

			if tc.status == http.StatusOK && !r.store.created[0].CreatedAt.Equal(r.now) {
				t.Errorf("session created at %v, want the clock of the finish, %v", r.store.created[0].CreatedAt, r.now)
			}
		})
	}
}

// TestFinishForgedExpiryBoundaries: with a challenge forged for an exact expiry
// (what a leaked key allows), the far-future rule bites at exactly one TTL.
func TestFinishForgedExpiryBoundaries(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		expires time.Duration
		status  int
	}{
		{"expires in one second", time.Second, http.StatusOK},
		{"expires in exactly one TTL", ttl, http.StatusOK},
		{"expires one second beyond a TTL", ttl + time.Second, http.StatusUnauthorized},
		{"expires already", 0, http.StatusUnauthorized},
		{"expired a second ago", -time.Second, http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			a := r.newAuthenticator()
			a.challenge = forgeChallenge(t, r.config().LoginKey, r.now.Add(tc.expires))

			if rec := r.finish(a.respond(t, requestOptions{})); rec.Code != tc.status {
				t.Errorf("finish = %d %s, want %d", rec.Code, rec.Body, tc.status)
			}
		})
	}
}

// TestFinishReplay: the challenge is stateless, so a replay is stopped where the
// session is written. The fake database refuses the second write as a conflict,
// as the real one does for a repeated granted_from, and the client is told what
// it is told for any failed login. Both attempts carry the same grant.
func TestFinishReplay(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	r.store.createErrs = []error{nil, errors.Join(store.ErrConflict, errDB)}

	body := r.ceremony()

	first := r.finish(body)
	second := r.finish(body)

	if first.Code != http.StatusOK {
		t.Fatalf("first finish = %d %s, want 200", first.Code, first.Body)
	}

	wantFailure(t, r, second, http.StatusUnauthorized, bodyInvalidLogin(), codeInvalidLogin)

	if len(r.store.created) != 2 {
		t.Fatalf("session writes = %d, want 2", len(r.store.created))
	}

	got, want := r.store.created[1], r.store.created[0]
	if string(got.GrantedFrom) != string(want.GrantedFrom) || got.KeyID == want.KeyID {
		t.Errorf("replay wrote grant %x for key %s; the first wrote %x for %s: the grant must repeat and the key must not",
			got.GrantedFrom, got.KeyID, want.GrantedFrom, want.KeyID)
	}
}

// TestFinishBodyLimitIsExact: a body of exactly MaxFinishBody bytes is read and
// answered, one byte more is refused before it is parsed, and a real assertion
// takes far less than the limit.
func TestFinishBodyLimitIsExact(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		size   int
		status int
	}{
		{"at the limit", login.MaxFinishBody, http.StatusOK},
		{"one byte over", login.MaxFinishBody + 1, http.StatusRequestEntityTooLarge},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			text := mustJSON(r.ceremony())

			if len(text) > login.MaxFinishBody/4 {
				t.Fatalf("a real finish body is %d bytes, which is more than a quarter of the limit", len(text))
			}

			rec := r.post(login.PathFinish, text+strings.Repeat(" ", tc.size-len(text)))

			if rec.Code != tc.status {
				t.Errorf("status = %d (%s), want %d", rec.Code, rec.Body, tc.status)
			}

			if tc.status == http.StatusRequestEntityTooLarge {
				wantFailure(t, r, rec, tc.status, errorBody("body_too_large", msgBodyTooLarge), "body_too_large")
			}
		})
	}
}

// isSessionCookie reports whether cookie is the session cookie for key, with
// every attribute the __Host- prefix and the threat model require.
func isSessionCookie(cookie *http.Cookie, key auth.Key) bool {
	return cookie.Name == "__Host-session" && cookie.Value == key.JWT &&
		cookie.Path == "/" && cookie.Domain == "" && cookie.MaxAge == 0 &&
		cookie.HttpOnly && cookie.Secure && cookie.SameSite == http.SameSiteLaxMode &&
		cookie.Expires.Unix() == key.ExpiresAt.Unix()
}
