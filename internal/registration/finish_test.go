package registration_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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
	"github.com/susu-dot-dev/authsu/internal/challenge"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/registration"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
	"github.com/susu-dot-dev/authsu/internal/webauthn"
)

const (
	ttl = registration.ChallengeTTL

	// maxInvitationTokenBytes is the length of the only invitation token
	// shape there is: the prefix and the body.
	maxInvitationTokenBytes = len("susu_inv_") + secret.BodyLen

	userID1 = "00000000-0000-7000-8000-000000000001"
	rowID2  = "00000000-0000-7000-8000-000000000002"
	// firstRunID3 is the id offered for the first-run invitation: the third id
	// finish asks for, after the user's and the passkey's.
	firstRunID3 = "00000000-0000-7000-8000-000000000003"
	// orgID4 is the id offered for the organization of the account, the fourth
	// id finish asks for, for the case that its invitation names none.
	orgID4 = "00000000-0000-7000-8000-000000000004"
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

// madeFor is a challenge the registration key made for the test's own choice of
// expiry (relative to the clock), token and name, as a leaked key would let an
// attacker make.
func madeFor(expires time.Duration, code, name, email string) func(*testing.T, *rig, []byte) []byte {
	return func(t *testing.T, r *rig, _ []byte) []byte {
		t.Helper()

		return forgeChallenge(t, r.config().RegistrationKey, r.now.Add(expires), registrationAD(code, name, email)...)
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

	status int
	body   string
	logged string
	// cause is an error the logged failure must wrap: the reason, which is in
	// the log and never in the response.
	cause error
	// redeems and creates are the store calls the finish itself made.
	redeems, creates int
}

// refusal is a case answered with a client-visible code and message.
func refusal(name string, status int, code, message string) finishCase {
	return finishCase{
		name: name, raw: "", authn: nil, challenge: nil, edit: nil, rewrite: nil, between: nil, cause: nil,
		status: status, body: errorBody(code, message), logged: code, redeems: 0, creates: 0,
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

// badPasskey is a 400 invalid_credential.
func badPasskey(name string) finishCase {
	return badRequest(name, codeInvalidCredential, msgInvalidCredential)
}

// badChallenge is a 400 invalid_challenge.
func badChallenge(name string) finishCase {
	return badRequest(name, codeInvalidChallenge, msgInvalidChallenge)
}

func (c finishCase) rawBody(text string) finishCase { c.raw = text; return c }

func (c finishCase) withAuthenticator(f func(*authenticator)) finishCase { c.authn = f; return c }

func (c finishCase) echoing(f func(*testing.T, *rig, []byte) []byte) finishCase {
	c.challenge = f
	return c
}

func (c finishCase) rewriting(f func(string) string) finishCase { c.rewrite = f; return c }

func (c finishCase) editing(f func(jsonBody)) finishCase { c.edit = f; return c }

// answeredBy changes the answer a case expects.
func (c finishCase) answeredBy(status int, code, message string) finishCase {
	c.status, c.body, c.logged = status, errorBody(code, message), code

	return c
}

func (c finishCase) because(cause error) finishCase { c.cause = cause; return c }

func (c finishCase) afterBegin(f func(*rig)) finishCase { c.between = f; return c }

// afterReads says how many invitation reads and account writes the finish made.
func (c finishCase) afterReads(redeems, creates int) finishCase {
	c.redeems, c.creates = redeems, creates

	return c
}

// shapeFailures are requests the decoder or a parser refuses.
func shapeFailures() []finishCase {
	cases := []finishCase{
		badRequest("not JSON", "invalid_json", "request body is not valid JSON").rawBody("{"),
		badRequest("empty body", "empty_body", "request body is empty").rawBody(" "),
		badRequest("unknown member", "unknown_field", "request body has an unknown field").
			editing(func(b jsonBody) { b.set("credential.extra", 1) }),
		badRequest("a member of the wrong type", "invalid_field_type", "a field has the wrong type").
			editing(func(b jsonBody) { b.set("credential.id", 7) }),
		badRequest("a member the client has no say in", "unknown_field", "request body has an unknown field").
			editing(func(b jsonBody) { b.set("role", "admin") }),
		badRequest("a repeated member", "duplicate_field", "request body repeats a field").
			rewriting(func(text string) string {
				return strings.Replace(text, `"name":"`+testName+`"`, `"name":"`+testName+`","name":"Mallory"`, 1)
			}),
		badRequest("a name that is not UTF-8", "invalid_text", "request body has text that is not valid UTF-8").
			rewriting(func(text string) string { return strings.Replace(text, testName, "Ali\xffce", 1) }),
		badRequest("invalid name", codeInvalidName, msgInvalidName).
			editing(func(b jsonBody) { b.set("name", "") }),
		badRequest("missing email", codeInvalidEmail, msgInvalidEmail).
			editing(func(b jsonBody) { b.remove("email") }),
		badRequest("invalid email", codeInvalidEmail, msgInvalidEmail).
			editing(func(b jsonBody) { b.set("email", "not an address") }),
		badRequest("an email that is not UTF-8", "invalid_text", "request body has text that is not valid UTF-8").
			rewriting(func(text string) string { return strings.Replace(text, testEmail, "a\xff@example.com", 1) }),
		refusal("no configuration", http.StatusServiceUnavailable, codeNotConfigured, msgNotConfigured).
			afterBegin(func(r *rig) { r.with(map[string]string{config.SecretHMAC: ""}) }),
	}

	// Every kind of malformed token: refused before the passkey is looked at
	// and before the store is read.
	tokens := invalidInvitationTokens()
	malformedTokens := make([]finishCase, len(tokens))

	for i, bad := range tokens {
		malformedTokens[i] = badRequest("invalid token: "+bad.name, codeInvalidInvitation, msgInvalidInvitation).
			editing(func(b jsonBody) { b.set("invitationCode", bad.value) })
	}

	return slices.Concat(cases, malformedTokens)
}

// envelopeFailures are credentials whose envelope is wrong.
func envelopeFailures() []finishCase {
	return []finishCase{
		badPasskey("credential type missing").editing(func(b jsonBody) { b.remove("credential.type") }),
		badPasskey("credential type is not public-key").
			editing(func(b jsonBody) { b.set("credential.type", "password") }),
		badPasskey("unsolicited client extension results").editing(func(b jsonBody) {
			b.set("credential.clientExtensionResults", jsonBody{"credProps": jsonBody{"rk": true}})
		}),
	}
}

// passkeyFailures are registrations the verifier refuses.
func passkeyFailures() []finishCase {
	return []finishCase{
		badPasskey("another origin").withAuthenticator(func(a *authenticator) { a.origin = "https://evil.example" }),
		badPasskey("another relying party").withAuthenticator(func(a *authenticator) { a.rpID = "evil.example" }),
		badPasskey("a login ceremony").withAuthenticator(func(a *authenticator) { a.clientDataType = "webauthn.get" }),
		badPasskey("user verification missing").withAuthenticator(func(a *authenticator) { a.flags = 0x01 | 0x40 }),
		badPasskey("a format that is not none").withAuthenticator(func(a *authenticator) { a.format = "packed" }),
		badPasskey("rawId is not the credential's id").
			editing(func(b jsonBody) { b.set("credential.rawId", b64([]byte("another-credential-id"))) }),
		badPasskey("attestation object is not CBOR").
			editing(func(b jsonBody) { b.set("credential.response.attestationObject", "AAAA") }),
		badPasskey("client data is not base64url").
			editing(func(b jsonBody) { b.set("credential.response.clientDataJSON", "not base64!") }),
	}
}

// transportFailures are transport lists too odd to be hints. Each is refused as
// a bad passkey, whole: a list is never truncated.
func transportFailures() []finishCase {
	refused := []struct {
		name       string
		transports []string
	}{
		{"an entry that is too long", []string{strings.Repeat("x", 33)}},
		{"an empty entry", []string{""}},
		{"a NUL", []string{transportUSB + "\x00"}},
		{"a control character", []string{transportUSB + "\t"}},
		{"non-ASCII", []string{"us\u00e9"}},
		{"far too long an entry", []string{strings.Repeat("x", 20000)}},
	}

	cases := make([]finishCase, 0, len(refused))

	for _, tc := range refused {
		cases = append(cases, badPasskey("transports with "+tc.name).
			editing(func(b jsonBody) { b.set("credential.response.transports", tc.transports) }))
	}

	return cases
}

// transportCountFailures are lists over the count limit. The decoder refuses a
// list over it before it allocates it, and a list too long to fit the body cap
// never reaches the decoder at all. Repeats count as sent.
func transportCountFailures() []finishCase {
	refused := []struct {
		name       string
		transports []string
		tooBig     bool
	}{
		{"one over the limit", numberedTransports(101), false},
		{"one over, all repeats", slices.Repeat([]string{transportUSB}, 101), false},
		{"one over, repeats merge below", slices.Concat(numberedTransports(51), numberedTransports(50)), false},
		{"far over the limit", slices.Repeat([]string{"a"}, 100000), true},
		{"far over, would merge to one", slices.Repeat([]string{transportInternal}, 20000), true},
	}

	cases := make([]finishCase, 0, len(refused))

	for _, tc := range refused {
		refusal := badRequest("transports: "+tc.name, "too_many_items", "request body has an array with too many items")

		if tc.tooBig {
			refusal = refusal.answeredBy(http.StatusRequestEntityTooLarge, "body_too_large", msgBodyTooLarge)
		}

		cases = append(cases, refusal.editing(func(b jsonBody) { b.set("credential.response.transports", tc.transports) }))
	}

	return cases
}

// numberedTransports returns n distinct transports in ascending order.
func numberedTransports(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("t%03d", i)
	}

	return out
}

// publicKeyFailures are passkeys whose public key is not a canonical ES256
// P-256 COSE_Key. Registration is where a key is validated, so each is a 400
// invalid_credential with no account written (TestFinishFailures checks that
// the account write was never reached), and login can rely on every stored key
// parsing.
func publicKeyFailures() []finishCase {
	key := func(change func(cose []byte) []byte) func(*authenticator) {
		return func(a *authenticator) { a.cose = change(slices.Clone(a.cose)) }
	}

	return []finishCase{
		badPasskey("the key is empty").withAuthenticator(key(func([]byte) []byte { return nil })),
		badPasskey("the key is not CBOR").withAuthenticator(key(func([]byte) []byte { return []byte("not a key") })),
		badPasskey("the key is truncated").withAuthenticator(key(func(c []byte) []byte { return c[:len(c)/2] })),
		badPasskey("the key is missing its last byte").withAuthenticator(key(func(c []byte) []byte { return c[:len(c)-1] })),
		badPasskey("the key's y coordinate is changed, so the point is not on the curve").
			withAuthenticator(key(func(c []byte) []byte { c[len(c)-1] ^= 0xff; return c })),
		badPasskey("the key's x coordinate is changed, so the point is not on the curve").
			withAuthenticator(key(func(c []byte) []byte { c[len(c)-36] ^= 0xff; return c })),
	}
}

// challengeFailures are valid passkeys answering a challenge that is forged,
// altered, stale, or made for another ceremony.
func challengeFailures() []finishCase {
	return []finishCase{
		badChallenge("version byte flipped").echoing(flipByte(offVersion)),
		badChallenge("expiry byte flipped").echoing(flipByte(offExpiry + 7)),
		badChallenge("nonce byte flipped").echoing(flipByte(offNonce)),
		badChallenge("tag byte flipped").echoing(flipByte(offTag + 31)),
		badChallenge("challenge truncated").echoing(
			func(_ *testing.T, _ *rig, c []byte) []byte { return c[:challenge.Len-1] }),
		badChallenge("challenge extended").echoing(
			func(_ *testing.T, _ *rig, c []byte) []byte { return append(slices.Clone(c), 0) }),
		badChallenge("challenge is a few bytes").echoing(
			func(*testing.T, *rig, []byte) []byte { return []byte{1, 2, 3} }),
		badChallenge("challenge is not ours at all").echoing(
			func(*testing.T, *rig, []byte) []byte { return make([]byte, challenge.Len) }),
		badChallenge("made by the login key").echoing(func(t *testing.T, r *rig, _ []byte) []byte {
			t.Helper()

			return forgeChallenge(t, r.config().LoginKey, r.now.Add(ttl), registrationAD(testCode, testName, testEmail)...)
		}),
		badChallenge("made for another token").echoing(madeFor(ttl, otherCode, testName, testEmail)),
		badChallenge("made for another name").echoing(madeFor(ttl, testCode, "Bob", testEmail)),
		badChallenge("made for another email").echoing(madeFor(ttl, testCode, testName, "bob@example.com")),
		badChallenge("made without an email").echoing(
			func(t *testing.T, r *rig, _ []byte) []byte {
				t.Helper()

				return forgeChallenge(t, r.config().RegistrationKey, r.now.Add(ttl), []byte(testCode), []byte(testName))
			}),
		badChallenge("finished with another token than it began with").
			editing(func(b jsonBody) { b.set("invitationCode", otherCode) }),
		badChallenge("finished with another name than it began with").
			editing(func(b jsonBody) { b.set("name", "Bob") }),
		badChallenge("finished with another email than it began with").
			editing(func(b jsonBody) { b.set("email", "bob@example.com") }),
		badChallenge("the secret changed since begin").
			afterBegin(func(r *rig) { r.with(map[string]string{config.SecretHMAC: strings.Repeat("z", 40)}) }),
		badChallenge("expired exactly at its expiry").afterBegin(func(r *rig) { r.now = r.now.Add(ttl) }),
		badChallenge("expired long ago").afterBegin(func(r *rig) { r.now = r.now.Add(24 * time.Hour) }),
		badChallenge("signed with a far-future expiry").echoing(madeFor(ttl+time.Second, testCode, testName, testEmail)),
		badChallenge("signed to last for years").echoing(madeFor(10*365*24*time.Hour, testCode, testName, testEmail)),
		badChallenge("the clock stepped back, so the expiry is further away than a TTL").
			afterBegin(func(r *rig) { r.now = r.now.Add(-time.Second) }),
	}
}

// invitationFailures are refusals at the invitation read.
func invitationFailures() []finishCase {
	read := func(c finishCase) finishCase { return c.afterReads(1, 0) }

	return []finishCase{
		read(refusal("the invitation became unredeemable since begin", http.StatusForbidden,
			codeInvalidInvitation, msgNotRedeemable).
			afterBegin(func(r *rig) { delete(r.store.invitations, testCode) })),
		read(refusal("the invitation lookup is unavailable", http.StatusServiceUnavailable,
			store.CodeInvitationCheckFailed, msgUnavailable).because(errDB).
			afterBegin(func(r *rig) { r.store.redeemErr = classified(apierr.Unavailable, store.CodeInvitationCheckFailed) })),
		read(defective("the invitation lookup is a defect", store.CodeInvitationCheckRejected).because(errDB).
			afterBegin(func(r *rig) { r.store.redeemErr = classified(apierr.Internal, store.CodeInvitationCheckRejected) })),
		read(defective("the invitation lookup fails without being classified", codeInternal).because(errDB).
			afterBegin(func(r *rig) { r.store.redeemErr = errDB })),
	}
}

// roleFailures are invitations whose type grants no role: the type is matched
// exactly, and an unknown one is refused rather than given a default.
func roleFailures() []finishCase {
	types := []string{"mystery", "", "FIRST_RUN", "first_run "}
	cases := make([]finishCase, 0, len(types))

	for _, invitationType := range types {
		cases = append(cases, defective(fmt.Sprintf("an invitation of type %q grants no role", invitationType),
			"registration_failed").afterReads(1, 0).
			afterBegin(func(r *rig) { r.store.invitations[testCode] = invitationType }))
	}

	return cases
}

// writeFailures are refusals at the account write.
func writeFailures() []finishCase {
	written := func(c finishCase, outcome error) finishCase {
		return c.because(errDB).afterReads(1, 1).afterBegin(func(r *rig) { r.store.createErrs = []error{outcome} })
	}

	return []finishCase{
		written(refusal("the account is refused as a conflict", http.StatusConflict, codeAcceptFailed, msgConflict),
			errors.Join(store.ErrConflict, errDB)),
		written(refusal("the account write is unavailable", http.StatusServiceUnavailable,
			store.CodeRegistrationAcceptFailed, msgUnavailable),
			classified(apierr.Unavailable, store.CodeRegistrationAcceptFailed)),
		written(defective("the account write is a defect", store.CodeRegistrationAcceptRejected),
			classified(apierr.Internal, store.CodeRegistrationAcceptRejected)),
		written(defective("the account write fails without being classified", codeInternal), errDB),
	}
}

// allFailures is every way a finish is refused.
func allFailures() []finishCase {
	return slices.Concat(
		shapeFailures(), envelopeFailures(), passkeyFailures(), publicKeyFailures(), transportFailures(),
		transportCountFailures(), challengeFailures(), invitationFailures(), roleFailures(), writeFailures())
}

// request builds the finish request the case sends, after begin has run.
func (c finishCase) request(t *testing.T, r *rig) string {
	t.Helper()

	a := newAuthenticator(t)

	if c.authn != nil {
		c.authn(&a)
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
// database is refused before it.
func TestFinishFailures(t *testing.T) {
	t.Parallel()

	for _, tc := range allFailures() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			text := tc.request(t, r)
			before := len(r.store.redeemed)
			rec := r.post(registration.PathFinish, text)

			wantFailure(t, r, rec, tc.status, tc.body, tc.logged)

			if tc.cause != nil && !errors.Is(r.logged[0], tc.cause) {
				t.Errorf("logged error %v does not wrap the cause %v", r.logged[0], tc.cause)
			}

			if got := len(r.store.redeemed) - before; got != tc.redeems {
				t.Errorf("invitation lookups = %d, want %d", got, tc.redeems)
			}

			if len(r.store.created) != tc.creates {
				t.Errorf("account writes = %d, want %d", len(r.store.created), tc.creates)
			}
		})
	}
}

// success is a finish that is accepted, and what must then be written.
type success struct {
	name  string
	authn func(*authenticator)
	edit  func(authenticator, jsonBody)
	// flags, aaguid and transports are what the store must be given.
	flags      uint8
	aaguid     string
	transports []string
}

// deviceBound is the default registration: UP | UV, one transport.
func deviceBound(name string) success {
	return success{
		name: name, authn: nil, edit: nil, flags: 0x05, aaguid: zeroAAGUID, transports: []string{transportInternal},
	}
}

func (c success) withAuthenticator(f func(*authenticator)) success { c.authn = f; return c }

func (c success) editing(f func(authenticator, jsonBody)) success { c.edit = f; return c }

func (c success) storing(flags uint8, aaguid string, transports []string) success {
	c.flags, c.aaguid, c.transports = flags, aaguid, transports

	return c
}

func successes() []success {
	many := make([]string, 100)
	for i := range many {
		many[i] = fmt.Sprintf("t%03d", i)
	}

	model := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	return []success{
		deviceBound("a device-bound passkey"),
		deviceBound("a synced passkey keeps its backup bits").
			withAuthenticator(func(a *authenticator) { a.flags = 0x01 | 0x04 | 0x08 | 0x10 | 0x40 }).
			storing(0x1d, zeroAAGUID, []string{transportInternal}),
		deviceBound("the model of the authenticator").
			withAuthenticator(func(a *authenticator) { a.aaguid = model }).
			storing(0x05, "00112233-4455-6677-8899-aabbccddeeff", []string{transportInternal}),
		deviceBound("transports are stored sorted and without repeats").
			withAuthenticator(func(a *authenticator) {
				a.transports = []string{transportUSB, transportInternal, transportUSB, "hybrid"}
			}).
			storing(0x05, zeroAAGUID, []string{"hybrid", transportInternal, transportUSB}),
		deviceBound("no transports reported").
			withAuthenticator(func(a *authenticator) { a.transports = nil }).
			storing(0x05, zeroAAGUID, nil),
		deviceBound("as many transports as are allowed").
			withAuthenticator(func(a *authenticator) { a.transports = many }).
			storing(0x05, zeroAAGUID, many),
		deviceBound("everything PublicKeyCredential.toJSON() produces").
			editing(func(a authenticator, b jsonBody) { a.asToJSONWrites(b) }),
		deviceBound("without the optional publicKey").editing(func(a authenticator, b jsonBody) {
			a.asToJSONWrites(b)
			b.remove("credential.response.publicKey")
		}),
		deviceBound("without the optional authenticatorAttachment").editing(func(a authenticator, b jsonBody) {
			a.asToJSONWrites(b)
			b.remove("credential.authenticatorAttachment")
		}),
		deviceBound("copies in the request that disagree with the attestation object are ignored").
			editing(func(_ authenticator, b jsonBody) {
				b.set("credential.response.authenticatorData", "ignored")
				b.set("credential.response.publicKey", "ignored")
				b.set("credential.response.publicKeyAlgorithm", -257)
			}),
		deviceBound("an unknown transport is kept").
			withAuthenticator(func(a *authenticator) { a.transports = []string{"carrier-pigeon", transportInternal} }).
			storing(0x05, zeroAAGUID, []string{"carrier-pigeon", transportInternal}),
		deviceBound("the longest transport is kept").
			withAuthenticator(func(a *authenticator) { a.transports = []string{"a", strings.Repeat("z", 32)} }).
			storing(0x05, zeroAAGUID, []string{"a", strings.Repeat("z", 32)}),
	}
}

// checkTokenHash holds that the store looks the invitation up by the hash of the
// whole token as the client sent it.
func checkTokenHash(t *testing.T, r *rig) {
	t.Helper()

	if want := secret.Hash(testCode); len(r.store.created) != 1 ||
		!bytes.Equal(r.store.created[0].Token.Hash(), want[:]) {
		t.Errorf("account token hash = %x, want secret.Hash(%q)", r.store.created[0].Token.Hash(), testCode)
	}
}

// TestFinishSucceeds pins the whole of a successful finish: the response, and
// exactly what is written, for each shape of authenticator.
func TestFinishSucceeds(t *testing.T) {
	t.Parallel()

	for _, tc := range successes() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			a := newAuthenticator(t)

			if tc.authn != nil {
				tc.authn(&a)
			}

			options := r.beginOK()
			body := a.respond(t, options)

			if tc.edit != nil {
				tc.edit(a, body)
			}

			before := len(r.store.redeemed)
			rec := r.post(registration.PathFinish, mustJSON(body))

			checkCreatedResponse(t, r, rec)

			if len(r.store.redeemed)-before != 1 || r.store.redeemed[before] != wantRedeem(testCode, r.now) {
				t.Errorf("invitation lookups at finish = %v, want one for the token at now", r.store.redeemed[before:])
			}

			wantAccount := store.NewAccount{
				UserID:          userID1,
				UserHandle:      unb64(t, options.PublicKey.User.ID),
				Role:            "admin",
				OrgID:           orgID4,
				OrgName:         mustOrgName(t, testName+"'s org"),
				Name:            mustName(t, testName),
				Email:           mustEmail(t, testEmail),
				Token:           mustToken(t, testCode),
				InvitationType:  firstRun,
				CredentialRowID: rowID2,
				CredentialID:    a.credID,
				PublicKey:       a.cose,
				Flags:           tc.flags,
				AAGUID:          tc.aaguid,
				Transports:      tc.transports,
				CreatedAt:       r.now,
				// No first-run secret is configured in this rig, but what a
				// write would need to create the invitation is always offered.
				FirstRun:          nil,
				FirstRunID:        firstRunID3,
				FirstRunLabel:     registration.FirstRunLabel,
				FirstRunExpiresAt: r.now.Add(input.ExpiryHorizon),
			}

			if len(r.store.created) != 1 || !sameAccount(r.store.created[0], wantAccount) {
				t.Errorf("account written = %+v\nwant              %+v", r.store.created, wantAccount)
			}

			checkTokenHash(t, r)
		})
	}
}

// checkCreatedResponse checks the whole of a 201: body, headers, and that
// registering issues no session and logs nothing.
func checkCreatedResponse(t *testing.T, r *rig, rec *httptest.ResponseRecorder) {
	t.Helper()

	wantBody := `{"userId":"` + userID1 + `","role":"admin"}` + "\n"
	if rec.Code != http.StatusCreated || rec.Body.String() != wantBody {
		t.Fatalf("response = %d %q, want 201 %q", rec.Code, rec.Body.String(), wantBody)
	}

	wantQuietSuccess(t, r, rec)
}

// TestFinishNamesTheAccountsOrganizationAfterIt: the organization the account is
// given is named exactly as the account is, whatever the name, so the parser of
// an organization's name never refuses what the parser of an account's name
// accepted (the store is never handed a name its column would refuse): the
// longest and the most escaped names, and names in every script.
func TestFinishNamesTheAccountsOrganizationAfterIt(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		testName,
		"A",
		strings.Repeat("a", input.MaxAccountNameBytes),
		strings.Repeat("<", input.MaxAccountNameBytes),
		strings.Repeat("\u00e9", input.MaxAccountNameBytes/2),
		strings.Repeat("\u65e5", input.MaxAccountNameBytes/3),
		"\U0001F600 emoji",
		"  padded  ",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			a := newAuthenticator(t)

			rec := r.begin(name)
			if rec.Code != http.StatusOK {
				t.Fatalf("begin = %d %s, want 200", rec.Code, rec.Body)
			}

			var options creationOptions

			err := json.Unmarshal(rec.Body.Bytes(), &options)
			if err != nil {
				t.Fatalf("begin body: %v", err)
			}

			body := a.respond(t, options)
			body["name"] = name

			rec = r.finish(body)
			if rec.Code != http.StatusCreated {
				t.Fatalf("finish = %d %s, want 201", rec.Code, rec.Body)
			}

			if len(r.store.created) != 1 {
				t.Fatalf("accounts written = %d, want 1", len(r.store.created))
			}

			got := r.store.created[0]
			if got.OrgID != orgID4 || got.OrgName.String() != name+"'s org" || got.Name.String() != name {
				t.Errorf("organization %q named %q for the account %q, want %q named %q",
					got.OrgID, got.OrgName.String(), got.Name.String(), orgID4, name+"'s org")
			}
		})
	}
}

// sameAccount compares accounts, treating no transports and an empty list as the
// same (the store writes both as []).
func sameAccount(got, want store.NewAccount) bool {
	if len(got.Transports) == 0 && len(want.Transports) == 0 {
		got.Transports, want.Transports = nil, nil
	}

	return reflect.DeepEqual(got, want)
}

// TestFinishChallengeClockBoundaries: the challenge is good from the second it
// is issued until the second before its expiry, and an expiry further ahead
// than one TTL is refused even when its tag is valid.
func TestFinishChallengeClockBoundaries(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// shift moves the clock between begin and finish.
		shift  time.Duration
		status int
	}{
		{"the clock a second behind begin", -time.Second, http.StatusBadRequest},
		{"the same instant", 0, http.StatusCreated},
		{"a second after begin", time.Second, http.StatusCreated},
		{"one second before expiry", ttl - time.Second, http.StatusCreated},
		{"exactly at expiry", ttl, http.StatusBadRequest},
		{"one second after expiry", ttl + time.Second, http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			body := r.ceremony(newAuthenticator(t))

			r.now = r.now.Add(tc.shift)

			if rec := r.finish(body); rec.Code != tc.status {
				t.Errorf("finish at %v = %d %s, want %d", tc.shift, rec.Code, rec.Body, tc.status)
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
		{"expires in one second", time.Second, http.StatusCreated},
		{"expires in exactly one TTL", ttl, http.StatusCreated},
		{"expires one second beyond a TTL", ttl + time.Second, http.StatusBadRequest},
		{"expires already", 0, http.StatusBadRequest},
		{"expired a second ago", -time.Second, http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			a := newAuthenticator(t)
			a.challenge = forgeChallenge(t, r.config().RegistrationKey, r.now.Add(tc.expires),
				registrationAD(testCode, testName, testEmail)...)

			body := a.respond(t, creationOptions{})

			if rec := r.finish(body); rec.Code != tc.status {
				t.Errorf("finish = %d %s, want %d", rec.Code, rec.Body, tc.status)
			}
		})
	}
}

// TestFinishReplay: the challenge is stateless, so a replay is stopped where the
// account is written. The fake database refuses the second write as a conflict,
// as the real one does for a repeated user handle or credential id, and the
// client is told so.
func TestFinishReplay(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	r.store.createErrs = []error{nil, errors.Join(store.ErrConflict, errDB)}

	body := r.ceremony(newAuthenticator(t))

	first := r.finish(body)
	second := r.finish(body)

	if first.Code != http.StatusCreated {
		t.Fatalf("first finish = %d %s, want 201", first.Code, first.Body)
	}

	wantFailure(t, r, second, http.StatusConflict, errorBody("registration_accept_failed", msgConflict),
		"registration_accept_failed")

	if len(r.store.created) != 2 {
		t.Fatalf("account writes = %d, want 2", len(r.store.created))
	}

	// The replay is the same registration: same handle, credential and token.
	got, want := r.store.created[1], r.store.created[0]
	if string(got.UserHandle) != string(want.UserHandle) || string(got.CredentialID) != string(want.CredentialID) ||
		got.Token != want.Token {
		t.Errorf("replayed write differs from the first: %+v vs %+v", got, want)
	}
}

// TestFinishBodyLimitIsExact: a body of exactly MaxFinishBody bytes is read and
// answered, one byte more is refused before it is parsed, and a request
// legitimately takes far less than the limit.
func TestFinishBodyLimitIsExact(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		size int
		// status is the answer: 201 when the whole body was read.
		status int
	}{
		{"at the limit", registration.MaxFinishBody, http.StatusCreated},
		{"one byte over", registration.MaxFinishBody + 1, http.StatusRequestEntityTooLarge},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			body := r.ceremony(newAuthenticator(t))
			text := mustJSON(body)

			if len(text) > registration.MaxFinishBody/4 {
				t.Fatalf("a real finish body is %d bytes, which is more than a quarter of the limit", len(text))
			}

			rec := r.post(registration.PathFinish, text+strings.Repeat(" ", tc.size-len(text)))

			if rec.Code != tc.status {
				t.Errorf("status = %d (%s), want %d", rec.Code, rec.Body, tc.status)
			}
		})
	}
}

// TestFinishBodyCapFitsEveryLegitimateRequest: MaxFinishBody must be larger than
// a request whose every member is at its own limit, or the cap would refuse a
// request the members would accept; and it must stay far below the default cap,
// which is what bounds the parsing work.
func TestFinishBodyCapFitsEveryLegitimateRequest(t *testing.T) {
	t.Parallel()

	b64Len := func(n int) int { return base64.RawURLEncoding.EncodedLen(n) }

	// Worst case JSON: every member at its limit, each byte of the name and
	// token escaped as \u00XX (six bytes), and a full list of full-length
	// transports.
	biggest := b64Len(1023)*2 + // id, rawId
		b64Len(webauthn.MaxClientDataJSON) +
		b64Len(webauthn.MaxAttestationObject) +
		b64Len(webauthn.MaxAttestationObject) + // the authenticatorData and publicKey copies
		(input.MaxAccountNameBytes+input.MaxEmailBytes+maxInvitationTokenBytes)*6 +
		webauthn.MaxTransports*(32+3) +
		1024 // member names, braces, quotes, commas

	if biggest > registration.MaxFinishBody {
		t.Errorf("a maximal finish request is about %d bytes, over MaxFinishBody = %d", biggest, registration.MaxFinishBody)
	}

	if registration.MaxFinishBody >= httpapi.DefaultMaxBody/8 {
		t.Errorf("MaxFinishBody = %d is not far below the default cap %d", registration.MaxFinishBody, httpapi.DefaultMaxBody)
	}

	if registration.MaxBeginBody <= (input.MaxAccountNameBytes+input.MaxEmailBytes+maxInvitationTokenBytes)*6 {
		t.Errorf("MaxBeginBody = %d cannot hold a maximal begin request", registration.MaxBeginBody)
	}
}
