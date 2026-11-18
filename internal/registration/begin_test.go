package registration_test

import (
	cryptorand "crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/challenge"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/registration"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// TestBeginSucceeds pins the whole response of a begin, byte for byte: the
// options a browser is given, and that the challenge is the one the registration
// key makes for this code and name, expiring after the TTL, with the nonce as the
// user handle.
func TestBeginSucceeds(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	rec := r.begin(testName)

	// The same challenge, made independently from the same entropy.
	made, handle, err := challenge.Create(
		r.config().RegistrationKey, counterEntropy(), r.now.Add(5*time.Minute), registrationAD(testCode, testName)...)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}

	want := fmt.Sprintf(`{"publicKey":{"rp":{"id":"example.com","name":"example.com"},`+
		`"user":{"id":%q,"name":"Alice","displayName":"Alice"},"challenge":%q,`+
		`"pubKeyCredParams":[{"type":"public-key","alg":-7}],"timeout":300000,"attestation":"none",`+
		`"authenticatorSelection":{"residentKey":"required","userVerification":"required"}}}`+"\n",
		b64(handle), b64(made))

	if rec.Code != http.StatusOK || rec.Body.String() != want {
		t.Errorf("response = %d %q\nwant       200 %q", rec.Code, rec.Body.String(), want)
	}

	wantQuietSuccess(t, r, rec)

	if want := []redeemCall{{code: testCode, now: r.now}}; !slices.Equal(r.store.redeemed, want) {
		t.Errorf("invitation lookups = %v, want %v", r.store.redeemed, want)
	}

	if len(r.store.created) != 0 || r.ids != 0 {
		t.Errorf("begin created %d accounts and allocated %d ids: nothing may exist before finish",
			len(r.store.created), r.ids)
	}
}

// TestBeginEchoesTheName: the name is shown by the browser's passkey prompt, so
// it must come back exactly as it was given, as both name and displayName, for
// text of any script.
func TestBeginEchoesTheName(t *testing.T) {
	t.Parallel()

	names := []string{
		testName, "Ren\u00e9e M\u00fcller", "\u7530\u4e2d\u502b", "\u0639\u0644\u064a", "Alice \U0001f600",
		"\uac00", strings.Repeat("n", 128), strings.Repeat("\u00e9", 64),
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			rec := r.begin(name)

			var options struct {
				PublicKey struct {
					User struct {
						Name        string `json:"name"`
						DisplayName string `json:"displayName"`
					} `json:"user"`
				} `json:"publicKey"`
			}

			err := json.Unmarshal(rec.Body.Bytes(), &options)
			if err != nil || rec.Code != http.StatusOK {
				t.Fatalf("begin = %d %s (%v)", rec.Code, rec.Body, err)
			}

			if user := options.PublicKey.User; user.Name != name || user.DisplayName != name {
				t.Errorf("user = %+v, want the name %q twice", user, name)
			}
		})
	}
}

// TestBeginChallengesAreUnique: WebAuthn needs fresh entropy per challenge, and
// the nonce (the user handle) is all the entropy a registration challenge has.
// Many begins for the same code and name, at the same instant, never repeat a
// challenge or a user handle.
func TestBeginChallengesAreUnique(t *testing.T) {
	t.Parallel()

	const begins = 200

	// The real entropy source: the fixture's counter wraps after a few begins.
	r := newRig(t)
	r.entropy = cryptorand.Reader
	challenges := map[string]bool{}
	handles := map[string]bool{}

	for range begins {
		options := r.beginOK()
		challenges[options.PublicKey.Challenge] = true
		handles[options.PublicKey.User.ID] = true
	}

	if len(challenges) != begins {
		t.Errorf("%d begins produced %d distinct challenges", begins, len(challenges))
	}

	if len(handles) != begins {
		t.Errorf("%d begins produced %d distinct user handles", begins, len(handles))
	}
}

// TestBeginChallengesRepeatWithoutEntropy proves the uniqueness test above can
// fail: when the entropy source returns the same bytes every time, two begins
// do produce the same challenge and the same handle. A change that made the
// nonce deterministic would therefore be caught by TestBeginChallengesAreUnique
// and not pass for want of a test that can fail.
func TestBeginChallengesRepeatWithoutEntropy(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	r.entropy = readerFunc(func(p []byte) (int, error) { clear(p); return len(p), nil })

	first, second := r.beginOK(), r.beginOK()

	if first.PublicKey.Challenge != second.PublicKey.Challenge || first.PublicKey.User.ID != second.PublicKey.User.ID {
		t.Error("constant entropy produced different challenges, so the uniqueness test proves nothing")
	}
}

// TestBeginChallengeIsBoundAndExpires checks what the issued challenge opens
// for, through the challenge package: this code and name, only this key, and
// only until the TTL.
func TestBeginChallengeIsBoundAndExpires(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	options := r.beginOK()
	issued := unb64(t, options.PublicKey.Challenge)
	handle := unb64(t, options.PublicKey.User.ID)
	cfg := r.config()

	this := registrationAD(testCode, testName)
	cases := []struct {
		name string
		key  []byte
		ad   [][]byte
		at   time.Duration
		ok   bool
	}{
		{"this code and name", cfg.RegistrationKey, this, 0, true},
		{"one second before the TTL", cfg.RegistrationKey, this, ttl - time.Second, true},
		{"exactly the TTL", cfg.RegistrationKey, this, ttl, false},
		{"another code", cfg.RegistrationKey, registrationAD(otherCode, testName), 0, false},
		{"another name", cfg.RegistrationKey, registrationAD(testCode, "Bob"), 0, false},
		{"code and name swapped", cfg.RegistrationKey, registrationAD(testName, testCode), 0, false},
		{"no associated data", cfg.RegistrationKey, nil, 0, false},
		{"the login key", cfg.LoginKey, this, 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			nonce, err := challenge.Open(tc.key, issued, r.now.Add(tc.at), ttl, tc.ad...)

			if (err == nil) != tc.ok {
				t.Fatalf("Open error = %v, want success: %v", err, tc.ok)
			}

			if err == nil && string(nonce) != string(handle) {
				t.Errorf("nonce = %x, want the user handle %x", nonce, handle)
			}
		})
	}
}

// beginFailure is one way a begin is refused.
type beginFailure struct {
	name  string
	setup func(*rig)
	body  string
	// status, response and logged are the answer and the one logged code.
	status   int
	response string
	logged   string
	// reads is how often the invitation was looked up.
	reads int
}

// malformed is a request the decoder or a parser refuses: 400, nothing read.
func malformed(name, body, code, message string) beginFailure {
	return beginFailure{
		name: name, setup: nil, body: body, status: http.StatusBadRequest,
		response: errorBody(code, message), logged: code, reads: 0,
	}
}

// failing is a begin whose invitation lookup ran and then failed in some way.
func failing(name string, setup func(*rig), status int, response, logged string) beginFailure {
	return beginFailure{
		name: name, setup: setup, body: beginJSON(testCode, testName), status: status,
		response: response, logged: logged, reads: 1,
	}
}

// refusedRequests are the begins refused before the database is read.
func refusedRequests() []beginFailure {
	badCode := func(name, body string) beginFailure {
		return malformed(name, body, codeInvalidInvitation, msgInvalidInvitation)
	}
	badName := func(name, body string) beginFailure {
		return malformed(name, body, codeInvalidName, msgInvalidName)
	}

	return []beginFailure{
		malformed("not JSON", "{", "invalid_json", "request body is not valid JSON"),
		malformed("empty body", "", "empty_body", "request body is empty"),
		malformed("unknown member", `{"invitationCode":"a","name":"b","role":"admin"}`,
			"unknown_field", "request body has an unknown field"),
		malformed("wrong type", `{"invitationCode":7,"name":"b"}`, "invalid_field_type", "a field has the wrong type"),
		malformed("repeated member", `{"invitationCode":"a","name":"b","name":"c"}`,
			"duplicate_field", "request body repeats a field"),
		badCode("missing code", `{"name":"b"}`),
		badCode("code outside the alphabet", beginJSON("not a code", testName)),
		badCode("code too long", beginJSON(strings.Repeat("a", 257), testName)),
		badName("missing name", `{"invitationCode":"`+testCode+`"}`),
		badName("name with a bidirectional override", beginJSON(testCode, "Al\u202eice")),
		badName("name too long", beginJSON(testCode, strings.Repeat("n", 129))),
		malformed("name is not UTF-8", `{"invitationCode":"`+testCode+`","name":"Ali`+"\xff"+`ce"}`,
			"invalid_text", "request body has text that is not valid UTF-8"),
		badCode("a bad code is reported before a bad name", beginJSON("", "")),
	}
}

// refusedByTheDatabase are the begins refused at or after the invitation lookup.
func refusedByTheDatabase() []beginFailure {
	return []beginFailure{
		{
			name: "invitation is not redeemable", setup: nil, body: beginJSON("unknown-code", testName),
			status: http.StatusForbidden, response: errorBody(codeInvalidInvitation, msgNotRedeemable),
			logged: codeInvalidInvitation, reads: 1,
		},
		failing("invitation lookup is unavailable",
			func(r *rig) { r.store.redeemErr = classified(apierr.Unavailable, store.CodeInvitationCheckFailed) },
			http.StatusServiceUnavailable, errorBody(store.CodeInvitationCheckFailed, msgUnavailable),
			store.CodeInvitationCheckFailed),
		failing("invitation lookup is a defect",
			func(r *rig) { r.store.redeemErr = classified(apierr.Internal, store.CodeInvitationCheckRejected) },
			http.StatusInternalServerError, bodyInternal, store.CodeInvitationCheckRejected),
		failing("invitation lookup fails without being classified",
			func(r *rig) { r.store.redeemErr = errDB },
			http.StatusInternalServerError, bodyInternal, codeInternal),
		failing("the system cannot make entropy",
			func(r *rig) { r.entropy = brokenEntropy() },
			http.StatusInternalServerError, bodyInternal, "registration_challenge_failed"),
	}
}

// TestBeginFailures: every way a begin is refused, with the exact answer and
// proof of what it did and did not touch.
func TestBeginFailures(t *testing.T) {
	t.Parallel()

	for _, tc := range slices.Concat(refusedRequests(), refusedByTheDatabase()) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)

			if tc.setup != nil {
				tc.setup(r)
			}

			rec := r.post(registration.PathBegin, tc.body)

			wantFailure(t, r, rec, tc.status, tc.response, tc.logged)

			if len(r.store.redeemed) != tc.reads {
				t.Errorf("invitation lookups = %d, want %d", len(r.store.redeemed), tc.reads)
			}

			if len(r.store.created) != 0 {
				t.Errorf("begin created %d accounts: it must write nothing", len(r.store.created))
			}
		})
	}
}

// TestBeginNeedsConfiguration: a deployment without usable configuration is the
// service's fault, so it is 503 with the one code auth gives it, whatever part
// of the configuration is wrong, and nothing is read from the database.
func TestBeginNeedsConfiguration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		settings map[string]string
	}{
		{"no secret", map[string]string{config.SecretHMAC: ""}},
		{"a short secret", map[string]string{config.SecretHMAC: "too-short"}},
		{"no API origin", map[string]string{config.VarAPIOrigin: ""}},
		{"no UI origin", map[string]string{config.VarUIOrigin: ""}},
		{"an origin that is not bare", map[string]string{config.VarUIOrigin: "https://example.com/path"}},
		{"plain http for a real host", map[string]string{config.VarUIOrigin: "http://example.com"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t).with(tc.settings)
			rec := r.begin(testName)

			wantFailure(t, r, rec, http.StatusServiceUnavailable,
				errorBody(codeNotConfigured, msgNotConfigured), codeNotConfigured)

			if len(r.store.redeemed) != 0 {
				t.Error("the database was read for an unconfigured deployment")
			}
		})
	}
}

// TestBeginBodyLimitIsExact: a body of exactly MaxBeginBody bytes is read and
// answered, one byte more is refused before it is parsed.
func TestBeginBodyLimitIsExact(t *testing.T) {
	t.Parallel()

	body := beginJSON(testCode, testName)
	padded := func(size int) string { return body + strings.Repeat(" ", size-len(body)) }

	cases := []struct {
		name   string
		body   string
		status int
	}{
		{"at the limit", padded(registration.MaxBeginBody), http.StatusOK},
		{"one byte over", padded(registration.MaxBeginBody + 1), http.StatusRequestEntityTooLarge},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			rec := r.post(registration.PathBegin, tc.body)

			if rec.Code != tc.status {
				t.Errorf("status = %d, want %d", rec.Code, tc.status)
			}

			if tc.status == http.StatusRequestEntityTooLarge {
				wantFailure(t, r, rec, tc.status, errorBody("body_too_large", msgBodyTooLarge), "body_too_large")
			}
		})
	}
}
