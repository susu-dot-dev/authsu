package login_test

import (
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/challenge"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/login"
)

const ttl = login.ChallengeTTL

// TestBeginSucceeds pins the whole response of a begin, byte for byte: the
// options a browser is given, and that the challenge is the one the login key
// makes, expiring after the TTL. Begin reads nothing from the database.
func TestBeginSucceeds(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	rec := r.post(login.PathBegin, "{}")

	// The same challenge, made independently from the same entropy.
	made, _, err := challenge.Create(r.config().LoginKey, counterEntropy(), r.now.Add(ttl))
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}

	want := fmt.Sprintf(`{"publicKey":{"challenge":%q,"rpId":"example.com","timeout":300000,`+
		`"userVerification":"required","allowCredentials":[]}}`+"\n", b64(made))

	if rec.Code != http.StatusOK || rec.Body.String() != want {
		t.Errorf("response = %d %q\nwant       200 %q", rec.Code, rec.Body.String(), want)
	}

	if got := rec.Header().Get("Content-Type"); got != jsonType {
		t.Errorf("Content-Type = %q, want %q", got, jsonType)
	}

	if got := rec.Header().Get("Cache-Control"); got != cacheNoStore {
		t.Errorf("Cache-Control = %q, want %s", got, cacheNoStore)
	}

	if len(rec.Result().Cookies()) != 0 || len(r.logged) != 0 {
		t.Errorf("cookies %v, logged %v: want none", rec.Result().Cookies(), r.logged)
	}

	if len(r.store.looked)+len(r.store.created)+len(r.issues) != 0 {
		t.Error("begin touched the store or created a key: it must read and write nothing")
	}
}

// TestBeginReadsNothingFromTheRequest: login has no input before the ceremony, so
// whatever the body holds, even nothing, is not read.
func TestBeginReadsNothingFromTheRequest(t *testing.T) {
	t.Parallel()

	for _, body := range []string{"", "{}", `{"credential":"x"}`, "not json at all"} {
		t.Run(fmt.Sprintf("%q", body), func(t *testing.T) {
			t.Parallel()

			rec := newRig(t).post(login.PathBegin, body)

			if rec.Code != http.StatusOK {
				t.Errorf("status = %d (%s), want 200", rec.Code, rec.Body)
			}
		})
	}
}

// TestBeginChallengesAreUnique: WebAuthn needs fresh entropy per challenge, and
// the nonce is all the entropy a login challenge has. Many begins at the same
// instant never repeat a challenge.
func TestBeginChallengesAreUnique(t *testing.T) {
	t.Parallel()

	const begins = 200

	// The real entropy source: the fixture's counter wraps after a few begins.
	r := newRig(t)
	r.entropy = cryptorand.Reader
	challenges := map[string]bool{}

	for range begins {
		challenges[r.beginOK().PublicKey.Challenge] = true
	}

	if len(challenges) != begins {
		t.Errorf("%d begins produced %d distinct challenges", begins, len(challenges))
	}
}

// TestBeginChallengesRepeatWithoutEntropy proves the uniqueness test above can
// fail: with an entropy source that returns the same bytes every time, two
// begins do produce the same challenge.
func TestBeginChallengesRepeatWithoutEntropy(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	r.entropy = readerFunc(func(p []byte) (int, error) { clear(p); return len(p), nil })

	if first, second := r.beginOK(), r.beginOK(); first.PublicKey.Challenge != second.PublicKey.Challenge {
		t.Error("constant entropy produced different challenges, so the uniqueness test proves nothing")
	}
}

// TestBeginChallengeOpensForLoginOnly checks what the issued challenge opens
// for, through the challenge package: only the login key, no associated data,
// and only until the TTL.
func TestBeginChallengeOpensForLoginOnly(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	issued := unb64(t, r.beginOK().PublicKey.Challenge)
	cfg := r.config()

	cases := []struct {
		name string
		key  []byte
		ad   [][]byte
		at   time.Duration
		ok   bool
	}{
		{"the login key", cfg.LoginKey, nil, 0, true},
		{"one second before the TTL", cfg.LoginKey, nil, ttl - time.Second, true},
		{"exactly the TTL", cfg.LoginKey, nil, ttl, false},
		{"the registration key", cfg.RegistrationKey, nil, 0, false},
		{"associated data it was not made for", cfg.LoginKey, [][]byte{[]byte("x")}, 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := challenge.Open(tc.key, issued, r.now.Add(tc.at), ttl, tc.ad...)

			if (err == nil) != tc.ok {
				t.Errorf("Open error = %v, want success: %v", err, tc.ok)
			}
		})
	}
}

// TestBeginFailures: every way a begin is refused, with the exact answer.
func TestBeginFailures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		settings map[string]string
		entropy  bool
		status   int
		response string
		logged   string
	}{
		{"no secret", map[string]string{config.SecretHMAC: ""}, false,
			http.StatusServiceUnavailable, errorBody(codeNotConfigured, msgNotConfigured), codeNotConfigured},
		{"a short secret", map[string]string{config.SecretHMAC: "too-short"}, false,
			http.StatusServiceUnavailable, errorBody(codeNotConfigured, msgNotConfigured), codeNotConfigured},
		{"no API origin", map[string]string{config.VarAPIOrigin: ""}, false,
			http.StatusServiceUnavailable, errorBody(codeNotConfigured, msgNotConfigured), codeNotConfigured},
		{"no UI origin", map[string]string{config.VarUIOrigin: ""}, false,
			http.StatusServiceUnavailable, errorBody(codeNotConfigured, msgNotConfigured), codeNotConfigured},
		{"an origin that is not bare", map[string]string{config.VarUIOrigin: "https://example.com/path"}, false,
			http.StatusServiceUnavailable, errorBody(codeNotConfigured, msgNotConfigured), codeNotConfigured},
		{"the system cannot make entropy", nil, true,
			http.StatusInternalServerError, bodyInternal, "login_challenge_failed"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t).with(tc.settings)

			if tc.entropy {
				r.entropy = brokenEntropy()
			}

			rec := r.post(login.PathBegin, "{}")

			wantFailure(t, r, rec, tc.status, tc.response, tc.logged)

			if len(r.store.looked)+len(r.store.created)+len(r.issues) != 0 {
				t.Error("a begin that failed touched the store or created a key")
			}
		})
	}
}

// TestBeginBodyLimitIsExact: a body of exactly MaxBeginBody bytes is read and
// answered, one byte more is refused before it is read.
func TestBeginBodyLimitIsExact(t *testing.T) {
	t.Parallel()

	padded := func(size int) string { return "{}" + strings.Repeat(" ", size-2) }

	cases := []struct {
		name   string
		body   string
		status int
	}{
		{"at the limit", padded(login.MaxBeginBody), http.StatusOK},
		{"one byte over", padded(login.MaxBeginBody + 1), http.StatusRequestEntityTooLarge},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			rec := r.post(login.PathBegin, tc.body)

			if rec.Code != tc.status {
				t.Errorf("status = %d, want %d", rec.Code, tc.status)
			}

			if tc.status == http.StatusRequestEntityTooLarge {
				wantFailure(t, r, rec, tc.status, errorBody("body_too_large", msgBodyTooLarge), "body_too_large")
			}
		})
	}
}

// TestBeginKeepsEntropyFailureForTheLog: the failure is the service's own, so a
// client sees only the opaque answer, and its cause is for the log.
func TestBeginKeepsEntropyFailureForTheLog(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	r.entropy = brokenEntropy()

	rec := r.post(login.PathBegin, "{}")

	if strings.Contains(rec.Body.String(), errEntropy.Error()) {
		t.Errorf("the cause reached the client: %s", rec.Body)
	}

	if len(r.logged) != 1 || r.logged[0].Kind != apierr.Internal || !errors.Is(r.logged[0], errEntropy) {
		t.Errorf("logged = %v, want one Internal error wrapping the cause", r.logged)
	}
}
