package auth_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

var errEntropy = errors.New("the entropy source is broken")

// failingReader fails every read.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errEntropy }

// counting records how many ids were taken.
type counting struct{ taken int }

func (c *counting) newID() string {
	c.taken++

	return "00000000-0000-7000-8000-00000000c0de"
}

// counted is a reader that counts the bytes it was asked for.
type counted struct {
	reader io.Reader
	asked  int
}

func (c *counted) Read(p []byte) (int, error) {
	c.asked += len(p)

	return c.reader.Read(p) //nolint:wrapcheck // a test double passes the wrapped reader's answer through
}

// firstBytes is the 32 bytes 0, 1, ... 31, the entropy of the known vectors.
func firstBytes() []byte {
	body := make([]byte, secret.BodyBytes)
	for i := range body {
		body[i] = byte(i)
	}

	return body
}

// Known vectors for firstBytes: the token and the hash of the whole string.
const (
	vectorSession     = "susu_ses_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	vectorSessionHash = "2dfa62136d8cac5aa3b8ef60572d06305e12a72a1c03206448cda367d32a1063"
	vectorKey         = "susu_key_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	vectorKeyHash     = "7b2c1f86aaee50b871fe0c2f49dd213517a39a4b21650ad96505f539a5d2ffe4"

	vectorCode        = "susu_code_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	vectorCodeHash    = "52b3f355dab5b9eb02b79ff0ee228a3357e8fb427cac5eaffa7090fc2d5cd7cb"
	vectorRefresh     = "susu_rt_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	vectorRefreshHash = "a6665c25701f99df7b5523351a23bff6573281004593a4f0ec087079c0e368ee"
	vectorAccess      = "susu_at_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	vectorAccessHash  = "c5dea4b0493dfc178c3dc663fa5b1f6da56b245c8f7b4bb4d4632cdefe9651ea"
)

func TestConstants(t *testing.T) {
	t.Parallel()

	// Kinds are the strings the database stores; the store's own constants are
	// the same values, so a credential is read under the kind it was written with.
	for name, pair := range map[string][2]string{
		"session": {auth.KindSession, store.KindSession},
		"api_key": {auth.KindAPIKey, store.KindAPIKey},
	} {
		if pair[0] != name || pair[1] != name {
			t.Errorf("kind %q = auth %q, store %q", name, pair[0], pair[1])
		}
	}

	checkLifetimes(t)

	if auth.AgentKeyLifetime > auth.MaxAgentKeyLifetime {
		t.Error("the default agent key lifetime is longer than the most IssueAPIKey allows")
	}

	if auth.MaxAgentKeyLifetime > auth.MaxUserKeyLifetime {
		t.Error("the user's key lifetimes are not within, and above, an agent's")
	}

	if auth.CodeLifetime >= auth.AccessTokenLifetime || auth.AccessTokenLifetime >= auth.RefreshTokenLifetime {
		t.Error("an OAuth code must be the shortest-lived secret and a refresh token the longest")
	}

	if auth.CookieName != "__Host-session" {
		t.Errorf("CookieName = %q", auth.CookieName)
	}
}

// checkLifetimes pins every lifetime auth sets: they are policy, so a change is
// a deliberate edit of this table.
func checkLifetimes(t *testing.T) {
	t.Helper()

	for _, lifetime := range []struct {
		name      string
		got, want time.Duration
	}{
		{"SessionLifetime", auth.SessionLifetime, 14 * 24 * time.Hour},
		{"AgentKeyLifetime", auth.AgentKeyLifetime, 90 * 24 * time.Hour},
		{"MaxAgentKeyLifetime", auth.MaxAgentKeyLifetime, 90 * 24 * time.Hour},
		{"MaxUserKeyLifetime", auth.MaxUserKeyLifetime, 365 * 24 * time.Hour},
		{"CodeLifetime", auth.CodeLifetime, time.Minute},
		{"RefreshTokenLifetime", auth.RefreshTokenLifetime, 30 * 24 * time.Hour},
		{"AccessTokenLifetime", auth.AccessTokenLifetime, 15 * time.Minute},
	} {
		if lifetime.got != lifetime.want {
			t.Errorf("%s = %v, want %v", lifetime.name, lifetime.got, lifetime.want)
		}
	}
}

// issueCase is one way to issue a secret, with what must be true of it.
type issueCase struct {
	name string
	// issue issues from r with newID at now.
	issue func(r io.Reader, newID func() string, now time.Time) (auth.Issued, error)
	// lifetime is how long the secret must live.
	lifetime time.Duration
	// tag is the kind of token it must be.
	tag secret.Tag
	// vector and vectorHash are the token and hash for firstBytes.
	vector, vectorHash string
	// idless is true for a secret that is stored under an id it already has,
	// so no id is taken and Issued.ID is empty.
	idless bool
}

// keyCase is an API key issued with a lifetime.
func keyCase(
	name string, key func(time.Duration) func(io.Reader, func() string, time.Time) (auth.Issued, error),
	lifetime time.Duration,
) issueCase {
	return issueCase{name, key(lifetime), lifetime, secret.TagAPIKey, vectorKey, vectorKeyHash, false}
}

func issueCases() []issueCase {
	key := func(lifetime time.Duration) func(io.Reader, func() string, time.Time) (auth.Issued, error) {
		return func(r io.Reader, newID func() string, now time.Time) (auth.Issued, error) {
			return auth.IssueAPIKey(r, newID, now, lifetime)
		}
	}

	userKey := func(lifetime time.Duration) func(io.Reader, func() string, time.Time) (auth.Issued, error) {
		return func(r io.Reader, newID func() string, now time.Time) (auth.Issued, error) {
			return auth.IssueUserAPIKey(r, newID, now, lifetime)
		}
	}

	return []issueCase{
		{"a session", auth.IssueSession, auth.SessionLifetime, secret.TagSession, vectorSession, vectorSessionHash, false},
		keyCase("a key of the agent lifetime", key, auth.AgentKeyLifetime),
		keyCase("a key of the longest lifetime", key, auth.MaxAgentKeyLifetime),
		keyCase("a key of one nanosecond", key, time.Nanosecond),
		keyCase("a key of a day", key, 24*time.Hour),
		keyCase("a user's key of the longest lifetime", userKey, auth.MaxUserKeyLifetime),
		{
			"an OAuth code", auth.IssueGrantCode, auth.CodeLifetime, secret.TagOAuthCode,
			vectorCode, vectorCodeHash, false,
		},
		{
			"an OAuth refresh token", func(r io.Reader, _ func() string, now time.Time) (auth.Issued, error) {
				return auth.IssueRefreshToken(r, now)
			},
			auth.RefreshTokenLifetime, secret.TagOAuthRefresh, vectorRefresh, vectorRefreshHash, true,
		},
		{
			"an OAuth access token", auth.IssueAccessToken, auth.AccessTokenLifetime, secret.TagOAuthAccess,
			vectorAccess, vectorAccessHash, false,
		},
	}
}

// TestIssue: what is issued is the token the client is shown, its hash, the id
// the caller chose and when it ends, and it is the exact shape the parser of its
// kind accepts, and no other parser does.
func TestIssue(t *testing.T) {
	t.Parallel()

	now := time.Date(2031, time.February, 3, 4, 5, 6, 0, time.UTC)

	for _, test := range issueCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ids := &counting{taken: 0}

			issued, err := test.issue(bytes.NewReader(firstBytes()), ids.newID, now)
			if err != nil {
				t.Fatalf("issue: %v", err)
			}

			if issued.Token != test.vector {
				t.Errorf("Token = %q, want %q", issued.Token, test.vector)
			}

			if hex.EncodeToString(issued.Hash) != test.vectorHash {
				t.Errorf("Hash = %x, want %s", issued.Hash, test.vectorHash)
			}

			want := secret.Hash(issued.Token)
			if !bytes.Equal(issued.Hash, want[:]) || len(issued.Hash) != sha256.Size {
				t.Errorf("Hash = %x, want secret.Hash(Token) = %x", issued.Hash, want)
			}

			checkIssuedID(t, issued, ids, test.idless)

			if !issued.ExpiresAt.Equal(now.Add(test.lifetime)) {
				t.Errorf("ExpiresAt = %v, want %v", issued.ExpiresAt, now.Add(test.lifetime))
			}

			checkParsesAs(t, issued.Token, test.tag)
		})
	}
}

// checkIssuedID checks the id of an issued secret: the one id from newID, or
// none at all for a secret that keeps the id it already has.
func checkIssuedID(t *testing.T, issued auth.Issued, ids *counting, idless bool) {
	t.Helper()

	wantID, wantTaken := "00000000-0000-7000-8000-00000000c0de", 1
	if idless {
		wantID, wantTaken = "", 0
	}

	if issued.ID != wantID || ids.taken != wantTaken {
		t.Errorf("ID = %q after %d id(s), want %q after %d", issued.ID, ids.taken, wantID, wantTaken)
	}
}

// checkParsesAs checks that token is accepted by the parser of tag, unchanged,
// with the hash the store would look it up by, and by no other parser.
func checkParsesAs(t *testing.T, token string, tag secret.Tag) {
	t.Helper()

	sessionToken, sessionErr := input.ParseSessionToken(token)
	keyToken, keyErr := input.ParseAPIKeyToken(token)
	_, invitationErr := input.ParseInvitationToken(token)

	accepted := map[secret.Tag]bool{
		secret.TagSession: sessionErr == nil, secret.TagAPIKey: keyErr == nil, secret.TagInvitation: invitationErr == nil,
	}

	for each, got := range accepted {
		if want := each == tag; got != want {
			t.Errorf("parser of %q accepted = %v, want %v", each, got, want)
		}
	}

	want := secret.Hash(token)

	var hash []byte

	switch tag {
	case secret.TagSession:
		hash = sessionToken.Hash()
	case secret.TagAPIKey:
		hash = keyToken.Hash()
	case secret.TagInvitation, secret.TagOAuthCode, secret.TagOAuthRefresh, secret.TagOAuthAccess:
		// No parser of these is in the table above: that every parser there
		// refuses them is the check. Their own parsers are internal/input's.
		return
	}

	if !bytes.Equal(hash, want[:]) {
		t.Errorf("the parser's hash = %x, want secret.Hash(token) = %x", hash, want)
	}
}

// TestIssuedTokensAreDistinct: with the real shape of entropy, two issues give
// two tokens and two hashes, and a session and a key from the same bytes are
// two unrelated secrets.
func TestIssuedTokensAreDistinct(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	seen := map[string]bool{}

	for range 50 {
		for _, issued := range []auth.Issued{r.issueSession(), r.issueKey()} {
			if seen[issued.Token] || seen[string(issued.Hash)] {
				t.Fatalf("%q was issued twice", issued.Token)
			}

			seen[issued.Token], seen[string(issued.Hash)] = true, true
		}
	}

	same := bytes.NewReader(firstBytes())

	session, err := auth.IssueSession(same, r.newID, r.now)
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	same.Reset(firstBytes())

	key, err := auth.IssueAPIKey(same, r.newID, r.now, time.Hour)
	if err != nil {
		t.Fatalf("IssueAPIKey: %v", err)
	}

	if bytes.Equal(session.Hash, key.Hash) || session.ID == key.ID {
		t.Error("a session and a key from the same random bytes are not distinct secrets")
	}

	if strings.TrimPrefix(session.Token, secret.Prefix(secret.TagSession)) !=
		strings.TrimPrefix(key.Token, secret.Prefix(secret.TagAPIKey)) {
		t.Error("the same bytes should give the same body under both tags")
	}
}

// TestIssueFailsWithTheEntropy: a reader that fails or ends early is an error,
// and nothing is issued: not a token, not a hash, and no id is taken.
func TestIssueFailsWithTheEntropy(t *testing.T) {
	t.Parallel()

	readers := map[string]func() io.Reader{
		"a failing reader":    func() io.Reader { return failingReader{} },
		"an empty reader":     func() io.Reader { return bytes.NewReader(nil) },
		"31 bytes":            func() io.Reader { return bytes.NewReader(firstBytes()[:secret.BodyBytes-1]) },
		"a reader of 1 byte":  func() io.Reader { return bytes.NewReader([]byte{1}) },
		"an exhausted reader": func() io.Reader { return io.LimitReader(bytes.NewReader(firstBytes()), 0) },
	}

	for _, test := range issueCases() {
		for name, newReader := range readers {
			t.Run(test.name+" from "+name, func(t *testing.T) {
				t.Parallel()

				ids := &counting{taken: 0}

				issued, err := test.issue(newReader(), ids.newID, time.Now())
				if err == nil {
					t.Fatal("no error from entropy that could not be read")
				}

				if issued.Token != "" || issued.ID != "" || issued.Hash != nil || !issued.ExpiresAt.IsZero() || ids.taken != 0 {
					t.Errorf("issued = %+v after %d id(s) on failure, want nothing", issued, ids.taken)
				}
			})
		}
	}

	_, err := auth.IssueSession(failingReader{}, (&counting{taken: 0}).newID, time.Now())
	if !errors.Is(err, errEntropy) {
		t.Errorf("error = %v, want the reader's error wrapped", err)
	}
}

// TestIssueTakesExactlyTheBodyOnce: a token is 32 bytes of entropy and no more,
// so a shared source is not drained.
func TestIssueTakesExactlyTheBodyOnce(t *testing.T) {
	t.Parallel()

	reader := &counted{reader: bytes.NewReader(bytes.Repeat([]byte{7}, 1000)), asked: 0}

	_, err := auth.IssueSession(reader, (&counting{taken: 0}).newID, time.Now())
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	if reader.asked != secret.BodyBytes {
		t.Errorf("asked the reader for %d bytes, want %d", reader.asked, secret.BodyBytes)
	}
}

// keyIssuer is one of the two ways to issue an API key, with the longest
// lifetime it accepts: an agent's key is capped at 90 days, a user's at a year.
type keyIssuer struct {
	name    string
	issue   func(r io.Reader, newID func() string, now time.Time, lifetime time.Duration) (auth.Issued, error)
	longest time.Duration
}

func keyIssuers() []keyIssuer {
	return []keyIssuer{
		{"an agent's key", auth.IssueAPIKey, auth.MaxAgentKeyLifetime},
		{"a user's key", auth.IssueUserAPIKey, auth.MaxUserKeyLifetime},
	}
}

// TestIssueAPIKeyLifetimeBounds: a key lives for a positive time that is at
// most its issuer's longest, to the nanosecond, and anything else is refused
// before any entropy is read or id taken. The same lifetimes are asked of both
// issuers, so the one that is allowed a year and the one that is not differ in
// exactly that.
func TestIssueAPIKeyLifetimeBounds(t *testing.T) {
	t.Parallel()

	now := time.Date(2031, time.February, 3, 4, 5, 6, 0, time.UTC)

	for _, issuer := range keyIssuers() {
		for _, test := range lifetimeCases(issuer.longest) {
			t.Run(issuer.name+"/"+test.name, func(t *testing.T) {
				t.Parallel()

				checkLifetime(t, issuer, test.lifetime, now)
			})
		}
	}
}

// lifetimeCase is a lifetime asked of an issuer.
type lifetimeCase struct {
	name     string
	lifetime time.Duration
}

// lifetimeCases are the lifetimes asked of an issuer whose longest is longest:
// the edges of its range and of the other issuer's.
func lifetimeCases(longest time.Duration) []lifetimeCase {
	return []lifetimeCase{
		{"zero", 0},
		{"minus one nanosecond", -time.Nanosecond},
		{"minus a second", -time.Second},
		{"minus the longest", -longest},
		{"the smallest negative", math.MinInt64},
		{"one nanosecond", time.Nanosecond},
		{"one second", time.Second},
		{"a day", 24 * time.Hour},
		{"the agent lifetime", auth.AgentKeyLifetime},
		{"one nanosecond under the longest", longest - time.Nanosecond},
		{"exactly the longest", longest},
		{"one nanosecond over the longest", longest + time.Nanosecond},
		{"one second over the longest", longest + time.Second},
		{"the other issuer's longest", auth.MaxUserKeyLifetime},
		{"a year", 365 * 24 * time.Hour},
		{"a year and a day", 366 * 24 * time.Hour},
		{"the largest duration", math.MaxInt64},
	}
}

// checkLifetime asks issuer for a key of lifetime: it is issued, ending at now
// plus the lifetime, when the lifetime is positive and at most the issuer's
// longest, and otherwise refused with ErrKeyLifetime before any entropy is read
// or id taken.
func checkLifetime(t *testing.T, issuer keyIssuer, lifetime time.Duration, now time.Time) {
	t.Helper()

	reader := &counted{reader: bytes.NewReader(firstBytes()), asked: 0}
	ids := &counting{taken: 0}

	issued, err := issuer.issue(reader, ids.newID, now, lifetime)

	if lifetime > 0 && lifetime <= issuer.longest {
		if err != nil || !issued.ExpiresAt.Equal(now.Add(lifetime)) {
			t.Errorf("issue = %+v, %v, want a key ending at %v", issued, err, now.Add(lifetime))
		}

		return
	}

	if !errors.Is(err, auth.ErrKeyLifetime) {
		t.Errorf("error = %v, want ErrKeyLifetime", err)
	}

	if issued.Token != "" || reader.asked != 0 || ids.taken != 0 {
		t.Errorf("issued = %+v, read %d bytes, took %d id(s): a refusal does nothing", issued, reader.asked, ids.taken)
	}
}

// TestSessionScope: a session is every scope by bundle, and callers cannot
// change what the next one gets.
func TestSessionScope(t *testing.T) {
	t.Parallel()

	got := auth.SessionScope()
	if !slices.Equal([]string(got), []string{scope.DefaultSession}) {
		t.Errorf("SessionScope = %v, want [%s]", got, scope.DefaultSession)
	}

	got[0] = "tampered"

	if again := auth.SessionScope(); again[0] != scope.DefaultSession {
		t.Errorf("SessionScope shares its storage: %v", again)
	}

	if auth.SessionScope().Expand().Len() != len(scope.Scopes()) {
		t.Error("a session does not have every scope")
	}
}

// cookieCase is a cookie and what must be true of it.
type cookieCase struct {
	cookie     *http.Cookie
	wantValue  string
	wantMaxAge int
	wantExpiry time.Time
	wantInHdr  []string
}

func setCookieCases() map[string]cookieCase {
	expires := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	issued := auth.Issued{ID: itemID, Token: vectorSession, Hash: nil, ExpiresAt: expires}

	return map[string]cookieCase{
		"issued": {
			auth.SessionCookie(issued), vectorSession, 0, expires,
			[]string{
				"__Host-session=" + vectorSession, "Path=/", "Expires=Wed, 02 Jan 2030 03:04:05 GMT",
				"HttpOnly", "Secure", "SameSite=Lax",
			},
		},
		"cleared": {
			auth.ClearSessionCookie(), "", -1, time.Time{},
			[]string{"__Host-session=;", "Path=/", "Max-Age=0", "HttpOnly", "Secure", "SameSite=Lax"},
		},
	}
}

// TestSessionCookie: the attributes are the whole point, so each is asserted,
// on the cookie and as the browser receives it.
func TestSessionCookie(t *testing.T) {
	t.Parallel()

	for name, tt := range setCookieCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tt.checkIdentity(t)
			tt.checkAttributes(t)
			tt.checkHeader(t)
		})
	}
}

// checkIdentity checks the cookie's name, value and lifetime.
func (tt cookieCase) checkIdentity(t *testing.T) {
	t.Helper()

	c := tt.cookie

	if c.Name != auth.CookieName || c.Value != tt.wantValue || c.MaxAge != tt.wantMaxAge {
		t.Errorf("cookie = %+v", c)
	}

	if !c.Expires.Equal(tt.wantExpiry) {
		t.Errorf("Expires = %v, want %v", c.Expires, tt.wantExpiry)
	}
}

// checkAttributes checks what __Host- requires, what keeps the cookie to this
// host, and what keeps it from script and from other sites.
func (tt cookieCase) checkAttributes(t *testing.T) {
	t.Helper()

	c := tt.cookie

	if !c.Secure || c.Path != "/" || c.Domain != "" {
		t.Errorf("Secure = %v, Path = %q, Domain = %q: want Secure, /, none", c.Secure, c.Path, c.Domain)
	}

	if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("HttpOnly = %v, SameSite = %v: want HttpOnly and Lax", c.HttpOnly, c.SameSite)
	}
}

// checkHeader checks the Set-Cookie line.
func (tt cookieCase) checkHeader(t *testing.T) {
	t.Helper()

	header := tt.cookie.String()

	for _, part := range tt.wantInHdr {
		if !strings.Contains(header, part) {
			t.Errorf("Set-Cookie %q does not contain %q", header, part)
		}
	}

	if strings.Contains(header, "Domain") {
		t.Errorf("Set-Cookie %q has a Domain", header)
	}
}

// TestSessionCookieAsABrowserParsesIt: the attributes survive serialisation.
func TestSessionCookieAsABrowserParsesIt(t *testing.T) {
	t.Parallel()

	for name, tt := range setCookieCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			parsed, err := http.ParseSetCookie(tt.cookie.String())
			if err != nil {
				t.Fatalf("ParseSetCookie: %v", err)
			}

			if parsed.Name != auth.CookieName || !parsed.Secure || !parsed.HttpOnly ||
				parsed.Path != "/" || parsed.SameSite != http.SameSiteLaxMode || parsed.Domain != "" {
				t.Errorf("parsed = %+v", parsed)
			}
		})
	}
}

// TestIssuedSessionIsWhatTheBoundaryAccepts is the seam between what login sets
// as a cookie and what the boundary reads back: a session issued, set as the
// cookie and returned by the browser is accepted by the boundary as the same
// token, and resolved under the session kind with its own hash's token.
func TestIssuedSessionIsWhatTheBoundaryAccepts(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	issued := r.sessionFor(roleMember)

	set := auth.SessionCookie(issued)

	rec := r.get(pathMe, requestCookie(set.Name, set.Value))
	if rec.Code != http.StatusOK || len(r.creds.calls) != 1 || r.creds.calls[0].token != issued.Token {
		t.Errorf("status = %d, store reads = %+v, want one read of the issued token", rec.Code, r.creds.calls)
	}

	key := r.apiKey(bearerSpec{scope: list()})

	rec = r.serveWith(r.standardRoutes(), pathMe, []string{bearer(key)}, nil)
	if rec.Code != http.StatusOK || r.handled[1].Principal.SecretID != key.ID {
		t.Errorf("an issued key was not accepted as a bearer token: %d", rec.Code)
	}
}

// TestIssuedSecretsFitTheSchema is the seam between what auth issues and the
// secrets table that stores it: the hash is the width of the column's CHECK,
// read from the migration's text so that a changed limit is noticed here and not
// by a failing insert in production.
func TestIssuedSecretsFitTheSchema(t *testing.T) {
	t.Parallel()

	hashLength := migrationLimits(t, `length\(hash\) = (\d+)`)[0]
	idLength := migrationLimits(t, `length\(id\) = (\d+)`)[0]
	r := newRig(t)

	for _, issued := range []auth.Issued{r.issueSession(), r.issueKey()} {
		if len(issued.Hash) != hashLength {
			t.Errorf("the hash is %d bytes; the schema requires %d", len(issued.Hash), hashLength)
		}

		if len(issued.ID) != idLength {
			t.Errorf("the id %q is %d characters; the schema requires %d", issued.ID, len(issued.ID), idLength)
		}
	}

	if got := len(auth.LoginGrant([]byte("x"))); got != migrationLimits(t, `length\(granted_from\) = (\d+)`)[0] {
		t.Errorf("a login grant is %d bytes, which is not what sessions.granted_from requires", got)
	}
}

// TestLoginGrant: the grant is the SHA-256 of the challenge, so a replay of the
// same challenge collides in the unique column.
func TestLoginGrant(t *testing.T) {
	t.Parallel()

	tests := map[string][]byte{
		"a challenge": []byte("0123456789abcdef0123456789abcdef"),
		"empty input": {},
		"nil":         nil,
		"one byte":    {0},
		"binary":      {0, 255, 1, 254, 2, 253},
		"long":        []byte(strings.Repeat("x", 1000)),
	}

	for name, challenge := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			want := sha256.Sum256(challenge)

			got := auth.LoginGrant(challenge)
			if string(got) != string(want[:]) || len(got) != 32 {
				t.Errorf("LoginGrant = %x, want %x", got, want)
			}

			if string(auth.LoginGrant(challenge)) != string(got) {
				t.Error("not deterministic: a replay would not collide")
			}
		})
	}

	if string(auth.LoginGrant([]byte("a"))) == string(auth.LoginGrant([]byte("b"))) {
		t.Error("different challenges have the same grant")
	}
}
