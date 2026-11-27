package auth_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// outcome is everything a request to the boundary may do, so each case states
// all of it: the response, what was logged, whether the route ran, and how
// often, and of which kind, the credential store was read.
type outcome struct {
	status int
	// body is the exact response body.
	body string
	// code is the code of the one logged error; "" means nothing was logged.
	code string
	// cause is an error the log entry must wrap.
	cause error
	// logContains is text that must be in the logged chain: the reason, which
	// is in the log and never in the response.
	logContains string
	// handled is whether the route's Handle ran.
	handled bool
	// storeCalls is how many times the credential store was read.
	storeCalls int
	// kind is the kind of credential every read asks for.
	kind string
}

// viaKey is the outcome for a request whose credential is an API key.
func (o outcome) viaKey() outcome {
	o.kind = auth.KindAPIKey

	return o
}

// viaGrant is the outcome for a request whose credential is an OAuth access
// token.
func (o outcome) viaGrant() outcome {
	o.kind = auth.KindGrant

	return o
}

// carried is what a request presents: Authorization header values and cookies.
type carried struct {
	headers []string
	cookies []*http.Cookie
}

// carryFn builds what a request presents after the rig exists, so it may store
// credentials and change them.
type carryFn func(*rig) carried

// cookieFn builds a request's cookies after the rig exists.
type cookieFn func(*rig) []*http.Cookie

// boundaryCase is one GET to the standard routes.
type boundaryCase struct {
	name   string
	target string
	// env overrides deployment settings; "" removes one.
	env       map[string]string
	cancelled bool
	carry     carryFn
	want      outcome
}

// rowOf is a case that presents what carry builds.
func rowOf(name, target string, carry carryFn, want outcome) boundaryCase {
	return boundaryCase{name: name, target: target, env: nil, cancelled: false, carry: carry, want: want}
}

// row is a case that presents only cookies.
func row(name, target string, cookies cookieFn, want outcome) boundaryCase {
	return rowOf(name, target, cookiesOnly(cookies), want)
}

// cookiesOnly presents cookies and nothing else.
func cookiesOnly(cookies cookieFn) carryFn {
	return func(r *rig) carried {
		if cookies == nil {
			return carried{headers: nil, cookies: nil}
		}

		return carried{headers: nil, cookies: cookies(r)}
	}
}

// headersOnly presents Authorization header values and nothing else.
func headersOnly(headers func(*rig) []string) carryFn {
	return func(r *rig) carried { return carried{headers: headers(r), cookies: nil} }
}

// header presents one Authorization header value.
func header(value func(*rig) string) carryFn {
	return headersOnly(func(r *rig) []string { return []string{value(r)} })
}

// literalHeader presents one fixed Authorization header value.
func literalHeader(value string) carryFn {
	return header(func(*rig) string { return value })
}

// inDeployment is the case in a deployment with these settings.
func (c boundaryCase) inDeployment(settings map[string]string) boundaryCase {
	c.env = settings

	return c
}

// gone is the case for a client that has already gone away.
func (c boundaryCase) gone() boundaryCase {
	c.cancelled = true

	return c
}

// chainText is the text of err and everything it wraps.
func chainText(err error) string {
	var parts []string

	for ; err != nil; err = errors.Unwrap(err) {
		parts = append(parts, err.Error())
	}

	return strings.Join(parts, " | ")
}

func (c boundaryCase) run(t *testing.T) {
	t.Helper()

	r := newRig(t).with(c.env)

	presented := c.presented(r)

	rec := r.serveCtx(r.standardRoutes(), c.target, presented, c.cancelled)

	c.checkResponse(t, r, rec)

	if got := len(r.handled); got != boolToInt(c.want.handled) {
		t.Errorf("route ran %d times, want ran = %v", got, c.want.handled)
	}

	if len(r.creds.calls) != c.want.storeCalls {
		t.Errorf("store read %d times, want %d: %v", len(r.creds.calls), c.want.storeCalls, r.creds.calls)
	}

	// Whatever a request did, the store is only ever asked about the kind the
	// carrier accepts, at the injected clock.
	for _, call := range r.creds.calls {
		if call.kind != c.want.kind || !call.now.Equal(r.now) {
			t.Errorf("store read = %+v, want kind %q at %v", call, c.want.kind, r.now)
		}
	}
}

// presented is what the case sends, built on r.
func (c boundaryCase) presented(r *rig) carried {
	if c.carry == nil {
		return carried{headers: nil, cookies: nil}
	}

	return c.carry(r)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}

	return 0
}

// checkResponse checks the status, the body and the log.
func (c boundaryCase) checkResponse(t *testing.T, r *rig, rec *httptest.ResponseRecorder) {
	t.Helper()

	want := c.want

	if want.code == "" {
		if rec.Code != want.status || rec.Body.String() != want.body || len(r.logged) != 0 {
			t.Errorf("response = %d %q (logged %v), want %d %q and nothing logged",
				rec.Code, rec.Body, r.logged, want.status, want.body)
		}

		return
	}

	wantFailure(t, r, rec, want.status, want.body, want.code, want.cause)

	if text := chainText(r.logged[0]); !strings.Contains(text, want.logContains) {
		t.Errorf("logged chain %q does not contain %q", text, want.logContains)
	}
}

// valid is a stored session of an administrator.
func valid(r *rig) []*http.Cookie { return []*http.Cookie{sessionCookie(r.session())} }

// validKey presents a stored API key with no scopes as a bearer token.
func validKey(r *rig) carried {
	return carried{headers: []string{bearer(r.apiKey(bearerSpec{scope: list()}))}, cookies: nil}
}

// sessionValue is a request carrying the session cookie with value.
func sessionValue(value string) cookieFn {
	return func(*rig) []*http.Cookie { return []*http.Cookie{requestCookie(auth.CookieName, value)} }
}

// many is the cookies of each of parts, in order.
func many(parts ...cookieFn) cookieFn {
	return func(r *rig) []*http.Cookie {
		all := make([]*http.Cookie, 0, len(parts))

		for _, part := range parts {
			all = append(all, part(r)...)
		}

		return all
	}
}

// twice is one set of cookies sent two times.
func twice(part cookieFn) cookieFn {
	return func(r *rig) []*http.Cookie {
		once := part(r)

		return append(once, once...)
	}
}

// named is a valid session sent under another cookie name.
func named(name string) cookieFn {
	return func(r *rig) []*http.Cookie { return []*http.Cookie{requestCookie(name, r.session().Token)} }
}

// plain is one cookie with this name and value.
func plain(name, value string) cookieFn {
	return func(*rig) []*http.Cookie { return []*http.Cookie{requestCookie(name, value)} }
}

// afterStoring makes a stored session, lets prep change the world, and sends
// the session's cookie.
func afterStoring(prep func(r *rig, issued auth.Issued)) cookieFn {
	return func(r *rig) []*http.Cookie {
		issued := r.session()
		prep(r, issued)

		return []*http.Cookie{sessionCookie(issued)}
	}
}

// revoked is a session the store no longer reports: revoked, expired, or its
// account revoked, which the store reports alike.
func revoked(r *rig, issued auth.Issued) { r.unstore(issued) }

// failing is a session whose store read fails with err.
func failing(err error) cookieFn {
	return afterStoring(func(r *rig, _ auth.Issued) { r.creds.err = err })
}

// failingKey is an API key whose store read fails with err.
func failingKey(err error) carryFn {
	return func(r *rig) carried {
		presented := validKey(r)
		r.creds.err = err

		return presented
	}
}

// withRole is a stored session whose account has role.
func withRole(role string) cookieFn {
	return func(r *rig) []*http.Cookie { return []*http.Cookie{sessionCookie(r.sessionFor(role))} }
}

// unauthenticated is the outcome of every refusal of a credential, after
// storeCalls reads of a session.
func unauthenticated(storeCalls int, logContains string) outcome {
	return outcome{
		status: http.StatusUnauthorized, body: bodyUnauthenticated, code: auth.CodeUnauthenticated,
		cause: nil, logContains: logContains, handled: false, storeCalls: storeCalls, kind: auth.KindSession,
	}
}

// ok is the outcome of a request that reached the route.
func ok(storeCalls int) outcome {
	return outcome{
		status: http.StatusOK, body: bodyOK, code: "", cause: nil, logContains: "", handled: true,
		storeCalls: storeCalls, kind: auth.KindSession,
	}
}

// unavailable is the outcome of a failure to resolve, after one read, that says
// nothing about the token.
func unavailable(cause error, logContains string) outcome {
	return outcome{
		status: http.StatusServiceUnavailable, body: bodyUnavailable, code: store.CodeSessionVerifyFailed,
		cause: cause, logContains: logContains, handled: false, storeCalls: 1, kind: auth.KindSession,
	}
}

// forbidden is the outcome of a signed-in caller who may not use the route.
func forbidden() outcome {
	return outcome{
		status: http.StatusForbidden, body: bodyForbidden, code: auth.CodeForbidden,
		cause: nil, logContains: "", handled: false, storeCalls: 1, kind: auth.KindSession,
	}
}

// Deployments with something missing or wrong.
func settings(name, value string) map[string]string { return map[string]string{name: value} }

func noSecret() map[string]string { return settings(config.SecretHMAC, "") }
func noAPI() map[string]string    { return settings(config.VarAPIOrigin, "") }
func nothingSet() map[string]string {
	return map[string]string{config.SecretHMAC: "", config.VarAPIOrigin: "", config.VarUIOrigin: ""}
}

// Reasons that are in the log.
//
//nolint:gosec // G101: these name the credential in a log message and are not credentials
const (
	logNoCredential = "no credential"
	logTwoCookies   = "more than one session cookie"
	logTwoHeaders   = "more than one Authorization header"
	logBoth         = "both a session cookie and a bearer token"
	logNotBearer    = "not a Bearer token"
	logNotActive    = "no active credential"
)

func noneCases() []boundaryCase {
	return []boundaryCase{
		row("none: no cookie", pathPublic, nil, ok(0)),
		row("none: garbage cookie", pathPublic, sessionValue("garbage"), ok(0)),
		row("none: two cookies", pathPublic, many(sessionValue("a"), sessionValue("b")), ok(0)),
		row("none: a valid session", pathPublic, valid, ok(0)),
		row("none: a revoked session", pathPublic, afterStoring(revoked), ok(0)),
		row("none: the store is failing", pathPublic, failing(errDB), ok(0)),
		rowOf("none: a valid key", pathPublic, validKey, ok(0)),
		rowOf("none: a garbage bearer", pathPublic, literalHeader("Bearer garbage"), ok(0)),
		row("none: configuration is missing", pathPublic, nil, ok(0)).inDeployment(noSecret()),
		row("none: nothing is configured", pathPublic, valid, ok(0)).inDeployment(nothingSet()),
	}
}

func cookieCases() []boundaryCase {
	return []boundaryCase{
		row("cookie: valid", pathMe, valid, ok(1)),
		row("cookie: none", pathMe, nil, unauthenticated(0, logNoCredential)),
		row("cookie: another name only", pathMe, plain("other", "x"), unauthenticated(0, logNoCredential)),
		row("cookie: name in another case", pathMe, named("__host-session"), unauthenticated(0, logNoCredential)),
		row("cookie: name without the prefix", pathMe, named("session"), unauthenticated(0, logNoCredential)),
		row("cookie: name with a suffix", pathMe, named(auth.CookieName+"2"), unauthenticated(0, logNoCredential)),
		row("cookie: empty", pathMe, sessionValue(""), unauthenticated(0, input.CodeInvalidSessionToken)),
		row("cookie: same valid one twice", pathMe, twice(valid), unauthenticated(0, logTwoCookies)),
		row("cookie: valid then bad", pathMe, many(valid, sessionValue("garbage")), unauthenticated(0, logTwoCookies)),
		row("cookie: bad then valid", pathMe, many(sessionValue("garbage"), valid), unauthenticated(0, logTwoCookies)),
		row("cookie: empty then valid", pathMe, many(sessionValue(""), valid), unauthenticated(0, logTwoCookies)),
		row("cookie: two valid sessions", pathMe, many(valid, valid), unauthenticated(0, logTwoCookies)),
		row("cookie: unrelated cookie beside it", pathMe, many(plain("theme", "dark"), valid), ok(1)),
	}
}

// bearerCases are the shapes an Authorization header can take.
func bearerCases() []boundaryCase {
	token := func(r *rig) string { return r.apiKey(bearerSpec{scope: list()}).Token }
	// around is a header that is the token with text before and after it.
	around := func(before, after string) carryFn {
		return header(func(r *rig) string { return before + token(r) + after })
	}
	same := func(r *rig) []string { h := "Bearer " + token(r); return []string{h, h} }
	mixed := func(r *rig) []string { return []string{"Bearer " + token(r), "Bearer garbage"} }
	parse := unauthenticated(0, input.CodeInvalidAPIKey).viaKey()
	notBearer := unauthenticated(0, logNotBearer).viaKey()
	failed := unavailable(errDB, "on fire").viaKey()
	classifiedDown := classified(apierr.Unavailable, store.CodeSessionVerifyFailed)
	classifiedBug := classified(apierr.Internal, store.CodeSessionVerifyRejected)

	return []boundaryCase{
		rowOf("bearer: valid", pathMe, validKey, ok(1).viaKey()),
		rowOf("bearer: scheme in lower case", pathMe, around("bearer ", ""), ok(1).viaKey()),
		rowOf("bearer: scheme in upper case", pathMe, around("BEARER ", ""), ok(1).viaKey()),
		rowOf("bearer: scheme in mixed case", pathMe, around("bEaReR ", ""), ok(1).viaKey()),
		rowOf("bearer: no header", pathMe, nil, unauthenticated(0, logNoCredential)),
		rowOf("bearer: the scheme alone", pathMe, literalHeader("Bearer"), notBearer),
		rowOf("bearer: the scheme and a space", pathMe, literalHeader("Bearer "), parse),
		rowOf("bearer: basic auth", pathMe, literalHeader("Basic dXNlcjpwYXNz"), notBearer),
		rowOf("bearer: a token with no scheme", pathMe, around("", ""), notBearer),
		rowOf("bearer: another scheme with a token", pathMe, around("Token ", ""), notBearer),
		rowOf("bearer: two spaces before the token", pathMe, around("Bearer  ", ""), parse),
		rowOf("bearer: a trailing space", pathMe, around("Bearer ", " "), parse),
		rowOf("bearer: a leading space", pathMe, around(" Bearer ", ""), notBearer),
		rowOf("bearer: a tab instead of a space", pathMe, around("Bearer\t", ""), notBearer),
		rowOf("bearer: two tokens in one header", pathMe,
			header(func(r *rig) string { t := token(r); return "Bearer " + t + " " + t }), parse),
		rowOf("bearer: the header sent twice", pathMe, headersOnly(same), unauthenticated(0, logTwoHeaders)),
		rowOf("bearer: a good header and a bad one", pathMe, headersOnly(mixed), unauthenticated(0, logTwoHeaders)),
		rowOf("bearer: garbage", pathMe, literalHeader("Bearer garbage"), parse),
		rowOf("bearer: a NUL in the token", pathMe, literalHeader("Bearer a\x00b"), parse),
		rowOf("bearer: an oversized token", pathMe, literalHeader("Bearer "+strings.Repeat("a", 5000)), parse),
		rowOf("bearer: a huge token", pathMe, literalHeader("Bearer "+strings.Repeat("a.", 50_000)), parse),
		rowOf("bearer: a failing store", pathMe, failingKey(errDB), failed),
		rowOf("bearer: a failing store, classified", pathMe, failingKey(classifiedDown), failed),
		rowOf("bearer: a store that rejected the read", pathMe, failingKey(classifiedBug), internalOutcome().viaKey()),
		rowOf("bearer: the request was cancelled", pathMe, validKey,
			unavailable(context.Canceled, "canceled").viaKey()).gone(),
	}
}

// bothCarriers: a request that carries a cookie and a bearer token is
// ambiguous and is refused before either is resolved.
func bothCarriers() []boundaryCase {
	refused := unauthenticated(0, logBoth)

	both := func(cookie func(*rig) *http.Cookie, headers func(*rig) []string) carryFn {
		return func(r *rig) carried {
			return carried{headers: headers(r), cookies: []*http.Cookie{cookie(r)}}
		}
	}
	session := func(r *rig) *http.Cookie { return sessionCookie(r.session()) }
	key := func(r *rig) []string { return []string{bearer(r.apiKey(bearerSpec{scope: list()}))} }
	garbage := func(*rig) []string { return []string{"Bearer garbage"} }

	return []boundaryCase{
		rowOf("both: a valid session and a valid key", pathMe, both(session, key), refused),
		rowOf("both: a valid session and a garbage bearer", pathMe, both(session, garbage), refused),
		rowOf("both: a garbage cookie and a valid key", pathMe,
			both(func(*rig) *http.Cookie { return requestCookie(auth.CookieName, "garbage") }, key), refused),
		rowOf("both: an empty cookie and a valid key", pathMe,
			both(func(*rig) *http.Cookie { return requestCookie(auth.CookieName, "") }, key), refused),
		rowOf("both: a valid session and an empty bearer", pathMe,
			both(session, func(*rig) []string { return []string{"Bearer "} }), refused),
		rowOf("both: a valid session and a non-bearer scheme", pathMe,
			both(session, func(*rig) []string { return []string{"Basic abc"} }), unauthenticated(0, logNotBearer)),
		rowOf("both: a valid session and two headers", pathMe,
			both(session, func(r *rig) []string { return append(key(r), key(r)...) }), unauthenticated(0, logTwoHeaders)),
	}
}

// shapes are the ways a value can fail to be a token of tag. None of them is
// accepted by the parser, so none costs a store read.
func shapes(tag secret.Tag) map[string]string {
	prefix := secret.Prefix(tag)
	body := strings.Repeat("A", secret.BodyLen)

	return map[string]string{
		"empty":                        "",
		"garbage":                      "garbage",
		"the prefix alone":             prefix,
		"the brand alone":              "susu_",
		"no prefix":                    body,
		"one character short":          prefix + body[:secret.BodyLen-1],
		"one character long":           prefix + body + "A",
		"a non-canonical last char":    prefix + body[:secret.BodyLen-1] + "B",
		"padding":                      prefix + body[:secret.BodyLen-1] + "=",
		"a plus":                       prefix + "+" + body[1:],
		"a slash":                      prefix + "/" + body[1:],
		"a dot":                        prefix + "." + body[1:],
		"a star":                       prefix + "*" + body[1:],
		"an upper-case prefix":         strings.ToUpper(prefix) + body,
		"a missing underscore":         strings.Replace(prefix, "_", "", 1) + body,
		"a doubled underscore":         strings.TrimSuffix(prefix, "_") + "__" + body,
		"a different brand":            "xusu_" + string(tag) + "_" + body,
		"three dotted parts":           "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln",
		"the token twice":              prefix + body + prefix + body,
		"an oversized value":           strings.Repeat("a", 5000),
		"an oversized value, prefixed": prefix + strings.Repeat("A", 5000),
	}
}

// cookieSafe reports whether value survives being sent as a cookie value
// unchanged: net/http drops the bytes a cookie value may not hold.
func cookieSafe(value string) bool {
	for i := range len(value) {
		c := value[i]
		if c < 0x21 || c > 0x7e || c == '"' || c == ',' || c == ';' || c == '\\' || c == '=' {
			return false
		}
	}

	return true
}

// shapeCases are values that are not a token of the kind the carrier accepts,
// in each carrier: always the same 401, with no read of the store.
func shapeCases() []boundaryCase {
	var cases []boundaryCase

	for name, value := range shapes(secret.TagSession) {
		if cookieSafe(value) {
			cases = append(cases, row("shape: cookie, "+name, pathMe, sessionValue(value),
				unauthenticated(0, input.CodeInvalidSessionToken)))
		}
	}

	for name, value := range shapes(secret.TagAPIKey) {
		cases = append(cases, rowOf("shape: bearer, "+name, pathMe, literalHeader("Bearer "+value),
			unauthenticated(0, input.CodeInvalidAPIKey).viaKey()))
	}

	for name, value := range shapes(secret.TagOAuthAccess) {
		// A value that is not a key's shape is refused by the key's parser, unless it
		// is a malformed access token, which the access token's parser refuses. Both
		// are the one 401 and cost no read.
		code := input.CodeInvalidAPIKey
		if strings.HasPrefix(value, secret.Prefix(secret.TagOAuthAccess)) {
			code = input.CodeInvalidAccessToken
		}

		cases = append(cases, rowOf("shape: bearer access token, "+name, pathMe, literalHeader("Bearer "+value),
			unauthenticated(0, code).viaKey()))
	}

	return cases
}

// kindCases are tokens of the right shape for another carrier: each carrier
// accepts exactly one kind, so a wrong-kind token is refused by its parser
// before the store is read.
func kindCases() []boundaryCase {
	sessionToken := func(r *rig) string { return r.session().Token }
	keyToken := func(r *rig) string { return r.apiKey(bearerSpec{scope: list()}).Token }
	invitation := func(r *rig) string { return r.foreign(secret.TagInvitation) }
	bodyUnder := func(from func(*rig) string, tag secret.Tag) func(*rig) string {
		return func(r *rig) string {
			return secret.Prefix(tag) + strings.TrimPrefix(from(r), secret.Prefix(secret.TagSession))
		}
	}
	inCookie := func(token func(*rig) string) cookieFn {
		return func(r *rig) []*http.Cookie { return []*http.Cookie{requestCookie(auth.CookieName, token(r))} }
	}
	asBearer := func(token func(*rig) string) carryFn {
		return header(func(r *rig) string { return "Bearer " + token(r) })
	}

	wrongForCookie := unauthenticated(0, input.CodeInvalidSessionToken)
	wrongForBearer := unauthenticated(0, input.CodeInvalidAPIKey).viaKey()

	base := []boundaryCase{
		rowOf("kind: a session token as a bearer", pathMe, asBearer(sessionToken), wrongForBearer),
		row("kind: an API key in the session cookie", pathMe, inCookie(keyToken), wrongForCookie),
		rowOf("kind: an invitation token as a bearer", pathMe, asBearer(invitation), wrongForBearer),
		row("kind: an invitation token in the session cookie", pathMe, inCookie(invitation), wrongForCookie),
		// The same random body under another tag is another token entirely: it
		// parses as that kind, and the store is asked, and finds nothing.
		rowOf("kind: a stored session's body under the key tag", pathMe,
			asBearer(bodyUnder(sessionToken, secret.TagAPIKey)), unauthenticated(1, logNotActive).viaKey()),
		row("kind: a stored key's body under the session tag", pathMe,
			inCookie(func(r *rig) string {
				return secret.Prefix(secret.TagSession) + strings.TrimPrefix(keyToken(r), secret.Prefix(secret.TagAPIKey))
			}), unauthenticated(1, logNotActive)),
	}

	// An OAuth code or refresh token is a bearer secret for the OAuth endpoints
	// only. Presented to authsu's own API, as a bearer or in the cookie, it is
	// refused by its shape before the store is read. An access token is the one
	// OAuth secret the API accepts, and only as a bearer: in the session cookie it
	// is a wrong kind like any other (grantCases covers it as a bearer).
	oauthTags := []secret.Tag{secret.TagOAuthCode, secret.TagOAuthRefresh}
	cases := make([]boundaryCase, 0, len(base)+2*len(oauthTags)+1)
	cases = append(cases, base...)
	cases = append(cases, row("kind: an OAuth at token in the session cookie", pathMe,
		inCookie(func(r *rig) string { return r.foreign(secret.TagOAuthAccess) }), wrongForCookie))

	for _, tag := range oauthTags {
		oauthToken := func(r *rig) string { return r.foreign(tag) }

		cases = append(cases,
			rowOf("kind: an OAuth "+string(tag)+" token as a bearer", pathMe, asBearer(oauthToken), wrongForBearer),
			row("kind: an OAuth "+string(tag)+" token in the session cookie", pathMe, inCookie(oauthToken), wrongForCookie),
		)
	}

	return cases
}

// inactiveCases are well-formed tokens of the right kind that the store does
// not report as active. The store owns the predicate (expiry, revocation, the
// account's and the agent's standing, the kind), so the boundary can only see
// that nothing was found, and that is always the same 401. Each is read once, at
// the injected clock.
func inactiveCases() []boundaryCase {
	unknownKey := func(r *rig) string { return "Bearer " + r.issueKey().Token }
	storedKey := func(r *rig) auth.Issued { return r.apiKey(bearerSpec{scope: list(), agent: agentOne}) }
	gone := unauthenticated(1, logNotActive)

	return []boundaryCase{
		row("inactive: a session that was never stored", pathMe,
			func(r *rig) []*http.Cookie { return []*http.Cookie{sessionCookie(r.issueSession())} }, gone),
		row("inactive: a session that was revoked", pathMe, afterStoring(revoked), gone),
		row("inactive: a session that expired", pathMe, afterStoring(revoked), gone),
		row("inactive: a session of a revoked account", pathMe, afterStoring(revoked), gone),
		rowOf("inactive: a key that was never stored", pathMe, header(unknownKey), gone.viaKey()),
		rowOf("inactive: a key that was revoked", pathMe, func(r *rig) carried {
			issued := r.apiKey(bearerSpec{scope: list()})
			r.unstore(issued)

			return carried{headers: []string{bearer(issued)}, cookies: nil}
		}, gone.viaKey()),
		rowOf("inactive: a key of a revoked account", pathMe, func(r *rig) carried {
			issued := r.apiKey(bearerSpec{scope: list()})
			r.unstore(issued)

			return carried{headers: []string{bearer(issued)}, cookies: nil}
		}, gone.viaKey()),
		rowOf("inactive: a key of a revoked agent", pathMe, func(r *rig) carried {
			issued := storedKey(r)
			r.unstore(issued)

			return carried{headers: []string{bearer(issued)}, cookies: nil}
		}, gone.viaKey()),
	}
}

// classified is a store failure the store has already classified, as it does.
func classified(kind apierr.Kind, code string) *apierr.Error {
	return apierr.New(kind, code, "sessions are temporarily unavailable").WithCause(errDB)
}

func internalOutcome() outcome {
	return outcome{
		status: http.StatusInternalServerError, body: bodyInternal, code: store.CodeSessionVerifyRejected,
		cause: errDB, logContains: "", handled: false, storeCalls: 1, kind: auth.KindSession,
	}
}

// oursCases are failures of ours: they say nothing about the token, so they are
// never a 401.
func oursCases() []boundaryCase {
	return []boundaryCase{
		row("ours: store failure", pathMe, failing(errDB), unavailable(errDB, "on fire")),
		row("ours: store failure, classified", pathMe, failing(classified(apierr.Unavailable, store.CodeSessionVerifyFailed)),
			unavailable(errDB, "on fire")),
		row("ours: store rejected the read", pathMe, failing(classified(apierr.Internal, store.CodeSessionVerifyRejected)),
			internalOutcome()),
		row("ours: the request was cancelled", pathMe, valid, unavailable(context.Canceled, "canceled")).gone(),
	}
}

// configCases: verifying a credential does not read the deployment's
// configuration, because a token carries nothing to check against it. A route
// that needs configuration asks for it itself (Call.Config), and is answered
// not_configured by its own handler. So the credential's outcome never depends
// on the deployment's settings.
func configCases() []boundaryCase {
	deployments := map[string]map[string]string{
		"no secret":           noSecret(),
		"short secret":        settings(config.SecretHMAC, "too-short"),
		"no API origin":       noAPI(),
		"insecure API origin": settings(config.VarAPIOrigin, "http://auth.example.com"),
		"no UI origin":        settings(config.VarUIOrigin, ""),
		"no configuration":    nothingSet(),
	}

	cases := make([]boundaryCase, 0, 6*len(deployments))

	for name, env := range deployments {
		cases = append(cases,
			row("config: "+name+", valid session", pathMe, valid, ok(1)).inDeployment(env),
			row("config: "+name+", valid session, admin route", pathAdmin, valid, ok(1)).inDeployment(env),
			rowOf("config: "+name+", valid key", pathMe, validKey, ok(1).viaKey()).inDeployment(env),
			row("config: "+name+", "+nameNoCookie, pathMe, nil, unauthenticated(0, logNoCredential)).inDeployment(env),
			row("config: "+name+", garbage cookie", pathMe, sessionValue("garbage"),
				unauthenticated(0, input.CodeInvalidSessionToken)).inDeployment(env),
			row("config: "+name+", revoked session", pathMe, afterStoring(revoked),
				unauthenticated(1, logNotActive)).inDeployment(env),
		)
	}

	return cases
}

// requirementCases: a requirement is applied to a verified caller, after the
// credential, so a caller without one learns nothing about the requirement.
func requirementCases() []boundaryCase {
	cases := make([]boundaryCase, 0, 12)
	cases = append(cases,
		row("admin: an administrator", pathAdmin, valid, ok(1)),
		row("admin: no cookie is 401, not 403", pathAdmin, nil, unauthenticated(0, logNoCredential)),
		row("admin: garbage is 401, not 403", pathAdmin, sessionValue("garbage"), unauthenticated(0, "")),
		row("admin: revoked is 401, not 403", pathAdmin, afterStoring(revoked), unauthenticated(1, logNotActive)),
		row("admin: store failure is 503", pathAdmin, failing(errDB), unavailable(errDB, "")),
		row("member: allowed where any session is", pathMe, withRole(roleMember), ok(1)),
		row("no role: allowed where any session is", pathMe, withRole(""), ok(1)),
	)

	roles := map[string]string{
		"a member":         roleMember,
		"no role":          "",
		"another case":     "ADMIN",
		"a trailing space": "admin ",
		"a longer name":    "not-admin",
	}

	for name, role := range roles {
		cases = append(cases, row("admin: "+name+" is 403", pathAdmin, withRole(role), forbidden()))
	}

	return cases
}

// idRouteCases: the same boundary on a route with a wildcard.
func idRouteCases() []boundaryCase {
	target := pathItems + itemID

	return []boundaryCase{
		row("id: valid id, valid session", target, valid, ok(1)),
		row("id: valid id, no cookie", target, nil, unauthenticated(0, logNoCredential)),
		row("id: valid id, garbage", target, sessionValue("garbage"), unauthenticated(0, "")),
		row("id: valid id, revoked", target, afterStoring(revoked), unauthenticated(1, logNotActive)),
		row("id: valid id, no configuration", target, valid, ok(1)).inDeployment(noSecret()),
	}
}

// TestBoundaryMatrix is the credential x requirement x outcome table: every
// way a request can present, or fail to present, a session or an API key,
// against a route that is open, one that needs a credential, and one that needs
// an administrator. The route must run only for the cases that pass every
// check, the store must be read only when the token has parsed as the kind its
// carrier accepts, and every refusal of a credential is the same 401.
func TestBoundaryMatrix(t *testing.T) {
	t.Parallel()

	var cases []boundaryCase

	for _, group := range [][]boundaryCase{
		noneCases(), cookieCases(), bearerCases(), bothCarriers(), shapeCases(), kindCases(), inactiveCases(),
		oursCases(), configCases(), requirementCases(), idRouteCases(),
	} {
		cases = append(cases, group...)
	}

	names := map[string]bool{}

	for _, tc := range cases {
		if names[tc.name] {
			t.Fatalf("two cases are named %q", tc.name)
		}

		names[tc.name] = true

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.run(t)
		})
	}
}

// refusalCases are the cases that are a refusal of the credential.
func refusalCases() []boundaryCase {
	var refusals []boundaryCase

	for _, group := range [][]boundaryCase{
		cookieCases(), bearerCases(), bothCarriers(), shapeCases(), kindCases(), inactiveCases(),
	} {
		for _, tc := range group {
			if tc.want.status == http.StatusUnauthorized && !tc.cancelled {
				refusals = append(refusals, tc)
			}
		}
	}

	return refusals
}

// checkRefusal checks that the case is answered with exactly bodyUnauthenticated
// and nothing else, without running the route or reading the store more than
// once.
func (c boundaryCase) checkRefusal(t *testing.T) {
	t.Helper()

	r := newRig(t).with(c.env)

	rec := r.serveCtx(r.standardRoutes(), c.target, c.presented(r), false)

	if rec.Code != http.StatusUnauthorized || len(r.handled) != 0 {
		t.Errorf("%s: status %d, route ran %d times", c.name, rec.Code, len(r.handled))
	}

	if !bytes.Equal(rec.Body.Bytes(), []byte(bodyUnauthenticated)) {
		t.Errorf("%s: body = %q, want exactly %q", c.name, rec.Body.Bytes(), bodyUnauthenticated)
	}

	if rec.Header().Get("Set-Cookie") != "" || rec.Header().Get("WWW-Authenticate") != "" {
		t.Errorf("%s: headers = %v: a refusal says nothing but the body", c.name, rec.Header())
	}

	if len(r.creds.calls) > 1 {
		t.Errorf("%s: the store was read %d times", c.name, len(r.creds.calls))
	}
}

// TestEveryRefusalIsTheSameBytes: whatever was wrong with the credential, the
// client gets the same status, the same body and the same headers, byte for
// byte, so a response is not an oracle for whether a credential exists, was
// revoked or expired, or was of the wrong kind. Only a failure of ours differs.
func TestEveryRefusalIsTheSameBytes(t *testing.T) {
	t.Parallel()

	refusals := refusalCases()
	if len(refusals) < 60 {
		t.Fatalf("only %d refusal cases were collected", len(refusals))
	}

	for _, tc := range refusals {
		tc.checkRefusal(t)
	}
}

// TestTheClockIsPassedToTheStore: the store decides what is expired or
// revoked, and the boundary tells it when "now" is, each request, from Deps.Now.
func TestTheClockIsPassedToTheStore(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	issued := r.session()
	key := r.apiKey(bearerSpec{scope: list()})

	first := r.now
	second := first.Add(36 * time.Hour)

	r.get(pathMe, sessionCookie(issued))

	r.now = second

	r.serveWith(r.standardRoutes(), pathMe, []string{bearer(key)}, nil)

	want := []credentialCall{
		{kind: auth.KindSession, token: issued.Token, now: first},
		{kind: auth.KindAPIKey, token: key.Token, now: second},
	}

	if len(r.creds.calls) != len(want) {
		t.Fatalf("store reads = %+v, want %+v", r.creds.calls, want)
	}

	for i, call := range r.creds.calls {
		if call.kind != want[i].kind || call.token != want[i].token || !call.now.Equal(want[i].now) {
			t.Errorf("read %d = %+v, want %+v", i, call, want[i])
		}
	}
}
