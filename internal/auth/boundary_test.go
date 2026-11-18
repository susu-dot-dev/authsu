//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package auth_test

import (
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
	"github.com/susu-dot-dev/authsu/internal/store"
)

// outcome is everything a request to the boundary may do, so each case states
// all of it: the response, what was logged, whether the route ran, and how
// often the store was read.
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
	// storeCalls is how many times the key store was read.
	storeCalls int
}

// cookieFn builds a request's cookies after the rig exists, so it may store
// keys and change them.
type cookieFn func(*rig) []*http.Cookie

// boundaryCase is one GET to the standard routes.
type boundaryCase struct {
	name   string
	target string
	// env overrides deployment settings; "" removes one.
	env       map[string]string
	cancelled bool
	cookies   cookieFn
	want      outcome
}

func row(name, target string, cookies cookieFn, want outcome) boundaryCase {
	return boundaryCase{name: name, target: target, env: nil, cancelled: false, cookies: cookies, want: want}
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

	var cookies []*http.Cookie
	if c.cookies != nil {
		cookies = c.cookies(r)
	}

	rec := r.serve(r.standardRoutes(), request{
		method: http.MethodGet, target: c.target, cookies: cookies, cancelled: c.cancelled,
	})

	c.checkResponse(t, r, rec)

	if got := len(r.handled); got != boolToInt(c.want.handled) {
		t.Errorf("route ran %d times, want ran = %v", got, c.want.handled)
	}

	if len(r.keys.calls) != c.want.storeCalls {
		t.Errorf("store read %d times, want %d: %v", len(r.keys.calls), c.want.storeCalls, r.keys.calls)
	}

	// Whatever a request did, the store is only ever asked about a session
	// key, at the injected clock.
	for _, call := range r.keys.calls {
		if call.kind != auth.KindSession || !call.now.Equal(r.now) {
			t.Errorf("store read = %+v, want kind %q at %v", call, auth.KindSession, r.now)
		}
	}
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
	return func(r *rig) []*http.Cookie { return []*http.Cookie{requestCookie(name, r.session().JWT)} }
}

// plain is one cookie with this name and value.
func plain(name, value string) cookieFn {
	return func(*rig) []*http.Cookie { return []*http.Cookie{requestCookie(name, value)} }
}

// afterStoring makes a stored session, lets prep change the world, and sends
// the session's cookie.
func afterStoring(prep func(r *rig, key auth.Key)) cookieFn {
	return func(r *rig) []*http.Cookie {
		key := r.session()
		prep(r, key)

		return []*http.Cookie{sessionCookie(key)}
	}
}

// revoked is a session whose row is gone: revoked, expired, or its account
// revoked, which the store reports alike.
func revoked(r *rig, key auth.Key) { r.unstore(key) }

// failing is a session whose store read fails with err.
func failing(err error) cookieFn {
	return afterStoring(func(r *rig, _ auth.Key) { r.keys.err = err })
}

// ownedBy is a session whose row belongs to another account.
func ownedBy(owner string) cookieFn {
	return afterStoring(func(r *rig, key auth.Key) { r.setRow(key, func(row *store.ActiveKey) { row.UserID = owner }) })
}

// withRole is a stored session whose account has role.
func withRole(role string) cookieFn {
	return func(r *rig) []*http.Cookie { return []*http.Cookie{sessionCookie(r.sessionFor(userID, role))} }
}

// rowWithJWK is a session whose stored JWK is jwk.
func rowWithJWK(jwk string) cookieFn {
	return afterStoring(func(r *rig, key auth.Key) {
		r.setRow(key, func(row *store.ActiveKey) { row.JWK = []byte(jwk) })
	})
}

// tampered is a session whose token is changed by edit.
func tampered(edit func(r *rig, jwt string) string) cookieFn {
	return func(r *rig) []*http.Cookie {
		return []*http.Cookie{requestCookie(auth.CookieName, edit(r, r.session().JWT))}
	}
}

// unauthenticated is the outcome of every refusal of a credential.
func unauthenticated(storeCalls int, logContains string) outcome {
	return outcome{
		status: http.StatusUnauthorized, body: bodyUnauthenticated, code: auth.CodeUnauthenticated,
		cause: nil, logContains: logContains, handled: false, storeCalls: storeCalls,
	}
}

// ok is the outcome of a request that reached the route.
func ok(storeCalls int) outcome {
	return outcome{
		status: http.StatusOK, body: bodyOK, code: "", cause: nil, logContains: "", handled: true, storeCalls: storeCalls,
	}
}

// notConfigured is the outcome of a deployment without configuration.
func notConfigured() outcome {
	return outcome{
		status: http.StatusServiceUnavailable, body: bodyNotConfigured, code: auth.CodeNotConfigured,
		cause: nil, logContains: "", handled: false, storeCalls: 0,
	}
}

// unavailable is the outcome of a failure to verify that says nothing about the
// token.
func unavailable(storeCalls int, cause error, logContains string) outcome {
	return outcome{
		status: http.StatusServiceUnavailable, body: bodyUnavailable, code: store.CodeSessionVerifyFailed,
		cause: cause, logContains: logContains, handled: false, storeCalls: storeCalls,
	}
}

// forbidden is the outcome of a signed-in caller who may not use the route.
func forbidden() outcome {
	return outcome{
		status: http.StatusForbidden, body: bodyForbidden, code: auth.CodeForbidden,
		cause: nil, logContains: "", handled: false, storeCalls: 1,
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
const (
	logNoCookie  = "no credential"
	logTwo       = "more than one session cookie"
	logNoKey     = "no active key"
	logNotOwner  = "subject is not the key's owner"
	logBadStored = "not a valid public key"
)

func noneCases() []boundaryCase {
	return []boundaryCase{
		row("none: no cookie", pathPublic, nil, ok(0)),
		row("none: garbage cookie", pathPublic, sessionValue("garbage"), ok(0)),
		row("none: two cookies", pathPublic, many(sessionValue("a"), sessionValue("b")), ok(0)),
		row("none: a valid session", pathPublic, valid, ok(0)),
		row("none: a revoked session", pathPublic, afterStoring(revoked), ok(0)),
		row("none: the store is failing", pathPublic, failing(errDB), ok(0)),
		row("none: configuration is missing", pathPublic, nil, ok(0)).inDeployment(noSecret()),
		row("none: nothing is configured", pathPublic, valid, ok(0)).inDeployment(nothingSet()),
	}
}

func cookieCases() []boundaryCase {
	return []boundaryCase{
		row("cookie: valid", pathMe, valid, ok(1)),
		row("cookie: none", pathMe, nil, unauthenticated(0, logNoCookie)),
		row("cookie: another name only", pathMe, plain("other", "x"), unauthenticated(0, logNoCookie)),
		row("cookie: name in another case", pathMe, named("__host-session"), unauthenticated(0, logNoCookie)),
		row("cookie: name without the prefix", pathMe, named("session"), unauthenticated(0, logNoCookie)),
		row("cookie: name with a suffix", pathMe, named(auth.CookieName+"2"), unauthenticated(0, logNoCookie)),
		row("cookie: empty", pathMe, sessionValue(""), unauthenticated(0, input.CodeInvalidToken)),
		row("cookie: same valid one twice", pathMe, twice(valid), unauthenticated(0, logTwo)),
		row("cookie: valid then bad", pathMe, many(valid, sessionValue("garbage")), unauthenticated(0, logTwo)),
		row("cookie: bad then valid", pathMe, many(sessionValue("garbage"), valid), unauthenticated(0, logTwo)),
		row("cookie: empty then valid", pathMe, many(sessionValue(""), valid), unauthenticated(0, logTwo)),
		row("cookie: two valid sessions", pathMe, many(valid, valid), unauthenticated(0, logTwo)),
		row("cookie: unrelated cookie beside it", pathMe, many(plain("theme", "dark"), valid), ok(1)),
	}
}

// tokenShapeCases are values that are not a token; none reaches the store.
func tokenShapeCases() []boundaryCase {
	cases := make([]boundaryCase, 0, 11)

	notJWT := map[string]string{
		"not a jwt":                 "garbage",
		"two segments":              "a.b",
		"empty segments":            "..",
		"three short segments":      "a.b.c",
		"at the limit, not a token": strings.Repeat("a", input.MaxTokenBytes),
	}

	notToken := map[string]string{
		"a plus":              "abc+def.ghi.jkl",
		"padding":             "abc=.def.ghi",
		"a slash":             "abc/def.ghi.jkl",
		"a star":              "abc*.def.ghi",
		"longer than a token": strings.Repeat("a", input.MaxTokenBytes+1),
		"a very long token":   strings.Repeat("a.", 50_000),
	}

	for name, value := range notJWT {
		cases = append(cases, row("token: "+name, pathMe, sessionValue(value), unauthenticated(0, "")))
	}

	for name, value := range notToken {
		cases = append(cases, row("token: "+name, pathMe, sessionValue(value), unauthenticated(0, input.CodeInvalidToken)))
	}

	return cases
}

// cutShort is a valid token with its tail missing.
func cutShort(_ *rig, jwt string) string { return jwt[:100] }

// flippedSignature is a valid token with one character of its signature
// changed, in the middle, so the encoding is still canonical and only the
// signature is wrong.
func flippedSignature(_ *rig, jwt string) string {
	at := len(jwt) - 10

	flipped := "A"
	if jwt[at] == 'A' {
		flipped = "B"
	}

	return jwt[:at] + flipped + jwt[at+1:]
}

// swappedPayload is a valid token whose claims are another account's.
func swappedPayload(r *rig, jwt string) string {
	mine, theirs := strings.Split(jwt, "."), strings.Split(r.sessionFor(otherUserID, auth.RoleAdmin).JWT, ".")

	return mine[0] + "." + theirs[1] + "." + mine[2]
}

// foreignRow is a session created for kind, stored only under kind, from a
// store that does or does not filter by it.
func foreignRow(kind string, ignoreKind bool) cookieFn {
	return func(r *rig) []*http.Cookie {
		key := r.createKey(r.issuer, kind)
		r.keys.ignoreKind = ignoreKind
		r.put(key, kind)

		return []*http.Cookie{sessionCookie(key)}
	}
}

// neverStored is a session that login never stored.
func neverStored(r *rig) []*http.Cookie {
	return []*http.Cookie{sessionCookie(r.createKey(r.issuer, auth.KindSession))}
}

// anotherKeysRow is a session whose row holds another key's public half.
func anotherKeysRow(r *rig) []*http.Cookie {
	key, other := r.session(), r.createKey(r.issuer, auth.KindSession)

	r.setRow(key, func(row *store.ActiveKey) {
		row.JWK = []byte(strings.ReplaceAll(other.JWK, other.ID.String(), key.ID.String()))
	})

	return []*http.Cookie{sessionCookie(key)}
}

// tokenCases are well-formed tokens that the signature, the database or the
// claims do not support. Each is the same 401.
func tokenCases() []boundaryCase {
	return []boundaryCase{
		row("token: cut short", pathMe, tampered(cutShort), unauthenticated(0, "")),
		row("token: signature changed", pathMe, tampered(flippedSignature), unauthenticated(1, "")),
		row("token: another account's claims", pathMe, tampered(swappedPayload), unauthenticated(0, "")),
		row("key: revoked", pathMe, afterStoring(revoked), unauthenticated(1, logNoKey)),
		row("key: account revoked", pathMe, afterStoring(revoked), unauthenticated(1, logNoKey)),
		row("key: expired row", pathMe, afterStoring(revoked), unauthenticated(1, logNoKey)),
		row("key: never stored", pathMe, neverStored, unauthenticated(1, logNoKey)),
		row("key: stored as an api key only", pathMe, foreignRow(auth.KindAPIKey, false), unauthenticated(1, logNoKey)),
		// A store that forgot to filter by kind still cannot make an api key
		// a session: the token's audience is signed.
		row("key: api key from a store that ignores kind", pathMe, foreignRow(auth.KindAPIKey, true),
			unauthenticated(1, "audience")),
		row("key: subject is not the row's owner", pathMe, ownedBy(otherUserID), unauthenticated(1, logNotOwner)),
		row("key: row holds another key", pathMe, anotherKeysRow, unauthenticated(1, "")),
	}
}

// foreignIssuer is a session created under issuer, which is stored and would
// verify but for its issuer.
func foreignIssuer(issuer auth.Issuer) cookieFn {
	return func(r *rig) []*http.Cookie {
		key := r.createKey(issuer, auth.KindSession)
		r.put(key, auth.KindSession)

		return []*http.Cookie{sessionCookie(key)}
	}
}

// issuerCases are issuers that are not this API's: refused before any read.
func issuerCases() []boundaryCase {
	bases := map[string]auth.Issuer{
		"another origin":      {Base: "https://other.example.com/keys", Insecure: false},
		"another path":        {Base: apiOrigin + "/other", Insecure: false},
		"the origin itself":   {Base: apiOrigin, Insecure: false},
		"another scheme":      {Base: localIssuer, Insecure: true},
		"a subdomain":         {Base: "https://evil.auth.example.com/keys", Insecure: false},
		"a suffix of the API": {Base: "https://auth.example.com.evil.test/keys", Insecure: false},
	}

	cases := make([]boundaryCase, 0, len(bases))

	for name, issuer := range bases {
		cases = append(cases, row("issuer: "+name, pathMe, foreignIssuer(issuer), unauthenticated(0, "issuer")))
	}

	return cases
}

// forgedClaims is a correctly signed session token whose claims mutate changed,
// with its row stored, so the one changed claim is the only reason to refuse
// it.
func forgedClaims(mutate func(map[string]any)) cookieFn {
	return func(r *rig) []*http.Cookie {
		token := forge(r.t, r.issuer, r.now, mutate)
		r.storeForged(token, userID, auth.RoleAdmin)

		return []*http.Cookie{requestCookie(auth.CookieName, token.JWT)}
	}
}

func without(claim string) func(map[string]any) {
	return func(claims map[string]any) { delete(claims, claim) }
}

func with(claim string, value any) func(map[string]any) {
	return func(claims map[string]any) { claims[claim] = value }
}

func claimRow(name string, mutate func(map[string]any), want outcome) boundaryCase {
	return row("claims: "+name, pathMe, forgedClaims(mutate), want)
}

func claimCases() []boundaryCase {
	past := time.Now().Add(-time.Minute).Unix()
	future := time.Now().Add(time.Hour).Unix()
	otherKid := apiOrigin + "/keys/" + otherItemID

	return []boundaryCase{
		claimRow("control: nothing wrong", nil, ok(1)),
		claimRow("expired", with(claimExp, past), unauthenticated(0, "expired")),
		claimRow("no expiry", without(claimExp), unauthenticated(0, "expiration")),
		claimRow("not yet valid", with("nbf", future), unauthenticated(0, "not yet valid")),
		claimRow("issued in the future", with(claimIat, future), unauthenticated(0, "future")),
		claimRow("no issued-at", without(claimIat), unauthenticated(0, "issued-at")),
		claimRow("another audience", with(claimAud, audForAPI), unauthenticated(1, "audience")),
		claimRow("no audience", without(claimAud), unauthenticated(1, "")),
		claimRow("audience among others", with(claimAud, []string{"x", audSession}), ok(1)),
		claimRow("unsupported version", with(claimVer, "japikey-v9"), unauthenticated(0, "version")),
		claimRow("no version", without(claimVer), unauthenticated(0, "version")),
		claimRow("no subject", without(claimSub), unauthenticated(0, "subject")),
		claimRow("empty subject", with(claimSub, ""), unauthenticated(0, "subject")),
		claimRow("subject is not a string", with(claimSub, 7), unauthenticated(0, "subject")),
		claimRow("another account's subject", with(claimSub, otherUserID), unauthenticated(1, logNotOwner)),
		claimRow("issuer names another kid", with(claimIss, otherKid), unauthenticated(0, "issuer")),
		claimRow("no issuer", without(claimIss), unauthenticated(0, "issuer")),
	}
}

// classified is a store failure the store has already classified, as it does.
func classified(kind apierr.Kind, code string) *apierr.Error {
	return apierr.New(kind, code, "sessions are temporarily unavailable").WithCause(errDB)
}

func internalOutcome() outcome {
	return outcome{
		status: http.StatusInternalServerError, body: bodyInternal, code: store.CodeSessionVerifyRejected,
		cause: errDB, logContains: "", handled: false, storeCalls: 1,
	}
}

// oursCases are failures of ours: they say nothing about the token, so they are
// never a 401.
func oursCases() []boundaryCase {
	badJWK := func(name, jwk string) boundaryCase {
		return row("ours: stored jwk "+name, pathMe, rowWithJWK(jwk), unavailable(1, nil, logBadStored))
	}

	otherKidJWK := afterStoring(func(r *rig, key auth.Key) {
		r.setRow(key, func(row *store.ActiveKey) {
			row.JWK = []byte(strings.ReplaceAll(key.JWK, key.ID.String(), otherItemID))
		})
	})

	return []boundaryCase{
		row("ours: store failure", pathMe, failing(errDB), unavailable(1, errDB, "on fire")),
		row("ours: store failure, classified", pathMe, failing(classified(apierr.Unavailable, store.CodeSessionVerifyFailed)),
			unavailable(1, errDB, "on fire")),
		row("ours: store rejected the read", pathMe, failing(classified(apierr.Internal, store.CodeSessionVerifyRejected)),
			internalOutcome()),
		row("ours: the request was cancelled", pathMe, valid, unavailable(0, nil, "timed out")).gone(),
		badJWK("is not json", "garbage"),
		badJWK("is empty", ""),
		badJWK("has no keys", `{"keys":[]}`),
		badJWK("is an array", `[]`),
		badJWK("is null", `null`),
		badJWK("is a private-only fragment", `{"keys":[{"kty":"EC","d":"x"}]}`),
		row("ours: stored jwk is for another kid", pathMe, otherKidJWK, unavailable(1, nil, logBadStored)),
	}
}

// configCases: configuration is read first, so without it nothing else is
// looked at and the answer does not depend on the cookie.
func configCases() []boundaryCase {
	deployments := map[string]map[string]string{
		"no secret":           noSecret(),
		"short secret":        settings(config.SecretHMAC, "too-short"),
		"no API origin":       noAPI(),
		"insecure API origin": settings(config.VarAPIOrigin, "http://auth.example.com"),
		"no UI origin":        settings(config.VarUIOrigin, ""),
		"no configuration":    nothingSet(),
	}

	cookies := map[string]cookieFn{"valid session": valid, nameNoCookie: nil, "garbage cookie": sessionValue("garbage")}
	cases := make([]boundaryCase, 0, (len(cookies)+1)*len(deployments))

	for name, env := range deployments {
		for cookieName, cookie := range cookies {
			cases = append(cases, row("config: "+name+", "+cookieName, pathMe, cookie, notConfigured()).inDeployment(env))
		}

		cases = append(cases, row("config: "+name+", admin route", pathAdmin, valid, notConfigured()).inDeployment(env))
	}

	return cases
}

// localhostCases: a localhost API is plain http, and only then.
func localhostCases() []boundaryCase {
	local := auth.IssuerFor(mustOrigin(localOrigin))
	here := settings(config.VarAPIOrigin, localOrigin)

	return []boundaryCase{
		row("localhost: a session over http", pathMe, foreignIssuer(local), ok(1)).inDeployment(here),
		row("localhost: no cookie", pathMe, nil, unauthenticated(0, logNoCookie)).inDeployment(here),
		row("localhost: a token for the https API", pathMe, valid, unauthenticated(0, "issuer")).inDeployment(here),
		row("https: a token for the localhost API", pathMe, foreignIssuer(local), unauthenticated(0, "issuer")),
	}
}

// requirementCases: a requirement is applied to a verified caller, after the
// credential, so a caller without one learns nothing about the requirement.
func requirementCases() []boundaryCase {
	cases := make([]boundaryCase, 0, 12)
	cases = append(cases,
		row("admin: an administrator", pathAdmin, valid, ok(1)),
		row("admin: no cookie is 401, not 403", pathAdmin, nil, unauthenticated(0, logNoCookie)),
		row("admin: garbage is 401, not 403", pathAdmin, sessionValue("garbage"), unauthenticated(0, "")),
		row("admin: revoked is 401, not 403", pathAdmin, afterStoring(revoked), unauthenticated(1, logNoKey)),
		row("admin: store failure is 503", pathAdmin, failing(errDB), unavailable(1, errDB, "")),
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
		row("id: valid id, no cookie", target, nil, unauthenticated(0, logNoCookie)),
		row("id: valid id, garbage", target, sessionValue("garbage"), unauthenticated(0, "")),
		row("id: valid id, revoked", target, afterStoring(revoked), unauthenticated(1, logNoKey)),
		row("id: valid id, no configuration", target, valid, notConfigured()).inDeployment(noSecret()),
	}
}

// TestBoundaryMatrix is the credential x requirement x outcome table: every
// way a request can present, or fail to present, a session, against a route that
// is open, one that needs a session, and one that needs an administrator. The
// route must run only for the cases that pass every check, and the store must
// be read only when the token has got far enough to name a key.
func TestBoundaryMatrix(t *testing.T) {
	t.Parallel()

	var cases []boundaryCase

	for _, group := range [][]boundaryCase{
		noneCases(), cookieCases(), tokenShapeCases(), tokenCases(), issuerCases(),
		claimCases(), oursCases(), configCases(), localhostCases(), requirementCases(), idRouteCases(),
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

// mustOrigin is a validated origin for building a case table, where there is no
// test to fail: a bad constant is a mistake in this file.
func mustOrigin(value string) config.Origin {
	parsed, err := config.ParseOrigin(value)
	if err != nil {
		panic(err)
	}

	return parsed
}
