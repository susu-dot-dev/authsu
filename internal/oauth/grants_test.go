//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package oauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/oauth"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// bodyNoGrants is the page of a user who has none.
const bodyNoGrants = `{"grants":[]}` + "\n"

// grantPath is the path of one grant.
func grantPath(id string) string { return oauth.PathGrants + "/" + id }

// as sends a request signed in as cookie's session.
func (r *rig) as(cookie *http.Cookie, method, target string) *httptest.ResponseRecorder {
	r.t.Helper()

	return r.serve(request{method: method, target: target, cookies: []*http.Cookie{cookie}})
}

// cookieFor signs in as owner.
func (r *rig) cookieFor(owner string) *http.Cookie {
	cookie, _ := r.signIn(owner)

	return cookie
}

// page is a list of grants as the API answered it.
type page struct {
	ids  []string
	next string
}

// pageOf reads a 200 list of grants.
func pageOf(t *testing.T, rec *httptest.ResponseRecorder) page {
	t.Helper()

	var body struct {
		Grants []struct {
			ID string `json:"id"`
		} `json:"grants"`
		Next string `json:"next"`
	}

	err := json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusOK || err != nil || body.Grants == nil {
		t.Fatalf("= %d %q (%v), want a 200 page", rec.Code, rec.Body, err)
	}

	out := page{next: body.Next}
	for _, grant := range body.Grants {
		out.ids = append(out.ids, grant.ID)
	}

	return out
}

// wantAPIError asserts an error in the API's format with this status and code.
func wantAPIError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()

	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	err := json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != status || err != nil || body.Error.Code != code || body.Error.Message == "" {
		t.Fatalf("= %d %q (%v), want %d %s", rec.Code, rec.Body, err, status, code)
	}
}

// anyStrings reads a decoded JSON array of strings.
func anyStrings(value any) []string {
	items, _ := value.([]any)
	out := make([]string, len(items))

	for i, item := range items {
		out[i], _ = item.(string)
	}

	return out
}

// TestGrantView: a grant is shown as the user needs it to recognise it: its id, the
// agent that holds it, the client it was approved for, the resource and the scopes
// (the resource's, and whether it also gets an ID token), when it was approved and
// when it lapses. It carries no token and no hash.
func TestGrantView(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	cookie, _ := r.signIn(userA)

	r.now = r.now.Add(time.Minute)
	approvedAt := r.now
	code := r.approve(setParam("scope", "openid mcp:write"))

	r.now = r.now.Add(10 * time.Second)
	wantTokens(t, r.postForm(oauth.PathToken, codeForm(code)))

	exchangedAt := r.now
	r.now = r.now.Add(time.Hour)

	rec := r.as(cookie, http.MethodGet, grantPath(grantID))
	wantNotCachedJSON(t, rec, http.StatusOK)

	got := decodeNumbers(t, rec.Body.Bytes())

	wantGrantMembers(t, got)

	if wantInteger(t, "createdAt", got["createdAt"]) != approvedAt.Unix() ||
		wantInteger(t, "expiresAt", got["expiresAt"]) != exchangedAt.Add(30*24*time.Hour).Unix() {
		t.Errorf("createdAt %v, expiresAt %v, want %d and 30 days after the exchange",
			got["createdAt"], got["expiresAt"], approvedAt.Unix())
	}

	for _, secretText := range []string{"susu_", "hash", "token", "code"} {
		if strings.Contains(rec.Body.String(), secretText) {
			t.Errorf("the grant %q mentions %q", rec.Body, secretText)
		}
	}
}

// wantGrantMembers asserts every member of the view of the grant TestGrantView
// approved, but its times.
func wantGrantMembers(t *testing.T, got map[string]any) {
	t.Helper()

	agent, _ := got["agent"].(map[string]any)

	if !all(len(got) == 9, got["id"] == grantID, len(agent) == 2, agent["id"] == newAgentID,
		agent["name"] == "Claude Code") {
		t.Errorf("grant = %v, want id, agent{id,name}, and seven more members", got)
	}

	if !all(got["clientId"] == clientURL, got["clientName"] == clientName, got["resource"] == resourceURL,
		got["openid"] == true, slices.Equal(anyStrings(got["scopes"]), []string{"mcp:write"})) {
		t.Errorf("grant = %v, want the client, the resource and the scopes that were approved", got)
	}
}

// listedRig is a rig where userA has three exchanged grants and a code nobody
// exchanged, and userB has one: and the caller's cookie and the ids of the
// caller's grants, newest first (the unexchanged code's is the newest).
func listedRig(t *testing.T) (*rig, *http.Cookie, []string) {
	t.Helper()

	r := newRig(t)
	cookie, _ := r.signIn(userA)

	for range 3 {
		r.exchanged(nil)
	}

	r.approve(nil)

	wantTokens(t, r.postForm(oauth.PathToken, codeForm(r.approveFor(userB, nil))))

	listed := pageOf(t, r.as(cookie, http.MethodGet, oauth.PathGrants))

	return r, cookie, listed.ids
}

// TestGrantList: the page is the caller's grants and only theirs, newest first,
// revoked ones included; a grant whose code was not exchanged is listed too,
// because whether a grant has an access token is no part of whether it exists; and
// the store is asked for the session's user with the page the query names.
func TestGrantList(t *testing.T) {
	t.Parallel()

	r, cookie, grants := listedRig(t)

	if len(grants) != 4 || !slices.IsSortedFunc(grants, func(a, b string) int { return strings.Compare(b, a) }) {
		t.Fatalf("grants = %v, want the caller's four, newest first", grants)
	}

	call := r.store.calls[len(r.store.calls)-1]
	if call.op != opList || call.owner != userA || call.limit.Int() != 25 {
		t.Errorf("store call = %+v, want the list for the caller with the default limit", call)
	}

	mine := pageOf(t, r.as(r.cookieFor(userB), http.MethodGet, oauth.PathGrants))
	if len(mine.ids) != 1 || slices.Contains(grants, mine.ids[0]) {
		t.Errorf("another user's page = %v, want one grant that is not the caller's", mine)
	}

	wantPages(t, r, cookie, grants)
}

// wantPages asserts the paging of the caller's grants, two at a time.
func wantPages(t *testing.T, r *rig, cookie *http.Cookie, grants []string) {
	t.Helper()

	first := pageOf(t, r.as(cookie, http.MethodGet, oauth.PathGrants+"?limit=2"))
	if !slices.Equal(first.ids, grants[:2]) || first.next != grants[1] {
		t.Errorf("first page = %v, want %v next %q", first, grants[:2], grants[1])
	}

	second := pageOf(t, r.as(cookie, http.MethodGet, oauth.PathGrants+"?limit=2&cursor="+first.next))
	if !slices.Equal(second.ids, grants[2:]) || second.next != "" {
		t.Errorf("second page = %v, want %v and no next", second, grants[2:])
	}

	call := r.store.calls[len(r.store.calls)-1]
	if cursor, set := call.cursor.ID(); !set || cursor.String() != first.next || call.limit.Int() != 2 {
		t.Errorf("store call = %+v, want cursor %s and limit 2", call, first.next)
	}
}

// TestGrantListOfAUserWithNone: the page of a user who has none is empty and not
// null.
func TestGrantListOfAUserWithNone(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	rec := r.as(r.cookieFor(userA), http.MethodGet, oauth.PathGrants)

	if rec.Code != http.StatusOK || rec.Body.String() != bodyNoGrants {
		t.Errorf("= %d %q, want %q", rec.Code, rec.Body, bodyNoGrants)
	}
}

// TestGrantListRefusesWhatItCannotRead: a limit or cursor that is not exactly
// right is refused, not corrected, and the store is not asked.
func TestGrantListRefusesWhatItCannotRead(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		query  string
		status int
		code   string
	}{
		"limit zero":             {"?limit=0", http.StatusBadRequest, "invalid_limit"},
		"limit over the maximum": {"?limit=101", http.StatusBadRequest, "invalid_limit"},
		"limit with a plus":      {"?limit=%2B5", http.StatusBadRequest, "invalid_limit"},
		"limit twice":            {"?limit=1&limit=2", http.StatusBadRequest, "invalid_limit"},
		"a cursor that is no id": {"?cursor=x", http.StatusBadRequest, "invalid_cursor"},
		"a cursor in capitals":   {"?cursor=" + strings.ToUpper(grantID), http.StatusBadRequest, "invalid_cursor"},
		"a cursor twice": {
			"?cursor=" + grantID + "&cursor=" + grantID, http.StatusBadRequest, "invalid_cursor",
		},
		"a query over the bound": {
			"?x=" + strings.Repeat("a", oauth.MaxGrantQuery), http.StatusRequestEntityTooLarge, "query_too_large",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			rec := r.as(r.cookieFor(userA), http.MethodGet, oauth.PathGrants+tt.query)

			if rec.Code != tt.status || !strings.Contains(rec.Body.String(), `"code":"`+tt.code+`"`) {
				t.Errorf("= %d %q, want %d %s", rec.Code, rec.Body, tt.status, tt.code)
			}

			if len(r.store.calls) != 0 {
				t.Errorf("store calls = %+v, want none", r.store.calls)
			}
		})
	}
}

// TestGrantOfAnotherUserIsNotFound: reading or revoking a grant that is another
// user's, or that does not exist, is one answer, a 404, so a request cannot probe
// another user's grants; and nothing of the other user's is changed, an
// unexchanged code included.
func TestGrantOfAnotherUserIsNotFound(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		for name, target := range map[string]string{
			"another user's grant":            grantPath(grantID),
			"no such grant":                   grantPath(nobody),
			"another user's unexchanged code": grantPath(idAfter(4)),
		} {
			t.Run(method+" "+name, func(t *testing.T) {
				t.Parallel()

				r := newRig(t)
				tokens := r.exchanged(nil) // userA's, as grantID
				code := r.approve(nil)     // a code, as idAfter(4)

				rec := r.as(r.cookieFor(userB), method, target)

				wantAPIError(t, rec, http.StatusNotFound, oauth.CodeGrantNotFound)

				if rec.Body.String() != errorBody(oauth.CodeGrantNotFound, "no such grant") {
					t.Errorf("body = %q", rec.Body)
				}

				if !r.active(tokens.access) {
					t.Error("another user's token was revoked")
				}

				wantTokens(t, r.postForm(oauth.PathToken, codeForm(code)))
			})
		}
	}
}

// TestGrantOfAnUnexchangedCode: a grant whose code was not exchanged is the user's:
// they can see it, and they can revoke it, after which its code is refused. A
// grant does not stop being theirs because nothing has presented its code yet, or
// because its access token is not there.
func TestGrantOfAnUnexchangedCode(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	cookie, _ := r.signIn(userA)
	code := r.approve(nil)

	rec := r.as(cookie, http.MethodGet, grantPath(grantID))
	got := decodeNumbers(t, rec.Body.Bytes())

	if rec.Code != http.StatusOK || got["id"] != grantID || got["revokedAt"] != nil {
		t.Fatalf("get = %d %q, want the grant, not revoked", rec.Code, rec.Body)
	}

	listed := pageOf(t, r.as(cookie, http.MethodGet, oauth.PathGrants))
	if len(listed.ids) != 1 || listed.ids[0] != grantID {
		t.Errorf("the list = %v, want the grant", listed)
	}

	r.now = r.now.Add(time.Second)

	rec = r.as(cookie, http.MethodDelete, grantPath(grantID))
	got = decodeNumbers(t, rec.Body.Bytes())

	if rec.Code != http.StatusOK || wantInteger(t, "revokedAt", got["revokedAt"]) != r.now.Unix() {
		t.Fatalf("revoke = %d %q, want the grant, revoked now", rec.Code, rec.Body)
	}

	wantOAuthError(t, r.postForm(oauth.PathToken, codeForm(code)), http.StatusBadRequest, oauthGrant)
}

// TestGrantPathMustBeAnID: a path that is not an id is refused before the store.
func TestGrantPathMustBeAnID(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			rec := r.as(r.cookieFor(userA), method, oauth.PathGrants+"/not-an-id")

			wantAPIError(t, rec, http.StatusBadRequest, "invalid_id")

			if len(r.store.calls) != 0 {
				t.Errorf("store calls = %+v, want none", r.store.calls)
			}
		})
	}
}

// TestGrantRevoke: revoking a grant ends it and its tokens at once, answers with the
// grant as the write left it and touches nothing else: another grant of the same
// user still works.
func TestGrantRevoke(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	cookie, _ := r.signIn(userA)

	one := r.exchanged(nil)
	two := r.exchanged(nil)

	r.now = r.now.Add(time.Minute)

	rec := r.as(cookie, http.MethodDelete, grantPath(grantID))
	got := decodeNumbers(t, rec.Body.Bytes())

	if rec.Code != http.StatusOK || got["id"] != grantID || wantInteger(t, "revokedAt", got["revokedAt"]) != r.now.Unix() {
		t.Fatalf("= %d %q, want the grant, revoked at %d", rec.Code, rec.Body, r.now.Unix())
	}

	call := r.store.calls[len(r.store.calls)-1]
	if !all(call.op == opRevokeGrant, call.owner == userA, call.id.String() == grantID, call.now.Equal(r.now)) {
		t.Errorf("store call = %+v, want the revocation of %s for the caller at %v", call, grantID, r.now)
	}

	if r.active(one.access) || r.refreshWorks(one.refresh) {
		t.Error("the revoked grant's tokens work")
	}

	if !r.active(two.access) || !r.refreshWorks(two.refresh) {
		t.Error("another grant of the user stopped working")
	}
}

// TestGrantRevokeIsIdempotent: revoking again succeeds and keeps the first time, and
// the list and the item show the grant revoked.
func TestGrantRevokeIsIdempotent(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	cookie, _ := r.signIn(userA)
	r.exchanged(nil)

	r.now = r.now.Add(time.Minute)
	revokedAt := r.now.Unix()

	r.as(cookie, http.MethodDelete, grantPath(grantID))

	r.now = r.now.Add(time.Hour)

	again := decodeNumbers(t, r.as(cookie, http.MethodDelete, grantPath(grantID)).Body.Bytes())
	if wantInteger(t, "revokedAt", again["revokedAt"]) != revokedAt {
		t.Errorf("revokedAt = %v, want the first time %d", again["revokedAt"], revokedAt)
	}

	item := decodeNumbers(t, r.as(cookie, http.MethodGet, grantPath(grantID)).Body.Bytes())
	if wantInteger(t, "revokedAt", item["revokedAt"]) != revokedAt {
		t.Errorf("revokedAt = %v, want %d", item["revokedAt"], revokedAt)
	}

	if listed := pageOf(t, r.as(cookie, http.MethodGet, oauth.PathGrants)); len(listed.ids) != 1 {
		t.Errorf("the list = %v, want the revoked grant still listed", listed)
	}
}

// grantCredential is a credential presented to the grant routes, and what each
// kind of route says to it.
type grantCredential struct {
	send   func(*rig, tokenBody) request
	read   int
	revoke int
}

// grantCredentials are the credentials the grant routes are tried with.
func grantCredentials() map[string]grantCredential {
	const unauthorized, forbidden, ok = http.StatusUnauthorized, http.StatusForbidden, http.StatusOK

	key := func(agent, keyScope, agentScope string) func(*rig, tokenBody) request {
		return func(r *rig, _ tokenBody) request {
			return request{authorization: r.signInKeyScoped(agent, keyScope, agentScope)}
		}
	}
	bearer := func(token func(tokenBody) string) func(*rig, tokenBody) request {
		return func(_ *rig, b tokenBody) request { return request{authorization: "Bearer " + token(b)} }
	}

	return map[string]grantCredential{
		"a session": {
			func(r *rig, _ tokenBody) request { return request{cookies: []*http.Cookie{r.cookieFor(userA)}} }, ok, ok,
		},
		"a user's key": {key("", `["default:user"]`, `[]`), ok, ok},
		"a user's key with only the scope to read": {key("", `["grant:read"]`, `[]`), ok, forbidden},
		"a user's key with only the scope to revoke": {
			key("", `["grant:revoke"]`, `[]`), forbidden, ok,
		},
		"a user's key with other scopes":   {key("", `["key:read","agent:read"]`, `[]`), forbidden, forbidden},
		"an agent with the default scopes": {key(agentA1, `["default:agent"]`, `["default:agent"]`), forbidden, forbidden},
		"an agent that holds the scope to read": {
			key(agentA1, `["grant:read","grant:revoke"]`, `["grant:read","grant:revoke"]`), ok, forbidden,
		},
		"no credential": {func(*rig, tokenBody) request { return request{} }, unauthorized, unauthorized},
		"an access token as a bearer": {
			bearer(func(b tokenBody) string { return b.access }), unauthorized, unauthorized,
		},
		"a refresh token as a bearer": {
			bearer(func(b tokenBody) string { return b.refresh }), unauthorized, unauthorized,
		},
		"a code as a bearer": {
			bearer(func(tokenBody) string { return tokenOf2(secret.TagOAuthCode) }), unauthorized, unauthorized,
		},
	}
}

// TestGrantCredentials: the grant routes are the user's own. A session and a user's
// key may read and revoke; an agent may read only with the scope for it and never
// revoke (agents are peers); a key without the scope may do neither; and an OAuth
// access token, a refresh token or a code is no credential here.
func TestGrantCredentials(t *testing.T) {
	t.Parallel()

	routes := []struct {
		method, target string
		want           func(grantCredential) int
	}{
		{http.MethodGet, oauth.PathGrants, func(c grantCredential) int { return c.read }},
		{http.MethodGet, grantPath(grantID), func(c grantCredential) int { return c.read }},
		{http.MethodDelete, grantPath(grantID), func(c grantCredential) int { return c.revoke }},
	}

	for name, tt := range grantCredentials() {
		for _, route := range routes {
			t.Run(name+" "+route.method+" "+route.target, func(t *testing.T) {
				t.Parallel()

				r := newRig(t)
				tokens := r.exchanged(nil)

				req := tt.send(r, tokens)
				req.method, req.target = route.method, route.target

				before := len(r.store.calls)
				rec := r.serve(req)
				want := route.want(tt)

				if rec.Code != want {
					t.Fatalf("= %d %q, want %d", rec.Code, rec.Body, want)
				}

				wantGrantEffect(t, r, rec, route.method, tokens, before)
			})
		}
	}
}

// wantGrantEffect asserts what a request to a grant route did: a refused one asked
// nothing of the store and changed nothing, and a revoke that was allowed revoked.
func wantGrantEffect(
	t *testing.T, r *rig, rec *httptest.ResponseRecorder, method string, tokens tokenBody, before int,
) {
	t.Helper()

	switch {
	case rec.Code == http.StatusOK && method == http.MethodDelete:
		if r.active(tokens.access) {
			t.Error("the grant was revoked and its access token is live")
		}
	case rec.Code == http.StatusOK:
	default:
		if len(r.store.calls) != before || !r.active(tokens.access) {
			t.Error("a refused request reached the store or revoked the grant")
		}

		if rec.Code == http.StatusUnauthorized && rec.Body.String() != bodyUnauth {
			t.Errorf("body = %q, want %q", rec.Body, bodyUnauth)
		}
	}
}

// TestGrantStoreFailures: the store's failure is the answer, classified, in the API's
// format, and never with the cause.
func TestGrantStoreFailures(t *testing.T) {
	t.Parallel()

	unavailable := apierr.New(apierr.Unavailable, store.CodeGrantListFailed, "grants are temporarily unavailable").
		WithCause(errDB)

	for name, tt := range map[string]struct{ method, target string }{
		"list":   {http.MethodGet, oauth.PathGrants},
		"get":    {http.MethodGet, grantPath(grantID)},
		"revoke": {http.MethodDelete, grantPath(grantID)},
	} {
		t.Run(name+" unavailable", func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			r.store.failure = unavailable

			rec := r.as(r.cookieFor(userA), tt.method, tt.target)

			want := errorBody(store.CodeGrantListFailed, "grants are temporarily unavailable")
			if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != want {
				t.Errorf("= %d %q, want %q", rec.Code, rec.Body, want)
			}
		})

		t.Run(name+" unclassified", func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			r.store.failure = errDB

			rec := r.as(r.cookieFor(userA), tt.method, tt.target)

			if rec.Code != http.StatusInternalServerError || rec.Body.String() != bodyInternal {
				t.Errorf("= %d %q, want %q", rec.Code, rec.Body, bodyInternal)
			}
		})
	}
}

// TestGrantRoutesTakeTheirMethodsOnly: a method a path does not declare is 405 with
// the Allow header.
func TestGrantRoutesTakeTheirMethodsOnly(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		target  string
		methods []string
		allow   string
	}{
		"the collection": {
			oauth.PathGrants, []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}, "GET",
		},
		"one grant": {grantPath(grantID), []string{http.MethodPost, http.MethodPut, http.MethodPatch}, "DELETE, GET"},
	}

	for name, tt := range tests {
		for _, method := range tt.methods {
			t.Run(name+" "+method, func(t *testing.T) {
				t.Parallel()

				r := newRig(t)
				rec := r.as(r.cookieFor(userA), method, tt.target)

				if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != tt.allow {
					t.Errorf("= %d Allow %q, want 405 with %q", rec.Code, rec.Header().Get("Allow"), tt.allow)
				}
			})
		}
	}
}
