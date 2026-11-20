//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package oauth_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/challenge"
	"github.com/susu-dot-dev/authsu/internal/oauth"
)

// invalidPendingBody is what a client is told for every pending request that
// cannot be used, whatever the reason: the reasons are only in the log.
const invalidPendingBody = `{"error":{"code":"invalid_oauth_request","message":` +
	`"the authorization request is not valid or has expired; start again from the application"}}` + "\n"

// requestTarget is the GET of a pending request.
func requestTarget(text string) string {
	return oauth.PathRequest + "?request=" + url.QueryEscape(text)
}

// wantInvalidPending asserts the one 400 for a pending request that cannot be
// used, logged once under its code, with no cookie set and nothing written.
func wantInvalidPending(t *testing.T, r *rig, status int, body string) {
	t.Helper()

	if status != http.StatusBadRequest || body != invalidPendingBody {
		t.Errorf("= %d %q, want 400 %q", status, body, invalidPendingBody)
	}

	if got := r.loggedCodes(); len(got) != 1 || got[0] != "invalid_oauth_request" {
		t.Errorf("logged %v, want one invalid_oauth_request", got)
	}

	if len(r.store.calls) != 0 {
		t.Error("the request reached the store")
	}
}

// sealed signs payload as a pending request that lapses after lifetime, with the
// deployment's request key unless key is given.
func sealed(t *testing.T, r *rig, key []byte, lifetime time.Duration, payload []byte) string {
	t.Helper()

	if key == nil {
		key = r.config().OAuthRequestKey
	}

	value, err := challenge.Seal(key, r.now.Add(lifetime), payload)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	return b64(value)
}

// requestView is a pending request edit and the view it is shown as.
type requestView struct {
	edit func(url.Values)
	want string
}

// requestViews are the views TestRequestView pins, with %d where the expiry goes.
func requestViews() map[string]requestView {
	return map[string]requestView{
		"the default scope": {
			edit: nil,
			want: `{"clientName":"Example Client","clientId":"` + clientURL + `","clientHost":"client.example.com",` +
				`"redirectHost":"client.example.com","resource":"` + resourceURL + `","resourceName":"Susu MCP",` +
				`"scopes":["mcp:read","mcp:write"],"openid":false,"expiresAt":%d}`,
		},
		"one scope and openid": {
			edit: setParam("scope", "openid mcp:write"),
			want: `{"clientName":"Example Client","clientId":"` + clientURL + `","clientHost":"client.example.com",` +
				`"redirectHost":"client.example.com","resource":"` + resourceURL + `","resourceName":"Susu MCP",` +
				`"scopes":["mcp:write"],"openid":true,"expiresAt":%d}`,
		},
		"scopes in the client's order": {
			edit: setParam("scope", "mcp:write mcp:read"),
			want: `{"clientName":"Example Client","clientId":"` + clientURL + `","clientHost":"client.example.com",` +
				`"redirectHost":"client.example.com","resource":"` + resourceURL + `","resourceName":"Susu MCP",` +
				`"scopes":["mcp:write","mcp:read"],"openid":false,"expiresAt":%d}`,
		},
		"a localhost redirect shows its port": {
			edit: setParam("redirect_uri", "http://localhost:5555/cb"),
			want: `{"clientName":"Example Client","clientId":"` + clientURL + `","clientHost":"client.example.com",` +
				`"redirectHost":"localhost:5555","resource":"` + resourceURL + `","resourceName":"Susu MCP",` +
				`"scopes":["mcp:read","mcp:write"],"openid":false,"expiresAt":%d}`,
		},
		"a loopback redirect shows its port": {
			edit: setParam("redirect_uri", "http://127.0.0.1:5555/cb"),
			want: `{"clientName":"Example Client","clientId":"` + clientURL + `","clientHost":"client.example.com",` +
				`"redirectHost":"127.0.0.1:5555","resource":"` + resourceURL + `","resourceName":"Susu MCP",` +
				`"scopes":["mcp:read","mcp:write"],"openid":false,"expiresAt":%d}`,
		},
	}
}

// TestRequestView: what the consent screen is shown for a pending request,
// exactly: the client's name beside the hosts this server checked (the host of
// the client_id and of the redirect URI, with a loopback's port), the resource,
// the resource's scopes in the client's order apart from openid, and when the
// request lapses. It needs no credential and sets no cookie.
func TestRequestView(t *testing.T) {
	t.Parallel()

	expiresAt := time.Date(2030, time.March, 4, 5, 16, 7, 0, time.UTC).Unix()

	tests := requestViews()

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			text := r.pending(tt.edit)
			rec := r.get(requestTarget(text))

			want := fmt.Sprintf(tt.want, expiresAt) + "\n"

			if rec.Code != http.StatusOK || rec.Body.String() != want {
				t.Errorf("= %d %s, want 200 %s", rec.Code, rec.Body, want)
			}

			if rec.Header().Get("Content-Type") != jsonType || rec.Header().Get("Cache-Control") != "no-store" ||
				len(rec.Result().Cookies()) != 0 {
				t.Errorf("headers = %v", rec.Header())
			}

			if len(r.logged) != 0 || len(r.store.calls) != 0 {
				t.Errorf("logged %v, store calls %v", r.loggedCodes(), r.store.calls)
			}
		})
	}
}

// TestRequestNeedsNoCredential: the view is the same for a request that carries
// a session, a bad cookie, or a bad Authorization header, because the route
// never reads them.
//
//nolint:tparallel // the rows share one rig, whose fake store appends to its call record unguarded
func TestRequestNeedsNoCredential(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	text := r.pending(nil)
	cookie, _ := r.signIn(userA)

	plain := r.get(requestTarget(text)).Body.String()

	//nolint:paralleltest // the rows share one rig, whose fake store appends to its call record unguarded
	for name, req := range map[string]request{
		"a session": {method: http.MethodGet, target: requestTarget(text), cookies: []*http.Cookie{cookie}},
		"a garbage cookie": {
			method: http.MethodGet, target: requestTarget(text),
			cookies: []*http.Cookie{{Name: "x", Value: "y"}}, //nolint:gosec // a request cookie carries no attributes
		},
		"a garbage bearer":    {method: http.MethodGet, target: requestTarget(text), authorization: "Bearer nope"},
		"a non-bearer header": {method: http.MethodGet, target: requestTarget(text), authorization: "Basic abc"},
	} {
		// Serial: the rows share one rig and so one store.
		t.Run(name, func(t *testing.T) {
			rec := r.serve(req)

			if rec.Code != http.StatusOK || rec.Body.String() != plain {
				t.Errorf("= %d %s, want the same view", rec.Code, rec.Body)
			}
		})
	}
}

// TestRequestParameter: the request parameter must be present, once.
func TestRequestParameter(t *testing.T) {
	t.Parallel()

	r0 := newRig(t)
	text := r0.pending(nil)

	tests := map[string]string{
		"missing":                 oauth.PathRequest,
		"another name":            oauth.PathRequest + "?req=" + text,
		"empty":                   oauth.PathRequest + "?request=",
		"no value":                oauth.PathRequest + "?request",
		"twice":                   oauth.PathRequest + "?request=" + text + "&request=" + text,
		"twice, one empty":        oauth.PathRequest + "?request=&request=" + text,
		"broken percent-encoding": oauth.PathRequest + "?request=%zz",
	}

	for name, target := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			rec := r.get(target)

			wantInvalidPending(t, r, rec.Code, rec.Body.String())
		})
	}
}

// TestRequestMalformedText: text that is not exactly what the authorization
// endpoint sent is refused, before it is opened where its length or spelling
// says it cannot be.
func TestRequestMalformedText(t *testing.T) {
	t.Parallel()

	r0 := newRig(t)
	text := r0.pending(nil)

	// A valid text ends in a character that completes its last byte; the
	// non-canonical spelling of the same bytes sets the unused bits.
	last := text[len(text)-1]
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	index := strings.IndexByte(alphabet, last)

	tests := map[string]string{
		"padded":                                 text + strings.Repeat("=", (4-len(text)%4)%4+1),
		"the standard alphabet":                  strings.Replace(text, "_", "/", 1) + "/",
		"a plus":                                 text[:10] + "+" + text[11:],
		"a space inside":                         text[:10] + " " + text[11:],
		"a newline at the end":                   text + "\n",
		"a trailing byte":                        text + "A",
		"one byte short":                         text[:len(text)-2],
		"empty":                                  "",
		"one character":                          "A",
		"not base64 at all":                      "this is not a request",
		"non-ASCII":                              text[:10] + "é" + text[11:],
		"at the longest a sealed value is, over": strings.Repeat("A", 5517),
		"far over the longest":                   strings.Repeat("A", 7000),
	}

	if index >= 0 && index%4 != 3 {
		// Setting a spare bit of the last character gives another spelling of the
		// same bytes, which strict decoding refuses.
		tests["a non-canonical last character"] = text[:len(text)-1] + string(alphabet[index|1])
	}

	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			rec := r.get(requestTarget(value))

			wantInvalidPending(t, r, rec.Code, rec.Body.String())
		})
	}
}

// TestRequestTamperedOrTruncated: no change to the sealed value, whichever byte
// it is in, and no cut of it, opens: a forged request is the same 400 as every
// other that cannot be used.
func TestRequestTamperedOrTruncated(t *testing.T) {
	t.Parallel()

	r := newRig(t)

	sealedBytes, err := b64decode(r.pending(setParam("state", "forge me")))
	if err != nil {
		t.Fatal(err)
	}

	for at := range sealedBytes {
		for _, flip := range []byte{0x01, 0x80} {
			forged := append([]byte(nil), sealedBytes...)
			forged[at] ^= flip

			rec := r.get(requestTarget(b64(forged)))
			if rec.Code != http.StatusBadRequest || rec.Body.String() != invalidPendingBody {
				t.Fatalf("byte %d xor %#x: = %d %s, want the 400", at, flip, rec.Code, rec.Body)
			}
		}
	}

	for length := range sealedBytes {
		rec := r.get(requestTarget(b64(sealedBytes[:length])))
		if rec.Code != http.StatusBadRequest || rec.Body.String() != invalidPendingBody {
			t.Fatalf("cut to %d bytes: = %d %s, want the 400", length, rec.Code, rec.Body)
		}
	}

	if rec := r.get(requestTarget(b64(sealedBytes))); rec.Code != http.StatusOK {
		t.Errorf("the untouched value = %d %s, want 200", rec.Code, rec.Body)
	}
}

// TestRequestExpiry: a request opens until the second it lapses, and not at it
// or after, and one that claims to live longer than PendingLifetime is refused
// even with a valid signature.
func TestRequestExpiry(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		advance time.Duration
		wantOK  bool
	}{
		"just made":           {advance: 0, wantOK: true},
		"a second before":     {advance: oauth.PendingLifetime - time.Second, wantOK: true},
		"exactly at the end":  {advance: oauth.PendingLifetime, wantOK: false},
		"a second after":      {advance: oauth.PendingLifetime + time.Second, wantOK: false},
		"a day after":         {advance: 24 * time.Hour, wantOK: false},
		"before it was made":  {advance: -time.Hour, wantOK: false},
		"a lifetime too long": {advance: -1, wantOK: false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			text := r.pending(nil)

			if tt.advance == -1 {
				// The same payload sealed to live a second longer than allowed.
				fields := pendingFields(t, r, text)
				payload, err := json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}

				text = sealed(t, r, nil, oauth.PendingLifetime+time.Second, payload)
			} else {
				r.now = r.now.Add(tt.advance)
			}

			rec := r.get(requestTarget(text))

			if tt.wantOK {
				if rec.Code != http.StatusOK {
					t.Errorf("= %d %s, want 200", rec.Code, rec.Body)
				}

				return
			}

			wantInvalidPending(t, r, rec.Code, rec.Body.String())
		})
	}
}

// TestRequestOfAnotherPurpose: a value that was signed for something else is not
// a pending request, even when the lengths and the tag would line up: a login or
// a registration challenge, a sealed payload under another derived key, and a
// sealed payload under a key that is not the deployment's.
func TestRequestOfAnotherPurpose(t *testing.T) {
	t.Parallel()

	r0 := newRig(t)
	cfg := r0.config()
	payload := encodeFields(t, pendingFields(t, r0, r0.pending(nil)))

	loginChallenge, _, err := challenge.Create(cfg.LoginKey, &sequence{reads: 1}, r0.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	registrationChallenge, _, err := challenge.Create(cfg.RegistrationKey, &sequence{reads: 2}, r0.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(*rig) string{
		"a login challenge":        func(*rig) string { return b64(loginChallenge) },
		"a registration challenge": func(*rig) string { return b64(registrationChallenge) },
		"sealed under the login key": func(r *rig) string {
			return sealed(t, r, cfg.LoginKey, time.Minute, payload)
		},
		"sealed under the registration key": func(r *rig) string {
			return sealed(t, r, cfg.RegistrationKey, time.Minute, payload)
		},
		"sealed under an unrelated key": func(r *rig) string {
			return sealed(t, r, []byte(strings.Repeat("k", 32)), time.Minute, payload)
		},
		"sealed under the key of another deployment": func(*rig) string {
			other := newRigWith(t, map[string]string{
				"AUTH_HMAC_SECRET": "another-deployments-secret-0123456789ABCDEF", "API_ORIGIN": apiOrigin, "UI_ORIGIN": uiOrigin,
			})

			return sealed(t, other, nil, time.Minute, payload)
		},
		"an empty sealed value": func(r *rig) string { return sealed(t, r, nil, time.Minute, nil) },
	}

	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			rec := r.get(requestTarget(build(r)))

			wantInvalidPending(t, r, rec.Code, rec.Body.String())
		})
	}
}

// encodeFields is the JSON of a payload's members.
func encodeFields(t *testing.T, fields map[string]any) []byte {
	t.Helper()

	out, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}

	return out
}

// TestRequestWithAPayloadThatDoesNotParse: a payload that is validly signed and
// has not expired is still read member by member through the parsers, so one that
// this version of the service would not have written, another version's or one
// with a defect, is refused and not trusted because it is signed. Every member is held
// to its parser, and the payload to its shape.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestRequestWithAPayloadThatDoesNotParse(t *testing.T) {
	t.Parallel()

	r0 := newRig(t)
	good := pendingFields(t, r0, r0.pending(setParam("nonce", "n1")))

	set := func(key string, value any) func(map[string]any) {
		return func(m map[string]any) { m[key] = value }
	}
	drop := func(key string) func(map[string]any) {
		return func(m map[string]any) { delete(m, key) }
	}

	tests := map[string]func(map[string]any){
		"clientId missing":                         drop("clientId"),
		"clientId is http":                         set("clientId", "http://client.example.com/c.json"),
		"clientId has a query":                     set("clientId", clientURL+"?x=1"),
		"clientId is a number":                     set("clientId", 5),
		"clientId over the bound":                  set("clientId", longURL(513)),
		"clientName missing":                       drop("clientName"),
		"clientName empty":                         set("clientName", ""),
		"clientName with a control":                set("clientName", "a\u0001b"),
		"clientName with a bidi override":          set("clientName", "a\u202eb"),
		"clientName over 128 bytes":                set("clientName", strings.Repeat("n", 129)),
		"clientName is a number":                   set("clientName", 5),
		"redirectUri missing":                      drop("redirectUri"),
		"redirectUri is javascript":                set("redirectUri", "javascript:alert(1)"),
		"redirectUri is http":                      set("redirectUri", "http://client.example.com/cb"),
		"redirectUri has a fragment":               set("redirectUri", redirectURL+"#x"),
		"redirectUri is null":                      set("redirectUri", nil),
		"codeChallenge missing":                    drop("codeChallenge"),
		"codeChallenge is short":                   set("codeChallenge", challengeVal[:42]),
		"codeChallenge is padded":                  set("codeChallenge", challengeVal[:42]+"="),
		"state has a control character":            set("state", "a\u0001b"),
		"state over the bound":                     set("state", strings.Repeat("s", 257)),
		"state is a number":                        set("state", 1),
		"nonce over the bound":                     set("nonce", strings.Repeat("n", 129)),
		"nonce is not ASCII":                       set("nonce", "é"),
		"resource missing":                         drop("resource"),
		"resource is not in the table":             set("resource", "https://evil.example.com/mcp"),
		"resource is the development one":          set("resource", "http://localhost:8788/mcp"),
		"resource with a trailing slash":           set("resource", resourceURL+"/"),
		"scope missing":                            drop("scope"),
		"scope empty":                              set("scope", ""),
		"scope unknown":                            set("scope", "mcp:admin"),
		"scope only openid":                        set("scope", "openid"),
		"scope repeated":                           set("scope", strings.Join([]string{"mcp:read", "mcp:read"}, " ")),
		"scope is an array":                        set("scope", []string{"mcp:read"}),
		"random missing":                           drop("random"),
		"random empty":                             set("random", ""),
		"random too short":                         set("random", "AAAA"),
		"random too long":                          set("random", strings.Repeat("A", 43)),
		"random padded":                            set("random", strings.Repeat("A", 22)+"=="),
		"random in the standard alphabet":          set("random", strings.Repeat("+", 22)),
		"random is a number":                       set("random", 5),
		"expiresAt missing":                        drop("expiresAt"),
		"expiresAt is zero":                        set("expiresAt", 0),
		"expiresAt is negative":                    set("expiresAt", -1),
		"expiresAt is beyond a browser":            set("expiresAt", float64(1<<53)),
		"expiresAt is a string":                    set("expiresAt", "1893456000"),
		"expiresAt is fractional":                  set("expiresAt", 1.5),
		"a member of the pending request is added": set("extra", true),
		"a member in another case": func(m map[string]any) {
			m["ClientId"] = m["clientId"]
			delete(m, "clientId")
		},
		"every member is null": func(m map[string]any) {
			for key := range m {
				m[key] = nil
			}
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fields := maps.Clone(good)

			mutate(fields)

			r := newRig(t)
			rec := r.get(requestTarget(sealed(t, r, nil, time.Minute, encodeFields(t, fields))))

			wantInvalidPending(t, r, rec.Code, rec.Body.String())
		})
	}

	raws := map[string]string{
		"not JSON":          `request`,
		"an empty payload":  ``,
		"an array":          `[]`,
		"null":              `null`,
		"a string":          `"x"`,
		"trailing data":     string(encodeFields(t, good)) + ` {}`,
		"a repeated member": strings.Replace(string(encodeFields(t, good)), `{`, `{"state":"a","state":"b",`, 1),
		"invalid UTF-8":     strings.Replace(string(encodeFields(t, good)), `"xyz"`, "\"\xff\"", 1),
	}

	for name, raw := range raws {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)
			rec := r.get(requestTarget(sealed(t, r, nil, time.Minute, []byte(raw))))

			wantInvalidPending(t, r, rec.Code, rec.Body.String())
		})
	}
}

// TestRequestFitsTheBounds: a sealed value of the largest size challenge allows
// is read, as far as its payload, and refused there and not for its size, and
// one a byte longer is refused before it is decoded: the route's query bound
// leaves room for every request that can be sealed.
func TestRequestFitsTheBounds(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	largest := sealed(t, r, nil, time.Minute, []byte(strings.Repeat("x", challenge.MaxPayloadLen)))

	rec := r.get(requestTarget(largest))

	wantInvalidPending(t, r, rec.Code, rec.Body.String())

	if len(r.logged) == 1 && strings.Contains(r.logged[0].Error(), "longer than any sealed value") {
		t.Errorf("the largest sealed value was refused for its size: %v", r.logged[0])
	}

	if rec := r.get(requestTarget(largest)); rec.Code == http.StatusRequestEntityTooLarge {
		t.Error("the largest sealed value is over the query bound")
	}
}
