//go:build e2e

//nolint:goconst,funlen,cyclop,maintidx,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// oauth_fetch_test.go: the Worker's outbound fetch of a client's metadata document
// under workerd, which is where TinyGo's net/http, the platform's fetch and the
// Worker's own timeout meet. A request to /oauth/authorize makes the Worker fetch
// the document at the client_id, and each case here serves the document
// differently. A document that cannot be used must end in the UI's error page, and
// never in a redirect to the client, whatever the other server did.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// oaDocument is the client's document with members replaced by extra.
func oaDocument(c *oauthClient, extra map[string]any) []byte {
	doc := map[string]any{
		paramClientID: c.id, memberClientName: c.name, memberRedirects: []string{c.redirect},
		memberAuthMethod: authMethodNone,
	}

	for name, value := range extra {
		if value == nil {
			delete(doc, name)

			continue
		}

		doc[name] = value
	}

	out, err := json.Marshal(doc)
	if err != nil {
		panic(err) // a map of strings and numbers always encodes
	}

	return out
}

// oaRedirects is the client's redirect URI and n more.
func oaRedirects(c *oauthClient, n int) []string {
	uris := make([]string, 0, n+1)
	uris = append(uris, c.redirect)

	for i := range n {
		uris = append(uris, "https://app.example/cb"+string(rune('a'+i)))
	}

	return uris
}

// oaFlush sends what has been written so far.
func oaFlush(w http.ResponseWriter) {
	flusher, ok := w.(http.Flusher)
	if ok {
		flusher.Flush()
	}
}

// oaHangUp closes the connection with no more of an answer.
func oaHangUp(w http.ResponseWriter) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}

	conn, _, err := hijacker.Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

// oaServeJSON answers with the body as JSON with the status.
func oaServeJSON(status int, body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", jsonType)
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}
}

// oaPadded is a valid document padded with spaces to exactly size bytes.
func oaPadded(c *oauthClient, size int) []byte {
	doc := c.document()

	return append(doc, bytes.Repeat([]byte(" "), size-len(doc))...)
}

// TestOAuthClientDocuments: the documents a client can serve, and what the Worker
// makes of each. The Worker's fetch is GET only, follows no redirect, accepts only
// a 200 with a JSON content type of at most 5 KiB, and the document must be the
// client_id's own with a client_name and valid redirect_uris. Every refusal is the
// UI's error page, with invalid_client for a client that is wrong and
// temporarily_unavailable for one that could not be reached.
//
//nolint:paralleltest // shares one database
func TestOAuthClientDocuments(t *testing.T) {
	newAdmin(t)

	const (
		invalid     = "invalid_client"
		unavailable = "temporarily_unavailable"
		consentPage = "consent"
		maxDoc      = 5 * 1024
	)

	cases := []struct {
		name  string
		serve func(c *oauthClient) http.HandlerFunc
		want  string // a UI error code, or consentPage
	}{
		{name: "a valid document", want: consentPage},
		{name: "a charset on the content type", serve: func(c *oauthClient) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				_, _ = w.Write(c.document())
			}
		}, want: consentPage},
		{name: "a document of exactly 5 KiB", serve: func(c *oauthClient) http.HandlerFunc { return oaServeJSON(200, oaPadded(c, maxDoc)) }, want: consentPage},
		{name: "a document of 5 KiB and a byte", serve: func(c *oauthClient) http.HandlerFunc { return oaServeJSON(200, oaPadded(c, maxDoc+1)) }, want: invalid},
		{name: "a document of 1 MiB", serve: func(c *oauthClient) http.HandlerFunc { return oaServeJSON(200, oaPadded(c, 1<<20)) }, want: invalid},
		{name: "an oversized document with no Content-Length", serve: func(c *oauthClient) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", jsonType)
				_, _ = w.Write(c.document())
				oaFlush(w)
				_, _ = w.Write(bytes.Repeat([]byte(" "), 64<<10))
			}
		}, want: invalid},
		{name: "text/plain", serve: func(c *oauthClient) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write(c.document())
			}
		}, want: invalid},
		{name: "text/html", serve: func(c *oauthClient) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write(c.document())
			}
		}, want: invalid},
		{name: "no content type", serve: func(c *oauthClient) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header()["Content-Type"] = nil // stops Go from sniffing one
				_, _ = w.Write(c.document())
			}
		}, want: invalid},
		{name: "another charset", serve: func(c *oauthClient) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json; charset=latin1")
				_, _ = w.Write(c.document())
			}
		}, want: invalid},
		{name: "application/jsonp", serve: func(c *oauthClient) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/jsonp")
				_, _ = w.Write(c.document())
			}
		}, want: invalid},
		{name: "a 404", serve: func(c *oauthClient) http.HandlerFunc { return oaServeJSON(404, c.document()) }, want: invalid},
		{name: "a 500", serve: func(c *oauthClient) http.HandlerFunc { return oaServeJSON(500, c.document()) }, want: invalid},
		{name: "a 201", serve: func(c *oauthClient) http.HandlerFunc { return oaServeJSON(201, c.document()) }, want: invalid},
		{name: "a 204", serve: func(*oauthClient) http.HandlerFunc { return oaServeJSON(204, nil) }, want: invalid},
		{name: "an empty body", serve: func(*oauthClient) http.HandlerFunc { return oaServeJSON(200, nil) }, want: invalid},
		{name: "not JSON", serve: func(*oauthClient) http.HandlerFunc { return oaServeJSON(200, []byte("<html>")) }, want: invalid},
		{name: "a JSON array", serve: func(*oauthClient) http.HandlerFunc { return oaServeJSON(200, []byte("[]")) }, want: invalid},
		{name: "JSON followed by more", serve: func(c *oauthClient) http.HandlerFunc {
			return oaServeJSON(200, append(c.document(), []byte(`{"x":1}`)...))
		}, want: invalid},
		{name: "another client_id", serve: func(c *oauthClient) http.HandlerFunc {
			return oaServeJSON(200, oaDocument(c, map[string]any{paramClientID: c.id + "x"}))
		}, want: invalid},
		{name: "the client_id in another case", serve: func(c *oauthClient) http.HandlerFunc {
			return oaServeJSON(200, oaDocument(c, map[string]any{paramClientID: strings.ReplaceAll(c.id, "client", "Client")}))
		}, want: invalid},
		{name: "no client_name", serve: func(c *oauthClient) http.HandlerFunc {
			return oaServeJSON(200, oaDocument(c, map[string]any{memberClientName: nil}))
		}, want: invalid},
		{name: "a client_name of 129 bytes", serve: func(c *oauthClient) http.HandlerFunc {
			return oaServeJSON(200, oaDocument(c, map[string]any{memberClientName: strings.Repeat("n", 129)}))
		}, want: invalid},
		{name: "a client_name of 128 bytes", serve: func(c *oauthClient) http.HandlerFunc {
			return oaServeJSON(200, oaDocument(c, map[string]any{memberClientName: strings.Repeat("n", 128)}))
		}, want: consentPage},
		{name: "no redirect_uris", serve: func(c *oauthClient) http.HandlerFunc {
			return oaServeJSON(200, oaDocument(c, map[string]any{memberRedirects: nil}))
		}, want: invalid},
		{name: "an empty redirect_uris", serve: func(c *oauthClient) http.HandlerFunc {
			return oaServeJSON(200, oaDocument(c, map[string]any{memberRedirects: []string{}}))
		}, want: invalid},
		{name: "redirect_uris that is a string", serve: func(c *oauthClient) http.HandlerFunc {
			return oaServeJSON(200, oaDocument(c, map[string]any{memberRedirects: c.redirect}))
		}, want: invalid},
		{name: "11 redirect_uris", serve: func(c *oauthClient) http.HandlerFunc {
			uris := oaRedirects(c, 10)

			return oaServeJSON(200, oaDocument(c, map[string]any{memberRedirects: uris}))
		}, want: invalid},
		{name: "10 redirect_uris", serve: func(c *oauthClient) http.HandlerFunc {
			uris := oaRedirects(c, 9)

			return oaServeJSON(200, oaDocument(c, map[string]any{memberRedirects: uris}))
		}, want: consentPage},
		{name: "an unusable redirect_uri beside a usable one", serve: func(c *oauthClient) http.HandlerFunc {
			return oaServeJSON(200, oaDocument(c, map[string]any{memberRedirects: []string{"javascript:alert(1)", "myapp://cb", c.redirect}}))
		}, want: consentPage},
		{name: "only unusable redirect_uris", serve: func(c *oauthClient) http.HandlerFunc {
			return oaServeJSON(200, oaDocument(c, map[string]any{memberRedirects: []string{"javascript:alert(1)", "myapp://cb"}}))
		}, want: invalid},
		{name: "a client secret", serve: func(c *oauthClient) http.HandlerFunc {
			return oaServeJSON(200, oaDocument(c, map[string]any{"client_secret": "s"}))
		}, want: invalid},
		{name: "a client secret authentication method", serve: func(c *oauthClient) http.HandlerFunc {
			return oaServeJSON(200, oaDocument(c, map[string]any{memberAuthMethod: "client_secret_basic"}))
		}, want: invalid},
		{name: "no authentication method", serve: func(c *oauthClient) http.HandlerFunc {
			return oaServeJSON(200, oaDocument(c, map[string]any{memberAuthMethod: nil}))
		}, want: consentPage},
		{name: "a repeated member", serve: func(c *oauthClient) http.HandlerFunc {
			doc := string(c.document())
			doc = strings.TrimSuffix(doc, "}") + `,"client_name":"Other"}`

			return oaServeJSON(200, []byte(doc))
		}, want: invalid},
		{name: "unknown members are ignored", serve: func(c *oauthClient) http.HandlerFunc {
			return oaServeJSON(200, oaDocument(c, map[string]any{"logo_uri": "https://app.example/l.png", "scope": "x"}))
		}, want: consentPage},
		{name: "a redirect to a valid document", serve: func(c *oauthClient) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/client.json" {
					http.Redirect(w, r, "/elsewhere.json", http.StatusFound)

					return
				}

				w.Header().Set("Content-Type", jsonType)
				_, _ = w.Write(c.document())
			}
		}, want: invalid},
		{name: "a permanent redirect", serve: func(*oauthClient) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/elsewhere.json", http.StatusPermanentRedirect)
			}
		}, want: invalid},
		{name: "a 304", serve: func(*oauthClient) http.HandlerFunc { return oaServeJSON(304, nil) }, want: invalid},
		{name: "a connection closed with no response", serve: func(*oauthClient) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				oaHangUp(w)
			}
		}, want: unavailable},
		{name: "a connection closed in the middle of the body", serve: func(c *oauthClient) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", jsonType)
				w.Header().Set("Content-Length", "4000")
				_, _ = w.Write(c.document()[:20])
				oaFlush(w)

				oaHangUp(w)
			}
		}, want: unavailable},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			client := newOAuthClient(t)

			if tt.serve != nil {
				client.servesWith(tt.serve(client))
			}

			got := authorize(t, client.authorizeQuery(newPKCE()))
			outcome := oaClassify(t, client, got)

			wantKind := "ui-error"
			if tt.want == consentPage {
				wantKind = "consent"
			}

			if outcome.kind != wantKind || (wantKind == "ui-error" && outcome.code != tt.want) {
				t.Errorf("outcome = %s %q (%d %s), want %s %q", outcome.kind, outcome.code, got.status, got.location(), wantKind, tt.want)
			}

			// Whatever the other server did, the person is never sent to the client.
			if strings.HasPrefix(got.location(), client.redirect) {
				t.Errorf("redirected to the client: %s", got.location())
			}

			// A redirect is not followed: the target was never asked for.
			for _, req := range client.seen() {
				if req.URL.Path != "/client.json" {
					t.Errorf("the Worker also requested %s", req.URL.Path)
				}
			}
		})
	}
}

// TestOAuthClientFetchRequest: what the Worker sends to a client's server, and
// what it does not. The request is a plain GET for JSON. It carries neither the
// user's cookie nor any Authorization header of the request that caused it, so a
// client_id cannot be used to harvest them.
//
//nolint:paralleltest // shares one database
func TestOAuthClientFetchRequest(t *testing.T) {
	holder := newOAuthHolder(t)
	client := newOAuthClient(t)

	query := client.authorizeQuery(newPKCE())
	got := send(t, request{
		path: pathOAuthAuthorize + "?" + query.Encode(), keepRedirect: true, token: holder.session,
		bearer: newToken(tagAPIKey), headers: map[string]string{"Origin": target.origin, "Referer": target.origin + "/x"},
	})
	pendingOf(t, got)

	seen := client.seen()
	if len(seen) != 1 {
		t.Fatalf("the Worker made %d requests to the client, want 1", len(seen))
	}

	req := seen[0]
	if req.Method != http.MethodGet || req.URL.Path != "/client.json" || req.URL.RawQuery != "" || req.ContentLength > 0 {
		t.Errorf("the Worker sent %s %s?%s with %d body bytes", req.Method, req.URL.Path, req.URL.RawQuery, req.ContentLength)
	}

	if accept := req.Header.Get("Accept"); accept != jsonType {
		t.Errorf("Accept = %q, want %s", accept, jsonType)
	}

	for _, name := range []string{"Cookie", "Authorization", "Origin", "Referer", "X-Forwarded-For", "Cf-Connecting-Ip"} {
		if value := req.Header.Get(name); value != "" {
			t.Errorf("the Worker sent %s: %q to the client's server", name, value)
		}
	}

	for name, values := range req.Header {
		for _, value := range values {
			if strings.Contains(value, holder.session) || strings.Contains(strings.ToLower(name), "session") {
				t.Errorf("the session reached the client's server in %s", name)
			}
		}
	}
}

// TestOAuthClientFetchUnreachable: a client_id whose server is not listening is a
// failure of the client to answer, which the person may try again: not an
// invalid client.
//
//nolint:paralleltest // shares one database
func TestOAuthClientFetchUnreachable(t *testing.T) {
	newAdmin(t)

	client := newOAuthClient(t)
	query := client.authorizeQuery(newPKCE())

	client.server.CloseClientConnections()
	client.server.Close()

	got := authorize(t, query)
	outcome := oaClassify(t, client, got)

	if outcome.kind != "ui-error" || outcome.code != "temporarily_unavailable" {
		t.Errorf("a client that is not listening = %s %q (%s), want the UI's temporarily_unavailable", outcome.kind, outcome.code, got.location())
	}
}

// TestOAuthClientFetchTimeout: the Worker gives up on a client that does not answer
// within 5 seconds. The platform sets no time limit on a subrequest, so this is the
// one check that the request's deadline aborts the subrequest, and a pending body
// read, under workerd. The two slow clients, one that never sends a header and one that
// stops in the middle of the body, run together to cost one wait. An
// authorization request writes nothing, so the test needs no database state and
// runs with the other parallel tests.
func TestOAuthClientFetchTimeout(t *testing.T) {
	t.Parallel()

	const (
		wait    = 5 * time.Second
		hangFor = 20 * time.Second
	)

	slow := []struct {
		name  string
		serve func(c *oauthClient) http.HandlerFunc
	}{
		{"no response header", func(*oauthClient) http.HandlerFunc {
			return func(_ http.ResponseWriter, r *http.Request) {
				select {
				case <-r.Context().Done():
				case <-time.After(hangFor):
				}
			}
		}},
		{"a body that stops", func(c *oauthClient) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", jsonType)
				w.Header().Set("Content-Length", "4000")
				_, _ = w.Write(c.document()[:20])
				oaFlush(w)

				select {
				case <-r.Context().Done():
				case <-time.After(hangFor):
				}
			}
		}},
	}

	for _, tt := range slow {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := newOAuthClient(t)
			client.servesWith(tt.serve(client))

			started := time.Now()
			got := authorize(t, client.authorizeQuery(newPKCE()))
			elapsed := time.Since(started)
			outcome := oaClassify(t, client, got)

			if outcome.kind != "ui-error" || outcome.code != "temporarily_unavailable" {
				t.Errorf("a client that stalls = %s %q (%s), want the UI's temporarily_unavailable", outcome.kind, outcome.code, got.location())
			}

			// The answer comes at the Worker's 5 s, not at the other server's 20 s and
			// not at once.
			if elapsed < wait-time.Second || elapsed > wait+4*time.Second {
				t.Errorf("answered after %s, want about %s", elapsed, wait)
			}

			t.Logf("%s: the Worker gave up after %s", tt.name, elapsed.Round(time.Millisecond))
		})
	}
}

// TestOAuthLoopbackRedirects: a client that lists a loopback redirect URI may use
// it on any port, and the loopback hosts are distinct from one another: localhost,
// 127.0.0.1 and [::1] never stand for each other, and nothing that merely looks
// like one is one. The code is sent to the URI the request named, and it is spent
// only at that exact URI.
//
//nolint:paralleltest // shares one database
func TestOAuthLoopbackRedirects(t *testing.T) {
	holder := newOAuthHolder(t)

	for _, tt := range []struct {
		name string
		// listed is the host the document lists, with a port that is not used.
		listed string
		// asked is the redirect URI of the request.
		asked string
		want  string // "consent" or a UI error code
	}{
		{"localhost on another port", "http://localhost:1/callback", "http://localhost:49999/callback", "consent"},
		{"localhost with no port", "http://localhost/callback", "http://localhost:49999/callback", "consent"},
		{"127.0.0.1 on another port", "http://127.0.0.1:1/callback", "http://127.0.0.1:49999/callback", "consent"},
		{"[::1] on another port", "http://[::1]:1/callback", "http://[::1]:49999/callback", "consent"},
		{"localhost for 127.0.0.1", "http://127.0.0.1:1/callback", "http://localhost:1/callback", "invalid_redirect_uri"},
		{"127.0.0.1 for localhost", "http://localhost:1/callback", "http://127.0.0.1:1/callback", "invalid_redirect_uri"},
		{"[::1] for localhost", "http://localhost:1/callback", "http://[::1]:1/callback", "invalid_redirect_uri"},
		{"localhost on another path", "http://localhost:1/callback", "http://localhost:1/other", "invalid_redirect_uri"},
		{"localhost with a query", "http://localhost:1/callback", "http://localhost:1/callback?x=1", "invalid_redirect_uri"},
		{"a subdomain of localhost", "http://localhost:1/callback", "http://a.localhost:1/callback", "invalid_redirect_uri"},
		{"localhost with a trailing dot", "http://localhost:1/callback", "http://localhost.:1/callback", "invalid_redirect_uri"},
		{"localhost in upper case", "http://localhost:1/callback", "http://LOCALHOST:1/callback", "invalid_redirect_uri"},
		{"a host that starts with localhost", "http://localhost:1/callback", "http://localhost.evil.example:1/callback", "invalid_redirect_uri"},
		{"userinfo that looks like localhost", "http://localhost:1/callback", "http://localhost@evil.example/callback", "invalid_redirect_uri"},
		{"localhost over https against a listed http one", "http://localhost:1/callback", "https://localhost:1/callback", "invalid_redirect_uri"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := newOAuthClient(t)
			client.servesWith(oaServeJSON(200, oaDocument(client, map[string]any{memberRedirects: []string{tt.listed}})))

			pair := newPKCE()
			query := client.authorizeQuery(pair)
			query.Set("redirect_uri", tt.asked)

			outcome := oaClassify(t, client, authorize(t, query))

			if tt.want == "consent" {
				if outcome.kind != "consent" {
					t.Fatalf("outcome = %s %q, want the consent page", outcome.kind, outcome.code)
				}

				// The code goes to the URI that was asked for, and is spent there only.
				pending := outcome.params.Get("request")
				redirect := consentRedirect(t, consent(t, holder.session, pending, true, newAgentChoice("loopback "+tt.name)))
				code := redirect.Query().Get("code")
				redirect.RawQuery = ""

				if redirect.String() != tt.asked {
					t.Errorf("the code was sent to %s, want %s", redirect, tt.asked)
				}

				// The exchange names the same URI, and a client that names another is
				// told the code does not match.
				a := approved{client: client, pkce: pair, code: code}

				form := a.codeForm()
				form.Set("redirect_uri", tt.asked)

				if got := postForm(t, pathOAuthToken, form); got.status != http.StatusOK {
					t.Errorf("the exchange at %s = %d %s, want 200", tt.asked, got.status, got.body)
				}

				return
			}

			if outcome.kind != "ui-error" || outcome.code != tt.want {
				t.Errorf("outcome = %s %q, want the UI's %s", outcome.kind, outcome.code, tt.want)
			}
		})
	}
}
