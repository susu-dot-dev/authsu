//go:build e2e

package e2e_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// This file checks the CSRF defence end to end: every route that changes
// something requires Content-Type: application/json, which a browser cannot
// send cross-origin without a CORS preflight, and the Worker answers a
// preflight only for the relying party's origin. The host tests prove the rule;
// these prove the Worker as TinyGo built it, behind workerd, sees the header
// the same way.

const (
	originHeader      = "Origin"
	evilOrigin        = "https://evil.example"
	contentTypeHeader = "Content-Type"
)

// unsafeRoutes are the routes that change something. Login begin and logout read
// no body, which is why the rule cannot depend on one.
func unsafeRoutes() []string {
	return []string{
		registerPath + "/begin", registerPath + "/finish",
		loginPath + "/begin", loginPath + "/finish",
		logoutPath,
	}
}

// rawPost sends a POST with an empty body and exactly the given headers.
func rawPost(t *testing.T, path string, headers map[string]string) reply {
	t.Helper()

	return rawRequest(t, http.MethodPost, path, "", headers)
}

func rawRequest(t *testing.T, method, path, body string, headers map[string]string) reply {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), method, target.baseURL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	for name, value := range headers {
		req.Header.Set(name, value)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	return reply{
		status: resp.StatusCode, body: string(data),
		setCookies: resp.Header.Values("Set-Cookie"), header: resp.Header,
	}
}

// TestUnsafeRoutesRequireJSON sends each unsafe route what a cross-site form
// or a no-cors fetch can send: no Content-Type, or a CORS-safelisted one, with
// an empty body and a foreign Origin. Each must be refused with 415 before its
// handler runs.
//
//nolint:paralleltest // shares one database with the other tests
func TestUnsafeRoutesRequireJSON(t *testing.T) {
	contentTypes := []string{"", "text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x"}

	for _, path := range unsafeRoutes() {
		for _, contentType := range contentTypes {
			t.Run(path+" "+contentType, func(t *testing.T) {
				headers := map[string]string{originHeader: evilOrigin, "Sec-Fetch-Site": "cross-site"}
				if contentType != "" {
					headers[contentTypeHeader] = contentType
				}

				got := rawPost(t, path, headers)
				if got.status != http.StatusUnsupportedMediaType || !strings.Contains(got.body, `"unsupported_media_type"`) {
					t.Errorf("POST %s (%q) = %d %s, want 415 unsupported_media_type", path, contentType, got.status, got.body)
				}

				if len(got.setCookies) != 0 {
					t.Errorf("a refused request set cookies: %v", got.setCookies)
				}
			})
		}
	}
}

// TestForeignOriginGetsNoCORS sends each unsafe route the preflight a browser
// sends before a cross-origin application/json POST, from an origin that is not
// the relying party's. The answer must not allow it: a non-2xx status and no
// Access-Control-* header, so the browser never sends the real request. No real
// response carries CORS headers either, so script on that origin could not read
// one.
//
//nolint:paralleltest // shares one database with the other tests
func TestForeignOriginGetsNoCORS(t *testing.T) {
	for _, path := range unsafeRoutes() {
		t.Run(path, func(t *testing.T) {
			preflight := rawRequest(t, http.MethodOptions, path, "", map[string]string{
				originHeader:                     evilOrigin,
				"Access-Control-Request-Method":  http.MethodPost,
				"Access-Control-Request-Headers": "content-type",
			})

			if preflight.status >= 200 && preflight.status < 300 {
				t.Errorf("preflight = %d, want a refusal", preflight.status)
			}

			posted := rawPost(t, path, map[string]string{originHeader: evilOrigin, contentTypeHeader: jsonContentType})

			for name, got := range map[string]reply{"preflight": preflight, "request": posted} {
				for header := range got.header {
					if strings.HasPrefix(header, "Access-Control-") {
						t.Errorf("%s carries CORS header %s: %q", name, header, got.header.Get(header))
					}
				}
			}
		})
	}
}

// TestRelyingPartyOriginMayCallCrossOrigin is the other half: the UI's origin
// (UI_ORIGIN, which differs from the Worker's own port) gets a
// preflight answer that lets a credentialed JSON POST proceed, and the real
// response may be read. The Worker as built and run under workerd must do this
// for every route, ahead of the 405 an OPTIONS would otherwise get.
//
//nolint:paralleltest // shares one database with the other tests
func TestRelyingPartyOriginMayCallCrossOrigin(t *testing.T) {
	for _, path := range unsafeRoutes() {
		t.Run(path, func(t *testing.T) {
			preflight := rawRequest(t, http.MethodOptions, path, "", map[string]string{
				originHeader:                     target.origin,
				"Access-Control-Request-Method":  http.MethodPost,
				"Access-Control-Request-Headers": "content-type",
			})

			if preflight.status != http.StatusNoContent {
				t.Errorf("preflight = %d %s, want 204", preflight.status, preflight.body)
			}

			for header, want := range map[string]string{
				"Access-Control-Allow-Origin":      target.origin,
				"Access-Control-Allow-Credentials": "true",
				"Access-Control-Allow-Methods":     http.MethodPost,
				"Access-Control-Allow-Headers":     contentTypeHeader,
			} {
				if got := preflight.header.Get(header); got != want {
					t.Errorf("preflight %s = %q, want %q", header, got, want)
				}
			}

			// An unauthenticated or empty POST still fails in its handler; what
			// matters is that the failure is readable by the UI's script.
			posted := rawPost(t, path, map[string]string{originHeader: target.origin, contentTypeHeader: jsonContentType})
			if got := posted.header.Get("Access-Control-Allow-Origin"); got != target.origin {
				t.Errorf("response Allow-Origin = %q, want %q", got, target.origin)
			}

			if got := posted.header.Get("Access-Control-Allow-Credentials"); got != "true" {
				t.Errorf("response Allow-Credentials = %q, want true", got)
			}
		})
	}
}

// TestCookieRoutesRequireJSON shows the rule holds where a cookie is the
// credential: a logout posted with the session cookie but without
// application/json is refused, and the session is untouched.
//
//nolint:paralleltest // shares one database with the other tests
func TestCookieRoutesRequireJSON(t *testing.T) {
	token := login(t, registerPasskey(t))

	got := rawPost(t, logoutPath, map[string]string{"Cookie": cookieName + "=" + token, contentTypeHeader: "text/plain"})
	if got.status != http.StatusUnsupportedMediaType {
		t.Errorf("POST %s with the cookie as text/plain = %d %s, want 415", logoutPath, got.status, got.body)
	}

	if got := call(t, http.MethodGet, sessionPath, nil, token); got.status != http.StatusOK {
		t.Errorf("the session after refused requests = %d %s, want 200", got.status, got.body)
	}

	expectCount(t, "japikeys WHERE revoked_at IS NULL", "1")
}
