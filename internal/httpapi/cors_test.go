package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
)

const (
	uiOrigin    = "https://susu.dev"
	evilOrigin  = "https://evil.example"
	contentType = "Content-Type"
	originName  = "Origin"
)

// corsTarget is a POST route behind CORS, as app.NewHandler builds one.
func corsTarget(allowed string) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/x", serve(http.MethodPost, func(httpapi.Request, *apierr.Error) {},
		respond(httpapi.JSON(http.StatusOK, 1))))

	return httpapi.CORS(func() string { return allowed }, httpapi.CORSPaths{}, mux)
}

func corsHeaders(rec *httptest.ResponseRecorder) []string {
	var names []string

	for name := range rec.Header() {
		if strings.HasPrefix(name, "Access-Control-") {
			names = append(names, name)
		}
	}

	slices.Sort(names)

	return names
}

// TestCORSAllowedOriginPreflight: the configured origin's preflight is
// answered with 204 and exactly the headers that let a JSON POST with
// credentials proceed.
func TestCORSAllowedOriginPreflight(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/x", nil)
	req.Header.Set(originName, uiOrigin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", "Content-Type")

	rec := httptest.NewRecorder()
	corsTarget(uiOrigin).ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}

	want := map[string]string{
		allowOrigin:              uiOrigin,
		allowCreds:               credsTrue,
		allowMethods:             http.MethodPost,
		allowHeaders:             contentType,
		"Access-Control-Max-Age": "600",
	}
	for name, value := range want {
		if got := rec.Header().Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}

	wantVary := []string{originName, "Access-Control-Request-Method", "Access-Control-Request-Headers"}
	if got := rec.Header().Values("Vary"); !slices.Equal(got, wantVary) {
		t.Errorf("Vary = %v, want %v", got, wantVary)
	}

	if rec.Body.Len() != 0 {
		t.Errorf("preflight body = %q, want empty", rec.Body)
	}
}

// TestCORSPreflightRefusesWhatTheAPIDoesNotUse: the allowed origin may not
// preflight a method or header the API does not use.
func TestCORSPreflightRefusesWhatTheAPIDoesNotUse(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		method, headers string
		wantMethods     string
		wantHeader      string
	}{
		"get": {method: http.MethodGet, headers: "", wantMethods: http.MethodGet, wantHeader: contentType},
		"delete": {
			method: http.MethodDelete, headers: lowerCT,
			wantMethods: http.MethodDelete, wantHeader: contentType,
		},
		"patch": {
			method: http.MethodPatch, headers: lowerCT,
			wantMethods: http.MethodPatch, wantHeader: contentType,
		},
		"put": {method: http.MethodPut, headers: "", wantMethods: "", wantHeader: contentType},
		"authorization header": {
			method: http.MethodPost, headers: "content-type, authorization",
			wantMethods: http.MethodPost, wantHeader: "",
		},
		"custom header": {
			method: http.MethodPost, headers: "x-evil",
			wantMethods: http.MethodPost, wantHeader: "",
		},
		"content-type any case": {
			method: http.MethodPost, headers: " CONTENT-TYPE ,",
			wantMethods: http.MethodPost, wantHeader: contentType,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/x", nil)
			req.Header.Set(originName, uiOrigin)
			req.Header.Set("Access-Control-Request-Method", tt.method)

			if tt.headers != "" {
				req.Header.Set("Access-Control-Request-Headers", tt.headers)
			}

			rec := httptest.NewRecorder()
			corsTarget(uiOrigin).ServeHTTP(rec, req)

			if got := rec.Header().Get(allowMethods); got != tt.wantMethods {
				t.Errorf("Allow-Methods = %q, want %q", got, tt.wantMethods)
			}

			if got := rec.Header().Get(allowHeaders); got != tt.wantHeader {
				t.Errorf("Allow-Headers = %q, want %q", got, tt.wantHeader)
			}
		})
	}
}

// TestCORSAllowedOriginResponse: an actual request from the allowed origin is
// served normally and may be read, with its cookie.
func TestCORSAllowedOriginResponse(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", strings.NewReader(""))
	req.Header.Set(originName, uiOrigin)
	setContentType(req, nil)

	rec := httptest.NewRecorder()
	corsTarget(uiOrigin).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	if got := rec.Header().Get(allowOrigin); got != uiOrigin {
		t.Errorf("Allow-Origin = %q, want %q", got, uiOrigin)
	}

	if got := rec.Header().Get(allowCreds); got != credsTrue {
		t.Errorf("Allow-Credentials = %q, want true", got)
	}

	if got := rec.Header().Values("Vary"); !slices.Equal(got, []string{originName}) {
		t.Errorf("Vary = %v, want [Origin]", got)
	}
}

// TestCORSRefusesEveryOtherOrigin is what keeps the CSRF defence: an origin
// that is not exactly the configured one gets no CORS header on a preflight
// (which is answered as before, 405) or on a real request, so the browser
// never sends, or lets script read, anything. Look-alikes and an unconfigured
// deployment are included.
func TestCORSRefusesEveryOtherOrigin(t *testing.T) {
	t.Parallel()

	tests := map[string]struct{ allowed, origin string }{
		"stranger":                 {uiOrigin, evilOrigin},
		"suffix look-alike":        {uiOrigin, "https://susu.dev.evil.example"},
		"prefix look-alike":        {uiOrigin, "https://evilsusu.dev"},
		"other scheme":             {uiOrigin, "http://susu.dev"},
		"other port":               {uiOrigin, "https://susu.dev:8443"},
		"subdomain":                {uiOrigin, "https://auth.susu.dev"},
		"different case":           {uiOrigin, "https://SUSU.dev"},
		"trailing slash":           {uiOrigin, "https://susu.dev/"},
		"null origin":              {uiOrigin, nullOrigin},
		"nothing configured":       {"", uiOrigin},
		"nothing configured, null": {"", nullOrigin},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			preflight := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/x", nil)
			preflight.Header.Set(originName, tt.origin)
			preflight.Header.Set("Access-Control-Request-Method", http.MethodPost)
			preflight.Header.Set("Access-Control-Request-Headers", lowerCT)

			post := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", strings.NewReader(""))
			post.Header.Set(originName, tt.origin)
			setContentType(post, nil)

			for kind, req := range map[string]*http.Request{"preflight": preflight, "request": post} {
				rec := httptest.NewRecorder()
				corsTarget(tt.allowed).ServeHTTP(rec, req)

				if kind == "preflight" && rec.Code != http.StatusMethodNotAllowed {
					t.Errorf("preflight = %d, want 405", rec.Code)
				}

				if got := corsHeaders(rec); len(got) != 0 {
					t.Errorf("%s carries CORS headers %v", kind, got)
				}

				if got := rec.Header().Values("Vary"); !slices.Equal(got, []string{originName}) {
					t.Errorf("%s Vary = %v, want [Origin]", kind, got)
				}
			}
		})
	}
}

// TestCORSIgnoresRequestsWithoutOrigin: same-origin and non-browser callers
// send no Origin and are not touched.
func TestCORSIgnoresRequestsWithoutOrigin(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", strings.NewReader(""))
	setContentType(req, nil)

	rec := httptest.NewRecorder()
	corsTarget(uiOrigin).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	if got := corsHeaders(rec); len(got) != 0 {
		t.Errorf("CORS headers %v on a request with no Origin", got)
	}

	if got := rec.Header().Values("Vary"); len(got) != 0 {
		t.Errorf("Vary = %v, want none", got)
	}
}

// TestCORSBareOptionsIsNotAPreflight: an OPTIONS from the allowed origin that
// does not name a method falls through to the route (405), though it still
// gets the allow headers a real response from that origin carries.
func TestCORSBareOptionsIsNotAPreflight(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/x", nil)
	req.Header.Set(originName, uiOrigin)

	rec := httptest.NewRecorder()
	corsTarget(uiOrigin).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}

	if got := rec.Header().Get(allowMethods); got != "" {
		t.Errorf("Allow-Methods = %q, want none", got)
	}
}
