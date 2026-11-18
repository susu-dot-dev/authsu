//go:build e2e

package e2e_test

import (
	"testing"
)

// Names the per-feature tests share.
const (
	allowGetPost       = "GET, POST"
	statusActiveJSON   = `"status":"active"`
	statusRevokedJSON  = `"status":"revoked"`
	nameNoRouteForPath = "two segments are no route"
)

// routingCase is a request the real router must answer in a particular way.
type routingCase struct {
	method, path string
	want         int
	// allow is the Allow header of a 405, empty otherwise.
	allow string
}

// expectRouting runs the cases against the real Worker, signed in as token. It
// pins what only the real build can show: TinyGo's mux matches the plain paths
// the router registers, a wildcard matches exactly one segment, and a wrong
// method is a 405 whose Allow header names the methods.
func expectRouting(t *testing.T, token string, cases map[string]routingCase) {
	t.Helper()

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			got := call(t, tt.method, tt.path, nil, token)
			if got.status != tt.want || got.header.Get("Allow") != tt.allow {
				t.Errorf("%s %s = %d (Allow %q) %s, want %d (Allow %q)",
					tt.method, tt.path, got.status, got.header.Get("Allow"), got.body, tt.want, tt.allow)
			}
		})
	}
}
