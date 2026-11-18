//go:build e2e

package e2e_test

import (
	"net/http"
	"testing"
)

// TestSmoke is the end-to-end walk the foundation must support: first run,
// registration, login, session read, logout, all through the real Worker.
//
//nolint:paralleltest // resets the shared database
func TestSmoke(t *testing.T) {
	pk := newAdmin(t)
	token := login(t, pk)

	get(t, pathSession, token).expect(t, "GET /api/session", http.StatusOK, "")
	post(t, pathLogout, nil, token).expect(t, "POST /api/logout", http.StatusNoContent, "")
	get(t, pathSession, token).expect(t, "GET /api/session after logout", http.StatusUnauthorized, codeUnauthenticated)
	expectCount(t, "users", "1")
}
