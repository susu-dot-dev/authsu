package app_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/store"
)

const mcpPath = "/mcp"

// mcpCall is a tools/call message for tool with the given arguments.
func mcpCall(tool, arguments string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":` + arguments + `}}`
}

// mcpResult is the part of a tools/call response the tests read.
type mcpResult struct {
	Result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		StructuredContent map[string]any `json:"structuredContent"`
		IsError           bool           `json:"isError"`
	} `json:"result"`
}

// invitationRow is the row the database returns for an invitation, as D1 sends
// it: integers as int64, text as string, NULL as nil.
func invitationRow() []any {
	return []any{
		someID, "member", "workshop", int64(5), int64(2), int64(4_102_444_800), nil, adminID, int64(1_700_000_000),
		nil, nil,
	}
}

// userRow is the row the database returns for an account: id, role,
// invitation_id, profile, revoked_at, created_at.
func userRow(id string) []any {
	return []any{id, "member", someID, `{"name":"Ada"}`, nil, int64(1_700_000_000)}
}

// orgRow is the row the database returns for an organization: id, kind, name,
// created_by, expires_at, created_at.
func orgRow() []any {
	return []any{someID, "standard", "Acme", adminID, nil, int64(1_700_000_000)}
}

// memberRow is the row the database returns for a member: id, org_id, is_admin,
// revoked_at, created_at.
func memberRow() []any {
	return []any{someID, someID, int64(0), nil, int64(1_700_000_000)}
}

// callerStanding is the last statement of a batch that can be refused: the
// caller's standing, here not revoked.
func callerStanding() store.Result {
	return store.Result{Changes: 0, Rows: [][]any{{int64(0)}}}
}

// newPublicKey is a recipient a client would send: the suite byte and a fresh
// X25519 public key, 44 base64url characters.
func newPublicKey(t *testing.T) string {
	t.Helper()

	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(append([]byte{1}, private.PublicKey().Bytes()...))
}

// toolCase is a tool and what the database answers to the route it reaches.
type toolCase struct {
	tool, arguments, scope string
	// db is the database's answer to the route, after the two credential reads.
	db step
	// wantStructured is a member the route's JSON answer must have.
	wantStructured string
	// memberOK is true for a tool whose route needs no admin role (the
	// organization ones: who may act is decided in the write), so a member who
	// names its scope is let through to it and not refused for the role.
	memberOK bool
}

// Members of the routes' answers that the cases look for, and the fragments of
// the statements that tell which the route asked.
const (
	memberStatus = "status"
	memberKind   = "kind"
	memberName   = "name"
	memberAdmin  = "admin"
	fromUsers    = "FROM users"
	selectTarget = "SELECT tu.id"
)

// toolCases is every tool, with the one answer its route is given.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func toolCases() []toolCase {
	return []toolCase{
		{
			tool: "list_invitations", arguments: `{}`, scope: "invitation:read",
			db:             step{match: "FROM invitations i", results: rows(invitationRow()), err: nil},
			wantStructured: "invitations",
		},
		{
			tool: "get_invitation", arguments: `{"id":"` + someID + `"}`, scope: "invitation:read",
			db:             step{match: "WHERE i.id = ?", results: rows(invitationRow()), err: nil},
			wantStructured: "uses",
		},
		{
			tool: "revoke_invitation", arguments: `{"id":"` + someID + `"}`, scope: "invitation:revoke",
			db: step{
				match:   "UPDATE secrets",
				results: []store.Result{{Changes: 1, Rows: nil}, {Changes: 0, Rows: [][]any{invitationRow()}}}, err: nil,
			},
			wantStructured: memberStatus,
		},
		{
			tool: "create_invitation", scope: "invitation:create",
			arguments: `{"type":"member","numInvites":1,"publicKey":"KEY"}`,
			db: step{
				match: "INSERT INTO secrets",
				results: []store.Result{
					{Changes: 1, Rows: nil}, {Changes: 1, Rows: nil}, {Changes: 0, Rows: [][]any{invitationRow()}},
				},
				err: nil,
			},
			wantStructured: "sealed",
		},
		{
			tool: "list_users", arguments: `{"limit":2}`, scope: "user:read",
			db:             step{match: fromUsers, results: rows(userRow(someID)), err: nil},
			wantStructured: "users",
		},
		{
			tool: "get_user", arguments: `{"id":"` + someID + `"}`, scope: "user:read",
			db:             step{match: fromUsers, results: rows(userRow(someID)), err: nil},
			wantStructured: "invitationId",
		},
		{
			tool: "revoke_user", arguments: `{"id":"` + someID + `"}`, scope: "user:revoke",
			db: step{
				match: selectTarget,
				results: []store.Result{
					{Changes: 0, Rows: [][]any{append(memberRow(), int64(0), int64(1), int64(1))}},
					{}, {}, {Changes: 1, Rows: [][]any{userRow(someID)}}, callerStanding(),
				},
				err: nil,
			},
			wantStructured: memberStatus,
		},
		{
			tool: "list_orgs", arguments: `{"limit":2}`, scope: "org:read", memberOK: true,
			db:             step{match: "FROM orgs o", results: rows(orgRow()), err: nil},
			wantStructured: "orgs",
		},
		{
			tool: "get_org", arguments: `{"id":"` + someID + `"}`, scope: "org:read", memberOK: true,
			db:             step{match: "FROM orgs o", results: rows(orgRow()), err: nil},
			wantStructured: memberKind,
		},
		{
			tool: "rename_org", arguments: `{"id":"` + someID + `","name":"Acme"}`, scope: "org:update", memberOK: true,
			db: step{
				match: "UPDATE orgs",
				results: []store.Result{
					{Changes: 1, Rows: [][]any{orgRow()}}, {}, callerStanding(),
				},
				err: nil,
			},
			wantStructured: memberName,
		},
		{
			tool: "delete_sandbox", arguments: `{"id":"` + someID + `"}`, scope: "sandbox:revoke", memberOK: true,
			db: step{
				match: "DELETE FROM orgs",
				results: []store.Result{
					{Changes: 1, Rows: [][]any{{someID, "sandbox", "Box", adminID, int64(4_102_444_800), int64(1_700_000_000)}}},
					{}, callerStanding(),
				},
				err: nil,
			},
			wantStructured: memberStatus,
		},
		{
			tool: "list_org_members", arguments: `{"id":"` + someID + `"}`, scope: "member:read", memberOK: true,
			db: step{
				match: "FROM users u",
				results: []store.Result{
					{Changes: 0, Rows: [][]any{memberRow()}}, {Changes: 0, Rows: [][]any{orgRow()}},
				},
				err: nil,
			},
			wantStructured: "members",
		},
		{
			tool: "set_member_admin", arguments: `{"id":"` + someID + `","admin":true}`, scope: "member:update",
			memberOK: true,
			db: step{
				match: selectTarget,
				results: []store.Result{
					{Changes: 0, Rows: [][]any{append(memberRow(), int64(1))}},
					{Changes: 1, Rows: [][]any{{someID}}}, callerStanding(),
				},
				err: nil,
			},
			wantStructured: memberAdmin,
		},
		{
			tool: "revoke_member", arguments: `{"id":"` + someID + `"}`, scope: "member:revoke", memberOK: true,
			db: step{
				match: selectTarget,
				results: []store.Result{
					{Changes: 0, Rows: [][]any{append(memberRow(), int64(0), int64(1), int64(1))}},
					{}, {}, {Changes: 1, Rows: [][]any{userRow(someID)}}, callerStanding(),
				},
				err: nil,
			},
			wantStructured: memberStatus,
		},
	}
}

// TestEveryToolReachesItsRouteAndTheRoutesRuleApplies is the seam test the mcp
// package relies on: /mcp declares only a valid credential, so what keeps a
// member (or a key without the scope) from an admin tool is the route the tool
// reaches. For every tool, through the real boundary, store and routes:
//
//   - an admin's key with the tool's scope gets the route's own answer;
//   - a member's key that names the same scope is refused by the role gate;
//   - an admin's key without the scope is refused for the scope;
//
// and a refused call never touches the database beyond the two credential reads.
// The organization tools differ in the second: their routes are not gated on the
// role, so a member who names the scope reaches the route and the write decides.
func TestEveryToolReachesItsRouteAndTheRoutesRuleApplies(t *testing.T) {
	t.Parallel()

	for _, tt := range toolCases() {
		t.Run(tt.tool, func(t *testing.T) {
			t.Parallel()

			tt.arguments = strings.ReplaceAll(tt.arguments, "KEY", newPublicKey(t))

			t.Run("an admin with the scope", func(t *testing.T) {
				t.Parallel()

				tt.adminWithScope(t)
			})
			t.Run("a member naming the scope", func(t *testing.T) {
				t.Parallel()

				tt.memberNamingScope(t)
			})
			t.Run("an admin without the scope", func(t *testing.T) {
				t.Parallel()

				tt.adminWithoutScope(t)
			})
		})
	}
}

// adminWithScope: the route answers as it would over REST.
func (tt toolCase) adminWithScope(t *testing.T) {
	t.Helper()

	scopes := `["` + tt.scope + `"]`
	key := newAPIKey(t)
	h := newHarness(t, fullEnv(),
		key.keyStep(adminID, roleAdmin, "", "", scopes), key.keyStep(adminID, roleAdmin, "", "", scopes), tt.db)

	rec := h.do(request{
		method: http.MethodPost, path: mcpPath, body: mcpCall(tt.tool, tt.arguments), headers: key.headers,
	})

	var got mcpResult

	err := json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || err != nil || got.Result.IsError {
		t.Fatalf("response = %d %s (%v)", rec.Code, rec.Body.String(), err)
	}

	if _, ok := got.Result.StructuredContent[tt.wantStructured]; !ok {
		t.Errorf("structured content = %v, want a %q member", got.Result.StructuredContent, tt.wantStructured)
	}

	if _, leaked := got.Result.StructuredContent["code"]; leaked {
		t.Errorf("the response carries a code in the clear: %s", rec.Body.String())
	}
}

// memberNamingScope: an admin tool is refused to a member for the role, and an
// organization tool, whose route does not gate on the role, reaches the route.
func (tt toolCase) memberNamingScope(t *testing.T) {
	t.Helper()

	scopes := `["` + tt.scope + `"]`
	key := newAPIKey(t)
	steps := make([]step, 0, 3)
	steps = append(steps,
		key.keyStep(memberID, roleMember, "", "", scopes), key.keyStep(memberID, roleMember, "", "", scopes))

	if !tt.memberOK {
		wantRefused(t, newHarness(t, fullEnv(), steps...), key, tt.tool, tt.arguments, `"code":"forbidden"`)

		return
	}

	// The role is not the gate, so the member reaches the route and the write
	// decides. The database answers nothing, which the route reads as an
	// organization or member the caller may not see.
	h := newHarness(t, fullEnv(), append(steps, step{match: "", results: emptyBatch(tt.db), err: nil})...)

	rec := h.do(request{
		method: http.MethodPost, path: mcpPath, body: mcpCall(tt.tool, tt.arguments), headers: key.headers,
	})

	var got mcpResult

	err := json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || err != nil || strings.Contains(rec.Body.String(), `"code":"forbidden"`) {
		t.Fatalf("response = %d %s (%v), want the route's own answer, not a role refusal", rec.Code, rec.Body.String(), err)
	}
}

// adminWithoutScope: the scope is the route's rule, whatever the role.
func (tt toolCase) adminWithoutScope(t *testing.T) {
	t.Helper()

	key := newAPIKey(t)
	other := `["agent:read"]`
	h := newHarness(t, fullEnv(),
		key.keyStep(adminID, roleAdmin, "", "", other), key.keyStep(adminID, roleAdmin, "", "", other))

	wantRefused(t, h, key, tt.tool, tt.arguments, `"code":"insufficient_scope"`)
}

// emptyBatch is the database's answer of nothing to every statement of the
// batch a step stands for, which the routes read as a thing the caller may not
// see.
func emptyBatch(of step) []store.Result {
	return make([]store.Result, len(of.results))
}

// wantRefused sends the call and expects a tool error that carries the route's
// refusal, after exactly the two credential reads and nothing else.
func wantRefused(t *testing.T, h *harness, key apiKey, tool, arguments, wantCode string) {
	t.Helper()

	rec := h.do(request{
		method: http.MethodPost, path: mcpPath, body: mcpCall(tool, arguments), headers: key.headers,
	})

	var got mcpResult

	err := json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || err != nil || !got.Result.IsError || len(got.Result.Content) != 1 ||
		!strings.Contains(strings.ReplaceAll(got.Result.Content[0].Text, " ", ""), wantCode) {
		t.Fatalf("response = %d %s (%v), want a tool error with %s", rec.Code, rec.Body.String(), err, wantCode)
	}

	if calls := h.exec.callCount(); calls != 2 {
		t.Errorf("Exec calls = %d, want the two credential reads", calls)
	}
}

// TestMCPRefusesWhatIsNotAnAPIKey: a signed-in browser's session is a valid
// credential at /mcp and is refused there, since the routes a tool reaches see
// only the Authorization header and the session would fail inside; a request
// with no credential is the one 401.
func TestMCPRefusesWhatIsNotAnAPIKey(t *testing.T) {
	t.Parallel()

	t.Run("a session", func(t *testing.T) {
		t.Parallel()

		signedIn := newSession(t, adminID)
		h := newHarness(t, fullEnv(), signedIn.activeSessionStep(roleAdmin))

		rec := h.do(request{
			method: http.MethodPost, path: mcpPath, body: `{"jsonrpc":"2.0","id":1,"method":"ping"}`,
			cookies: []*http.Cookie{signedIn.cookie},
		})

		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"api_key_required"`) {
			t.Errorf("response = %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("a cookie does not reach the routes, and a key beside it does not rescue it", func(t *testing.T) {
		t.Parallel()

		signedIn := newSession(t, adminID)
		key := newAPIKey(t)
		h := newHarness(t, fullEnv())

		rec := h.do(request{
			method: http.MethodPost, path: mcpPath, body: mcpCall("list_invitations", `{}`),
			headers: key.headers, cookies: []*http.Cookie{signedIn.cookie},
		})

		// The boundary refuses a request that carries both kinds of credential
		// before it reads the store.
		if rec.Code != http.StatusUnauthorized || h.exec.callCount() != 0 {
			t.Errorf("response = %d %s, Exec calls = %d", rec.Code, rec.Body.String(), h.exec.callCount())
		}
	})
}

// TestMCPInitializeNeedsNoDatabaseBeyondTheCredential: a message that is not a
// tool call is answered by the endpoint itself, so the only thing it reads is
// the credential, once. It never runs the routes.
func TestMCPInitializeNeedsNoDatabaseBeyondTheCredential(t *testing.T) {
	t.Parallel()

	key := newAPIKey(t)
	h := newHarness(t, fullEnv(), key.keyStep(adminID, roleAdmin, "", "", `[]`))

	rec := h.do(request{
		method: http.MethodPost, path: mcpPath, headers: key.headers,
		body: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
	})

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"protocolVersion":"2025-06-18"`) {
		t.Errorf("response = %d %s", rec.Code, rec.Body.String())
	}

	if calls := h.exec.callCount(); calls != 1 {
		t.Errorf("Exec calls = %d, want only the credential's", calls)
	}
}
