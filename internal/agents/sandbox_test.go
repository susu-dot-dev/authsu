//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package agents_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/agents"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// This file is the sandbox half of the agent routes (docs/orgs_design.md): an
// agent is created in a sandbox by the user who administers it, an agent's
// create always lands in the agent's own sandbox, and an agent reaches only the
// agents of its own sandbox (ordinary agents reach only ordinary ones), while a
// user reaches all of their own. The store enforces the rules in its writes; the
// fake store here restates them, so what these tests pin is what the handlers
// ask of the store and answer from it.

const (
	// Sandboxes. sandboxMine is administered by user A, sandboxOther by user B,
	// sandboxExpired by A but has run out, and sandboxNone does not exist.
	sandboxMine    = "00000000-0000-7000-8000-0000000005a1"
	sandboxOther   = "00000000-0000-7000-8000-0000000005b1"
	sandboxExpired = "00000000-0000-7000-8000-0000000005e1"
	sandboxNone    = "00000000-0000-7000-8000-0000000005ff"
	// sandboxSecond is another sandbox of A, for a second confinement.
	sandboxSecond = "00000000-0000-7000-8000-0000000005a2"

	// Agents of A: two in sandboxMine, one in sandboxSecond, and ordinary ones
	// are agentA1 and agentA2.
	agentInMine1   = "00000000-0000-7000-8000-0000000006a1"
	agentInMine2   = "00000000-0000-7000-8000-0000000006a2"
	agentInSecond  = "00000000-0000-7000-8000-0000000006a3"
	agentOfOtherSB = "00000000-0000-7000-8000-0000000006b1"

	codeSandboxNotFound  = agents.CodeSandboxNotFound
	codeSandboxInherited = agents.CodeSandboxInherited
	codeInvalidSandbox   = "invalid_sandbox_id"
	codeInvalidSandboxQ  = "invalid_sandbox_filter"
)

// withSandbox is stored placed in sandbox.
func withSandbox(agent store.Agent, sandbox string) store.Agent {
	agent.SandboxID = &sandbox

	return agent
}

// sandboxRig is a rig with user A's agents in and out of sandboxes, and the
// sandboxes themselves.
func sandboxRig(t *testing.T) *rig {
	t.Helper()

	rg := newRig(t)

	rg.store.sandboxes[sandboxMine] = fakeSandbox{admin: userA, expired: false}
	rg.store.sandboxes[sandboxSecond] = fakeSandbox{admin: userA, expired: false}
	rg.store.sandboxes[sandboxExpired] = fakeSandbox{admin: userA, expired: true}
	rg.store.sandboxes[sandboxOther] = fakeSandbox{admin: userB, expired: false}

	rg.seed(userA,
		stored(agentA1, "ordinary one", 100, nil),
		stored(agentA2, "ordinary two", 200, nil),
		withSandbox(stored(agentInMine1, "in mine one", 300, nil), sandboxMine),
		withSandbox(stored(agentInMine2, "in mine two", 400, new(int64(450))), sandboxMine),
		withSandbox(stored(agentInSecond, "in second", 500, nil), sandboxSecond),
	)
	rg.seed(userB, withSandbox(stored(agentOfOtherSB, "b's", 600, nil), sandboxOther))

	return rg
}

// caller is who makes a request: a session, a user's own key, or an agent of
// user A that holds the scopes to list, read and create agents, in a sandbox
// ("" for none).
type caller struct {
	name string
	// agent is the acting agent's id, "" for the user themselves; viaKey makes
	// the user a key and not a session.
	agent, sandbox string
	viaKey         bool
}

// sender sends a request as a caller.
type sender func(method, target, body string) *httptest.ResponseRecorder

// credential signs the caller in as user A and returns what sends its requests.
func (c caller) credential(rg *rig) sender {
	switch {
	case c.agent != "":
		header := rg.signInKey(keySpec{
			owner: userA, role: roleMember, scope: scope.List{agentRead, agentCreate},
			agent: c.agent, agentScopes: scope.List{agentRead, agentCreate}.JSON(), sandbox: c.sandbox,
		})

		return func(method, target, body string) *httptest.ResponseRecorder {
			return rg.withKey(header, method, target, body)
		}
	case c.viaKey:
		header := rg.signInKey(keySpec{owner: userA, role: roleMember, scope: scope.List{scope.DefaultUser}})

		return func(method, target, body string) *httptest.ResponseRecorder {
			return rg.withKey(header, method, target, body)
		}
	default:
		cookie := rg.signIn(userA, roleMember)

		return func(method, target, body string) *httptest.ResponseRecorder {
			return rg.as(cookie, method, target, body)
		}
	}
}

// idsOf is the agent ids of a list response, in order.
func idsOf(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()

	var list agents.ListResponse

	err := json.Unmarshal(rec.Body.Bytes(), &list)
	if err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}

	ids := make([]string, 0, len(list.Agents))
	for _, agent := range list.Agents {
		ids = append(ids, agent.ID)
	}

	return ids
}

// callers are every way of being user A, with what each is confined to.
func callers() []caller {
	return []caller{
		{name: "a session", agent: "", sandbox: "", viaKey: false},
		{name: "the user's own key", agent: "", sandbox: "", viaKey: true},
		{name: "an ordinary agent", agent: agentA1, sandbox: "", viaKey: true},
		{name: "an agent of the first sandbox", agent: agentInMine1, sandbox: sandboxMine, viaKey: true},
		{name: "an agent of the second sandbox", agent: agentInSecond, sandbox: sandboxSecond, viaKey: true},
	}
}

// TestListReachesOnlyWhatTheCallerMay is the confinement of the list, over every
// caller and every filter: the user sees all of their agents, an ordinary agent
// only ordinary ones and an agent of a sandbox only that sandbox's, and a
// sandbox filter narrows and never widens. Another user's agents are in no
// answer.
func TestListReachesOnlyWhatTheCallerMay(t *testing.T) {
	t.Parallel()

	// The agents newest first.
	all := []string{agentInSecond, agentInMine2, agentInMine1, agentA2, agentA1}

	tests := []struct {
		name   string
		caller caller
		query  string
		want   []string
	}{
		{"a session sees every agent", callers()[0], "", all},
		{"a user key sees every agent", callers()[1], "", all},
		{"an ordinary agent sees only ordinary agents", callers()[2], "", []string{agentA2, agentA1}},
		{"a sandbox agent sees only its sandbox", callers()[3], "", []string{agentInMine2, agentInMine1}},
		{"another sandbox's agent sees only its own", callers()[4], "", []string{agentInSecond}},

		{"the user filters to one sandbox", callers()[0], "?sandbox=" + sandboxMine, []string{agentInMine2, agentInMine1}},
		{"the user filters to another", callers()[0], "?sandbox=" + sandboxSecond, []string{agentInSecond}},
		{"the user filters to a sandbox with none", callers()[1], "?sandbox=" + sandboxExpired, []string{}},
		{"the user filters to someone else's sandbox", callers()[0], "?sandbox=" + sandboxOther, []string{}},
		{"a sandbox agent filters to its own", callers()[3], "?sandbox=" + sandboxMine, []string{agentInMine2, agentInMine1}},
		{"a sandbox agent filters to another sandbox", callers()[3], "?sandbox=" + sandboxSecond, []string{}},
		{"an ordinary agent filters to a sandbox", callers()[2], "?sandbox=" + sandboxMine, []string{}},
		{"the filter and the page together", callers()[0], "?sandbox=" + sandboxMine + "&limit=1", []string{agentInMine2}},
		{"the filter and a cursor", callers()[0], "?sandbox=" + sandboxMine + "&cursor=" + agentInMine2,
			[]string{agentInMine1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := sandboxRig(t)
			send := tt.caller.credential(rg)

			rec := send(http.MethodGet, collection+tt.query, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body %q", rec.Code, rec.Body.String())
			}

			if got := idsOf(t, rec); !slices.Equal(got, tt.want) {
				t.Errorf("agents = %v, want %v", got, tt.want)
			}

			if len(rg.store.calls) != 1 {
				t.Fatalf("store calls = %+v, want one", rg.store.calls)
			}

			call := rg.store.calls[0]

			confined := tt.caller.agent != ""
			if call.owner != userA || call.confined != confined || call.confinedTo != tt.caller.sandbox {
				t.Errorf("reach = owner %q confined %v to %q, want %q, %v, %q",
					call.owner, call.confined, call.confinedTo, userA, confined, tt.caller.sandbox)
			}
		})
	}
}

// TestListOfAnotherUserIsEmptyWhateverTheSandbox: user B's sandbox agent is
// reached by B alone, and A's sandbox filter naming B's sandbox finds nothing
// of B's.
func TestListOfAnotherUserIsEmptyWhateverTheSandbox(t *testing.T) {
	t.Parallel()

	rg := sandboxRig(t)

	rec := rg.as(rg.signIn(userB, roleMember), http.MethodGet, collection, "")
	if got := idsOf(t, rec); !slices.Equal(got, []string{agentOfOtherSB}) {
		t.Errorf("B's agents = %v, want only B's own", got)
	}

	rec = rg.as(rg.signIn(userB, roleMember), http.MethodGet, collection+"?sandbox="+sandboxMine, "")
	if got := idsOf(t, rec); len(got) != 0 {
		t.Errorf("B's agents in A's sandbox = %v, want none", got)
	}
}

// TestListRefusesASandboxFilterItCannotRead: the sandbox query is parsed once,
// refused and not corrected, and the store is not asked.
func TestListRefusesASandboxFilterItCannotRead(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, query string }{
		{"present but empty", "?sandbox="},
		{"upper case", "?sandbox=" + strings.ToUpper(sandboxMine)},
		{"not an id", "?sandbox=nope"},
		{"the first-page sentinel", "?sandbox=g"},
		{"given twice", "?sandbox=" + sandboxMine + "&sandbox=" + sandboxMine},
		{"given twice, different", "?sandbox=" + sandboxMine + "&sandbox=" + sandboxSecond},
		{"a list", "?sandbox=" + url.QueryEscape(sandboxMine+","+sandboxSecond)},
		{"an injection", "?sandbox=" + url.QueryEscape("' OR '1'='1")},
		{"a trailing space", "?sandbox=" + url.QueryEscape(sandboxMine+" ")},
		{"a NUL", "?sandbox=" + sandboxMine + "%00"},
	}

	for _, tt := range tests {
		for _, who := range callers() {
			t.Run(tt.name+" as "+who.name, func(t *testing.T) {
				t.Parallel()

				rg := sandboxRig(t)
				send := who.credential(rg)

				rec := send(http.MethodGet, collection+tt.query, "")

				wantCode(t, rg, rec, http.StatusBadRequest, codeInvalidSandboxQ)
				rg.untouched()
			})
		}
	}
}

// TestGetReachesOnlyWhatTheCallerMay is the same confinement for one agent: an
// agent outside the caller's reach is the 404 of an agent that does not exist.
func TestGetReachesOnlyWhatTheCallerMay(t *testing.T) {
	t.Parallel()

	targets := []string{agentA1, agentInMine1, agentInMine2, agentInSecond, agentOfOtherSB, nobody}

	// reached[caller] is which targets each caller may read.
	reached := map[string][]string{
		"a session":                      {agentA1, agentInMine1, agentInMine2, agentInSecond},
		"the user's own key":             {agentA1, agentInMine1, agentInMine2, agentInSecond},
		"an ordinary agent":              {agentA1},
		"an agent of the first sandbox":  {agentInMine1, agentInMine2},
		"an agent of the second sandbox": {agentInSecond},
	}

	for _, who := range callers() {
		for _, target := range targets {
			t.Run(who.name+" reading "+target, func(t *testing.T) {
				t.Parallel()

				rg := sandboxRig(t)
				send := who.credential(rg)

				rec := send(http.MethodGet, itemPrefix+target, "")

				if slices.Contains(reached[who.name], target) {
					if rec.Code != http.StatusOK {
						t.Fatalf("status = %d, body %q, want 200", rec.Code, rec.Body.String())
					}

					var got agents.Agent

					err := json.Unmarshal(rec.Body.Bytes(), &got)
					if err != nil || got.ID != target {
						t.Errorf("body %q (%v), want agent %s", rec.Body.String(), err, target)
					}

					return
				}

				wantFailure(t, rg, rec, http.StatusNotFound, bodyNotFound, codeNotFound)

				call := rg.store.calls[0]
				if call.confined != (who.agent != "") || call.confinedTo != who.sandbox {
					t.Errorf("reach = confined %v to %q", call.confined, call.confinedTo)
				}
			})
		}
	}
}

// TestAgentJSONShowsItsSandbox: sandboxId is present for an agent in a sandbox
// and absent for an ordinary one, in a list, a read, a rename and a revoke.
func TestAgentJSONShowsItsSandbox(t *testing.T) {
	t.Parallel()

	withSandboxJSON := func(id, name string, createdAt int64, sandbox string) string {
		plain := agentJSON(id, name, createdAt, nil)

		return strings.TrimSuffix(plain, "}") + `,"sandboxId":"` + sandbox + `"}`
	}

	tests := []struct {
		name         string
		method, path string
		body         string
		want         string
	}{
		{"read an agent in a sandbox", http.MethodGet, itemPrefix + agentInMine1, "",
			withSandboxJSON(agentInMine1, "in mine one", 300, sandboxMine)},
		{"read an ordinary agent", http.MethodGet, itemPrefix + agentA1, "",
			agentJSON(agentA1, "ordinary one", 100, nil)},
		{"rename an agent in a sandbox", http.MethodPatch, itemPrefix + agentInSecond, bodyRenamed,
			withSandboxJSON(agentInSecond, "renamed", 500, sandboxSecond)},
		{"rename an ordinary agent", http.MethodPatch, itemPrefix + agentA1, bodyRenamed,
			agentJSON(agentA1, "renamed", 100, nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := sandboxRig(t)

			rec := rg.as(rg.signIn(userA, roleMember), tt.method, tt.path, tt.body)

			wantOK(t, rg, rec, http.StatusOK, tt.want+"\n")
		})
	}

	t.Run("revoke an agent in a sandbox", func(t *testing.T) {
		t.Parallel()

		rg := sandboxRig(t)

		rec := rg.as(rg.signIn(userA, roleMember), http.MethodDelete, itemPrefix+agentInSecond, "")

		var got agents.Agent

		err := json.Unmarshal(rec.Body.Bytes(), &got)
		if err != nil || rec.Code != http.StatusOK {
			t.Fatalf("response = %d %q (%v)", rec.Code, rec.Body.String(), err)
		}

		if got.SandboxID == nil || *got.SandboxID != sandboxSecond || got.Status != agents.StatusRevoked {
			t.Errorf("revoked agent = %+v, want revoked in %s", got, sandboxSecond)
		}
	})
}

// TestRenameAndRevokeStayOwnerScoped: the user reaches their sandbox agents
// with the owner-scoped routes, and another user's sandbox agent is the 404 of
// one that does not exist.
func TestRenameAndRevokeStayOwnerScoped(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodPatch, http.MethodDelete} {
		t.Run(method+" of another user's sandbox agent", func(t *testing.T) {
			t.Parallel()

			rg := sandboxRig(t)

			rec := rg.as(rg.signIn(userA, roleMember), method, itemPrefix+agentOfOtherSB, bodyRenamed)

			wantFailure(t, rg, rec, http.StatusNotFound, bodyNotFound, codeNotFound)
		})
	}
}

// createInSandboxBody is a create naming a sandbox, as raw JSON text.
func createInSandboxBody(raw string) string { return `{"name":"x","sandboxId":` + raw + `}` }

// TestCreateInASandbox is the create of a user: an agent in a sandbox they
// administer is created and reports it; one in anyone else's, an expired one or
// one that does not exist is the same 404, and nothing is written. The store's
// write decides, so the table is what the handler asks and answers.
func TestCreateInASandbox(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		caller  caller
		sandbox string
		status  int
		want    string // the sandbox in the response, "" for none
	}{
		{"own sandbox, by session", callers()[0], sandboxMine, http.StatusCreated, sandboxMine},
		{"own sandbox, by key", callers()[1], sandboxMine, http.StatusCreated, sandboxMine},
		{"another own sandbox", callers()[0], sandboxSecond, http.StatusCreated, sandboxSecond},
		{"someone else's sandbox", callers()[0], sandboxOther, http.StatusNotFound, ""},
		{"someone else's sandbox, by key", callers()[1], sandboxOther, http.StatusNotFound, ""},
		{"an expired sandbox", callers()[0], sandboxExpired, http.StatusNotFound, ""},
		{"a sandbox that does not exist", callers()[0], sandboxNone, http.StatusNotFound, ""},
		{"an agent id as the sandbox", callers()[0], agentA1, http.StatusNotFound, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := sandboxRig(t)
			send := tt.caller.credential(rg)

			rec := send(http.MethodPost, collection, createInSandboxBody(`"`+tt.sandbox+`"`))

			if tt.status == http.StatusNotFound {
				wantFailure(t, rg, rec, http.StatusNotFound,
					errorBody(codeSandboxNotFound, "no such sandbox"), codeSandboxNotFound)

				if len(rg.store.rows) != 6 {
					t.Errorf("a refused create left an agent behind: %d agents", len(rg.store.rows))
				}

				return
			}

			checkInSandbox(t, rg, rec, tt.want)

			written := rg.store.calls[0].agent
			if written.Sandbox.String() != tt.sandbox || written.CreatedBy != "" || written.Owner != userA {
				t.Errorf("written = sandbox %q by %q for %q, want %q by nobody for %q",
					written.Sandbox.String(), written.CreatedBy, written.Owner, tt.sandbox, userA)
			}
		})
	}
}

// checkInSandbox checks a create that succeeded: the response and the stored
// agent both say the new agent is in want, or in none when it is "".
func checkInSandbox(t *testing.T, rg *rig, rec *httptest.ResponseRecorder, want string) {
	t.Helper()

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %q, want 201", rec.Code, rec.Body.String())
	}

	reported := ""
	if in := created(t, rec.Body.Bytes()).Agent.SandboxID; in != nil {
		reported = *in
	}

	if reported != want || strings.Contains(rec.Body.String(), "sandboxId") != (want != "") {
		t.Errorf("response %s reports sandbox %q, want %q", rec.Body.String(), reported, want)
	}

	if got := rg.store.sandboxOf(newAgentID); got != want {
		t.Errorf("stored sandbox = %q, want %q", got, want)
	}
}

// TestCreateWithoutASandbox: no sandboxId, null, and a user's ordinary create
// are all an ordinary agent, with no sandboxId in the response.
func TestCreateWithoutASandbox(t *testing.T) {
	t.Parallel()

	for name, body := range map[string]string{
		"absent": `{"name":"x"}`,
		"null":   createInSandboxBody("null"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rg := sandboxRig(t)

			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, body)
			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d, body %q", rec.Code, rec.Body.String())
			}

			if strings.Contains(rec.Body.String(), "sandboxId") {
				t.Errorf("an ordinary agent reports a sandbox: %s", rec.Body.String())
			}

			if got := rg.store.calls[0].agent.Sandbox.String(); got != "" {
				t.Errorf("written sandbox = %q, want none", got)
			}
		})
	}
}

// TestCreateRefusesASandboxIdItCannotRead: a sandboxId that is not exactly a
// canonical id (or not a string) is refused before anything is issued or
// written, whoever asks.
func TestCreateRefusesASandboxIdItCannotRead(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		code string
	}{
		{"an empty string", `""`, codeInvalidSandbox},
		{"upper case", `"` + strings.ToUpper(sandboxMine) + `"`, codeInvalidSandbox},
		{"not an id", `"nope"`, codeInvalidSandbox},
		{"with a trailing newline", `"` + sandboxMine + `\n"`, codeInvalidSandbox},
		{"with a NUL", `"` + sandboxMine + `\u0000"`, codeInvalidSandbox},
		{"an injection", `"' OR '1'='1"`, codeInvalidSandbox},
		{"a number", `5`, codeFieldType},
		{"true", `true`, codeFieldType},
		{"an object", `{}`, codeFieldType},
		{"an array of ids", `["` + sandboxMine + `"]`, codeFieldType},
	}

	for _, tt := range tests {
		for _, who := range callers() {
			t.Run(tt.name+" as "+who.name, func(t *testing.T) {
				t.Parallel()

				rg := sandboxRig(t)
				send := who.credential(rg)

				rec := send(http.MethodPost, collection, createInSandboxBody(tt.raw))

				wantBadRequest(t, rg, rec, tt.code)
				rg.untouched()
			})
		}
	}
}

// TestAnAgentsCreateLandsInItsOwnSandbox: an agent that creates an agent gets
// one in its own sandbox, or an ordinary one when it is in none. It may leave
// the sandbox out or repeat its own; naming any other is refused whatever that
// sandbox is (its user's own, someone else's, one that does not exist), and the
// store is never asked. The sandbox the write stored is what is reported.
func TestAnAgentsCreateLandsInItsOwnSandbox(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		creator caller
		body    string
		status  int
		want    string // the sandbox of the new agent, "" for none
		code    string
	}{
		{"a sandbox agent names nothing", callers()[3], `{"name":"x"}`, http.StatusCreated, sandboxMine, ""},
		{"a sandbox agent names null", callers()[3], createInSandboxBody("null"), http.StatusCreated, sandboxMine, ""},
		{"a sandbox agent names its own", callers()[3], createInSandboxBody(`"` + sandboxMine + `"`),
			http.StatusCreated, sandboxMine, ""},
		{"another sandbox's agent names nothing", callers()[4], `{"name":"x"}`, http.StatusCreated, sandboxSecond, ""},
		{"an ordinary agent names nothing", callers()[2], `{"name":"x"}`, http.StatusCreated, "", ""},
		{"a sandbox agent names another of the user's", callers()[3], createInSandboxBody(`"` + sandboxSecond + `"`),
			http.StatusForbidden, "", codeSandboxInherited},
		{"a sandbox agent names someone else's", callers()[3], createInSandboxBody(`"` + sandboxOther + `"`),
			http.StatusForbidden, "", codeSandboxInherited},
		{"a sandbox agent names one that does not exist", callers()[3], createInSandboxBody(`"` + sandboxNone + `"`),
			http.StatusForbidden, "", codeSandboxInherited},
		{"an ordinary agent names a sandbox of its user", callers()[2], createInSandboxBody(`"` + sandboxMine + `"`),
			http.StatusForbidden, "", codeSandboxInherited},
		{"an ordinary agent names a sandbox that does not exist", callers()[2], createInSandboxBody(`"` + sandboxNone + `"`),
			http.StatusForbidden, "", codeSandboxInherited},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := sandboxRig(t)
			send := tt.creator.credential(rg)

			rec := send(http.MethodPost, collection, tt.body)

			if tt.status != http.StatusCreated {
				wantCode(t, rg, rec, tt.status, tt.code)

				if len(rg.issueCalls) != 0 || rg.writes() != 0 {
					t.Errorf("a refused create issued %d keys and %d writes", len(rg.issueCalls), rg.writes())
				}

				return
			}

			checkInSandbox(t, rg, rec, tt.want)

			// The write names the creating agent, which is what makes the store
			// read the sandbox from its row.
			if rg.store.calls[0].agent.CreatedBy != tt.creator.agent {
				t.Errorf("created by %q, want %q", rg.store.calls[0].agent.CreatedBy, tt.creator.agent)
			}
		})
	}
}

// TestAnAgentChoosingScopesIsRefusedBeforeItsSandbox: the order of the refusals
// of an agent's create is fixed, scopes first, so a request with both wrong is
// told the first and never the second.
func TestAnAgentChoosingScopesIsRefusedBeforeItsSandbox(t *testing.T) {
	t.Parallel()

	rg := sandboxRig(t)
	send := callers()[3].credential(rg)

	rec := send(http.MethodPost, collection,
		`{"name":"x","scopes":["agent:read"],"sandboxId":"`+sandboxSecond+`"}`)

	wantCode(t, rg, rec, http.StatusForbidden, agents.CodeScopesInherited)
}

// TestAnAgentWhoseSandboxExpiredCreatesNothing: the creating agent's sandbox is
// checked in the write, so an agent authenticated just before its sandbox ran
// out creates nothing. It is the conflict every refusal of an agent's write is,
// and no agent is left behind.
func TestAnAgentWhoseSandboxExpiredCreatesNothing(t *testing.T) {
	t.Parallel()

	rg := sandboxRig(t)
	rg.store.sandboxes[sandboxMine] = fakeSandbox{admin: userA, expired: true}

	send := callers()[3].credential(rg)

	rec := send(http.MethodPost, collection, `{"name":"x"}`)

	wantFailure(t, rg, rec, http.StatusConflict,
		errorBody("agent_limit_reached", "an account may have at most 25 active agents"), agents.CodeLimit)

	if got := rg.store.sandboxOf(newAgentID); got != "" || len(rg.store.rows) != 6 {
		t.Errorf("a refused create left %d agents (new one in %q)", len(rg.store.rows), got)
	}
}

// TestASandboxRefusalCarriesTheConflictToo: the store's refusal of a sandbox
// also wraps the conflict every refused create is, and the sandbox is judged
// first, so the client is told the sandbox is missing and not that it is at the
// limit.
func TestASandboxRefusalCarriesTheConflictToo(t *testing.T) {
	t.Parallel()

	rg := sandboxRig(t)
	rg.store.failures[methodCreate] = store.ErrSandboxUnavailable

	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, createInSandboxBody(`"`+sandboxMine+`"`))

	wantFailure(t, rg, rec, http.StatusNotFound, errorBody(codeSandboxNotFound, "no such sandbox"), codeSandboxNotFound)

	rg = sandboxRig(t)
	rg.store.failures[methodCreate] = store.ErrConflict

	rec = rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, createInSandboxBody(`"`+sandboxMine+`"`))

	wantFailure(t, rg, rec, http.StatusConflict,
		errorBody("agent_limit_reached", "an account may have at most 25 active agents"), agents.CodeLimit)
}

// TestASandboxedAgentMayUseOnlyTheListTheReadAndTheCreate: every other agent
// route refuses it at the boundary, before the store, with its own code.
func TestASandboxedAgentMayUseOnlyTheListTheReadAndTheCreate(t *testing.T) {
	t.Parallel()

	for _, route := range everyRoute() {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()

			rg := sandboxRig(t)
			send := callers()[3].credential(rg)

			rec := send(route.method, route.target, route.body)

			usable := route.name == routeList || route.name == routeCreate || route.name == routeGet
			if usable {
				if rec.Code == http.StatusForbidden {
					t.Errorf("%s is refused to a sandboxed agent: %s", route.name, rec.Body.String())
				}

				return
			}

			wantCode(t, rg, rec, http.StatusForbidden, "sandbox_confined")
			rg.untouched()
		})
	}
}
