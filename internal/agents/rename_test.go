package agents_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/store"
)

// TestRename: the agent comes back as the write left it, and the store is
// asked, for the session's user, to rename exactly the agent in the path.
func TestRename(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		agent  store.Agent
		body   string
		status int
		want   string
		// stored is the name the agent has afterwards.
		stored string
	}{
		{
			name: "an active agent", agent: stored(agentA1, nameAlpha, 100, nil), body: bodyRenamed,
			status: http.StatusOK, want: agentJSON(agentA1, "renamed", 100, nil), stored: "renamed",
		},
		{
			name: "the same name", agent: stored(agentA1, nameAlpha, 100, nil), body: `{"name":"alpha"}`,
			status: http.StatusOK, want: agentJSON(agentA1, nameAlpha, 100, nil), stored: nameAlpha,
		},
		{
			name: "a name kept as sent", agent: stored(agentA1, nameAlpha, 100, nil), body: `{"name":"  b  "}`,
			status: http.StatusOK, want: agentJSON(agentA1, "  b  ", 100, nil), stored: "  b  ",
		},
		{
			name: "a revoked agent keeps its name", agent: stored(agentA1, nameAlpha, 100, new(int64(150))), body: bodyRenamed,
			status: http.StatusConflict, want: errorBody("agent_revoked", "the agent is revoked and cannot be changed"),
			stored: nameAlpha,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, tt.agent)

			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPatch, itemPrefix+agentA1, tt.body)

			if tt.status == http.StatusOK {
				wantOK(t, rg, rec, tt.status, tt.want+"\n")
			} else {
				wantFailure(t, rg, rec, tt.status, tt.want, "agent_revoked")
			}

			if got := rg.store.agent(t, agentA1).Name; got != tt.stored {
				t.Errorf("the agent is named %q afterwards, want %q", got, tt.stored)
			}

			if len(rg.store.calls) != 1 || rg.store.calls[0].method != methodRename ||
				rg.store.calls[0].owner != userA || rg.store.calls[0].id != agentA1 {
				t.Errorf("store calls = %+v, want one rename of %s for %s", rg.store.calls, agentA1, userA)
			}
		})
	}
}

// TestRenameFindsNothingToRename: an agent that does not exist, and the ids that
// are not agents at all.
func TestRenameFindsNothingToRename(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rg.seed(userA, stored(agentA1, nameAlpha, 100, nil))

	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPatch, itemPrefix+nobody, bodyX)

	wantFailure(t, rg, rec, http.StatusNotFound, bodyNotFound, codeNotFound)

	if got := rg.store.agent(t, agentA1).Name; got != nameAlpha {
		t.Errorf("another agent was renamed to %q", got)
	}
}

// TestRenameRefusesWhatItCannotUse: nothing reaches the store.
func TestRenameRefusesWhatItCannotUse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		body   string
		status int
		code   string
	}{
		{name: "no body", body: "", status: http.StatusBadRequest, code: "empty_body"},
		{name: "no name", body: `{}`, status: http.StatusBadRequest, code: "missing_agent_name"},
		{name: "a null name", body: `{"name":null}`, status: http.StatusBadRequest, code: "missing_agent_name"},
		{name: "an empty name", body: `{"name":""}`, status: http.StatusBadRequest, code: codeInvalidName},
		{name: "a blank name", body: `{"name":"   "}`, status: http.StatusBadRequest, code: codeInvalidName},
		{name: "a control character", body: `{"name":"a\u0000b"}`, status: http.StatusBadRequest, code: codeInvalidName},
		{name: "a format character", body: `{"name":"a\u200bb"}`, status: http.StatusBadRequest, code: codeInvalidName},
		{name: "a bidi override", body: `{"name":"a\u202eb"}`, status: http.StatusBadRequest, code: codeInvalidName},
		{name: "decomposed text", body: `{"name":"cafe\u0301"}`, status: http.StatusBadRequest, code: codeInvalidName},
		{
			name: "too long", body: `{"name":"` + strings.Repeat("a", 257) + `"}`,
			status: http.StatusBadRequest, code: codeInvalidName,
		},
		{
			name: "too long in four-byte characters", body: nameBodyOf(strings.Repeat("\U0001F600", 257)),
			status: http.StatusBadRequest, code: codeInvalidName,
		},
		{name: "a number", body: `{"name":5}`, status: http.StatusBadRequest, code: codeFieldType},
		{name: "not json", body: `name=x`, status: http.StatusBadRequest, code: codeInvalidJSON},
		{
			name: "an unknown member", body: `{"name":"a","revoked":true}`,
			status: http.StatusBadRequest, code: codeUnknownField,
		},
		{name: "a repeated name", body: `{"name":"a","name":"b"}`, status: http.StatusBadRequest, code: "duplicate_field"},
		{name: "trailing data", body: `{"name":"a"}x`, status: http.StatusBadRequest, code: "trailing_data"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, stored(agentA1, nameAlpha, 100, nil))

			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPatch, itemPrefix+agentA1, tt.body)

			wantCode(t, rg, rec, tt.status, tt.code)
			rg.untouched()
		})
	}
}

// nameBodyOf is the body of a request naming name, for a table built outside a
// test.
func nameBodyOf(name string) string { return `{"name":"` + name + `"}` }

// TestRenameMissingNameMessage pins the exact refusal of a missing name.
func TestRenameMissingNameMessage(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPatch, itemPrefix+agentA1, `{}`)

	wantFailure(t, rg, rec, http.StatusBadRequest,
		errorBody("missing_agent_name", "name is required"), "missing_agent_name")
}

// TestRenameAcceptsNamesAtTheLimit: the bounds are those of a create, in
// characters, whatever their width in bytes, and the name is stored as sent.
func TestRenameAcceptsNamesAtTheLimit(t *testing.T) {
	t.Parallel()

	widths := []struct {
		name string
		char string
	}{
		{name: "one byte", char: "a"},
		{name: "two bytes", char: "\u00e9"},
		{name: "four bytes", char: "\U0001F600"},
	}

	for _, tt := range widths {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, stored(agentA1, nameAlpha, 100, nil))

			name := strings.Repeat(tt.char, 256)
			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPatch, itemPrefix+agentA1, nameBody(t, name))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body %.200q, want 200", rec.Code, rec.Body.String())
			}

			if got := rg.store.agent(t, agentA1).Name; got != name || len(got) > 1024 {
				t.Errorf("stored %d bytes, want the %d-byte name as sent", len(got), len(name))
			}
		})
	}
}
