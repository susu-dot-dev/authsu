//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// Everything this file defines at package level is prefixed "agent" so that it
// cannot collide with the helpers of another area's test file.

const (
	// agentLabelsColumn is the labels column every agent statement returns.
	agentLabelsColumn = "(SELECT json_group_array(label) FROM (SELECT label FROM agent_labels " +
		"WHERE agent_id = agents.id ORDER BY label)) AS labels"

	agentsUnavailable = "agents are temporarily unavailable"
	agentOwner        = "user-1"
	agentTarget       = "01900000-0000-7000-8000-000000000042"

	// agentSandbox and agentOtherSandbox are two sandboxes.
	agentSandbox      = "01900000-0000-7000-8000-0000000005a1"
	agentOtherSandbox = "01900000-0000-7000-8000-0000000005a2"
	agentCursorID     = "01900000-0000-7000-8000-000000000050"

	// agentLargestID is the greatest id an agent can have, in the order the
	// database sorts text: the first page's cursor must be above it.
	agentLargestID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
)

// agentIDAt returns the canonical id of the n-th agent. A larger n is a later
// agent and sorts higher.
func agentIDAt(n int) string { return fmt.Sprintf("01900000-0000-7000-8000-%012d", n) }

// agentRowAt is a returned agent row: id, name, scopes, revoked_at, created_at,
// labels (the JSON text of an array, as json_group_array returns it) and
// sandbox_id (NULL for an ordinary agent).
func agentRowAt(n int) []any {
	return row(agentIDAt(n), "agent "+strconv.Itoa(n), `["default:agent"]`, nil, int64(1_700_000_000+n), "[]", nil)
}

// agentRow is the row of the agent agentTarget.
func agentRow() []any {
	return row(agentTarget, "build bot", `["default:agent"]`, nil, int64(1_700_000_000), "[]", nil)
}

// agentRevokedRow is agentRow once it is revoked.
func agentRevokedRow() []any { return with(agentRow(), 3, int64(1_700_000_100)) }

func mustAgentName(tb testing.TB, raw string) input.AgentName {
	tb.Helper()

	name, err := input.ParseAgentName(raw)
	if err != nil {
		tb.Fatalf("parse agent name %q: %v", raw, err)
	}

	return name
}

func mustAgentSandboxID(tb testing.TB, raw string) input.SandboxID {
	tb.Helper()

	id, err := input.ParseSandboxID(raw)
	if err != nil {
		tb.Fatalf("parse sandbox id %q: %v", raw, err)
	}

	return id
}

func mustAgentID(tb testing.TB) input.ID {
	tb.Helper()

	id, err := input.ParseID(agentTarget)
	if err != nil {
		tb.Fatalf("parse id %q: %v", agentTarget, err)
	}

	return id
}

func mustAgentCursor(tb testing.TB, values ...string) input.Cursor {
	tb.Helper()

	cursor, err := input.ParseCursor(values)
	if err != nil {
		tb.Fatalf("parse cursor %q: %v", values, err)
	}

	return cursor
}

// mustAgentFilter is the list filter that names the label in values, or none.
func mustAgentFilter(tb testing.TB, values ...string) store.AgentFilter {
	tb.Helper()

	filter, err := input.ParseLabelFilter(values)
	if err != nil {
		tb.Fatalf("parse label filter %q: %v", values, err)
	}

	return store.AgentFilter{Label: filter, Sandbox: input.SandboxFilter{}}
}

// mustAgentSandboxFilter is the list filter that names the sandbox in values.
func mustAgentSandboxFilter(tb testing.TB, values ...string) store.AgentFilter {
	tb.Helper()

	filter, err := input.ParseSandboxFilter(values)
	if err != nil {
		tb.Fatalf("parse sandbox filter %q: %v", values, err)
	}

	return store.AgentFilter{Label: input.LabelFilter{}, Sandbox: filter}
}

func mustAgentLabelPatch(tb testing.TB, add, remove []string) input.LabelPatch {
	tb.Helper()

	patch, err := input.ParseLabelPatch(add, remove)
	if err != nil {
		tb.Fatalf("parse label patch %q %q: %v", add, remove, err)
	}

	return patch
}

func mustAgentLabelSet(tb testing.TB, labels ...string) input.LabelSet {
	tb.Helper()

	set, err := input.ParseLabelSet(labels)
	if err != nil {
		tb.Fatalf("parse label set %q: %v", labels, err)
	}

	return set
}

func mustAgentLimit(tb testing.TB, values ...string) input.PageLimit {
	tb.Helper()

	limit, err := input.ParsePageLimit(values)
	if err != nil {
		tb.Fatalf("parse limit %q: %v", values, err)
	}

	return limit
}

// agentRevoked is a batch of the two statements a revoke runs: the first
// returned rows, and the second changed keys.
func agentRevoked(keys int64, rows ...[]any) outcome {
	return outcome{results: []store.Result{{Changes: 0, Rows: rows}, {Changes: keys, Rows: nil}}, err: nil}
}

// agentWriteFailures is infraFailures for an operation that writes nothing a
// constraint of the data could refuse (rename and revoke): a conflict is a
// defect there, and not something for the feature to map.
func agentWriteFailures(statements int, failed, rejected string) []failure {
	failures := infraFailures(statements, failed, rejected, agentsUnavailable)

	for i := range failures {
		if failures[i].conflict {
			failures[i].conflict = false
			failures[i].want = wantErr{kind: apierr.Internal, code: rejected, description: internalDescription}
		}
	}

	return failures
}

// agentOp is one operation that reads an agent row, for the tables that hold
// for all of them.
type agentOp struct {
	name     string
	rejected string

	// one is true when the operation reads exactly one row, false for a page.
	one bool

	// outcome is the batch the operation gets for the rows its first statement
	// returned.
	outcome func(rows ...[]any) outcome

	// call runs the operation and returns the agents it read.
	call func(*store.Store) ([]store.Agent, error)
}

// agentReadOps are the operations that decode agent rows.
func agentReadOps(t *testing.T) []agentOp {
	t.Helper()

	ctx := context.Background()
	id := mustAgentID(t)
	name := mustAgentName(t, "renamed")
	limit := mustAgentLimit(t)
	cursor := mustAgentCursor(t)

	single := func(agent store.Agent, err error) ([]store.Agent, error) { return []store.Agent{agent}, err }

	return []agentOp{
		{
			name: "list", rejected: store.CodeAgentListRejected, one: false, outcome: returning,
			call: func(s *store.Store) ([]store.Agent, error) {
				page, err := s.ListAgents(ctx, store.OwnAgents(agentOwner), cursor, limit, mustAgentFilter(t))

				return page.Agents, passErr(err)
			},
		},
		{
			name: "get", rejected: store.CodeAgentLookupRejected, one: true, outcome: returning,
			call: func(s *store.Store) ([]store.Agent, error) {
				return single(s.GetAgent(ctx, store.OwnAgents(agentOwner), id))
			},
		},
		{
			name: "patch", rejected: store.CodeAgentUpdateRejected, one: true,
			// A patch of a name and no labels: the rename, then the read.
			outcome: func(rows ...[]any) outcome {
				return outcome{results: []store.Result{{Changes: 1, Rows: nil}, {Changes: 0, Rows: rows}}, err: nil}
			},
			call: func(s *store.Store) ([]store.Agent, error) {
				return single(s.PatchAgent(ctx, agentOwner, id, store.AgentPatch{
					Name: &name, Labels: mustAgentLabelPatch(t, nil, nil), MaxLabels: input.MaxLabelsPerAgent,
				}))
			},
		},
		{
			name: "revoke", rejected: store.CodeAgentRevokeRejected, one: true,
			outcome: func(rows ...[]any) outcome { return agentRevoked(0, rows...) },
			call: func(s *store.Store) ([]store.Agent, error) {
				return single(s.RevokeAgent(ctx, agentOwner, id, now))
			},
		},
	}
}

// agentDecodingCase is a returned row and the agent it decodes to.
type agentDecodingCase struct {
	name string
	row  []any
	want store.Agent
}

// agentDecodingCases are the rows TestAgentDecoding reads.
func agentDecodingCases() []agentDecodingCase {
	revokedAt := int64(1_700_000_100)

	return []agentDecodingCase{
		{name: "an active agent", row: agentRow(), want: store.Agent{
			ID: agentTarget, Name: "build bot", Scopes: `["default:agent"]`, RevokedAt: nil, CreatedAt: 1_700_000_000,
			Labels: []string{},
		}},
		{name: "a revoked agent", row: agentRevokedRow(), want: store.Agent{
			ID: agentTarget, Name: "build bot", Scopes: `["default:agent"]`, RevokedAt: &revokedAt, CreatedAt: 1_700_000_000,
			Labels: []string{},
		}},
		{name: "a multibyte name is kept as is", row: with(agentRow(), 1, "ビルド・ボット 🤖"), want: store.Agent{
			ID: agentTarget, Name: "ビルド・ボット 🤖", Scopes: `["default:agent"]`, RevokedAt: nil, CreatedAt: 1_700_000_000,
			Labels: []string{},
		}},
		{name: "one label", row: with(agentRow(), 5, `["prod"]`), want: store.Agent{
			ID: agentTarget, Name: "build bot", Scopes: `["default:agent"]`, RevokedAt: nil, CreatedAt: 1_700_000_000,
			Labels: []string{"prod"},
		}},
		{name: "labels are kept in the order the database gave them",
			row: with(agentRow(), 5, `["a","b.c","d-e","f_g","0"]`), want: store.Agent{
				ID: agentTarget, Name: "build bot", Scopes: `["default:agent"]`, RevokedAt: nil, CreatedAt: 1_700_000_000,
				Labels: []string{"a", "b.c", "d-e", "f_g", "0"},
			}},
		{name: "labels with whitespace in the JSON", row: with(agentRow(), 5, ` [ "a" , "b" ] `), want: store.Agent{
			ID: agentTarget, Name: "build bot", Scopes: `["default:agent"]`, RevokedAt: nil, CreatedAt: 1_700_000_000,
			Labels: []string{"a", "b"},
		}},
		{name: "an agent in a sandbox", row: with(agentRow(), 6, agentSandbox), want: store.Agent{
			ID: agentTarget, Name: "build bot", Scopes: `["default:agent"]`, RevokedAt: nil, CreatedAt: 1_700_000_000,
			Labels: []string{}, SandboxID: new(agentSandbox),
		}},
		{name: "a revoked agent in a sandbox, with labels",
			row: with(with(agentRevokedRow(), 6, agentSandbox), 5, `["a"]`), want: store.Agent{
				ID: agentTarget, Name: "build bot", Scopes: `["default:agent"]`, RevokedAt: &revokedAt, CreatedAt: 1_700_000_000,
				Labels: []string{"a"}, SandboxID: new(agentSandbox),
			}},
	}
}

// TestAgentDecoding holds how a returned row becomes an Agent, for every
// operation that reads one: they share a reader, and a column it reads wrongly
// would be wrong everywhere.
func TestAgentDecoding(t *testing.T) {
	t.Parallel()

	for _, op := range agentReadOps(t) {
		for _, test := range agentDecodingCases() {
			t.Run(op.name+"/"+test.name, func(t *testing.T) {
				t.Parallel()

				fake := newFake(op.outcome(test.row))

				got, err := op.call(fake.store())
				checkErr(t, err, nil)

				if !reflect.DeepEqual(got, []store.Agent{test.want}) {
					t.Errorf("agents = %+v (labels %#v), want %+v (labels %#v)", got, got[0].Labels, test.want, test.want.Labels)
				}
			})
		}
	}
}

// TestAgentDefects holds that a row that is not the agent the statement
// promises is a defect and not a missing agent or a wrong one: a lookup must
// not read a broken row as an absent one.
func TestAgentDefects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		row  []any
	}{
		{name: "id is an integer", row: with(agentRow(), 0, int64(1))},
		{name: "id is NULL", row: with(agentRow(), 0, nil)},
		{name: "name is NULL", row: with(agentRow(), 1, nil)},
		{name: "name is a blob", row: with(agentRow(), 1, []byte("bot"))},
		{name: "scopes is NULL", row: with(agentRow(), 2, nil)},
		{name: "scopes is an integer", row: with(agentRow(), 2, int64(1))},
		{name: "revoked_at is a float", row: with(agentRow(), 3, 1.7e9)},
		{name: "revoked_at is text", row: with(agentRow(), 3, "yesterday")},
		{name: "created_at is a float", row: with(agentRow(), 4, 1.7e9)},
		{name: "created_at is text", row: with(agentRow(), 4, "now")},
		{name: "created_at is NULL", row: with(agentRow(), 4, nil)},
		{name: "labels is NULL", row: with(agentRow(), 5, nil)},
		{name: "labels is an integer", row: with(agentRow(), 5, int64(1))},
		{name: "labels is a blob", row: with(agentRow(), 5, []byte("[]"))},
		{name: "labels is not JSON", row: with(agentRow(), 5, "a,b")},
		{name: "labels is empty text", row: with(agentRow(), 5, "")},
		{name: "labels is a JSON object", row: with(agentRow(), 5, `{"a":1}`)},
		{name: "labels is a JSON string", row: with(agentRow(), 5, `"a"`)},
		{name: "labels is JSON null", row: with(agentRow(), 5, `null`)},
		{name: "labels holds a number", row: with(agentRow(), 5, `[1]`)},
		{name: "labels holds null: not read as an empty label", row: with(agentRow(), 5, `[null]`)},
		{name: "labels holds null after a label", row: with(agentRow(), 5, `["a",null]`)},
		{name: "labels holds a nested array", row: with(agentRow(), 5, `[["a"]]`)},
		{name: "labels is truncated", row: with(agentRow(), 5, `["a"`)},
		{name: "sandbox_id is an integer", row: with(agentRow(), 6, int64(1))},
		{name: "sandbox_id is a blob", row: with(agentRow(), 6, []byte(agentSandbox))},
		{name: "sandbox_id is a float", row: with(agentRow(), 6, 1.5)},
		{name: "a column too few", row: agentRow()[:6]},
		{name: "the sandbox column is missing", row: agentRow()[:6]},
		{name: "the labels column is missing", row: agentRow()[:5]},
		{name: "a column too many", row: append(agentRow(), "extra")},
		{name: "an empty row", row: row()},
	}

	for _, op := range agentReadOps(t) {
		for _, test := range tests {
			t.Run(op.name+"/"+test.name, func(t *testing.T) {
				t.Parallel()

				fake := newFake(op.outcome(test.row))

				got, err := op.call(fake.store())

				checkErr(t, err, defectOf(op.rejected))

				if len(got) > 0 && got[0].ID != "" {
					t.Errorf("a defective row returned %+v", got)
				}
			})
		}
	}
}

// TestAgentSingleRowDefects holds that more than one row from a statement
// aimed at one agent is a defect, and no row is the agent not being there.
func TestAgentSingleRowDefects(t *testing.T) {
	t.Parallel()

	for _, op := range agentReadOps(t) {
		if !op.one {
			continue
		}

		t.Run(op.name+"/two rows", func(t *testing.T) {
			t.Parallel()

			fake := newFake(op.outcome(agentRow(), agentRow()))

			_, err := op.call(fake.store())

			checkErr(t, err, defectOf(op.rejected))
		})

		t.Run(op.name+"/no row", func(t *testing.T) {
			t.Parallel()

			fake := newFake(op.outcome())

			_, err := op.call(fake.store())
			if !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("error = %v, want ErrNotFound", err)
			}

			if _, isAPI := errors.AsType[*apierr.Error](err); isAPI {
				t.Errorf("a missing agent %v is classified; the feature must decide that", err)
			}
		})
	}
}

// agentPagingCase is one page read: how many rows the database gave back for a
// limit, and the page that makes.
type agentPagingCase struct {
	name  string
	limit input.PageLimit

	// size is the page size the limit stands for, so the statement must ask for
	// size+1 rows.
	size int

	// returned is how many rows the database gave back, agents how many of them
	// are on the page, and next whether the page names a following one.
	returned int
	agents   int
	next     bool
}

// checkAgentPage asserts the page a read produced: the first agents of the rows,
// in the database's order, and a cursor that is the id of the last of them.
func checkAgentPage(t *testing.T, page store.AgentPage, fake *fakeExec, test agentPagingCase) {
	t.Helper()

	if page.Agents == nil {
		t.Fatalf("page has nil agents, want %d", test.agents)
	}

	ids := make([]string, len(page.Agents))
	for i, agent := range page.Agents {
		ids[i] = agent.ID
	}

	checkPage(t, pageResult{ids: ids, next: page.Next, args: fake.calls[0][0].Args, argc: 7, idAt: agentIDAt},
		pageWant{size: test.size, ids: test.agents, next: test.next})
}

// TestListAgentsPaging holds how the rows of a page become the page: the query
// asks for one row more than the page holds, and that extra row only says there
// is a next page, whose cursor is the last agent that is returned.
func TestListAgentsPaging(t *testing.T) {
	t.Parallel()

	three := mustAgentLimit(t, "3")
	one := mustAgentLimit(t, "1")

	tests := []agentPagingCase{
		{name: "no agents", limit: three, size: 3, returned: 0, agents: 0, next: false},
		{name: "fewer than the limit", limit: three, size: 3, returned: 2, agents: 2, next: false},
		{name: "exactly the limit: no next page", limit: three, size: 3, returned: 3, agents: 3, next: false},
		{name: "one more than the limit: a next page", limit: three, size: 3, returned: 4, agents: 3, next: true},
		{name: "a limit of one, with a next page", limit: one, size: 1, returned: 2, agents: 1, next: true},
		{name: "a limit of one, the last agent", limit: one, size: 1, returned: 1, agents: 1, next: false},
		{name: "the default limit", limit: mustAgentLimit(t), size: 25, returned: 26, agents: 25, next: true},
		{name: "the largest limit", limit: mustAgentLimit(t, "100"), size: 100, returned: 101, agents: 100, next: true},
		{name: "a zero PageLimit is read as 1", limit: input.PageLimit{}, size: 1, returned: 2, agents: 1, next: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Newest first: ids fall down the page.
			rows := make([][]any, test.returned)
			for i := range rows {
				rows[i] = agentRowAt(1000 - i)
			}

			fake := newFake(returning(rows...))

			page, err := fake.store().ListAgents(
				context.Background(), store.OwnAgents(agentOwner), mustAgentCursor(t), test.limit, mustAgentFilter(t))
			checkErr(t, err, nil)

			checkAgentPage(t, page, fake, test)
		})
	}
}

// TestListAgentsMoreRowsThanAsked holds that a database that returns more rows
// than the LIMIT it was given is a defect: the page would silently hold agents
// the cursor does not account for.
func TestListAgentsMoreRowsThanAsked(t *testing.T) {
	t.Parallel()

	fake := newFake(returning(agentRowAt(5), agentRowAt(4), agentRowAt(3)))

	page, err := fake.store().ListAgents(
		context.Background(), store.OwnAgents(agentOwner), mustAgentCursor(t), mustAgentLimit(t, "1"), mustAgentFilter(t))

	checkErr(t, err, defectOf(store.CodeAgentListRejected))

	if page.Agents != nil || page.Next != "" {
		t.Errorf("a defective page returned %+v", page)
	}
}

// listStatementCase is one list and the arguments it must bind.
type listStatementCase struct {
	name   string
	reach  store.AgentReach
	cursor input.Cursor
	limit  input.PageLimit

	filter store.AgentFilter

	// before is the cursor argument, or "" for the first page's bound.
	before string
	rows   int64

	// label, confined, confinedTo and sandbox are the arguments the filters
	// and the reach become: NULL (nil) for none.
	label      any
	confined   int64
	confinedTo any
	sandbox    any
}

// listStatementCases are the lists TestListAgentsStatement pins.
func listStatementCases(t *testing.T) []listStatementCase {
	t.Helper()

	return []listStatementCase{
		{name: "first page", reach: store.OwnAgents(agentOwner), cursor: mustAgentCursor(t), limit: mustAgentLimit(t),
			filter: mustAgentFilter(t), before: "", rows: 26, label: nil, confined: 0, confinedTo: nil, sandbox: nil},
		{name: "after a cursor", reach: store.OwnAgents(agentOwner), cursor: mustAgentCursor(t, agentCursorID),
			limit: mustAgentLimit(t, "7"), filter: mustAgentFilter(t), before: agentCursorID, rows: 8,
			label: nil, confined: 0, confinedTo: nil, sandbox: nil},
		{name: "filtered by a label", reach: store.OwnAgents(agentOwner), cursor: mustAgentCursor(t),
			limit: mustAgentLimit(t, "3"), filter: mustAgentFilter(t, "prod"), before: "", rows: 4,
			label: "prod", confined: 0, confinedTo: nil, sandbox: nil},
		{name: "filtered, after a cursor", reach: store.OwnAgents(agentOwner), cursor: mustAgentCursor(t, agentCursorID),
			limit: mustAgentLimit(t, "3"), filter: mustAgentFilter(t, "a.b_c-1"), before: agentCursorID, rows: 4,
			label: "a.b_c-1", confined: 0, confinedTo: nil, sandbox: nil},
		{name: "filtered by a sandbox", reach: store.OwnAgents(agentOwner), cursor: mustAgentCursor(t),
			limit: mustAgentLimit(t, "3"), filter: mustAgentSandboxFilter(t, agentSandbox), before: "", rows: 4,
			label: nil, confined: 0, confinedTo: nil, sandbox: agentSandbox},
		{name: "an agent of a sandbox is confined to it", reach: store.SandboxAgents(agentOwner, agentSandbox),
			cursor: mustAgentCursor(t), limit: mustAgentLimit(t, "3"), filter: mustAgentFilter(t), before: "", rows: 4,
			label: nil, confined: 1, confinedTo: agentSandbox, sandbox: nil},
		{name: "an ordinary agent is confined to none", reach: store.SandboxAgents(agentOwner, ""),
			cursor: mustAgentCursor(t), limit: mustAgentLimit(t, "3"), filter: mustAgentFilter(t), before: "", rows: 4,
			label: nil, confined: 1, confinedTo: nil, sandbox: nil},
		{name: "a confined agent filtering by another sandbox", reach: store.SandboxAgents(agentOwner, agentSandbox),
			cursor: mustAgentCursor(t), limit: mustAgentLimit(t, "3"), filter: mustAgentSandboxFilter(t, agentOtherSandbox),
			before: "", rows: 4, label: nil, confined: 1, confinedTo: agentSandbox, sandbox: agentOtherSandbox},
		{name: "everything at once", reach: store.SandboxAgents(agentOwner, agentSandbox),
			cursor: mustAgentCursor(t, agentCursorID), limit: mustAgentLimit(t, "2"),
			filter: store.AgentFilter{
				Label:   mustAgentFilter(t, "prod").Label,
				Sandbox: mustAgentSandboxFilter(t, agentSandbox).Sandbox,
			},
			before: agentCursorID, rows: 3, label: "prod", confined: 1, confinedTo: agentSandbox, sandbox: agentSandbox},
	}
}

// TestListAgentsStatement pins the query's guards and its arguments in
// placeholder order: the owner scopes the page, the cursor is an exclusive
// upper bound on the id, the first page has a bound above every id, the reach
// (confined or not, and to which sandbox) is two arguments of its own and the
// sandbox filter is the last.
func TestListAgentsStatement(t *testing.T) {
	t.Parallel()

	for _, test := range listStatementCases(t) {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning())

			_, err := fake.store().ListAgents(context.Background(), test.reach, test.cursor, test.limit, test.filter)
			checkErr(t, err, nil)

			before := test.before
			if before == "" {
				var isText bool

				before, isText = fake.calls[0][0].Args[1].(string)
				if !isText || before <= agentLargestID {
					t.Errorf("first page bound %#v does not sort above every id", fake.calls[0][0].Args[1])
				}
			}

			checkBatch(t, fake, wantStatement{
				fragments: []string{
					"FROM agents",
					"WHERE user_id = ?1 AND id < ?2",
					// The filter is a semi-join on the labels' primary key: one row
					// per agent however many labels it has, and NULL is no filter.
					"AND (?4 IS NULL OR EXISTS (SELECT 1 FROM agent_labels f WHERE f.agent_id = agents.id AND f.label = ?4))",
					// The reach: a confined caller matches its own sandbox by IS,
					// so NULL is the ordinary agents and nothing else.
					"AND (?5 = 0 OR sandbox_id IS ?6)",
					// The sandbox filter only narrows.
					"AND (?7 IS NULL OR sandbox_id = ?7)",
					"ORDER BY id DESC",
					"LIMIT ?3",
				},
				args: []any{
					agentOwner, before, test.rows, test.label, test.confined, test.confinedTo, test.sandbox,
				},
			})
		})
	}
}

// TestListAgentsFailures holds how a failed or malformed batch is reported.
func TestListAgentsFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 1, store.CodeAgentListFailed, store.CodeAgentListRejected, agentsUnavailable,
		func(s *store.Store) error {
			return lastErr(s.ListAgents(
				context.Background(), store.OwnAgents(agentOwner), mustAgentCursor(t), mustAgentLimit(t), mustAgentFilter(t)))
		})
}

// TestGetAgentStatement pins that the owner and the reach are part of the match,
// so another user's agent and one outside a sandbox the caller is confined to
// are not found, and the arguments in order.
func TestGetAgentStatement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		reach      store.AgentReach
		confined   int64
		confinedTo any
	}{
		{"the user", store.OwnAgents(agentOwner), 0, nil},
		{"an agent of a sandbox", store.SandboxAgents(agentOwner, agentSandbox), 1, agentSandbox},
		{"an ordinary agent", store.SandboxAgents(agentOwner, ""), 1, nil},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(agentRow()))

			_, err := fake.store().GetAgent(context.Background(), test.reach, mustAgentID(t))
			checkErr(t, err, nil)

			checkBatch(t, fake, wantStatement{
				fragments: []string{
					"SELECT id, name, scopes, revoked_at, created_at,",
					"sandbox_id FROM agents",
					"WHERE id = ?1 AND user_id = ?2 AND (?3 = 0 OR sandbox_id IS ?4)",
				},
				args: []any{agentTarget, agentOwner, test.confined, test.confinedTo},
			})
		})
	}
}

// TestAgentReach holds what the reach reports, and that its zero value is no
// one's: no owner, and not confined, so it can match nothing by accident.
func TestAgentReach(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		reach    store.AgentReach
		owner    string
		confined bool
		sandbox  string
	}{
		{"the zero reach", store.AgentReach{}, "", false, ""},
		{"the user", store.OwnAgents(agentOwner), agentOwner, false, ""},
		{"an agent of a sandbox", store.SandboxAgents(agentOwner, agentSandbox), agentOwner, true, agentSandbox},
		{"an ordinary agent", store.SandboxAgents(agentOwner, ""), agentOwner, true, ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if test.reach.Owner() != test.owner || test.reach.Confined() != test.confined ||
				test.reach.Sandbox() != test.sandbox {
				t.Errorf("reach = %q, %v, %q; want %q, %v, %q", test.reach.Owner(), test.reach.Confined(),
					test.reach.Sandbox(), test.owner, test.confined, test.sandbox)
			}
		})
	}
}

// TestGetAgentFailures holds how a failed or malformed batch is reported.
func TestGetAgentFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 1, store.CodeAgentLookupFailed, store.CodeAgentLookupRejected, agentsUnavailable,
		func(s *store.Store) error {
			return lastErr(s.GetAgent(context.Background(), store.OwnAgents(agentOwner), mustAgentID(t)))
		})
}

// createAgentCase is a user's create and the batch it writes.
type createAgentCase struct {
	name  string
	agent store.NewAgent
	// labels are the labels the agent is created with, in the order they are
	// written.
	labels []string
}

// createAgentCases are the creates TestCreateAgentStatements pins.
func createAgentCases(t *testing.T) []createAgentCase {
	t.Helper()

	expires := time.Unix(1_707_776_123, 0)

	return []createAgentCase{
		{name: "a typical agent", agent: store.NewAgent{
			ID: agentTarget, Owner: agentOwner, Name: mustAgentName(t, "build bot"), Scopes: `["default:agent"]`,
			KeyScope: `["agent:read"]`, MaxActive: 25, KeyID: "key-1", KeyHash: hashOf(1),
			KeyExpiresAt: expires, CreatedAt: now,
		}},
		{name: "a multibyte name and another limit", agent: store.NewAgent{
			ID: agentCursorID, Owner: "user-2", Name: mustAgentName(t, "ボット 🤖"), Scopes: `[]`,
			KeyScope: `[]`, MaxActive: 1, KeyID: "key-2", KeyHash: hashOf(2), KeyExpiresAt: expires.Add(time.Hour),
			CreatedAt: now.Add(time.Minute),
		}},
		{name: "one label", labels: []string{"prod"}, agent: store.NewAgent{
			ID: agentTarget, Owner: agentOwner, Name: mustAgentName(t, "build bot"), Scopes: `["default:agent"]`,
			KeyScope: `["agent:read"]`, MaxActive: 25, KeyID: "key-1", KeyHash: hashOf(1),
			KeyExpiresAt: expires, CreatedAt: now, Labels: mustAgentLabelSet(t, "prod"),
		}},
		{name: "labels are written in the order sent, not sorted", labels: []string{"zeta", "alpha", "mid"},
			agent: store.NewAgent{
				ID: agentTarget, Owner: agentOwner, Name: mustAgentName(t, "build bot"), Scopes: `["default:agent"]`,
				KeyScope: `["agent:read"]`, MaxActive: 25, KeyID: "key-1", KeyHash: hashOf(1),
				KeyExpiresAt: expires, CreatedAt: now, Labels: mustAgentLabelSet(t, "zeta", "alpha", "mid"),
			}},
		{name: "in a sandbox", agent: store.NewAgent{
			ID: agentTarget, Owner: agentOwner, Name: mustAgentName(t, "build bot"), Scopes: `["default:agent"]`,
			KeyScope: `["agent:read"]`, MaxActive: 25, KeyID: "key-1", KeyHash: hashOf(1),
			KeyExpiresAt: expires, CreatedAt: now, Sandbox: mustAgentSandboxID(t, agentSandbox),
		}},
		{name: "in a sandbox, with labels", labels: []string{"b", "a"}, agent: store.NewAgent{
			ID: agentCursorID, Owner: "user-2", Name: mustAgentName(t, "ボット 🤖"), Scopes: `[]`,
			KeyScope: `[]`, MaxActive: 1, KeyID: "key-2", KeyHash: hashOf(2), KeyExpiresAt: expires.Add(time.Hour),
			CreatedAt: now.Add(time.Minute), Labels: mustAgentLabelSet(t, "b", "a"),
			Sandbox: mustAgentSandboxID(t, agentOtherSandbox),
		}},
		{name: "the most labels, each the longest", labels: longestLabelSet(), agent: store.NewAgent{
			ID: agentTarget, Owner: agentOwner, Name: mustAgentName(t, "build bot"), Scopes: `["default:agent"]`,
			KeyScope: `["agent:read"]`, MaxActive: 25, KeyID: "key-1", KeyHash: hashOf(1),
			KeyExpiresAt: expires, CreatedAt: now, Labels: mustAgentLabelSet(t, longestLabelSet()...),
		}},
	}
}

// longestLabelSet is the most labels a create may carry, each the longest there
// is.
func longestLabelSet() []string {
	labels := make([]string, input.MaxLabelsPerCreate)
	for i := range labels {
		labels[i] = longestLabelOf("label-" + strconv.Itoa(i) + "-")
	}

	return labels
}

// labelStatements are the statements that give the new agent each of labels, in
// order.
func labelStatements(agent string, labels []string) []wantStatement {
	statements := make([]wantStatement, len(labels))
	for i, label := range labels {
		statements[i] = createLabelStatement(agent, label)
	}

	return statements
}

// createLabelStatement is the statement that gives the new agent label.
func createLabelStatement(agent, label string) wantStatement {
	return wantStatement{
		fragments: []string{
			"INSERT INTO agent_labels (agent_id, label)",
			// The agent id is read from the agent's row: no agent, no id, and the
			// batch fails as a conflict instead of on the foreign key.
			"VALUES ((SELECT id FROM agents WHERE id = ?1), ?2)",
		},
		args: []any{agent, label},
	}
}

// agentInsertFragments are the guards of the insert of a user's agent, which is
// the same text for an ordinary create, a create in a sandbox and the consent
// that creates an agent.
func agentInsertFragments() []string {
	return []string{
		"INSERT INTO agents (id, user_id, name, scopes, created_at, sandbox_id)",
		"SELECT ?1, u.id, ?2, ?3, ?4, ?7 FROM users u",
		// The owner must be active, read from users, and under the limit:
		// the count is part of the write.
		"WHERE u.id = ?5 AND u.revoked_at IS NULL",
		// Agents of a sandbox that has expired as of the write do not count.
		"AND (SELECT count(*) FROM agents a WHERE a.user_id = u.id AND a.revoked_at IS NULL",
		"AND (a.sandbox_id IS NULL OR EXISTS (SELECT 1 FROM orgs g WHERE g.id = a.sandbox_id AND g.expires_at > ?4))) < ?6",
		// A sandbox must be a sandbox, unexpired as of the create, and the
		// owner's to administer: all in the write.
		"AND (?7 IS NULL OR EXISTS (SELECT 1 FROM orgs g JOIN org_admins m ON m.org_id = g.id",
		"WHERE g.id = ?7 AND g.kind = ?8 AND g.expires_at > ?4 AND m.user_id = u.id))",
		// The stored list and sandbox come back from the write itself.
		"RETURNING scopes, sandbox_id",
	}
}

// createAgentWant is the batch a create must write: the sandbox guard when there
// is a sandbox, the agent, its key's secret, its key, then each label in order.
// The agent is before the key and the labels because they read its row, and the
// key follows its secret.
func createAgentWant(test createAgentCase) []wantStatement {
	agent := test.agent

	var guard []wantStatement

	var sandbox any

	if agent.Sandbox.String() != "" {
		sandbox = agent.Sandbox.String()
		guard = []wantStatement{{
			fragments: []string{
				"INSERT INTO org_admins (org_id, user_id, created_at)",
				// A NULL org_id is the NOT NULL failure that names the sandbox,
				// and only when the sandbox is not the owner's.
				"SELECT NULL, ?2, ?3 WHERE NOT EXISTS (SELECT 1 FROM orgs g JOIN org_admins m ON m.org_id = g.id",
				"WHERE g.id = ?1 AND g.kind = ?4 AND g.expires_at > ?3 AND m.user_id = ?2)",
			},
			args: []any{agent.Sandbox.String(), agent.Owner, agent.CreatedAt.Unix(), store.OrgKindSandbox},
		}}
	}

	fixed := []wantStatement{
		{
			fragments: agentInsertFragments(),
			args: []any{
				agent.ID, agent.Name.String(), agent.Scopes, agent.CreatedAt.Unix(),
				agent.Owner, int64(agent.MaxActive), sandbox, store.OrgKindSandbox,
			},
		},
		{
			fragments: []string{"INSERT INTO secrets (id, kind, hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)"},
			args: []any{
				agent.KeyID, store.KindAPIKey, agent.KeyHash, agent.KeyExpiresAt.Unix(), agent.CreatedAt.Unix(),
			},
		},
		{
			fragments: []string{
				"INSERT INTO api_keys (id, kind, user_id, agent_id, name, scope)",
				// The key's owner, agent and name are the agent row's, not
				// arguments: no agent, no owner, and the batch fails, secret
				// included.
				"(SELECT user_id FROM agents WHERE id = ?3)",
				"(SELECT id FROM agents WHERE id = ?3)",
				"(SELECT name FROM agents WHERE id = ?3)",
			},
			args: []any{agent.KeyID, store.KindAPIKey, agent.ID, agent.KeyScope},
		},
	}

	return slices.Concat(guard, fixed, labelStatements(agent.ID, test.labels))
}

// TestCreateAgentStatements pins the batch a create writes: the guards that make
// the agent conditional on its owner, and the key whose owner is read from the
// agent's row so that no agent means a failed batch. A create in a sandbox is
// preceded by the guard that says the sandbox is why it failed.
func TestCreateAgentStatements(t *testing.T) {
	t.Parallel()

	for _, test := range createAgentCases(t) {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			agent := test.agent
			inSandbox := agent.Sandbox.String() != ""

			// The agent insert returns the scopes and sandbox it stored, which is
			// what the caller reports. Here the row holds what was offered.
			var sandbox any
			if inSandbox {
				sandbox = agent.Sandbox.String()
			}

			fake := newFake(createdAgent(inSandbox, row(agent.Scopes, sandbox), test.labels...))

			stored, err := fake.store().CreateAgent(context.Background(), agent)
			checkErr(t, err, nil)

			if stored.Scopes != agent.Scopes || stored.SandboxID != agent.Sandbox.String() {
				t.Errorf("stored = %+v, want scopes %q in sandbox %q", stored, agent.Scopes, agent.Sandbox.String())
			}

			want := createAgentWant(test)
			checkBatch(t, fake, want...)

			// Literals of the kinds are never written: the kind of the agent's
			// key and of a sandbox are bound.
			for i, statement := range fake.calls[0] {
				text := squash(statement.Query)
				if strings.Contains(text, "'api_key'") || strings.Contains(text, "'sandbox'") {
					t.Errorf("statement %d writes a kind as a literal; bind it", i)
				}
			}
		})
	}
}

// TestSandboxExpiryIsExclusiveAtTheRequestSecond holds that a sandbox is judged
// by one instant, the second of the request, and that a sandbox whose expiry is
// that very second has expired: every comparison with expires_at in the create's
// batch is a strict "expires_at > ?N" against an argument that is the create's
// time as whole seconds. The sub-second part of the clock is dropped, and so
// cannot make a sandbox that expires this second stand a moment longer. The
// real comparison runs only in the end-to-end tests; this pins its operator
// and the instant it is given.
func TestSandboxExpiryIsExclusiveAtTheRequestSecond(t *testing.T) {
	t.Parallel()

	second := time.Unix(1_700_000_200, 0)
	expiry := regexp.MustCompile(`expires_at (\S+) \?(\d+)`)

	tests := []struct {
		name string
		// at is the request's clock reading.
		at      time.Time
		sandbox string
		by      string // the creating agent, "" for the user's own create
		// judged is how many comparisons with an expiry the batch holds: the
		// agent count and the sandbox clause of the insert (every create; the
		// clause reads the creating agent's sandbox for a create by an agent),
		// and, for a user's create in a sandbox, the guard before it.
		judged int
	}{
		{name: "an ordinary create", at: second, judged: 2},
		{name: "an ordinary create a moment into the second", at: second.Add(999 * time.Millisecond), judged: 2},
		{name: "a create in a sandbox", at: second, sandbox: agentSandbox, judged: 3},
		{name: "a create in a sandbox a moment into the second", at: second.Add(999 * time.Millisecond),
			sandbox: agentSandbox, judged: 3},
		{name: "a create by an agent", at: second, by: "agent-1", judged: 2},
		{name: "a create by an agent a moment into the second", at: second.Add(999 * time.Millisecond),
			by: "agent-1", judged: 2},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			agent := store.NewAgent{
				ID: agentTarget, Owner: agentOwner, Name: mustAgentName(t, "bot"), Scopes: "[]", KeyScope: "[]",
				MaxActive: 25, KeyID: "key-1", KeyHash: hashOf(1), KeyExpiresAt: test.at, CreatedAt: test.at,
				CreatedBy: test.by,
			}
			if test.sandbox != "" {
				agent.Sandbox = mustAgentSandboxID(t, test.sandbox)
			}

			var sandbox any
			if test.sandbox != "" {
				sandbox = test.sandbox
			}

			fake := newFake(createdAgent(test.sandbox != "", row("[]", sandbox)))

			_, err := fake.store().CreateAgent(context.Background(), agent)
			checkErr(t, err, nil)

			judged := 0
			for _, statement := range fake.calls[0] {
				judged += checkExpiryComparisons(t, statement, expiry, test.at)
			}

			if judged != test.judged {
				t.Errorf("the batch compares an expiry %d times, want %d", judged, test.judged)
			}
		})
	}
}

// checkExpiryComparisons checks each comparison with expires_at in a statement:
// it is a strict ">" against an argument that is at as whole seconds. It returns
// how many there are.
func checkExpiryComparisons(t *testing.T, statement store.Statement, expiry *regexp.Regexp, at time.Time) int {
	t.Helper()

	matches := expiry.FindAllStringSubmatch(squash(statement.Query), -1)

	for _, match := range matches {
		if match[1] != ">" {
			t.Errorf("an expiry is compared with %q, want a strict >:\n%s", match[1], statement.Query)
		}

		position, err := strconv.Atoi(match[2])
		if err != nil || position < 1 || position > len(statement.Args) {
			t.Fatalf("expires_at is compared with ?%s, not an argument of %v", match[2], statement.Args)
		}

		if got := statement.Args[position-1]; got != at.Unix() {
			t.Errorf("expires_at is compared with %v, want the request's whole second %d", got, at.Unix())
		}
	}

	return len(matches)
}

// TestCreateAgentFailures holds that a limit or a revoked owner (conflicts) and
// every other failure come back as classified.
func TestCreateAgentFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 3, store.CodeAgentCreateFailed, store.CodeAgentCreateRejected, agentsUnavailable,
		func(s *store.Store) error {
			return lastErr(s.CreateAgent(context.Background(), store.NewAgent{
				ID: agentTarget, Owner: agentOwner, Name: mustAgentName(t, "bot"), Scopes: "[]", KeyScope: "[]",
				MaxActive: 25, KeyID: "key-1", KeyHash: hashOf(3), KeyExpiresAt: now, CreatedAt: now,
			}))
		})
}

// TestCreateAgentWithLabelsFailures: the same failures, for a batch that also
// writes labels. The batch has a result for each statement, so one too few or
// too many is a defect whatever the labels, and a NOT NULL failure (the agent
// was not created, so no statement after it had an agent to name) is still the
// conflict the feature answers as the limit.
func TestCreateAgentWithLabelsFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 5, store.CodeAgentCreateFailed, store.CodeAgentCreateRejected, agentsUnavailable,
		func(s *store.Store) error {
			return lastErr(s.CreateAgent(context.Background(), store.NewAgent{
				ID: agentTarget, Owner: agentOwner, Name: mustAgentName(t, "bot"), Scopes: "[]", KeyScope: "[]",
				MaxActive: 25, KeyID: "key-1", KeyHash: hashOf(3), KeyExpiresAt: now, CreatedAt: now,
				Labels: mustAgentLabelSet(t, "a", "b"),
			}))
		})
}

// agentByAgentInsertFragments are the guards of the insert of an agent that
// another agent creates.
func agentByAgentInsertFragments() []string {
	return []string{
		"INSERT INTO agents (id, user_id, name, scopes, created_at, sandbox_id)",
		// Scopes and sandbox come from the creating agent's row.
		"SELECT ?1, u.id, ?2, c.scopes, ?4, c.sandbox_id FROM users u",
		// It must be the owner's and not revoked.
		"JOIN agents c ON c.user_id = u.id AND c.id = ?3 AND c.revoked_at IS NULL",
		"WHERE u.id = ?5 AND u.revoked_at IS NULL",
		// Agents of a sandbox that has expired as of the write do not count.
		"AND (SELECT count(*) FROM agents a WHERE a.user_id = u.id AND a.revoked_at IS NULL",
		"AND (a.sandbox_id IS NULL OR EXISTS (SELECT 1 FROM orgs g WHERE g.id = a.sandbox_id AND g.expires_at > ?4))) < ?6",
		// Its sandbox must still stand, when it has one.
		"AND (c.sandbox_id IS NULL OR EXISTS (SELECT 1 FROM orgs g",
		"WHERE g.id = c.sandbox_id AND g.kind = c.sandbox_kind AND g.expires_at > ?4))",
		// The creating agent's list and sandbox, as the write read them, come back.
		"RETURNING scopes, sandbox_id",
	}
}

// TestCreateAgentByAgentStatements pins the batch an agent's create writes. The
// new agent's scopes are read from the creating agent's row in the write and are
// not an argument at all, the creating agent must be the owner's and active, and
// the key's scope is still the one the caller chose (it is checked against the
// creating key by the feature, which holds the key's list).
func TestCreateAgentByAgentStatements(t *testing.T) {
	t.Parallel()

	expires := time.Unix(1_707_776_123, 0)
	agent := store.NewAgent{
		ID: agentTarget, Owner: agentOwner, Name: mustAgentName(t, "child"),
		// A request's idea of the scopes and of the sandbox must never reach the
		// write.
		Scopes: `["user:read"]`, KeyScope: `["default:agent"]`, CreatedBy: agentCursorID,
		Sandbox:   mustAgentSandboxID(t, agentOtherSandbox),
		MaxActive: 25, KeyID: "key-1", KeyHash: hashOf(1), KeyExpiresAt: expires, CreatedAt: now,
	}

	// The creating agent's row holds other scopes than the request offered, and
	// the write returns the row's: that is what the caller must report.
	const creatorScopes = `["default:agent","agent:create"]`

	fake := newFake(createdAgent(false, row(creatorScopes, agentSandbox)))

	stored, err := fake.store().CreateAgent(context.Background(), agent)
	checkErr(t, err, nil)

	if stored.Scopes != creatorScopes || stored.SandboxID != agentSandbox {
		t.Errorf("stored = %+v, want the creating agent's scopes %q and sandbox %q", stored, creatorScopes, agentSandbox)
	}

	checkBatch(t, fake,
		wantStatement{
			fragments: agentByAgentInsertFragments(),
			args: []any{
				agent.ID, agent.Name.String(), agent.CreatedBy, agent.CreatedAt.Unix(), agent.Owner, int64(agent.MaxActive),
			},
		},
		wantStatement{
			fragments: []string{"INSERT INTO secrets (id, kind, hash, expires_at, created_at)"},
			args: []any{
				agent.KeyID, store.KindAPIKey, agent.KeyHash, agent.KeyExpiresAt.Unix(), agent.CreatedAt.Unix(),
			},
		},
		wantStatement{
			fragments: []string{"(SELECT user_id FROM agents WHERE id = ?3)"},
			args:      []any{agent.KeyID, store.KindAPIKey, agent.ID, agent.KeyScope},
		},
	)

	for _, arg := range fake.calls[0][0].Args {
		if arg == agent.Scopes {
			t.Error("the request's scopes were bound in an agent's create; they must come from the creating agent's row")
		}

		if arg == agent.Sandbox.String() {
			t.Error("the request's sandbox was bound in an agent's create; it must come from the creating agent's row")
		}
	}

	if len(fake.calls[0]) != 3 {
		t.Errorf("an agent's create ran %d statements, want 3: it needs no sandbox guard", len(fake.calls[0]))
	}
}

// TestCreateAgentByAgentFailures holds that a revoked creating agent, a revoked
// owner and the limit (conflicts) and every other failure come back classified.
func TestCreateAgentByAgentFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 3, store.CodeAgentCreateFailed, store.CodeAgentCreateRejected, agentsUnavailable,
		func(s *store.Store) error {
			return lastErr(s.CreateAgent(context.Background(), store.NewAgent{
				ID: agentTarget, Owner: agentOwner, Name: mustAgentName(t, "bot"), Scopes: "[]", KeyScope: "[]",
				CreatedBy: agentCursorID, MaxActive: 25, KeyID: "key-1", KeyHash: hashOf(3), KeyExpiresAt: now, CreatedAt: now,
			}))
		})
}

// createdAgent is the outcome of a create batch whose agent insert returned the
// row it stored (first: its scopes and its sandbox) and whose key insert
// returned nothing, followed by one result for each label the batch wrote. A
// create in a sandbox starts with the result of the sandbox guard, which
// changes nothing when the sandbox is usable.
func createdAgent(guarded bool, first []any, labels ...string) outcome {
	// The agent insert returns its row; every later statement (the key's
	// secret, the key, then each label) changes one row and returns none.
	results := make([]store.Result, 0, 1+1+2+len(labels))

	if guarded {
		results = append(results, store.Result{Changes: 0, Rows: nil})
	}

	results = append(results, store.Result{Changes: 1, Rows: [][]any{first}})

	for range 2 + len(labels) {
		results = append(results, store.Result{Changes: 1, Rows: nil})
	}

	return outcome{results: results, err: nil}
}

// TestCreateAgentResultShape holds that a batch which succeeded without the
// promised row is a defect, never a missing agent or a made-up scope list: the
// key insert depends on the agent row, so a result without it means the
// database did not do what the statements say.
func TestCreateAgentResultShape(t *testing.T) {
	t.Parallel()

	two := func(rows [][]any) outcome {
		return outcome{err: nil, results: []store.Result{
			{Changes: 1, Rows: rows}, {Changes: 1, Rows: nil}, {Changes: 1, Rows: nil},
		}}
	}

	tests := []struct {
		name string
		out  outcome
	}{
		{name: "no row returned", out: two(nil)},
		{name: "two rows returned", out: two([][]any{row("[]", nil), row("[]", nil)})},
		{name: "scopes not text", out: two([][]any{row(int64(1), nil)})},
		{name: "scopes is NULL", out: two([][]any{row(nil, nil)})},
		{name: "the sandbox is an integer", out: two([][]any{row("[]", int64(1))})},
		{name: "the sandbox is a blob", out: two([][]any{row("[]", []byte("x"))})},
		{name: "the sandbox column is missing", out: two([][]any{row("[]")})},
		{name: "an extra column", out: two([][]any{row("[]", nil, "[]")})},
		{name: "no column", out: two([][]any{row()})},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(test.out)

			stored, err := fake.store().CreateAgent(context.Background(), store.NewAgent{
				ID: agentTarget, Owner: agentOwner, Name: mustAgentName(t, "bot"), Scopes: "[]", KeyScope: "[]",
				MaxActive: 25, KeyID: "key-1", KeyHash: hashOf(3), KeyExpiresAt: now, CreatedAt: now,
			})

			checkErr(t, err, defectOf(store.CodeAgentCreateRejected))

			if stored != (store.CreatedAgent{}) {
				t.Errorf("stored = %+v on a defect, want none", stored)
			}
		})
	}
}

// TestCreateAgentInASandboxFailures: the same failures for a create that names a
// sandbox, which has the guard as a fourth statement and so the results to match.
func TestCreateAgentInASandboxFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 4, store.CodeAgentCreateFailed, store.CodeAgentCreateRejected, agentsUnavailable,
		func(s *store.Store) error {
			return lastErr(s.CreateAgent(context.Background(), store.NewAgent{
				ID: agentTarget, Owner: agentOwner, Name: mustAgentName(t, "bot"), Scopes: "[]", KeyScope: "[]",
				MaxActive: 25, KeyID: "key-1", KeyHash: hashOf(3), KeyExpiresAt: now, CreatedAt: now,
				Sandbox: mustAgentSandboxID(t, agentSandbox),
			}))
		})
}

// TestCreateAgentTellsTheSandboxFromTheLimit: a create fails as a conflict when
// the owner is at the limit, revoked, or the creating agent is gone, and as
// ErrSandboxUnavailable (which keeps the conflict in its chain) only when the
// column the database names is the sandbox guard's. A conflict that names
// another column, or none, is never the sandbox's, in a create that names one
// too.
func TestCreateAgentTellsTheSandboxFromTheLimit(t *testing.T) {
	t.Parallel()

	notNull := func(column string) error {
		return store.Classify(dbError("D1_ERROR: NOT NULL constraint failed: " + column + ": SQLITE_CONSTRAINT_NOTNULL"))
	}

	tests := []struct {
		name           string
		sandbox        string
		cause          error
		sandboxRefused bool
	}{
		{"the guard's column", agentSandbox, notNull("org_admins.org_id"), true},
		{"the guard's column, for a create in no sandbox", "", notNull("org_admins.org_id"), true},
		{"the key's owner: the limit or a revoked owner", agentSandbox, notNull("api_keys.user_id"), false},
		{"the key's owner, in no sandbox", "", notNull("api_keys.user_id"), false},
		{"a label's agent", agentSandbox, notNull("agent_labels.agent_id"), false},
		{"no column named", agentSandbox, notNull(""), false},
		{"the guard's table but another column", agentSandbox, notNull("org_admins.user_id"), false},
		{"a unique value", agentSandbox, store.Classify(dbError(
			"D1_ERROR: UNIQUE constraint failed: secrets.hash: SQLITE_CONSTRAINT_UNIQUE")), false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var sandbox input.SandboxID
			if test.sandbox != "" {
				sandbox = mustAgentSandboxID(t, test.sandbox)
			}

			fake := newFake(failing(test.cause))

			_, err := fake.store().CreateAgent(context.Background(), store.NewAgent{
				ID: agentTarget, Owner: agentOwner, Name: mustAgentName(t, "bot"), Scopes: "[]", KeyScope: "[]",
				MaxActive: 25, KeyID: "key-1", KeyHash: hashOf(3), KeyExpiresAt: now, CreatedAt: now, Sandbox: sandbox,
			})

			if !errors.Is(err, store.ErrConflict) {
				t.Fatalf("error = %v, want ErrConflict in the chain", err)
			}

			if got := errors.Is(err, store.ErrSandboxUnavailable); got != test.sandboxRefused {
				t.Errorf("ErrSandboxUnavailable = %v, want %v for %v", got, test.sandboxRefused, err)
			}

			if _, isAPI := errors.AsType[*apierr.Error](err); isAPI {
				t.Errorf("conflict %v is classified; the feature must decide that", err)
			}
		})
	}
}

// labelsJSON is the labels column as json_group_array returns it.
func labelsJSON(labels ...string) string {
	encoded, err := json.Marshal(labels)
	if err != nil {
		panic(err)
	}

	return string(encoded)
}

// patchRead is the one batch of a patch: writes statements that change rows,
// then the read, whose rows are what the patch returns.
func patchRead(writes int, rows ...[]any) outcome {
	results := make([]store.Result, writes+1)
	results[writes] = store.Result{Changes: 0, Rows: rows}

	return outcome{results: results, err: nil}
}

// TestPatchAgentOutcomes holds the outcomes of a patch: the row is whatever the
// closing read saw, so a revoked agent comes back unchanged for the caller to
// refuse, and no row is a missing agent.
func TestPatchAgentOutcomes(t *testing.T) {
	t.Parallel()

	revokedAt := int64(1_700_000_100)
	name := mustAgentName(t, "renamed")

	tests := []struct {
		name string
		rows [][]any
		want store.Agent
		err  error
	}{
		{name: "patched, no labels", rows: [][]any{with(agentRow(), 1, "renamed")}, want: store.Agent{
			ID: agentTarget, Name: "renamed", Scopes: `["default:agent"]`, RevokedAt: nil, CreatedAt: 1_700_000_000,
			Labels: []string{},
		}},
		{name: "patched, with labels", rows: [][]any{with(agentRow(), 5, labelsJSON("a", "b"))}, want: store.Agent{
			ID: agentTarget, Name: "build bot", Scopes: `["default:agent"]`, RevokedAt: nil, CreatedAt: 1_700_000_000,
			Labels: []string{"a", "b"},
		}},
		{name: "revoked comes back as it is and says so", rows: [][]any{agentRevokedRow()}, want: store.Agent{
			ID: agentTarget, Name: "build bot", Scopes: `["default:agent"]`, RevokedAt: &revokedAt, CreatedAt: 1_700_000_000,
			Labels: []string{},
		}},
		{name: "no such agent", rows: nil, err: store.ErrNotFound},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(patchRead(1, test.rows...))

			got, err := fake.store().PatchAgent(context.Background(), agentOwner, mustAgentID(t), store.AgentPatch{
				Name: &name, Labels: mustAgentLabelPatch(t, nil, nil), MaxLabels: 20,
			})

			if !errors.Is(err, test.err) {
				t.Fatalf("error = %v, want %v", err, test.err)
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("agent = %+v, want %+v", got, test.want)
			}
		})
	}
}

// patchRename is the statement a patch's rename must be.
func patchRename(name input.AgentName) wantStatement {
	return wantStatement{
		fragments: []string{
			"UPDATE agents",
			"SET name = ?1",
			// A revoked agent is final.
			"WHERE id = ?2 AND user_id = ?3 AND revoked_at IS NULL",
		},
		args: []any{name.String(), agentTarget, agentOwner},
	}
}

// patchReadStatement is the closing read of every patch.
func patchReadStatement() wantStatement {
	return wantStatement{
		fragments: []string{
			"SELECT id, name, scopes, revoked_at, created_at,",
			agentLabelsColumn,
			"FROM agents WHERE id = ?1 AND user_id = ?2",
		},
		args: []any{agentTarget, agentOwner},
	}
}

// patchRemoval is the statement that removes label.
func patchRemoval(label string) wantStatement {
	return wantStatement{
		fragments: []string{
			"DELETE FROM agent_labels",
			"WHERE agent_id = ?1 AND label = ?2",
			// The guard is in the delete: the owner's, and not revoked.
			"AND EXISTS (SELECT 1 FROM agents a WHERE a.id = ?1 AND a.user_id = ?3 AND a.revoked_at IS NULL)",
		},
		args: []any{agentTarget, label, agentOwner},
	}
}

// patchAddition is the statement that adds label, for agents of at most limit.
func patchAddition(label string, limit int64) wantStatement {
	return wantStatement{
		fragments: []string{
			"INSERT INTO agent_labels (agent_id, label)",
			// A NULL agent_id at the cap is a NOT NULL failure of the batch;
			// having the label already is never over the cap.
			"SELECT CASE WHEN (SELECT count(*) FROM agent_labels l WHERE l.agent_id = a.id) < ?4",
			"OR EXISTS (SELECT 1 FROM agent_labels l WHERE l.agent_id = a.id AND l.label = ?2) THEN a.id END, ?2",
			// Only the owner's active agent: otherwise no row, and no insert.
			"FROM agents a WHERE a.id = ?1 AND a.user_id = ?3 AND a.revoked_at IS NULL",
			"ON CONFLICT DO NOTHING",
		},
		args: []any{agentTarget, label, agentOwner, limit},
	}
}

// TestPatchAgentStatements pins the batch a patch writes, in order: the rename,
// each removal, each addition, then the read. Every write names the owner and
// skips a revoked agent in its own text, and the arguments are in placeholder
// order.
func TestPatchAgentStatements(t *testing.T) {
	t.Parallel()

	name := mustAgentName(t, "ボット 🤖")
	none := mustAgentLabelPatch(t, nil, nil)
	read := patchReadStatement()

	tests := []struct {
		name  string
		patch store.AgentPatch
		want  []wantStatement
	}{
		{
			name:  "nothing but the read",
			patch: store.AgentPatch{Name: nil, Labels: none, MaxLabels: 20},
			want:  []wantStatement{read},
		},
		{
			name:  "a rename",
			patch: store.AgentPatch{Name: &name, Labels: none, MaxLabels: 20},
			want:  []wantStatement{patchRename(name), read},
		},
		{
			name:  "one addition",
			patch: store.AgentPatch{Name: nil, Labels: mustAgentLabelPatch(t, []string{"a"}, nil), MaxLabels: 20},
			want:  []wantStatement{patchAddition("a", 20), read},
		},
		{
			name:  "one removal",
			patch: store.AgentPatch{Name: nil, Labels: mustAgentLabelPatch(t, nil, []string{"a"}), MaxLabels: 20},
			want:  []wantStatement{patchRemoval("a"), read},
		},
		{
			name: "everything: rename, removals in order, additions in order, read",
			patch: store.AgentPatch{
				Name: &name, Labels: mustAgentLabelPatch(t, []string{"z", "b"}, []string{"y", "c"}), MaxLabels: 7,
			},
			want: []wantStatement{
				patchRename(name), patchRemoval("y"), patchRemoval("c"),
				patchAddition("z", 7), patchAddition("b", 7), read,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(patchRead(len(test.want)-1, agentRow()))

			_, err := fake.store().PatchAgent(context.Background(), agentOwner, mustAgentID(t), test.patch)
			checkErr(t, err, nil)

			checkBatch(t, fake, test.want...)
		})
	}
}

// TestPatchAgentTheLabelCapIsTheCallers: a conflict is the batch refusing a
// patch that would leave the agent over the limit, and it is returned as the
// bare sentinel for the feature to name, not classified.
func TestPatchAgentTheLabelCapIsTheCallers(t *testing.T) {
	t.Parallel()

	notNull := store.Classify(dbError(
		"D1_ERROR: NOT NULL constraint failed: agent_labels.agent_id: SQLITE_CONSTRAINT_NOTNULL"))
	fake := newFake(failing(notNull))

	_, err := fake.store().PatchAgent(context.Background(), agentOwner, mustAgentID(t), store.AgentPatch{
		Name: nil, Labels: mustAgentLabelPatch(t, []string{"a"}, nil), MaxLabels: 20,
	})

	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("error = %v, want ErrConflict", err)
	}

	if _, isAPI := errors.AsType[*apierr.Error](err); isAPI {
		t.Errorf("the label cap %v is classified; the feature must decide that", err)
	}
}

// TestPatchAgentFailures holds how the rest of the failures are reported. A
// patch of only labels is two statements here (one addition and the read).
func TestPatchAgentFailures(t *testing.T) {
	t.Parallel()

	patch := store.AgentPatch{Name: nil, Labels: mustAgentLabelPatch(t, []string{"a"}, nil), MaxLabels: 20}

	for _, f := range infraFailures(2, store.CodeAgentUpdateFailed, store.CodeAgentUpdateRejected, agentsUnavailable) {
		// A conflict is the label cap, which is the feature's to name.
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(f.outcome)

			_, err := fake.store().PatchAgent(context.Background(), agentOwner, mustAgentID(t), patch)

			checkFailure(t, err, f)

			if errors.Is(err, store.ErrNotFound) {
				t.Error("a failure is reported as a missing agent")
			}
		})
	}
}

// TestPatchAgentDefects holds that a closing read that is not exactly one agent
// is a defect.
func TestPatchAgentDefects(t *testing.T) {
	t.Parallel()

	patch := store.AgentPatch{Name: nil, Labels: mustAgentLabelPatch(t, nil, nil), MaxLabels: 20}

	tests := []struct {
		name string
		rows [][]any
	}{
		{name: "two rows", rows: [][]any{agentRow(), agentRow()}},
		{name: "labels is not text", rows: [][]any{with(agentRow(), 5, int64(1))}},
		{name: "labels is NULL", rows: [][]any{with(agentRow(), 5, nil)}},
		{name: "labels is not JSON", rows: [][]any{with(agentRow(), 5, "a,b")}},
		{name: "labels is a JSON object", rows: [][]any{with(agentRow(), 5, `{"a":1}`)}},
		{name: "labels is a JSON string", rows: [][]any{with(agentRow(), 5, `"a"`)}},
		{name: "labels is JSON null", rows: [][]any{with(agentRow(), 5, `null`)}},
		{name: "labels holds a number", rows: [][]any{with(agentRow(), 5, `[1]`)}},
		{name: "labels holds null", rows: [][]any{with(agentRow(), 5, `[null]`)}},
		{name: "labels holds an array", rows: [][]any{with(agentRow(), 5, `[["a"]]`)}},
		{name: "labels is empty text", rows: [][]any{with(agentRow(), 5, "")}},
		{name: "labels is truncated JSON", rows: [][]any{with(agentRow(), 5, `["a"`)}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(patchRead(0, test.rows...))

			got, err := fake.store().PatchAgent(context.Background(), agentOwner, mustAgentID(t), patch)

			checkErr(t, err, defectOf(store.CodeAgentUpdateRejected))

			if got.ID != "" {
				t.Errorf("a defective result returned %+v", got)
			}
		})
	}
}

// revokeStatements are the two statements a revoke runs, in order.
func revokeStatements() []wantStatement {
	return []wantStatement{
		{
			fragments: []string{
				"UPDATE agents",
				// An agent already revoked keeps its earlier time.
				"SET revoked_at = COALESCE(revoked_at, ?1)",
				"WHERE id = ?2 AND user_id = ?3",
				"RETURNING id, name, scopes, revoked_at, created_at,",
				agentLabelsColumn,
			},
			args: []any{now.Unix(), agentTarget, agentOwner},
		},
		{
			fragments: []string{
				// The secrets of the agent's keys, and of its OAuth grants and their
				// access tokens, found under the owner as well.
				"UPDATE secrets",
				"SET revoked_at = ?1",
				"WHERE id IN (SELECT id FROM api_keys WHERE agent_id = ?2 AND user_id = ?3 " +
					"UNION ALL SELECT id FROM oauth_grants WHERE agent_id = ?2 AND user_id = ?3 " +
					"UNION ALL SELECT t.id FROM oauth_access_tokens t JOIN oauth_grants g ON g.id = t.grant_id " +
					"WHERE g.agent_id = ?2 AND g.user_id = ?3)",
				// A due revocation keeps its time; a later one is brought forward.
				"AND (revoked_at IS NULL OR revoked_at > ?1)",
				// Only once the agent is revoked, and only the owner's agent.
				"AND EXISTS (SELECT 1 FROM agents WHERE id = ?2 AND user_id = ?3 AND revoked_at IS NOT NULL)",
			},
			args: []any{now.Unix(), agentTarget, agentOwner},
		},
	}
}

// TestRevokeAgent holds the outcomes of a revoke: the row is whatever the first
// statement left, and the key update that follows is part of the same batch.
func TestRevokeAgent(t *testing.T) {
	t.Parallel()

	revokedAt := int64(1_700_000_100)
	revoked := store.Agent{
		ID: agentTarget, Name: "build bot", Scopes: `["default:agent"]`, RevokedAt: &revokedAt, CreatedAt: 1_700_000_000,
		Labels: []string{},
	}

	tests := []struct {
		name    string
		outcome outcome
		want    store.Agent
		err     error
	}{
		{name: "revoked with two keys", outcome: agentRevoked(2, agentRevokedRow()), want: revoked},
		{name: "revoked with no key left to revoke", outcome: agentRevoked(0, agentRevokedRow()), want: revoked},
		{name: "no such agent", outcome: agentRevoked(0), err: store.ErrNotFound},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(test.outcome)

			got, err := fake.store().RevokeAgent(context.Background(), agentOwner, mustAgentID(t), now)

			if !errors.Is(err, test.err) {
				t.Fatalf("error = %v, want %v", err, test.err)
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("agent = %+v, want %+v", got, test.want)
			}

			checkBatch(t, fake, revokeStatements()...)
		})
	}
}

// TestRevokeAgentFailures holds that a conflict is as much a defect as a schema
// rule: a revoke sets nothing the data could collide with.
func TestRevokeAgentFailures(t *testing.T) {
	t.Parallel()

	for _, f := range agentWriteFailures(2, store.CodeAgentRevokeFailed, store.CodeAgentRevokeRejected) {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(f.outcome)

			_, err := fake.store().RevokeAgent(context.Background(), agentOwner, mustAgentID(t), now)

			checkFailure(t, err, f)

			if errors.Is(err, store.ErrNotFound) {
				t.Error("a failure is reported as a missing agent")
			}
		})
	}
}

// TestAgentQueriesAreChecked guards the package-wide query checks against
// passing because they never saw the agent queries.
func TestAgentQueriesAreChecked(t *testing.T) {
	t.Parallel()

	queries := packageQueries(t)

	for _, name := range []string{
		"agentListQuery", "agentGetQuery", "insertAgentQuery", "insertAgentKeyQuery", "insertAgentLabelQuery",
		"insertSecretQuery",
		"agentPatchRenameQuery", "agentPatchReadQuery", "agentLabelAddQuery", "agentLabelRemoveQuery",
		"agentRevokeQuery", "agentRevokeKeysQuery",
	} {
		if _, ok := queries[name]; !ok {
			t.Errorf("query %s was not found", name)
		}
	}
}

// TestAgentQueriesScopeToTheOwner holds that every statement that reads or
// changes an agent names the owner in its match, so that an agent of another
// user can be neither seen nor changed. The key insert is the one exception: its
// owner is read from the agent's row.
func TestAgentQueriesScopeToTheOwner(t *testing.T) {
	t.Parallel()

	queries := packageQueries(t)

	for _, name := range []string{
		"agentListQuery", "agentGetQuery", "agentPatchRenameQuery", "agentPatchReadQuery",
		"agentLabelAddQuery", "agentLabelRemoveQuery", "agentRevokeQuery", "agentRevokeKeysQuery",
	} {
		if !strings.Contains(squash(queries[name]), "user_id = ?") {
			t.Errorf("%s does not match on the owner:\n%s", name, queries[name])
		}
	}
}

// TestAgentCodes pins the wire codes the operations report. Clients and
// dashboards match on them, so they change only deliberately.
func TestAgentCodes(t *testing.T) {
	t.Parallel()

	tests := []struct{ got, want string }{
		{store.CodeAgentListFailed, "agent_list_failed"},
		{store.CodeAgentListRejected, "agent_list_rejected"},
		{store.CodeAgentLookupFailed, "agent_lookup_failed"},
		{store.CodeAgentLookupRejected, "agent_lookup_rejected"},
		{store.CodeAgentCreateFailed, "agent_create_failed"},
		{store.CodeAgentCreateRejected, "agent_create_rejected"},
		{store.CodeAgentUpdateFailed, "agent_update_failed"},
		{store.CodeAgentUpdateRejected, "agent_update_rejected"},
		{store.CodeAgentRevokeFailed, "agent_revoke_failed"},
		{store.CodeAgentRevokeRejected, "agent_revoke_rejected"},
	}

	for _, test := range tests {
		if test.got != test.want {
			t.Errorf("code %q, want %q", test.got, test.want)
		}
	}
}

// TestAgentsFirstPageSortsAboveEveryID holds the property the first page relies
// on: its bound is above every id input.ParseID accepts, in the order SQLite
// compares text (BINARY collation: byte by byte), so `id < bound` is true for
// every agent and the first page needs no query of its own.
//
// An id is 36 characters of [0-9a-f] with dashes at fixed offsets, so the
// greatest is all 'f' and the least all '0'; the bound is checked against both
// of those, against ids that differ from the greatest at each position, and
// against what a change of the id format (upper case, other letters, a longer
// id) would have to preserve. A format that put a character above 'g' in an id
// breaks this test, which is the point: it would otherwise silently drop agents
// from the first page.
func TestAgentsFirstPageSortsAboveEveryID(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"the greatest id":                    agentLargestID,
		"the least id":                       "00000000-0000-0000-0000-000000000000",
		"a UUIDv7":                           "01900000-0000-7000-8000-000000000050",
		"the greatest id with a zero first":  "0fffffff-ffff-ffff-ffff-ffffffffffff",
		"the greatest id but the last digit": "ffffffff-ffff-ffff-ffff-fffffffffffe",
	}

	// One id for each position that is a digit, with that digit the greatest and
	// the others the least, and the reverse.
	for position := range len(agentLargestID) {
		if agentLargestID[position] == '-' {
			continue
		}

		high := []byte("00000000-0000-0000-0000-000000000000")
		high[position] = 'f'
		tests[fmt.Sprintf("only position %d is f", position)] = string(high)

		low := []byte(agentLargestID)
		low[position] = '0'
		tests[fmt.Sprintf("only position %d is 0", position)] = string(low)
	}

	for name, id := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			parsed, err := input.ParseID(id)
			if err != nil {
				t.Fatalf("test bug: %q is not an id: %v", id, err)
			}

			if parsed.String() >= store.AgentsFirstPage {
				t.Errorf("id %q does not sort below the first page bound %q", id, store.AgentsFirstPage)
			}
		})
	}

	// The bound is not itself an id, so no agent can be the bound.
	_, err := input.ParseID(store.AgentsFirstPage)
	if err == nil {
		t.Errorf("the first page bound %q parses as an id", store.AgentsFirstPage)
	}

	// Every character an id may hold sorts below the bound's one character.
	for _, c := range "0123456789abcdef-" {
		if string(c) >= store.AgentsFirstPage {
			t.Errorf("id character %q does not sort below %q", c, store.AgentsFirstPage)
		}
	}
}
