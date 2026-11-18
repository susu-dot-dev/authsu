//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package store_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
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
	agentsUnavailable = "agents are temporarily unavailable"
	agentOwner        = "user-1"
	agentTarget       = "01900000-0000-7000-8000-000000000042"
	agentCursorID     = "01900000-0000-7000-8000-000000000050"

	// agentLargestID is the greatest id an agent can have, in the order the
	// database sorts text: the first page's cursor must be above it.
	agentLargestID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
)

// agentIDAt returns the canonical id of the n-th agent. A larger n is a later
// agent and sorts higher.
func agentIDAt(n int) string { return fmt.Sprintf("01900000-0000-7000-8000-%012d", n) }

// agentRowAt is a returned agent row: id, name, scopes, revoked_at, created_at.
func agentRowAt(n int) []any {
	return row(agentIDAt(n), "agent "+strconv.Itoa(n), "default:agent", nil, int64(1_700_000_000+n))
}

// agentRow is the row of the agent agentTarget.
func agentRow() []any {
	return row(agentTarget, "build bot", "default:agent", nil, int64(1_700_000_000))
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

// agentPlaceholder matches a bound parameter: a bare ? or a numbered ?N.
var agentPlaceholder = regexp.MustCompile(`\?(\d*)`)

var (
	errAgentMixed = errors.New("bare and numbered placeholders are mixed")
	errAgentGap   = errors.New("numbered placeholders have a gap")
)

// agentParameters returns how many arguments a query binds. Bare placeholders
// are counted one by one; numbered ones are one argument per number, and the
// numbers must be 1 to n with no gap. Mixing the two is refused, since SQLite
// numbers a bare ? after the highest number seen so far.
func agentParameters(query string) (int, error) {
	bare, highest := 0, 0
	seen := map[int]bool{}

	for _, match := range agentPlaceholder.FindAllStringSubmatch(query, -1) {
		if match[1] == "" {
			bare++

			continue
		}

		number, err := strconv.Atoi(match[1])
		if err != nil {
			return 0, fmt.Errorf("placeholder %q: %w", match[0], err)
		}

		seen[number] = true
		highest = max(highest, number)
	}

	switch {
	case bare > 0 && len(seen) > 0:
		return 0, errAgentMixed
	case bare > 0:
		return bare, nil
	}

	for number := 1; number <= highest; number++ {
		if !seen[number] {
			return 0, fmt.Errorf("%w: ?%d is missing below ?%d", errAgentGap, number, highest)
		}
	}

	return highest, nil
}

// TestAgentParameters validates the placeholder counting the checks below rely
// on.
func TestAgentParameters(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		query   string
		want    int
		wantErr bool
	}{
		{name: "none", query: "SELECT 1", want: 0},
		{name: "bare", query: "WHERE a = ? AND b = ?", want: 2},
		{name: "numbered, one reused", query: "WHERE a = ?1 AND b = ?2 AND c > ?1", want: 2},
		{name: "numbered in a different order", query: "SET a = ?3 WHERE b = ?1 AND c = ?2", want: 3},
		{name: "a gap", query: "WHERE a = ?1 AND b = ?3", wantErr: true},
		{name: "mixed", query: "WHERE a = ?1 AND b = ?", wantErr: true},
		{name: "a number too large", query: "WHERE a = ?99999999999999999999", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := agentParameters(test.query)
			if (err != nil) != test.wantErr || got != test.want {
				t.Errorf("agentParameters = %d, %v; want %d, error %v", got, err, test.want, test.wantErr)
			}
		})
	}
}

// checkAgentBatch is checkStatements for queries that number their
// placeholders: the fake must have seen exactly one batch of the wanted
// statements, each with the wanted fragments and the exact arguments, and each
// binding as many arguments as its text has parameters.
func checkAgentBatch(t *testing.T, fake *fakeExec, want ...wantStatement) {
	t.Helper()

	if len(fake.calls) != 1 {
		t.Fatalf("exec called %d times, want exactly one batch", len(fake.calls))
	}

	got := fake.calls[0]
	if len(got) != len(want) {
		t.Fatalf("batch has %d statements, want %d", len(got), len(want))
	}

	for i, expected := range want {
		query := squash(got[i].Query)

		for _, fragment := range expected.fragments {
			if !strings.Contains(query, fragment) {
				t.Errorf("statement %d lacks %q:\n%s", i, fragment, query)
			}
		}

		if !reflect.DeepEqual(got[i].Args, expected.args) {
			t.Errorf("statement %d args = %#v, want %#v", i, got[i].Args, expected.args)
		}

		count, err := agentParameters(query)
		if err != nil || count != len(got[i].Args) {
			t.Errorf("statement %d has %d parameters (%v) for %d args:\n%s", i, count, err, len(got[i].Args), query)
		}
	}
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

// agentReadOps are the four operations that decode agent rows.
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
				page, err := s.ListAgents(ctx, agentOwner, cursor, limit)

				return page.Agents, passErr(err)
			},
		},
		{
			name: "get", rejected: store.CodeAgentLookupRejected, one: true, outcome: returning,
			call: func(s *store.Store) ([]store.Agent, error) { return single(s.GetAgent(ctx, agentOwner, id)) },
		},
		{
			name: "rename", rejected: store.CodeAgentUpdateRejected, one: true, outcome: returning,
			call: func(s *store.Store) ([]store.Agent, error) {
				return single(s.RenameAgent(ctx, agentOwner, id, name))
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

// TestAgentDecoding holds how a returned row becomes an Agent, for every
// operation that reads one: they share a reader, and a column it reads wrongly
// would be wrong everywhere.
func TestAgentDecoding(t *testing.T) {
	t.Parallel()

	revokedAt := int64(1_700_000_100)

	tests := []struct {
		name string
		row  []any
		want store.Agent
	}{
		{name: "an active agent", row: agentRow(), want: store.Agent{
			ID: agentTarget, Name: "build bot", Scopes: "default:agent", RevokedAt: nil, CreatedAt: 1_700_000_000,
		}},
		{name: "a revoked agent", row: agentRevokedRow(), want: store.Agent{
			ID: agentTarget, Name: "build bot", Scopes: "default:agent", RevokedAt: &revokedAt, CreatedAt: 1_700_000_000,
		}},
		{name: "a multibyte name is kept as is", row: with(agentRow(), 1, "ビルド・ボット 🤖"), want: store.Agent{
			ID: agentTarget, Name: "ビルド・ボット 🤖", Scopes: "default:agent", RevokedAt: nil, CreatedAt: 1_700_000_000,
		}},
	}

	for _, op := range agentReadOps(t) {
		for _, test := range tests {
			t.Run(op.name+"/"+test.name, func(t *testing.T) {
				t.Parallel()

				fake := newFake(op.outcome(test.row))

				got, err := op.call(fake.store())
				checkErr(t, err, nil)

				if !reflect.DeepEqual(got, []store.Agent{test.want}) {
					t.Errorf("agents = %+v, want %+v", got, test.want)
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
		{name: "a column too few", row: agentRow()[:4]},
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

	if page.Agents == nil || len(page.Agents) != test.agents {
		t.Fatalf("page has %d agents (nil %v), want %d", len(page.Agents), page.Agents == nil, test.agents)
	}

	for i, agent := range page.Agents {
		if agent.ID != agentIDAt(1000-i) {
			t.Errorf("agent %d is %s, want %s: order must be the database's", i, agent.ID, agentIDAt(1000-i))
		}
	}

	wantNext := ""
	if test.next {
		wantNext = agentIDAt(1000 - (test.agents - 1))
	}

	if page.Next != wantNext {
		t.Errorf("next = %q, want %q", page.Next, wantNext)
	}

	if args := fake.calls[0][0].Args; len(args) != 3 || args[2] != int64(test.size+1) {
		t.Errorf("args = %#v, want the page size plus one (%d) last", args, test.size+1)
	}
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

			page, err := fake.store().ListAgents(context.Background(), agentOwner, mustAgentCursor(t), test.limit)
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

	page, err := fake.store().ListAgents(context.Background(), agentOwner, mustAgentCursor(t), mustAgentLimit(t, "1"))

	checkErr(t, err, defectOf(store.CodeAgentListRejected))

	if page.Agents != nil || page.Next != "" {
		t.Errorf("a defective page returned %+v", page)
	}
}

// TestListAgentsStatement pins the query's guards and its arguments in
// placeholder order: the owner scopes the page, the cursor is an exclusive
// upper bound on the id, and the first page has a bound above every id.
func TestListAgentsStatement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		cursor input.Cursor
		limit  input.PageLimit

		// before is the cursor argument, or "" for the first page's bound.
		before string
		rows   int64
	}{
		{name: "first page", cursor: mustAgentCursor(t), limit: mustAgentLimit(t), before: "", rows: 26},
		{name: "after a cursor", cursor: mustAgentCursor(t, agentCursorID), limit: mustAgentLimit(t, "7"),
			before: agentCursorID, rows: 8},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning())

			_, err := fake.store().ListAgents(context.Background(), agentOwner, test.cursor, test.limit)
			checkErr(t, err, nil)

			before := test.before
			if before == "" {
				var isText bool

				before, isText = fake.calls[0][0].Args[1].(string)
				if !isText || before <= agentLargestID {
					t.Errorf("first page bound %#v does not sort above every id", fake.calls[0][0].Args[1])
				}
			}

			checkAgentBatch(t, fake, wantStatement{
				fragments: []string{
					"FROM agents",
					"WHERE user_id = ?1 AND id < ?2",
					"ORDER BY id DESC",
					"LIMIT ?3",
				},
				args: []any{agentOwner, before, test.rows},
			})
		})
	}
}

// TestListAgentsFailures holds how a failed or malformed batch is reported.
func TestListAgentsFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 1, store.CodeAgentListFailed, store.CodeAgentListRejected, agentsUnavailable,
		func(s *store.Store) error {
			return lastErr(s.ListAgents(context.Background(), agentOwner, mustAgentCursor(t), mustAgentLimit(t)))
		})
}

// TestGetAgentStatement pins that the owner is part of the match, so another
// user's agent is not found, and the arguments in order.
func TestGetAgentStatement(t *testing.T) {
	t.Parallel()

	fake := newFake(returning(agentRow()))

	_, err := fake.store().GetAgent(context.Background(), agentOwner, mustAgentID(t))
	checkErr(t, err, nil)

	checkAgentBatch(t, fake, wantStatement{
		fragments: []string{
			"SELECT id, name, scopes, revoked_at, created_at FROM agents",
			"WHERE id = ? AND user_id = ?",
		},
		args: []any{agentTarget, agentOwner},
	})
}

// TestGetAgentFailures holds how a failed or malformed batch is reported.
func TestGetAgentFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 1, store.CodeAgentLookupFailed, store.CodeAgentLookupRejected, agentsUnavailable,
		func(s *store.Store) error {
			return lastErr(s.GetAgent(context.Background(), agentOwner, mustAgentID(t)))
		})
}

// TestCreateAgentStatements pins the batch a create writes: the guards that make
// the agent conditional on its owner, and the key whose owner is read from the
// agent's row so that no agent means a failed batch.
func TestCreateAgentStatements(t *testing.T) {
	t.Parallel()

	expires := time.Unix(1_707_776_123, 0)

	tests := []struct {
		name  string
		agent store.NewAgent
	}{
		{name: "a typical agent", agent: store.NewAgent{
			ID: agentTarget, Owner: agentOwner, Name: mustAgentName(t, "build bot"), Scopes: "default:agent",
			MaxActive: 25, KeyID: "kid-1", KeyJWK: `{"keys":[{}]}`, KeyExpiresAt: expires, CreatedAt: now,
		}},
		{name: "a multibyte name and another limit", agent: store.NewAgent{
			ID: agentCursorID, Owner: "user-2", Name: mustAgentName(t, "ボット 🤖"), Scopes: "a:b c:d",
			MaxActive: 1, KeyID: "kid-2", KeyJWK: `{"keys":[]}`, KeyExpiresAt: expires.Add(time.Hour),
			CreatedAt: now.Add(time.Minute),
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(applied(2))

			err := fake.store().CreateAgent(context.Background(), test.agent)
			checkErr(t, err, nil)

			agent := test.agent

			checkAgentBatch(t, fake,
				wantStatement{
					fragments: []string{
						"INSERT INTO agents (id, user_id, name, scopes, created_at)",
						"SELECT ?1, u.id, ?2, ?3, ?4 FROM users u",
						// The owner must be active, read from users, and under the limit:
						// the count is part of the write.
						"WHERE u.id = ?5 AND u.revoked_at IS NULL",
						"AND (SELECT count(*) FROM agents a WHERE a.user_id = u.id AND a.revoked_at IS NULL) < ?6",
					},
					args: []any{
						agent.ID, agent.Name.String(), agent.Scopes, agent.CreatedAt.Unix(),
						agent.Owner, int64(agent.MaxActive),
					},
				},
				wantStatement{
					fragments: []string{
						"INSERT INTO japikeys (kid, user_id, kind, jwk, expires_at, agent_id, scope, created_at)",
						// The key's owner is the agent row's, not an argument.
						"(SELECT user_id FROM agents WHERE id = ?)",
					},
					args: []any{
						agent.KeyID, agent.ID, store.KindAPIKey, agent.KeyJWK, agent.KeyExpiresAt.Unix(),
						agent.ID, agent.Scopes, agent.CreatedAt.Unix(),
					},
				},
			)

			if strings.Contains(squash(fake.calls[0][1].Query), "'api_key'") {
				t.Error("the key insert writes the kind as a literal; bind store.KindAPIKey")
			}
		})
	}
}

// TestCreateAgentFailures holds that a limit or a revoked owner (conflicts) and
// every other failure come back as classified.
func TestCreateAgentFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 2, store.CodeAgentCreateFailed, store.CodeAgentCreateRejected, agentsUnavailable,
		func(s *store.Store) error {
			return passErr(s.CreateAgent(context.Background(), store.NewAgent{
				ID: agentTarget, Owner: agentOwner, Name: mustAgentName(t, "bot"), Scopes: "default:agent",
				MaxActive: 25, KeyID: "kid-1", KeyJWK: "{}", KeyExpiresAt: now, CreatedAt: now,
			}))
		})
}

// TestRenameAgent holds the outcomes of a rename: the row is whatever the one
// statement left, so a revoked agent comes back unchanged for the caller to
// refuse, and no row is a missing agent.
func TestRenameAgent(t *testing.T) {
	t.Parallel()

	revokedAt := int64(1_700_000_100)

	tests := []struct {
		name string
		rows [][]any
		want store.Agent
		err  error
	}{
		{name: "renamed", rows: [][]any{with(agentRow(), 1, "renamed")}, want: store.Agent{
			ID: agentTarget, Name: "renamed", Scopes: "default:agent", RevokedAt: nil, CreatedAt: 1_700_000_000,
		}},
		{name: "revoked keeps its name and says so", rows: [][]any{agentRevokedRow()}, want: store.Agent{
			ID: agentTarget, Name: "build bot", Scopes: "default:agent", RevokedAt: &revokedAt, CreatedAt: 1_700_000_000,
		}},
		{name: "no such agent", rows: nil, err: store.ErrNotFound},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(test.rows...))

			got, err := fake.store().RenameAgent(context.Background(), agentOwner, mustAgentID(t),
				mustAgentName(t, "renamed"))

			if !errors.Is(err, test.err) {
				t.Fatalf("error = %v, want %v", err, test.err)
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("agent = %+v, want %+v", got, test.want)
			}

			// A revoked agent is final: the CASE leaves its name, and the owner
			// is part of the match.
			checkAgentBatch(t, fake, wantStatement{
				fragments: []string{
					"UPDATE agents",
					"SET name = CASE WHEN revoked_at IS NULL THEN ?1 ELSE name END",
					"WHERE id = ?2 AND user_id = ?3",
					"RETURNING id, name, scopes, revoked_at, created_at",
				},
				args: []any{"renamed", agentTarget, agentOwner},
			})
		})
	}
}

// TestRenameAgentFailures holds that a conflict is as much a defect as a
// schema rule: a rename sets nothing the data could collide with.
func TestRenameAgentFailures(t *testing.T) {
	t.Parallel()

	for _, f := range agentWriteFailures(1, store.CodeAgentUpdateFailed, store.CodeAgentUpdateRejected) {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(f.outcome)

			_, err := fake.store().RenameAgent(context.Background(), agentOwner, mustAgentID(t),
				mustAgentName(t, "renamed"))

			checkFailure(t, err, f)

			if errors.Is(err, store.ErrNotFound) {
				t.Error("a failure is reported as a missing agent")
			}
		})
	}
}

// TestRevokeAgent holds the outcomes of a revoke: the row is whatever the first
// statement left, and the key update that follows is part of the same batch.
func TestRevokeAgent(t *testing.T) {
	t.Parallel()

	revokedAt := int64(1_700_000_100)

	tests := []struct {
		name    string
		outcome outcome
		want    store.Agent
		err     error
	}{
		{name: "revoked with two keys", outcome: agentRevoked(2, agentRevokedRow()), want: store.Agent{
			ID: agentTarget, Name: "build bot", Scopes: "default:agent", RevokedAt: &revokedAt, CreatedAt: 1_700_000_000,
		}},
		{name: "revoked with no key left to revoke", outcome: agentRevoked(0, agentRevokedRow()), want: store.Agent{
			ID: agentTarget, Name: "build bot", Scopes: "default:agent", RevokedAt: &revokedAt, CreatedAt: 1_700_000_000,
		}},
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

			checkAgentBatch(t, fake,
				wantStatement{
					fragments: []string{
						"UPDATE agents",
						// An agent already revoked keeps its earlier time.
						"SET revoked_at = COALESCE(revoked_at, ?1)",
						"WHERE id = ?2 AND user_id = ?3",
						"RETURNING id, name, scopes, revoked_at, created_at",
					},
					args: []any{now.Unix(), agentTarget, agentOwner},
				},
				wantStatement{
					fragments: []string{
						"UPDATE japikeys",
						"SET revoked_at = ?1",
						"WHERE agent_id = ?2",
						"AND user_id = ?3",
						// A due revocation keeps its time; a later one is brought forward.
						"AND (revoked_at IS NULL OR revoked_at > ?1)",
						// Only once the agent is revoked, and only the owner's agent.
						"AND EXISTS (SELECT 1 FROM agents WHERE id = ?2 AND user_id = ?3 AND revoked_at IS NOT NULL)",
					},
					args: []any{now.Unix(), agentTarget, agentOwner},
				},
			)
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
		"agentListQuery", "agentGetQuery", "insertAgentQuery", "insertAgentKeyQuery",
		"agentRenameQuery", "agentRevokeQuery", "agentRevokeKeysQuery",
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
		"agentListQuery", "agentGetQuery", "agentRenameQuery", "agentRevokeQuery", "agentRevokeKeysQuery",
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
		{store.KindAPIKey, "api_key"},
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
