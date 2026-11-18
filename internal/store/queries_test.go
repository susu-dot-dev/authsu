//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package store_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// This file checks every query in the package without naming them: it reads the
// package's own source and takes each constant whose name ends in "Query".
// An operation added later is covered as soon as it follows that convention,
// and a query that does not (built by concatenation, or named otherwise) fails
// the first test here.

// packageQueries returns the value of every ...Query constant of the package's
// non-test source files, by name.
func packageQueries(t *testing.T) map[string]string {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}

	queries := map[string]string{}

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			fileQueries(t, name, queries)
		}
	}

	return queries
}

// fileQueries adds the query constants of one source file.
func fileQueries(t *testing.T, name string, into map[string]string) {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}

	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}

		for _, spec := range gen.Specs {
			if values, ok := spec.(*ast.ValueSpec); ok {
				collectQueries(t, name, values, into)
			}
		}
	}
}

// collectQueries adds the query constants of one const spec.
func collectQueries(t *testing.T, file string, spec *ast.ValueSpec, into map[string]string) {
	t.Helper()

	for i, name := range spec.Names {
		if !strings.HasSuffix(name.Name, "Query") {
			continue
		}

		var literal *ast.BasicLit

		if i < len(spec.Values) {
			literal, _ = spec.Values[i].(*ast.BasicLit)
		}

		if literal == nil || literal.Kind != token.STRING {
			t.Errorf("%s: %s must be a single string literal, so that it can be checked", file, name.Name)

			continue
		}

		text, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatalf("%s: unquote %s: %v", file, name.Name, err)
		}

		into[name.Name] = text
	}
}

// TestQueriesAreFound guards the other tests of this file against passing
// because they found nothing.
func TestQueriesAreFound(t *testing.T) {
	t.Parallel()

	queries := packageQueries(t)

	for _, name := range []string{
		"activeKeyQuery", "updateFlagsQuery", "insertSessionQuery", "revokeKeyQuery",
		"invitationQuery", "insertUserQuery", "insertCredentialQuery", "credentialQuery",
		"firstRunStateQuery", "insertFirstRunQuery",
	} {
		if _, ok := queries[name]; !ok {
			t.Errorf("query %s was not found", name)
		}
	}
}

// mayDelete is the one place a row is deleted for real, and the table it may
// delete from. Accounts, invitations, agents and keys are revoked and stay,
// because the audit trail and the single-use guarantees depend on the rows
// existing (see the migrations). An agent's labels are different: they are
// mutable metadata its owner edits, with no authority to record (migration
// 0006), and removing one deletes its row.
//
//nolint:gochecknoglobals // a fixed table shared by the tests below
var mayDelete = map[string]string{"agentLabelRemoveQuery": "agent_labels"}

// TestNoQueryDeletes holds that nothing is ever deleted, except the labels of an
// agent: and those only by the query named in mayDelete, only from the table it
// names, and from nothing else in the same statement.
func TestNoQueryDeletes(t *testing.T) {
	t.Parallel()

	deletes := regexp.MustCompile(`(?i)\bDELETE\b`)

	for name, query := range packageQueries(t) {
		if !deletes.MatchString(query) {
			continue
		}

		table, allowed := mayDelete[name]
		if !allowed {
			t.Errorf("%s deletes:\n%s", name, query)

			continue
		}

		if got := squash(query); !strings.HasPrefix(got, "DELETE FROM "+table+" ") {
			t.Errorf("%s may delete only from %s:\n%s", name, table, query)
		}

		if strings.Count(strings.ToUpper(query), "DELETE") != 1 {
			t.Errorf("%s deletes more than once:\n%s", name, query)
		}
	}

	// The allowance names a query that exists, so it cannot go stale and
	// silently permit a future query of the same name.
	for name := range mayDelete {
		if _, found := packageQueries(t)[name]; !found {
			t.Errorf("mayDelete names %s, which is not a query", name)
		}
	}
}

// TestQueriesBindValuesTheCodeOwns holds that the values Go gives meaning to
// are bound as arguments from their one definition and not repeated as
// literals in SQL.
func TestQueriesBindValuesTheCodeOwns(t *testing.T) {
	t.Parallel()

	for name, query := range packageQueries(t) {
		for _, literal := range []string{"'first_run'", "'session'"} {
			if strings.Contains(query, literal) {
				t.Errorf("%s contains the literal %s; bind the constant instead", name, literal)
			}
		}
	}
}

// TestQueryColumnsHaveUniqueNames holds that every column a query returns has
// a name of its own: a batch returns rows keyed by name, so two columns of the
// same name collapse into one and the row comes back short.
func TestQueryColumnsHaveUniqueNames(t *testing.T) {
	t.Parallel()

	for name, query := range packageQueries(t) {
		for _, list := range columnLists(query) {
			names, problem := columnNames(list)
			if problem != "" {
				t.Errorf("%s: %s", name, problem)

				continue
			}

			seen := map[string]bool{}

			for _, column := range names {
				if seen[column] {
					t.Errorf("%s returns the column name %q more than once: %v", name, column, names)
				}

				seen[column] = true
			}
		}
	}
}

// TestColumnParsing validates the loose parser the test above relies on.
func TestColumnParsing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		query   string
		lists   []string
		names   []string
		problem string
	}{
		{name: "aliases", query: "SELECT a.x AS x, b.x AS y FROM t a JOIN u b",
			lists: []string{"a.x AS x, b.x AS y"}, names: []string{"x", "y"}, problem: ""},
		{name: "a bare column is its own name", query: "SELECT k.jwk, id FROM t k",
			lists: []string{"k.jwk, id"}, names: []string{"jwk", "id"}, problem: ""},
		{name: "commas and FROM inside parentheses and quotes",
			query: "SELECT COALESCE(a, ', FROM') AS c, (SELECT 1 FROM z WHERE q = 'a,b') AS d FROM t",
			lists: []string{"COALESCE(a, ', FROM') AS c, (SELECT 1 FROM z WHERE q = 'a,b') AS d"},
			names: []string{"c", "d"}, problem: ""},
		{name: "case and layout do not matter", query: "select\n  a\n  as\n  x\nfrom\n t",
			lists: []string{"a as x"}, names: []string{"x"}, problem: ""},
		{name: "no FROM", query: "SELECT EXISTS (SELECT 1 FROM users) AS u, 1 AS v",
			lists: []string{"EXISTS (SELECT 1 FROM users) AS u, 1 AS v"}, names: []string{"u", "v"}, problem: ""},
		{name: "an expression with no alias", query: "SELECT count(*) FROM t",
			lists: []string{"count(*)"}, names: nil, problem: "has no name"},
		{name: "a star", query: "SELECT * FROM t", lists: []string{"*"}, names: nil, problem: "has no name"},
		{name: "table star", query: "SELECT t.* FROM t", lists: []string{"t.*"}, names: nil, problem: "has no name"},
		{name: "insert returning", query: "INSERT INTO t (a) SELECT ? WHERE 1 RETURNING id, a AS b",
			lists: []string{"id, a AS b"}, names: []string{"id", "b"}, problem: ""},
		{name: "update returning", query: "UPDATE t SET a = 1 RETURNING id",
			lists: []string{"id"}, names: []string{"id"}, problem: ""},
		{name: "insert select is not a returned list", query: "INSERT INTO t (a, b) SELECT ?, ? FROM u",
			lists: nil, names: nil, problem: ""},
		{name: "a duplicate is visible to the caller", query: "SELECT a.id, b.id FROM t a JOIN t b",
			lists: []string{"a.id, b.id"}, names: []string{"id", "id"}, problem: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			lists := columnLists(test.query)
			if !reflect.DeepEqual(lists, test.lists) {
				t.Fatalf("lists = %q, want %q", lists, test.lists)
			}

			if len(lists) == 0 {
				return
			}

			names, problem := columnNames(lists[0])

			if test.problem == "" && problem != "" || test.problem != "" && !strings.Contains(problem, test.problem) {
				t.Fatalf("problem = %q, want %q", problem, test.problem)
			}

			if test.problem == "" && !reflect.DeepEqual(names, test.names) {
				t.Errorf("names = %q, want %q", names, test.names)
			}
		})
	}
}

// columnLists returns the text of each column list a query returns: the list of
// a query that starts with SELECT, and the list of a RETURNING clause.
func columnLists(query string) []string {
	text := strings.Join(strings.Fields(query), " ")

	var lists []string

	if len(text) >= len("SELECT ") && strings.EqualFold(text[:len("SELECT ")], "SELECT ") {
		rest := text[len("SELECT "):]

		end := topLevelKeyword(rest, "FROM")
		if end < 0 {
			end = len(rest)
		}

		lists = append(lists, strings.TrimSpace(rest[:end]))
	}

	if at := topLevelKeyword(text, "RETURNING"); at >= 0 {
		lists = append(lists, strings.TrimSpace(text[at+len("RETURNING"):]))
	}

	return lists
}

// topLevelKeyword returns the index of the first occurrence of word outside
// parentheses and quotes, delimited by non-identifier characters, or -1.
func topLevelKeyword(text, word string) int {
	depth := 0

	var quote rune

	for i, char := range text {
		switch {
		case quote != 0:
			if char == quote {
				quote = 0
			}
		case char == '\'' || char == '"':
			quote = char
		case char == '(':
			depth++
		case char == ')':
			depth--
		case depth == 0 && matchesWord(text, i, word):
			return i
		}
	}

	return -1
}

// matchesWord reports whether text has word at i, as a whole word.
func matchesWord(text string, i int, word string) bool {
	if len(text)-i < len(word) || !strings.EqualFold(text[i:i+len(word)], word) {
		return false
	}

	before := i == 0 || !isIdentifier(rune(text[i-1]))
	after := i+len(word) == len(text) || !isIdentifier(rune(text[i+len(word)]))

	return before && after
}

func isIdentifier(char rune) bool {
	return char == '_' || unicode.IsLetter(char) || unicode.IsDigit(char)
}

// columnNames returns the name of each column of a list, lower-cased. An item
// with no name (a star, or an expression without AS) is reported as a problem.
func columnNames(list string) ([]string, string) {
	bare := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`)
	alias := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

	var names []string

	for _, item := range splitTopLevel(list) {
		item = strings.TrimSpace(item)

		if at := lastTopLevelAs(item); at >= 0 {
			name := strings.TrimSpace(item[at+len("AS"):])
			if !alias.MatchString(name) {
				return nil, "column " + strconv.Quote(item) + " has an unusable alias"
			}

			names = append(names, strings.ToLower(name))

			continue
		}

		if !bare.MatchString(item) {
			return nil, "column " + strconv.Quote(item) + " has no name: alias it with AS"
		}

		names = append(names, strings.ToLower(item[strings.LastIndex(item, ".")+1:]))
	}

	return names, ""
}

// splitTopLevel splits a list at the commas outside parentheses and quotes.
func splitTopLevel(list string) []string {
	var (
		items []string
		quote rune
	)

	depth, start := 0, 0

	for i, char := range list {
		switch {
		case quote != 0:
			if char == quote {
				quote = 0
			}
		case char == '\'' || char == '"':
			quote = char
		case char == '(':
			depth++
		case char == ')':
			depth--
		case char == ',' && depth == 0:
			items = append(items, list[start:i])
			start = i + 1
		}
	}

	return append(items, list[start:])
}

// lastTopLevelAs returns the index of the last AS outside parentheses and
// quotes, or -1.
func lastTopLevelAs(item string) int {
	last, depth := -1, 0

	var quote rune

	for i, char := range item {
		switch {
		case quote != 0:
			if char == quote {
				quote = 0
			}
		case char == '\'' || char == '"':
			quote = char
		case char == '(':
			depth++
		case char == ')':
			depth--
		case depth == 0 && matchesWord(item, i, "AS"):
			last = i
		}
	}

	return last
}

// errStopRecording ends an operation after the fake has recorded its statements.
var errStopRecording = errors.New("stop after recording")

// longestLabelOf pads prefix with 'z' to exactly the longest label there is.
func longestLabelOf(prefix string) string {
	return prefix + strings.Repeat("z", input.MaxLabelBytes-len(prefix))
}

// largestPatch is the largest patch a request can carry: a name, and the most
// labels to remove and to add, each of the longest length.
func largestPatch(t *testing.T) store.AgentPatch {
	t.Helper()

	name := mustAgentName(t, "agent")
	added := make([]string, input.MaxLabelsPerPatch)
	removed := make([]string, input.MaxLabelsPerPatch)

	for i := range added {
		added[i] = longestLabelOf("add-" + strconv.Itoa(i) + "-")
		removed[i] = longestLabelOf("remove-" + strconv.Itoa(i) + "-")
	}

	return store.AgentPatch{Name: &name, Labels: mustAgentLabelPatch(t, added, removed), MaxLabels: 1 << 30}
}

// operations is every exported method of the Store, each called with the
// largest values its inputs can carry. The fake it runs over fails the call
// after recording its statements, which is all the tests below read.
//
// A method added to the Store must be added here: TestEveryOperationIsListed
// fails until it is.
func operations(t *testing.T) map[string]func(*store.Store) {
	t.Helper()

	ctx := context.Background()
	farthest := time.Unix(input.MaxSafeInteger, 0)
	agentID := mustAgentID(t)
	invitation := newInvitation(t)
	invitation.ExpiresAt = invExpiry(t, now.Add(input.ExpiryHorizon).Unix(), now)

	return map[string]func(*store.Store){
		"ActiveKey": func(s *store.Store) { _, _, _ = s.ActiveKey(ctx, "kid", store.KindSession, farthest) },
		"CreateSession": func(s *store.Store) {
			_ = s.CreateSession(ctx, store.NewSession{
				KeyID: "kid", CredentialRowID: "cred", JWK: "{}", ExpiresAt: farthest, GrantedFrom: []byte{1},
				Flags: 0xff, CreatedAt: farthest,
			})
		},
		"RevokeKey": func(s *store.Store) { _, _ = s.RevokeKey(ctx, "user", "kid", farthest) },
		"RedeemableInvitationType": func(s *store.Store) {
			_, _, _ = s.RedeemableInvitationType(ctx, mustCode(t, "code"), farthest)
		},
		"CreateAccount": func(s *store.Store) {
			_ = s.CreateAccount(ctx, newAccount(t, func(a *store.NewAccount) { a.Flags, a.CreatedAt = 0xff, farthest }))
		},
		"CredentialByID": func(s *store.Store) { _, _, _ = s.CredentialByID(ctx, []byte{1}) },
		"FirstRunState":  func(s *store.Store) { _, _ = s.FirstRunState(ctx) },
		"CreateFirstRunInvitation": func(s *store.Store) {
			_, _ = s.CreateFirstRunInvitation(ctx, "id", mustCode(t, "code"), "label", farthest)
		},
		"ListInvitations": func(s *store.Store) { _, _ = s.ListInvitations(ctx) },
		"CreateInvitation": func(s *store.Store) {
			_, _ = s.CreateInvitation(ctx, invitation)
		},
		"UpdateNumInvites": func(s *store.Store) {
			_, _, _ = s.UpdateNumInvites(ctx, invID(t), invNum(t, input.MaxNumInvites))
		},
		"RevokeInvitation": func(s *store.Store) { _, _ = s.RevokeInvitation(ctx, invID(t), farthest) },
		"ListUsers":        func(s *store.Store) { _, _ = s.ListUsers(ctx) },
		"GetUser":          func(s *store.Store) { _, _ = s.GetUser(ctx, mustUserID(t, userID1)) },
		"RevokeUser": func(s *store.Store) {
			_, _ = s.RevokeUser(ctx, mustUserID(t, userID1), userAdminRole, farthest)
		},
		"ListAgents": func(s *store.Store) {
			_, _ = s.ListAgents(ctx, "owner", mustAgentCursor(t, agentIDAt(1)), mustAgentLimit(t, "100"),
				mustAgentFilter(t, strings.Repeat("z", input.MaxLabelBytes)))
		},
		"GetAgent": func(s *store.Store) { _, _ = s.GetAgent(ctx, "owner", agentID) },
		"CreateAgent": func(s *store.Store) {
			_, _ = s.CreateAgent(ctx, store.NewAgent{
				ID: "id", Owner: "owner", Name: mustAgentName(t, "agent"), Scopes: "[]", KeyScope: "[]", MaxActive: 1 << 30,
				KeyID: "kid", KeyJWK: "{}", KeyExpiresAt: farthest, CreatedAt: farthest,
				Labels: mustAgentLabelSet(t, longestLabelSet()...),
			})
		},
		"PatchAgent":  func(s *store.Store) { _, _ = s.PatchAgent(ctx, "owner", agentID, largestPatch(t)) },
		"RevokeAgent": func(s *store.Store) { _, _ = s.RevokeAgent(ctx, "owner", agentID, farthest) },
	}
}

// TestEveryOperationIsListed holds the table above to the Store's exported
// methods, so the tests that read it cannot skip an operation added later.
func TestEveryOperationIsListed(t *testing.T) {
	t.Parallel()

	storeType := reflect.TypeFor[*store.Store]()
	listed := operations(t)

	for method := range storeType.Methods() {
		if listed[method.Name] == nil {
			t.Errorf("exported method %s is not in operations", method.Name)
		}
	}

	if storeType.NumMethod() != len(listed) {
		t.Errorf("Store has %d exported methods, operations lists %d", storeType.NumMethod(), len(listed))
	}
}

// TestEveryArgumentIsPortable holds the seam between the Go values bound to a
// statement and what D1 receives. The platform port takes nil, integers,
// floats, text and blobs and nothing else (a time.Time, an int or a bool would
// be converted, or refused, by whoever happens to implement the port), and an
// integer travels through JavaScript as a float64, so it must be exactly
// representable: no larger than 2^53-1 in magnitude, whatever the clock says.
// Every statement of every operation is held to it, with the largest values the
// operation's inputs can carry.
func TestEveryArgumentIsPortable(t *testing.T) {
	t.Parallel()

	for name, call := range operations(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(failing(errStopRecording))
			call(fake.store())

			if len(fake.calls) != 1 {
				t.Fatalf("exec called %d times, want one batch", len(fake.calls))
			}

			for i, statement := range fake.calls[0] {
				for at, arg := range statement.Args {
					switch value := arg.(type) {
					case nil, string, []byte:
					case int64:
						if value > input.MaxSafeInteger || value < -input.MaxSafeInteger {
							t.Errorf("statement %d argument %d is %d, beyond what JavaScript holds exactly", i, at, value)
						}
					default:
						t.Errorf("statement %d argument %d is a %T, which the platform port does not take", i, at, arg)
					}
				}
			}
		})
	}
}
