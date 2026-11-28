//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package store_test

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"regexp"
	"slices"
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
// and a query that does not (named otherwise, or not a constant expression of
// string literals and other string constants) fails the first test here.
//
// A query may be a concatenation of literals and other constants, such as the
// shared predicate every resolve includes, and it is checked as the text the
// database receives.

// packageQueries returns the value of every ...Query constant of the package's
// non-test source files, by name.
func packageQueries(t *testing.T) map[string]string {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}

	consts := map[string]ast.Expr{}

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			fileConsts(t, name, consts)
		}
	}

	queries := map[string]string{}

	for name, expr := range consts {
		if !strings.HasSuffix(name, "Query") {
			continue
		}

		text, err := constText(expr, consts, nil)
		if err != nil {
			t.Errorf("%s must be a constant string expression, so that it can be checked: %v", name, err)

			continue
		}

		queries[name] = text
	}

	return queries
}

// fileConsts adds the package-level constants of one source file that are given
// a value, by name.
func fileConsts(t *testing.T, name string, into map[string]ast.Expr) {
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
			values, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}

			for i, ident := range values.Names {
				if i < len(values.Values) {
					into[ident.Name] = values.Values[i]
				}
			}
		}
	}
}

var (
	errNotConstant = errors.New("not a constant string expression")
	errConstCycle  = errors.New("constant refers to itself")
)

// constText evaluates a constant string expression: string literals, names of
// other constants of the package, parentheses and "+". Anything else, such as a
// function call, is refused: the query would then not be text a test can read.
// seen holds the names being evaluated, to refuse a cycle.
func constText(expr ast.Expr, consts map[string]ast.Expr, seen []string) (string, error) {
	switch node := expr.(type) {
	case *ast.BasicLit:
		return literalText(node)
	case *ast.ParenExpr:
		return constText(node.X, consts, seen)
	case *ast.Ident:
		if slices.Contains(seen, node.Name) {
			return "", fmt.Errorf("%w: %s", errConstCycle, node.Name)
		}

		value, ok := consts[node.Name]
		if !ok {
			return "", fmt.Errorf("%w: %s is not a constant of the package", errNotConstant, node.Name)
		}

		return constText(value, consts, append(seen, node.Name))
	case *ast.BinaryExpr:
		return sumText(node, consts, seen)
	default:
		return "", fmt.Errorf("%w: %T", errNotConstant, expr)
	}
}

// literalText is the value of a string literal.
func literalText(node *ast.BasicLit) (string, error) {
	if node.Kind != token.STRING {
		return "", fmt.Errorf("%w: literal %s", errNotConstant, node.Value)
	}

	text, err := strconv.Unquote(node.Value)
	if err != nil {
		return "", fmt.Errorf("unquote %s: %w", node.Value, err)
	}

	return text, nil
}

// sumText is the value of the concatenation of two constant strings.
func sumText(node *ast.BinaryExpr, consts map[string]ast.Expr, seen []string) (string, error) {
	if node.Op != token.ADD {
		return "", fmt.Errorf("%w: operator %s", errNotConstant, node.Op)
	}

	left, err := constText(node.X, consts, seen)
	if err != nil {
		return "", err
	}

	right, err := constText(node.Y, consts, seen)
	if err != nil {
		return "", err
	}

	return left + right, nil
}

// TestConstText validates the evaluator the query checks rely on, including what
// it refuses.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestConstText(t *testing.T) {
	t.Parallel()

	consts := map[string]ast.Expr{}

	for name, source := range map[string]string{
		"a": "`x ` + b", "b": "\"y\"", "c": "(a + \" z\")", "n": "1", "f": "g()", "m": "a - b",
		"loop": "loop2", "loop2": "loop",
	} {
		expr, err := parser.ParseExpr(source)
		if err != nil {
			t.Fatalf("parse %q: %v", source, err)
		}

		consts[name] = expr
	}

	tests := []struct {
		name string
		want string
		fail bool
	}{
		{name: "b", want: "y"},
		{name: "a", want: "x y"},
		{name: "c", want: "x y z"},
		{name: "n", fail: true},
		{name: "f", fail: true},
		{name: "m", fail: true},
		{name: "loop", fail: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := constText(consts[test.name], consts, nil)
			if (err != nil) != test.fail || got != test.want {
				t.Errorf("constText = %q, %v; want %q, failure %v", got, err, test.want, test.fail)
			}
		})
	}

	_, err := constText(&ast.Ident{Name: "missing"}, consts, nil)
	if err == nil {
		t.Error("an unknown constant was evaluated")
	}

	_, err = constText(&ast.BasicLit{Kind: token.STRING, Value: "`unterminated"}, consts, nil)
	if err == nil {
		t.Error("a malformed literal was evaluated")
	}

	_, err = constText(&ast.BinaryExpr{X: &ast.BasicLit{Kind: token.INT, Value: "1"}, Op: token.ADD,
		Y: &ast.BasicLit{Kind: token.STRING, Value: "`a`"}}, consts, nil)
	if err == nil {
		t.Error("a sum with a non-string was evaluated")
	}

	_, err = constText(&ast.BinaryExpr{X: &ast.BasicLit{Kind: token.STRING, Value: "`a`"}, Op: token.ADD,
		Y: &ast.BasicLit{Kind: token.INT, Value: "1"}}, consts, nil)
	if err == nil {
		t.Error("a sum with a non-string was evaluated")
	}
}

// TestQueriesAreFound guards the other tests of this file against passing
// because they found nothing.
func TestQueriesAreFound(t *testing.T) {
	t.Parallel()

	queries := packageQueries(t)

	for _, name := range []string{
		"insertSecretQuery", "resolveSessionQuery", "resolveAPIKeyQuery", "revokeSecretQuery",
		"updateFlagsQuery", "insertSessionQuery",
		"invitationQuery", "insertUserQuery", "insertCredentialQuery", "credentialQuery",
		"firstRunStateQuery", "insertFirstRunSecretQuery", "insertFirstRunInvitationQuery",
		"listInvitationsQuery", "readInvitationQuery", "insertInvitationQuery", "updateNumInvitesQuery",
		"revokeInvitationSecretQuery", "insertInvitationOrgQuery", "insertPersonalOrgQuery",
		"insertOrgAdminQuery",
		"listUsersQuery", "getUserQuery", "revokeUserQuery", "revokeUserSecretsQuery", "revokeUserAgentsQuery",
		"agentRevokeKeysQuery",
		"keyListQuery", "keyGetQuery", "insertUserKeyQuery", "keyRenameQuery", "keyRevokeQuery",
		"insertGrantQuery", "grantListQuery", "grantGetQuery", "grantRevokeQuery", "grantRevokeAccessQuery",
		"rotateCodeQuery", "rotateRefreshQuery", "replaceAccessQuery", "insertAccessSecretQuery",
		"insertAccessRowQuery", "introspectQuery", "resolveGrantQuery", "revokeRefreshTokenQuery", "revokeRefreshAccessQuery",
		"revokeAccessTokenQuery", "supersedeGrantQuery", "supersedeAccessQuery",
		"insertSandboxQuery", "insertCreatorAdminQuery", "callerStandingQuery", "getOrgQuery",
		"listOrgsQuery", "renameOrgQuery", "orgStandingQuery", "deleteSandboxQuery",
		"listMembersQuery", "memberStandingQuery", "promoteMemberQuery", "demoteMemberQuery",
		"revokeStandingQuery",
	} {
		if _, ok := queries[name]; !ok {
			t.Errorf("query %s was not found", name)
		}
	}
}

// mayDelete is the one place a row is deleted for real, and the table it may
// delete from. Accounts, invitations, agents, sessions and keys are revoked and
// stay, because the audit trail and the single-use guarantees depend on the rows
// existing (see the migration): a session's replay guard must outlive the
// session. An agent's labels are different: they are mutable metadata its owner
// edits, with no authority to record, and removing one deletes its row.
//
//nolint:gochecknoglobals // a fixed table shared by the tests below
var mayDelete = map[string]string{
	"agentLabelRemoveQuery": "agent_labels",

	// Organizations: a sandbox is deleted by hand and is the only organization
	// ever deleted; a standard organization stays for life. An administrator row
	// is deleted when its member is demoted. Neither is a record that must
	// outlive its subject.
	"deleteSandboxQuery": "orgs",
	"demoteMemberQuery":  "org_admins",
}

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
// literals in SQL: the invitation type that is redeemable only once, the
// kind of every secret, the kinds of organization and the roles of an invitation's
// organization.
// The schema fixes each kind in a CHECK, which is a different place and is held
// to the constants by TestKindsMatchTheMigration and TestOrgKindsMatchTheMigration.
func TestQueriesBindValuesTheCodeOwns(t *testing.T) {
	t.Parallel()

	for name, query := range packageQueries(t) {
		for _, literal := range []string{
			"'" + store.InvitationFirstRun + "'", "'" + store.KindInvitation + "'",
			"'" + store.KindSession + "'", "'" + store.KindAPIKey + "'",
			"'" + store.KindOAuthGrant + "'", "'" + store.KindOAuthAccess + "'",
			"'" + store.OrgKindStandard + "'", "'" + store.OrgKindSandbox + "'",
			"'" + store.OrgRoleMember + "'", "'" + store.OrgRoleAdmin + "'",
		} {
			if strings.Contains(query, literal) {
				t.Errorf("%s contains the literal %s; bind the constant instead", name, literal)
			}
		}
	}
}

// TestQueriesNumberTheirParametersConsistently holds that no query mixes bare
// and numbered placeholders, which SQLite would number after the highest
// numbered one and which would silently shift the arguments, and that numbered
// ones have no gap. A query built from the shared predicate is bare throughout.
func TestQueriesNumberTheirParametersConsistently(t *testing.T) {
	t.Parallel()

	for name, query := range packageQueries(t) {
		_, err := parameterCount(query)
		if err != nil {
			t.Errorf("%s: %v:\n%s", name, err, query)
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
		{name: "a bare column is its own name", query: "SELECT k.scope, id FROM t k",
			lists: []string{"k.scope, id"}, names: []string{"scope", "id"}, problem: ""},
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

// placeholder matches a bound parameter: a bare ? or a numbered ?N.
var placeholder = regexp.MustCompile(`\?(\d*)`)

var (
	errMixedPlaceholders = errors.New("bare and numbered placeholders are mixed")
	errPlaceholderGap    = errors.New("numbered placeholders have a gap")
)

// parameterCount returns how many arguments a query binds. Bare placeholders
// are counted one by one; numbered ones are one argument per number, and the
// numbers must be 1 to n with no gap. Mixing the two is refused, since SQLite
// numbers a bare ? after the highest number seen so far.
func parameterCount(query string) (int, error) {
	bare, highest := 0, 0
	seen := map[int]bool{}

	for _, match := range placeholder.FindAllStringSubmatch(query, -1) {
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
		return 0, errMixedPlaceholders
	case bare > 0:
		return bare, nil
	}

	for number := 1; number <= highest; number++ {
		if !seen[number] {
			return 0, fmt.Errorf("%w: ?%d is missing below ?%d", errPlaceholderGap, number, highest)
		}
	}

	return highest, nil
}

// TestParameterCount validates the placeholder counting the checks below rely
// on.
func TestParameterCount(t *testing.T) {
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

			got, err := parameterCount(test.query)
			if (err != nil) != test.wantErr || got != test.want {
				t.Errorf("parameterCount = %d, %v; want %d, error %v", got, err, test.want, test.wantErr)
			}
		})
	}
}

// checkBatch is checkStatements for queries that number their
// placeholders: the fake must have seen exactly one batch of the wanted
// statements, each with the wanted fragments and the exact arguments, and each
// binding as many arguments as its text has parameters.
func checkBatch(t *testing.T, fake *fakeExec, want ...wantStatement) {
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

		count, err := parameterCount(query)
		if err != nil || count != len(got[i].Args) {
			t.Errorf("statement %d has %d parameters (%v) for %d args:\n%s", i, count, err, len(got[i].Args), query)
		}
	}
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
//
//nolint:funlen // one line per operation; splitting it would only scatter the table
func operations(t *testing.T) map[string]func(*store.Store) {
	t.Helper()

	ctx := context.Background()
	farthest := time.Unix(input.MaxSafeInteger, 0)
	agentID := mustAgentID(t)
	invitation := newInvitation(t)
	invitation.ExpiresAt = invExpiry(t, now.Add(input.ExpiryHorizon).Unix(), now)
	invitation.CreatedAt = farthest
	invitation.Org = newInvitationOrg(t, "admin")

	return map[string]func(*store.Store){
		"ResolveSession": func(s *store.Store) {
			_, _, _ = s.ResolveSession(ctx, mustSessionToken(t, 3), farthest)
		},
		"ResolveAPIKey": func(s *store.Store) {
			_, _, _ = s.ResolveAPIKey(ctx, mustAPIKeyToken(t, 3), farthest)
		},
		"CreateSession": func(s *store.Store) {
			_ = s.CreateSession(ctx, store.NewSession{
				ID: "id", Hash: hashOf(1), CredentialRowID: "cred", GrantedFrom: hashOf(2), ExpiresAt: farthest,
				Flags: 0xff, CreatedAt: farthest,
			})
		},
		"RevokeSecret": func(s *store.Store) { _, _ = s.RevokeSecret(ctx, "user", "id", farthest) },
		"RedeemableInvitationType": func(s *store.Store) {
			_, _, _ = s.RedeemableInvitationType(ctx, mustInvitationToken(t, 3), nil, farthest)
		},
		"CreateAccount": func(s *store.Store) {
			_ = s.CreateAccount(ctx, newAccount(t, func(a *store.NewAccount) {
				a.Flags, a.CreatedAt, a.FirstRunExpiresAt = 0xff, farthest, farthest
			}))
		},
		"CredentialByID":  func(s *store.Store) { _, _, _ = s.CredentialByID(ctx, []byte{1}) },
		"FirstRunState":   func(s *store.Store) { _, _ = s.FirstRunState(ctx) },
		"ListInvitations": func(s *store.Store) { _, _ = s.ListInvitations(ctx) },
		"GetInvitation":   func(s *store.Store) { _, _ = s.GetInvitation(ctx, invID(t)) },
		"CreateInvitation": func(s *store.Store) {
			_, _ = s.CreateInvitation(ctx, invitation)
		},
		"UpdateNumInvites": func(s *store.Store) {
			_, _, _ = s.UpdateNumInvites(ctx, invID(t), invNum(t, input.MaxNumInvites), farthest)
		},
		"RevokeInvitation": func(s *store.Store) { _, _ = s.RevokeInvitation(ctx, invID(t), farthest) },
		"ListUsers":        func(s *store.Store) { _, _ = s.ListUsers(ctx) },
		"GetUser":          func(s *store.Store) { _, _ = s.GetUser(ctx, mustUserID(t, userID1)) },
		"RevokeUser": func(s *store.Store) {
			_, _ = s.RevokeUser(ctx, mustUserID(t, userID1), userID2, userAdminRole, farthest)
		},
		"ListAgents": func(s *store.Store) {
			filter := mustAgentFilter(t, strings.Repeat("z", input.MaxLabelBytes))
			filter.Sandbox = mustAgentSandboxFilter(t, agentSandbox).Sandbox

			_, _ = s.ListAgents(ctx, store.SandboxAgents("owner", agentSandbox),
				mustAgentCursor(t, agentIDAt(1)), mustAgentLimit(t, "100"), filter)
		},
		"GetAgent": func(s *store.Store) {
			_, _ = s.GetAgent(ctx, store.SandboxAgents("owner", agentSandbox), agentID)
		},
		"CreateAgent": func(s *store.Store) {
			_, _ = s.CreateAgent(ctx, store.NewAgent{
				ID: "id", Owner: "owner", Name: mustAgentName(t, "agent"), Scopes: "[]", KeyScope: "[]", MaxActive: 1 << 30,
				KeyID: "key-id", KeyHash: hashOf(1), KeyExpiresAt: farthest, CreatedAt: farthest,
				Labels: mustAgentLabelSet(t, longestLabelSet()...), Sandbox: mustAgentSandboxID(t, agentSandbox),
			})
		},
		"PatchAgent":  func(s *store.Store) { _, _ = s.PatchAgent(ctx, "owner", agentID, largestPatch(t)) },
		"RevokeAgent": func(s *store.Store) { _, _ = s.RevokeAgent(ctx, "owner", agentID, farthest) },
		"ListKeys": func(s *store.Store) {
			_, _ = s.ListKeys(ctx, "owner", mustAgentCursor(t, agentIDAt(1)), mustAgentLimit(t, "100"))
		},
		"GetKey": func(s *store.Store) { _, _ = s.GetKey(ctx, "owner", agentID) },
		"CreateKey": func(s *store.Store) {
			_ = s.CreateKey(ctx, store.NewKey{
				ID: "key-id", Owner: "owner", Name: mustKeyName(t, strings.Repeat("\U00010000", input.MaxKeyNameRunes)),
				Scope: "[]", Hash: hashOf(1), ExpiresAt: farthest, MaxActive: 1 << 30, CreatedAt: farthest,
			})
		},
		"RenameKey": func(s *store.Store) {
			worst := mustKeyName(t, strings.Repeat("\U00010000", input.MaxKeyNameRunes))

			_, _ = s.RenameKey(ctx, "owner", agentID, worst, farthest)
		},
		"RevokeKey": func(s *store.Store) { _, _ = s.RevokeKey(ctx, "owner", agentID, "presented", farthest) },
		"CreateGrant": func(s *store.Store) {
			_ = s.CreateGrant(ctx, oauthWorstGrant(t, farthest))
		},
		"ListGrants": func(s *store.Store) {
			_, _ = s.ListGrants(ctx, "owner", mustAgentCursor(t, agentIDAt(1)), mustAgentLimit(t, "100"))
		},
		"GetGrant":    func(s *store.Store) { _, _ = s.GetGrant(ctx, "owner", agentID) },
		"RevokeGrant": func(s *store.Store) { _, _ = s.RevokeGrant(ctx, "owner", agentID, farthest) },
		"ExchangeCode": func(s *store.Store) {
			exchange := exchangeCases(t)[0].exchange
			exchange.Tokens = oauthWorstTokens(farthest)

			_, _ = s.ExchangeCode(ctx, exchange, farthest)
		},
		"Refresh": func(s *store.Store) {
			exchange := refreshCases(t)[0].exchange
			exchange.Tokens = oauthWorstTokens(farthest)

			_, _ = s.Refresh(ctx, exchange, farthest)
		},
		"IntrospectAccessToken": func(s *store.Store) {
			_, _, _ = s.IntrospectAccessToken(ctx, mustAccessToken(t, 3), mustResourceID(t), farthest)
		},
		"ResolveGrant": func(s *store.Store) {
			_, _, _ = s.ResolveGrant(ctx, mustAccessToken(t, 3), mustLoginResourceID(t), farthest)
		},
		"RevokeRefreshToken": func(s *store.Store) {
			_ = s.RevokeRefreshToken(ctx, mustRefreshToken(t, 3), oauthWorstClientID(t), farthest)
		},
		"RevokeAccessToken": func(s *store.Store) {
			_ = s.RevokeAccessToken(ctx, mustAccessToken(t, 3), oauthWorstClientID(t), farthest)
		},
		"CreateSandbox": func(s *store.Store) {
			_, _ = s.CreateSandbox(ctx, store.NewSandbox{
				ID: "id", Name: orgWorstName(t), Creator: "owner",
				ExpiresAt: farthest, Limit: 1 << 30, CreatedAt: farthest,
			})
		},
		"GetOrg": func(s *store.Store) { _, _ = s.GetOrg(ctx, agentID, "owner", "role") },
		"ListOrgs": func(s *store.Store) {
			_, _ = s.ListOrgs(ctx, "owner", "role", orgCursorOf(t, agentIDAt(1)), orgLimitOf(t, "100"))
		},
		"RenameOrg": func(s *store.Store) {
			_, _ = s.RenameOrg(ctx, agentID, orgWorstName(t), "owner", "role", farthest)
		},
		"DeleteSandbox": func(s *store.Store) { _, _ = s.DeleteSandbox(ctx, agentID, "owner", "role") },
		"ListMembers": func(s *store.Store) {
			_, _ = s.ListMembers(ctx, agentID, "owner", "role", orgCursorOf(t, agentIDAt(1)), orgLimitOf(t, "100"))
		},
		"SetMemberAdmin": func(s *store.Store) { _, _ = s.SetMemberAdmin(ctx, agentID, true, "owner", "role", farthest) },
		"RevokeMember":   func(s *store.Store) { _, _ = s.RevokeMember(ctx, agentID, "owner", "role", farthest) },
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
