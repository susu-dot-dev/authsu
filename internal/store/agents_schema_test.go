package store_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/susu-dot-dev/authsu/internal/input"
)

// This file extends the seam of schema_test.go to the agent columns, with that
// file's bound table and checks. agents.name, agents.scopes and api_keys.scope bound BYTES and
// refuse NUL, because SQLite's length() on TEXT stops at the first NUL.

// agentDefaultScopes is the shape of the scope list every agent is created
// with (the agents feature's default bundle). Go chooses it, so it is not an
// input, but it is written to two columns whose CHECK it must fit.
const agentDefaultScopes = "default:agent"

// agentWorstName is the longest AgentName by bytes: the most runes the parser
// allows, each of the longest UTF-8 form.
func agentWorstName(t *testing.T) input.AgentName {
	t.Helper()

	return mustAgentName(t, strings.Repeat("\U00010000", input.MaxAgentNameRunes))
}

// keyWorstName is the longest KeyName by bytes: the most runes the parser
// allows, each of the longest UTF-8 form.
func keyWorstName(t *testing.T) input.KeyName {
	t.Helper()

	return mustKeyName(t, strings.Repeat("\U00010000", input.MaxKeyNameRunes))
}

// agentSchemaBounds lists the agent columns' Go values with the CHECK each must
// fit inside.
func agentSchemaBounds(t *testing.T) []bound {
	t.Helper()

	name := agentWorstName(t)

	// column is the start of a size CHECK of free text, so that a pattern matches
	// only the one column it names.
	column := func(name string) string {
		return fmt.Sprintf(`CHECK \(typeof\(%[1]s\) = 'text' AND instr\(%[1]s, char\(0\)\) = 0 AND `, name)
	}

	return []bound{
		// agents.name and api_keys.name have the same CHECK, so each pattern names the
		// column that follows it: the agent's scopes, and the key's scope.
		{name: "agents.name bytes",
			pattern: column("name") + `length\(cast\(name AS BLOB\)\) BETWEEN (\d+) AND (\d+)\), scopes TEXT`,
			lowest:  1, highest: len(name.String()), exact: false},
		// The scope lists are Go's to size: a ScopeList's stored form is at most
		// input.MaxScopeListJSONBytes, and at least "[]".
		{name: "agents.scopes bytes",
			pattern: column("scopes") + `length\(cast\(scopes AS BLOB\)\) BETWEEN (\d+) AND (\d+)\)`,
			lowest:  len("[]"), highest: input.MaxScopeListJSONBytes, exact: false},
		// A key's name has the agent name's rule: the most runes, each the longest.
		{name: "api_keys.name bytes",
			pattern: column("name") + `length\(cast\(name AS BLOB\)\) BETWEEN (\d+) AND (\d+)\), scope TEXT`,
			lowest:  1, highest: len(keyWorstName(t).String()), exact: false},
		// The pattern ends at the key's foreign key: oauth_grants.scope has a CHECK of
		// the same shape, with its own bound (oauthSchemaBounds).
		{name: "api_keys.scope bytes",
			pattern: column("scope") + `length\(cast\(scope AS BLOB\)\) BETWEEN (\d+) AND (\d+)\), FOREIGN KEY`,
			lowest:  len("[]"), highest: input.MaxScopeListJSONBytes, exact: false},
		// The longest label is exactly the CHECK's upper bound, and the
		// shortest its lower: a label's alphabet is ASCII, so bytes are
		// characters.
		{name: "agent_labels.label bytes", pattern: column("label") +
			`length\(cast\(label AS BLOB\)\) BETWEEN (\d+) AND (\d+)\)`,
			lowest: 1, highest: len(worstLabel(t)), exact: false},
	}
}

// worstLabel is the longest Label by bytes.
func worstLabel(t *testing.T) string {
	t.Helper()

	label, err := input.ParseLabel(strings.Repeat("z", input.MaxLabelBytes))
	if err != nil {
		t.Fatalf("parse the longest label: %v", err)
	}

	return label.String()
}

// TestAgentBoundsFitTheSchema holds that every value Go can send for an agent
// fits its CHECK.
func TestAgentBoundsFitTheSchema(t *testing.T) {
	t.Parallel()

	text := migrations(t)

	for _, b := range agentSchemaBounds(t) {
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()

			matches := regexp.MustCompile(b.pattern).FindAllStringSubmatch(text, -1)
			if len(matches) != 1 {
				t.Fatalf("%d CHECKs match %s, want exactly one; was the migration text changed?", len(matches), b.pattern)
			}

			checkBound(t, b, matches[0][1:])
		})
	}
}

// TestAgentBoundsAreMeaningful guards the table above against a pattern that
// matches but proves nothing: the worst name must really be the largest, and
// the parser must really refuse the NUL the CHECK refuses.
func TestAgentBoundsAreMeaningful(t *testing.T) {
	t.Parallel()

	name := agentWorstName(t).String()

	if want := input.MaxAgentNameRunes * utf8.UTFMax; len(name) != want {
		t.Errorf("worst-case name is %d bytes, want %d", len(name), want)
	}

	_, err := input.ParseAgentName(strings.Repeat("\U00010000", input.MaxAgentNameRunes+1))
	if err == nil {
		t.Error("a name of one rune more than the maximum was accepted")
	}

	// The CHECK refuses NUL (length() would stop at it); so must the parser.
	for _, raw := range []string{"\x00", "a\x00b", "bot\x00" + strings.Repeat("x", 4096)} {
		_, err = input.ParseAgentName(raw)
		if err == nil {
			t.Errorf("a name holding NUL was accepted: %q", raw[:min(len(raw), 8)])
		}
	}

	if agentDefaultScopes == "" || strings.ContainsRune(agentDefaultScopes, 0) {
		t.Errorf("the default scopes %q break the CHECK (1 to 1024 bytes, no NUL)", agentDefaultScopes)
	}
}

// TestLabelBoundsAreMeaningful guards the label row above against a pattern that
// matches but proves nothing: the worst label must really be the largest the
// parser accepts, and the CHECK's refusal of NUL must be the parser's too.
func TestLabelBoundsAreMeaningful(t *testing.T) {
	t.Parallel()

	if got := worstLabel(t); len(got) != input.MaxLabelBytes {
		t.Errorf("the worst label is %d bytes, want %d", len(got), input.MaxLabelBytes)
	}

	_, err := input.ParseLabel(strings.Repeat("z", input.MaxLabelBytes+1))
	if err == nil {
		t.Error("a label one byte over the maximum was accepted")
	}

	// An accepted label is ASCII, so no character is wider than a byte and the
	// byte bound is the character bound.
	for _, raw := range []string{"a", "z", "0", "9", ".", "_", "-", "az09._-"} {
		label, parseErr := input.ParseLabel(raw)
		if parseErr != nil || utf8.RuneCountInString(label.String()) != len(label.String()) {
			t.Errorf("label %q: %v; want an ASCII label", raw, parseErr)
		}
	}

	// The CHECK refuses NUL (length() would stop at it); so must the parser.
	for _, raw := range []string{"\x00", "a\x00b", "ab\x00" + strings.Repeat("c", 4096)} {
		_, err = input.ParseLabel(raw)
		if err == nil {
			t.Errorf("a label holding NUL was accepted: %q", raw[:min(len(raw), 8)])
		}
	}
}

// TestLabelMigrationShape holds the parts of the schema that the behaviour of the
// store depends on and that no Go value can show: the primary key that makes a
// label a member of a set (an add's ON CONFLICT target, and the filter's
// probe), and the cascade from the agent.
func TestLabelMigrationShape(t *testing.T) {
	t.Parallel()

	text := migrations(t)

	tests := []struct {
		name    string
		pattern string
	}{
		{name: "a label belongs to one agent and is unique within it", pattern: `PRIMARY KEY \(agent_id, label\)`},
		{
			name:    "the agent is a foreign key that cascades",
			pattern: `agent_id TEXT NOT NULL REFERENCES agents \(id\) ON DELETE CASCADE`,
		},
		{name: "agent_id is NOT NULL: the cap's batch failure depends on it", pattern: `agent_id TEXT NOT NULL`},
		{name: "the table is WITHOUT ROWID, keyed by the primary key", pattern: `\) WITHOUT ROWID;`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if matches := regexp.MustCompile(test.pattern).FindAllString(text, -1); len(matches) == 0 {
				t.Errorf("no migration matches %s", test.pattern)
			}
		})
	}
}

// TestLargestPatchIsLargest guards the "largest values" that
// TestEveryArgumentIsPortable runs PatchAgent with: every label of it must be
// exactly the longest there is, and there must be the most a request may carry,
// or the test would prove less than it says.
func TestLargestPatchIsLargest(t *testing.T) {
	t.Parallel()

	patch := largestPatch(t)

	for name, labels := range map[string][]input.Label{"added": patch.Labels.Add(), "removed": patch.Labels.Remove()} {
		if len(labels) != input.MaxLabelsPerPatch {
			t.Errorf("%s %d labels, want %d", name, len(labels), input.MaxLabelsPerPatch)
		}

		for _, label := range labels {
			if len(label.String()) != input.MaxLabelBytes {
				t.Errorf("%s label %q is %d bytes, want %d", name, label.String(), len(label.String()), input.MaxLabelBytes)
			}
		}
	}
}
