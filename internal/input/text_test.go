package input_test

import (
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
)

// The display-text types share their rules (primitives_internal_test.go proves
// the primitive); each table here adds the type's own bound, in its own unit.

func accountNameSpec() textSpec {
	return textSpec{max: input.MaxAccountNameBytes, runes: false, allowEmpty: false, identifying: true}
}

func agentNameSpec() textSpec {
	return textSpec{max: input.MaxAgentNameRunes, runes: true, allowEmpty: false, identifying: false}
}

func keyNameSpec() textSpec {
	return textSpec{max: input.MaxKeyNameRunes, runes: true, allowEmpty: false, identifying: false}
}

func labelSpec() textSpec {
	return textSpec{max: input.MaxInvitationLabelRunes, runes: true, allowEmpty: true, identifying: false}
}

func parseAccountName(raw string) (string, error) {
	return strAdapter(input.ParseAccountName, input.AccountName.String)(raw)
}

func parseAgentName(raw string) (string, error) {
	return strAdapter(input.ParseAgentName, input.AgentName.String)(raw)
}

func parseKeyName(raw string) (string, error) {
	return strAdapter(input.ParseKeyName, input.KeyName.String)(raw)
}

func parseLabel(raw string) (string, error) {
	return strAdapter(input.ParseInvitationLabel, input.InvitationLabel.String)(raw)
}

func TestParseAccountName(t *testing.T) {
	t.Parallel()
	runStringTable(t, textCases(accountNameSpec()), parseAccountName, input.CodeInvalidName)
}

func TestParseAgentName(t *testing.T) {
	t.Parallel()
	runStringTable(t, textCases(agentNameSpec()), parseAgentName, input.CodeInvalidAgentName)
}

func TestParseKeyName(t *testing.T) {
	t.Parallel()
	runStringTable(t, textCases(keyNameSpec()), parseKeyName, input.CodeInvalidKeyName)
}

func TestParseInvitationLabel(t *testing.T) {
	t.Parallel()
	runStringTable(t, textCases(labelSpec()), parseLabel, input.CodeInvalidLabel)
}

// TestTextBoundsFitTheSchema pins the arithmetic the bound constants rely on.
func TestTextBoundsFitTheSchema(t *testing.T) {
	t.Parallel()

	const (
		profileMaxBytes   = 1024 // users.profile CHECK, migration 0001
		agentNameMaxBytes = 1024 // agents.name CHECK, migration 0001
		keyNameMaxBytes   = 1024 // api_keys.name CHECK, migration 0001
		maxRuneBytes      = 4
		objectSyntax      = len(`{"name":""}`)
		maxJSONExpansion  = 6 // "<" becomes \u003c in encoding/json
	)

	if got := input.MaxAccountNameBytes*maxJSONExpansion + objectSyntax; got > profileMaxBytes {
		t.Errorf("worst-case profile JSON is %d bytes, over the %d-byte CHECK", got, profileMaxBytes)
	}

	if got := input.MaxAgentNameRunes * maxRuneBytes; got > agentNameMaxBytes {
		t.Errorf("worst-case agent name is %d bytes, over the %d-byte CHECK", got, agentNameMaxBytes)
	}

	if got := input.MaxKeyNameRunes * maxRuneBytes; got > keyNameMaxBytes {
		t.Errorf("worst-case key name is %d bytes, over the %d-byte CHECK", got, keyNameMaxBytes)
	}
}

// TestTextDescriptionsStateTheBound keeps the fixed client-facing text in step
// with the exported constants.
func TestTextDescriptionsStateTheBound(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		parse func(string) (string, error)
		code  string
		max   int
	}{
		{"account name", parseAccountName, input.CodeInvalidName, input.MaxAccountNameBytes},
		{"agent name", parseAgentName, input.CodeInvalidAgentName, input.MaxAgentNameRunes},
		{"key name", parseKeyName, input.CodeInvalidKeyName, input.MaxKeyNameRunes},
		{"label", parseLabel, input.CodeInvalidLabel, input.MaxInvitationLabelRunes},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := tc.parse("\x00")
			requireMentions(t, descriptionOf(t, err, tc.code), tc.max)
		})
	}
}

// TestZeroTextValuesAreEmpty documents that the zero value is the empty string,
// which is why the parsers (apart from the label's) refuse "".
func TestZeroTextValuesAreEmpty(t *testing.T) {
	t.Parallel()

	var (
		name  input.AccountName
		agent input.AgentName
		key   input.KeyName
		label input.InvitationLabel
	)

	if name.String() != "" || agent.String() != "" || key.String() != "" || label.String() != "" {
		t.Error("zero values are not empty")
	}
}

func FuzzParseAccountName(f *testing.F) {
	fuzzString(f, seedsOf(textCases(accountNameSpec())), input.ParseAccountName, input.AccountName.String,
		input.CodeInvalidName, textOracle(accountNameSpec()))
}

func FuzzParseAgentName(f *testing.F) {
	fuzzString(f, seedsOf(textCases(agentNameSpec())), input.ParseAgentName, input.AgentName.String,
		input.CodeInvalidAgentName, textOracle(agentNameSpec()))
}

func FuzzParseKeyName(f *testing.F) {
	fuzzString(f, seedsOf(textCases(keyNameSpec())), input.ParseKeyName, input.KeyName.String,
		input.CodeInvalidKeyName, textOracle(keyNameSpec()))
}

func FuzzParseInvitationLabel(f *testing.F) {
	fuzzString(f, seedsOf(textCases(labelSpec())), input.ParseInvitationLabel, input.InvitationLabel.String,
		input.CodeInvalidLabel, textOracle(labelSpec()))
}
