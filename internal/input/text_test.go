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

func orgNameSpec() textSpec {
	return textSpec{max: input.MaxOrgNameRunes, runes: true, allowEmpty: false, identifying: false}
}

func clientNameSpec() textSpec {
	return textSpec{max: input.MaxClientNameBytes, runes: false, allowEmpty: false, identifying: true}
}

func parseAccountName(raw string) (string, error) {
	return strAdapter(input.ParseAccountName, input.AccountName.String)(raw)
}

func parseClientName(raw string) (string, error) {
	return strAdapter(input.ParseClientName, input.ClientName.String)(raw)
}

func parseAgentName(raw string) (string, error) {
	return strAdapter(input.ParseAgentName, input.AgentName.String)(raw)
}

func parseKeyName(raw string) (string, error) {
	return strAdapter(input.ParseKeyName, input.KeyName.String)(raw)
}

func parseOrgName(raw string) (string, error) {
	return strAdapter(input.ParseOrgName, input.OrgName.String)(raw)
}

func parseLabel(raw string) (string, error) {
	return strAdapter(input.ParseInvitationLabel, input.InvitationLabel.String)(raw)
}

func TestParseAccountName(t *testing.T) {
	t.Parallel()
	runStringTable(t, textCases(accountNameSpec()), parseAccountName, input.CodeInvalidName)
}

func TestParseClientName(t *testing.T) {
	t.Parallel()
	runStringTable(t, textCases(clientNameSpec()), parseClientName, input.CodeInvalidClientName)
}

func TestParseAgentName(t *testing.T) {
	t.Parallel()
	runStringTable(t, textCases(agentNameSpec()), parseAgentName, input.CodeInvalidAgentName)
}

func TestParseKeyName(t *testing.T) {
	t.Parallel()
	runStringTable(t, textCases(keyNameSpec()), parseKeyName, input.CodeInvalidKeyName)
}

func TestParseOrgName(t *testing.T) {
	t.Parallel()
	runStringTable(t, textCases(orgNameSpec()), parseOrgName, input.CodeInvalidOrgName)
}

func TestParseInvitationLabel(t *testing.T) {
	t.Parallel()
	runStringTable(t, textCases(labelSpec()), parseLabel, input.CodeInvalidLabel)
}

// TestEveryAccountNameIsAnOrgName holds that the organization created for an
// account can always be named after it: for every account name the parser
// accepts, of the cases of every text rule, "<name>'s org" is accepted by the
// organization name's parser, and OrgNameOf produces exactly that.
func TestEveryAccountNameIsAnOrgName(t *testing.T) {
	t.Parallel()

	for _, tc := range textCases(accountNameSpec()) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			requireAccountNameIsOrgName(t, tc.in)
		})
	}
}

// requireAccountNameIsOrgName checks one raw value: if it is an account name it
// is an organization name with the suffix, and the conversion adds only that.
func requireAccountNameIsOrgName(t *testing.T, raw string) {
	t.Helper()

	name, err := input.ParseAccountName(raw)
	if err != nil {
		return
	}

	want := raw + "'s org"

	org, err := input.ParseOrgName(want)
	if err != nil {
		t.Fatalf("the personal organization name %q is not an organization name: %v", want, err)
	}

	if got := input.OrgNameOf(name); got != org || got.String() != want {
		t.Fatalf("OrgNameOf(%q) = %q, want %q", raw, got.String(), want)
	}
}

// FuzzEveryAccountNameIsAnOrgName is the same property over arbitrary text.
func FuzzEveryAccountNameIsAnOrgName(f *testing.F) {
	for _, seed := range seedsOf(textCases(accountNameSpec())) {
		f.Add(seed)
	}

	f.Fuzz(requireAccountNameIsOrgName)
}

// TestTextBoundsFitTheSchema pins the arithmetic the bound constants rely on.
func TestTextBoundsFitTheSchema(t *testing.T) {
	t.Parallel()

	const (
		profileMaxBytes   = 1024 // users.profile CHECK, migration 0001
		agentNameMaxBytes = 1024 // agents.name CHECK, migration 0001
		orgNameMaxBytes   = 1024 // orgs.name CHECK, migration 0001
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

	if got := input.MaxOrgNameRunes * maxRuneBytes; got > orgNameMaxBytes {
		t.Errorf("worst-case organization name is %d bytes, over the %d-byte CHECK", got, orgNameMaxBytes)
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
		{"client name", parseClientName, input.CodeInvalidClientName, input.MaxClientNameBytes},
		{"agent name", parseAgentName, input.CodeInvalidAgentName, input.MaxAgentNameRunes},
		{"key name", parseKeyName, input.CodeInvalidKeyName, input.MaxKeyNameRunes},
		{"organization name", parseOrgName, input.CodeInvalidOrgName, input.MaxOrgNameRunes},
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
		named input.ClientName
		agent input.AgentName
		key   input.KeyName
		org   input.OrgName
		label input.InvitationLabel
	)

	if named.String() != "" || name.String() != "" || agent.String() != "" || key.String() != "" || org.String() != "" ||
		label.String() != "" {
		t.Error("zero values are not empty")
	}
}

func FuzzParseAccountName(f *testing.F) {
	fuzzString(f, seedsOf(textCases(accountNameSpec())), input.ParseAccountName, input.AccountName.String,
		input.CodeInvalidName, textOracle(accountNameSpec()))
}

func FuzzParseClientName(f *testing.F) {
	fuzzString(f, seedsOf(textCases(clientNameSpec())), input.ParseClientName, input.ClientName.String,
		input.CodeInvalidClientName, textOracle(clientNameSpec()))
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

func FuzzParseOrgName(f *testing.F) {
	fuzzString(f, seedsOf(textCases(orgNameSpec())), input.ParseOrgName, input.OrgName.String,
		input.CodeInvalidOrgName, textOracle(orgNameSpec()))
}
