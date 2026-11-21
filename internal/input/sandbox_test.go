//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package input_test

import (
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
)

// The sandbox id is the canonical UUID rule of ID, under its own code, in a
// body (SandboxID) and in a query (SandboxFilter).

func parseSandboxID(raw string) (string, error) {
	return strAdapter(input.ParseSandboxID, input.SandboxID.String)(raw)
}

func TestParseSandboxID(t *testing.T) {
	t.Parallel()
	runStringTable(t, idCases(), parseSandboxID, input.CodeInvalidSandboxID)
}

func TestZeroSandboxIDNamesNothing(t *testing.T) {
	t.Parallel()

	if got := (input.SandboxID{}).String(); got != "" {
		t.Errorf("the zero SandboxID is %q, want empty", got)
	}
}

func FuzzParseSandboxID(f *testing.F) {
	fuzzString(f, seedsOf(idCases()), input.ParseSandboxID, input.SandboxID.String, input.CodeInvalidSandboxID,
		uuidPattern.MatchString)
}

// sandboxFilterCase is one row of the sandbox filter table.
type sandboxFilterCase struct {
	name   string
	values []string
	want   string // the sandbox when set
	set    bool
	ok     bool
}

func sandboxFilterCases() []sandboxFilterCase {
	const id = "0194f3a2-7b1c-7d3e-9a4b-123456789abc"

	const other = "f47ac10b-58cc-4372-a567-0e02b2c3d479"

	return []sandboxFilterCase{
		{"absent (nil) is no filter", nil, "", false, true},
		{"absent (empty slice) is no filter", []string{}, "", false, true},
		{"one id", []string{id}, id, true, true},
		{"present but empty is refused, not read as absent", []string{""}, "", false, false},
		{"repeated, the same", []string{id, id}, "", false, false},
		{"repeated, different", []string{id, other}, "", false, false},
		{"repeated, the second invalid", []string{id, "x"}, "", false, false},
		{"repeated, the first empty", []string{"", id}, "", false, false},
		{"three values", []string{id, id, id}, "", false, false},
		{"upper case", []string{"0194F3A2-7B1C-7D3E-9A4B-123456789ABC"}, "", false, false},
		{"no dashes", []string{"0194f3a27b1c7d3e9a4b123456789abc"}, "", false, false},
		{"a comma list is one invalid id", []string{id + "," + other}, "", false, false},
		{"a trailing space", []string{id + " "}, "", false, false},
		{"NUL", []string{id + "\x00"}, "", false, false},
		{"a SQL injection", []string{"' OR '1'='1"}, "", false, false},
		{"invalid UTF-8", []string{"\xff"}, "", false, false},
	}
}

func TestParseSandboxFilter(t *testing.T) {
	t.Parallel()

	_, probe := input.ParseSandboxFilter([]string{"x"})
	description := descriptionOf(t, probe, input.CodeInvalidSandboxFilter)

	for _, tc := range sandboxFilterCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := input.ParseSandboxFilter(tc.values)
			sandbox, set := got.Sandbox()

			if tc.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
			} else {
				requireFixedRefusal(t, err, input.CodeInvalidSandboxFilter, description)
			}

			// A refused filter is the zero filter: nothing set, no id.
			if set != tc.set || sandbox.String() != tc.want {
				t.Errorf("Sandbox() = %q, %v; want %q, %v", sandbox.String(), set, tc.want, tc.set)
			}
		})
	}
}

func FuzzParseSandboxFilter(f *testing.F) {
	for _, tc := range sandboxFilterCases() {
		if len(tc.values) == 1 && len(tc.values[0]) < 80 {
			f.Add(tc.values[0], uint8(1))
		}
	}

	f.Add("", uint8(0))
	f.Add("0194f3a2-7b1c-7d3e-9a4b-123456789abc", uint8(2))

	f.Fuzz(func(t *testing.T, raw string, mode uint8) {
		values := queryValues(raw, mode)
		got, err := input.ParseSandboxFilter(values)

		want := len(values) == 0 || (len(values) == 1 && uuidPattern.MatchString(raw))
		if !requireOutcome(t, values, err, want, input.CodeInvalidSandboxFilter) {
			return
		}

		sandbox, set := got.Sandbox()
		if set != (len(values) == 1) || (set && sandbox.String() != raw) {
			t.Fatalf("Sandbox() = %q, %v for %q", sandbox.String(), set, values)
		}
	})
}
