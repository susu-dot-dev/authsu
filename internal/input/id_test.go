//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package input_test

import (
	"regexp"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
)

func parseID(raw string) (string, error) {
	return strAdapter(input.ParseID, input.ID.String)(raw)
}

// idCases extends the UUID primitive's table with the cases of the ID type:
// the same canonical rule, as seen by a handler.
func idCases() []parseCase {
	return []parseCase{
		{"v7 sample", "0194f3a2-7b1c-7d3e-9a4b-123456789abc", true},
		{"v4 sample", "f47ac10b-58cc-4372-a567-0e02b2c3d479", true},
		{"nil uuid", "00000000-0000-0000-0000-000000000000", true},
		{"max uuid", "ffffffff-ffff-ffff-ffff-ffffffffffff", true},
		{"empty", "", false},
		{"upper-case", "0194F3A2-7B1C-7D3E-9A4B-123456789ABC", false},
		{"mixed case", "0194f3a2-7B1c-7d3e-9a4b-123456789abc", false},
		{"no dashes", "0194f3a27b1c7d3e9a4b123456789abc", false},
		{"dashes misplaced", "0194f3a-27b1c-7d3e-9a4b-123456789abc", false},
		{"35 characters", "0194f3a2-7b1c-7d3e-9a4b-123456789ab", false},
		{"37 characters", "0194f3a2-7b1c-7d3e-9a4b-123456789abcd", false},
		{"surrounding braces", "{0194f3a2-7b1c-7d3e-9a4b-123456789abc}", false},
		{"urn prefix", "urn:uuid:0194f3a2-7b1c-7d3e-9a4b-123456789abc", false},
		{"leading space", " 0194f3a2-7b1c-7d3e-9a4b-123456789ab", false},
		{"trailing newline", "0194f3a2-7b1c-7d3e-9a4b-123456789ab\n", false},
		{"NUL", "0194f3a2-7b1c-7d3e-9a4b-123456789ab\x00", false},
		{"non-hex", "0194f3a2-7b1c-7d3e-9a4b-123456789abg", false},
		{"multibyte", "0194f3a2-7b1c-7d3e-9a4b-123456789a\u00e9", false},
		{"invalid utf8", "0194f3a2-7b1c-7d3e-9a4b-123456789a\xff", false},
		{"sql injection", "' OR '1'='1", false},
		{"percent wildcard", "%", false},
		{"two ids", "0194f3a2-7b1c-7d3e-9a4b-123456789abc0194f3a2-7b1c-7d3e-9a4b-123456789abc", false},
	}
}

func TestParseID(t *testing.T) {
	t.Parallel()
	runStringTable(t, idCases(), parseID, input.CodeInvalidID)
}

func TestIDLenMatchesTheSchema(t *testing.T) {
	t.Parallel()

	// Every id column: CHECK (length(id) = 36 AND id NOT GLOB '*[^0-9a-f-]*').
	if input.IDLen != 36 {
		t.Errorf("IDLen = %d, want 36", input.IDLen)
	}

	id, err := input.ParseID("0194f3a2-7b1c-7d3e-9a4b-123456789abc")
	if err != nil {
		t.Fatal(err)
	}

	if len(id.String()) != input.IDLen {
		t.Errorf("len(String()) = %d, want %d", len(id.String()), input.IDLen)
	}
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func FuzzParseID(f *testing.F) {
	fuzzString(f, seedsOf(idCases()), input.ParseID, input.ID.String, input.CodeInvalidID, uuidPattern.MatchString)
}
