package input_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/challenge"
	"github.com/susu-dot-dev/authsu/internal/input"
)

// pendingRandomChars is the random value the pending request carries, at its
// longest (the plan: 16 to 32 bytes), as base64url: 43 characters.
const pendingRandomChars = 43

// payloadKeyOverhead is generous room for the member names, quotes, colons,
// commas and braces of a JSON object of the nine members, which is under 200
// bytes, and for the framing a caller adds around them.
const payloadKeyOverhead = 512

// TestPendingRequestFitsItsPayload: the pending request holds a client_id, a
// redirect_uri, a code_challenge, state, a nonce, a resource, the scopes, a
// client_name and a random value, each at the largest its parser accepts, and the
// sealed payload (challenge.MaxPayloadLen) must hold all of them at once, with
// room to spare. A parser's bound cannot be raised without this test saying
// whether the request still fits.
//
// The arithmetic is in bytes. A member that holds only URL characters, scope
// names or base64url is written as it is; State and Nonce may hold any VSCHAR,
// of which the double quote and the backslash are written as two bytes by
// JSON, and so may the client_name, so these three are counted twice. The
// request must be encoded with the HTML escape turned off
// (json.Encoder.SetEscapeHTML(false)): with Go's default '<', '>' and '&' are
// written as 6 bytes each, which no bound here could absorb.
func TestPendingRequestFitsItsPayload(t *testing.T) {
	t.Parallel()

	plain := input.MaxClientIDBytes + input.MaxRedirectURIBytes + input.CodeChallengeLen + input.MaxResourceBytes +
		input.MaxOAuthScopeBytes + pendingRandomChars
	escaped := 2 * (input.MaxStateBytes + input.MaxNonceBytes + input.MaxClientNameBytes)
	worst := plain + escaped + payloadKeyOverhead

	// A quarter of the payload is spare at the very least.
	if limit := challenge.MaxPayloadLen / 4 * 3; worst > limit {
		t.Errorf("the worst case is %d bytes, over %d (three quarters of %d)", worst, limit, challenge.MaxPayloadLen)
	}

	// The same, by encoding the widest request there can be.
	worstEscaped := strings.Repeat(`"`, input.MaxStateBytes)
	// Every member the plan names, as text, at its widest.
	request := map[string]string{
		"client_id":      "https://example.com/" + strings.Repeat("a", input.MaxClientIDBytes-len("https://example.com/")),
		"redirect_uri":   "https://example.com/" + strings.Repeat("a", input.MaxRedirectURIBytes-len("https://example.com/")),
		"code_challenge": strings.Repeat("A", input.CodeChallengeLen),
		"state":          worstEscaped,
		"nonce":          strings.Repeat(`\`, input.MaxNonceBytes),
		"resource":       strings.Repeat("r", input.MaxResourceBytes),
		"scope":          strings.Repeat("s", input.MaxOAuthScopeBytes),
		"client_name":    strings.Repeat(`"`, input.MaxClientNameBytes),
		"random":         strings.Repeat("R", pendingRandomChars),
	}

	var encoded bytes.Buffer

	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)

	err := encoder.Encode(request)
	if err != nil {
		t.Fatal(err)
	}

	if encoded.Len() > worst || encoded.Len() > challenge.MaxPayloadLen/4*3 {
		t.Errorf("the widest request encodes to %d bytes; the arithmetic allows %d, and the payload %d",
			encoded.Len(), worst, challenge.MaxPayloadLen)
	}

	t.Logf("widest request: %d bytes of %d (%d without framing)", encoded.Len(), challenge.MaxPayloadLen, plain+escaped)
}

// TestBoundsAreWhatTheMigrationsAreToCarry pins the numbers the schema CHECKs of
// oauth_grants are sized to, so a bound cannot change without the migration
// being changed with it: the test fails and names the column.
func TestBoundsAreWhatTheMigrationsAreToCarry(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		column string
		got    int
		want   int
	}{
		{"oauth_grants.client_id", input.MaxClientIDBytes, 512},
		{"oauth_grants.redirect_uri", input.MaxRedirectURIBytes, 512},
		{"oauth_grants.client_name", input.MaxClientNameBytes, 128},
		{"oauth_grants.resource", input.MaxResourceBytes, 128},
		{"oauth_grants.scope", input.MaxOAuthScopeBytes, 256},
		{"oauth_grants.code_challenge", input.CodeChallengeLen, 43},
		{"oauth_grants.nonce", input.MaxNonceBytes, 128},
		{"the pending request's state", input.MaxStateBytes, 256},
		{"a document's redirect_uris", input.MaxRedirectURIs, 10},
		{"a document", input.MaxClientMetadataBytes, 5120},
		{"scope names", input.MaxOAuthScopeEntries, 16},
		{"a verifier, shortest", input.MinCodeVerifierLen, 43},
		{"a verifier, longest", input.MaxCodeVerifierLen, 128},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: the bound is %d, the migration is sized to %d", tc.column, tc.got, tc.want)
		}
	}
}
