//go:build e2e

//nolint:goconst,funlen,cyclop,lll,gosmopolitan,maintidx // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// registration_test.go drives POST /api/register/begin and /finish against the
// real Worker: TinyGo wasm, workerd, the real D1 driver and SQLite. The unit
// tests fake the database and run the verifier under Go; what only this suite
// can prove is:
//
//   - every stored column of an account and its first passkey, as the real SQL
//     and the real D1 round trip leave them (types, bytes, JSON spelling);
//   - the worst-case name (6x JSON escaping) still fits the users.profile CHECK
//     through the real database, so a valid request is never a 500;
//   - that every refusal leaves NOTHING behind (users and credentials stay 0);
//   - that begin is stateless and its answers do not reveal why a code is bad;
//   - the atomic point of acceptance under real concurrency (exactly one
//     winner, losers get a clean 4xx, never a 5xx) and the UNIQUE constraints.
//
// REVIEW.md categories covered: input edge cases (names, codes, every body
// shape), interleaving (racing finishes, replay races), payload size (bytes vs
// runes, the exact byte of every bound, 32 KiB body cap), permission confusion
// (client-chosen role, another ceremony's challenge) and type/bound confusion
// (JSON strings vs bytes, the 6x escape expansion vs the 1024-byte CHECK).

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

const (
	regCodeInvalid = "invalid_invitation"
	regCodeName    = "invalid_name"
	regCodeCred    = "invalid_credential"
	regCodeChal    = "invalid_challenge"
	regCodeAccept  = "registration_accept_failed"

	// regUnknownCode is a well-formed invitation token that nothing stores.
	regUnknownCode = "susu_inv_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	regNoRoleType = "e2e_no_role"
	// Invitation tokens of their own, each a canonical "susu_inv_" token.
	regNoRoleCode = "susu_inv_dFLNhvV0ciEeD06FuZjP7Ty-Og8cKv2K9NysZmJlzgw"
	regSpareCode  = "susu_inv_edv2XbaMr24dSyI95lN8x7nAOloEjPObJbUYchtso2U"
	regFirstRunID = "00000000-0000-7000-8000-00000000c001"
)

// regSeedInvitation inserts an invitation whose token is code (stored as its
// hash, the way the Worker stores it) with the given type, cap and state:
// "revoked" revokes its secret at second 1, "expired" lets it expire at second 1.
func regSeedInvitation(t *testing.T, id, code, kind string, numInvites int, extra string) {
	t.Helper()

	seedSecret(t, id, kindInvitation, code)

	switch extra {
	case "":
	case "revoked":
		seed(t, "UPDATE secrets SET revoked_at = 1 WHERE id = ?", id)
	case "expired":
		seed(t, "UPDATE secrets SET expires_at = 1 WHERE id = ?", id)
	default:
		t.Fatalf("unknown extra %q", extra)
	}

	seed(t, "INSERT INTO invitations (id, type, label, num_invites) VALUES (?, ?, 'e2e', ?)", id, kind, numInvites)
}

// regSeedAdminAndFirstRun is the state of a registered first admin, as the
// Worker leaves it, so later tests can add invitations of their own.
func regOpenFirstRun(t *testing.T) {
	t.Helper()

	reset(t)
	frExpectStatus(t, "open first run", frPending)
}

// regDecode parses a response body into v.
func regDecode(t *testing.T, got reply, v any) {
	t.Helper()

	err := json.Unmarshal([]byte(got.body), v)
	if err != nil {
		t.Fatalf("parse %q: %v", got.body, err)
	}
}

// regFinishCounts asserts the two tables registration writes.
func regExpectNothingWritten(t *testing.T, what string) {
	t.Helper()

	if got := count(t, "users"); got != "0" {
		t.Errorf("%s: users = %s, want 0", what, got)
	}

	if got := count(t, "credentials"); got != "0" {
		t.Errorf("%s: credentials = %s, want 0", what, got)
	}
}

// regMutate decodes a finish body, lets edit change the generic structure and
// re-encodes it.
func regMutate(t *testing.T, body []byte, edit func(map[string]any)) []byte {
	t.Helper()

	var doc map[string]any

	err := json.Unmarshal(body, &doc)
	if err != nil {
		t.Fatalf("parse finish body: %v", err)
	}

	edit(doc)

	return mustJSON(t, doc)
}

// regCredential returns the credential object of a decoded finish body.
func regCredential(doc map[string]any) map[string]any {
	cred, _ := doc["credential"].(map[string]any)

	return cred
}

// regResponse returns the response object of a decoded finish body.
func regResponse(doc map[string]any) map[string]any {
	resp, _ := regCredential(doc)["response"].(map[string]any)

	return resp
}

// ---- the happy path, column by column ---------------------------------------

// TestRegistrationStoresEveryColumn registers the first admin through the real
// endpoints and checks every column the Worker wrote, including the spelling of
// the two JSON columns, the binary columns as BLOBs, and the types SQLite
// stored (a number must not come back as a float or text through D1).
//
//nolint:paralleltest // shares one database
func TestRegistrationStoresEveryColumn(t *testing.T) {
	regOpenFirstRun(t)

	options := mustBeginRegistration(t, firstRunSecret, "Alice")

	auth := newAuthenticator()
	auth.priv = newKey(t)
	// Unsorted, with a duplicate and an unknown value: the Worker stores them
	// canonical (sorted, de-duplicated), unknown values included.
	auth.transports = []string{"usb", "internal", "usb", "hybrid", "x-future"}
	auth.flags = flagUP | flagUV | flagAT | 0x08 | 0x10 // + BE + BS

	body := auth.finishBody(t, options, firstRunSecret, "Alice")

	got := post(t, pathRegisterEnd, body, "")
	got.expect(t, "finish", http.StatusCreated, "")

	var out registered

	regDecode(t, got, &out)

	if out.Role != roleAdmin || len(out.UserID) != 36 {
		t.Errorf("response = %+v, want an admin with a 36-char id", out)
	}

	if got.header.Get("Content-Type") != jsonType || got.header.Get("Cache-Control") != "no-store" {
		t.Errorf("headers = %v", got.header)
	}

	if got.session() != "" {
		t.Errorf("finish issued a session: %v", got.setCookies)
	}

	expectCount(t, "users", "1")
	expectCount(t, "credentials", "1")
	expectCount(t, "invitations", "1")

	handle, err := base64.RawURLEncoding.DecodeString(options.PublicKey.User.ID)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}

	challenge, err := base64.RawURLEncoding.DecodeString(options.PublicKey.Challenge)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}

	// users
	user := func(column string) string { return scalar(t, "SELECT "+column+" FROM users") }

	for column, want := range map[string]string{
		"id":                  out.UserID,
		"role":                "admin",
		"typeof(role)":        "text",
		"profile":             `{"name":"Alice"}`,
		"typeof(profile)":     "text",
		"typeof(user_handle)": "blob",
		"hex(user_handle)":    strings.ToUpper(hex.EncodeToString(handle)),
		"length(user_handle)": "32",
		"revoked_at IS NULL":  "1",
		"typeof(created_at)":  "integer",
		"abs(created_at - strftime('%s','now')) < 60":  "1",
		"invitation_id = (SELECT id FROM invitations)": "1",
	} {
		if gotValue := user(column); gotValue != want {
			t.Errorf("users.%s = %q, want %q", column, gotValue, want)
		}
	}

	// The challenge's nonce (bytes 9..41) is the user handle.
	if !bytes.Equal(challenge[9:41], handle) {
		t.Errorf("user handle %x is not the challenge nonce %x", handle, challenge[9:41])
	}

	// credentials
	cred := func(column string) string { return scalar(t, "SELECT "+column+" FROM credentials") }

	wantAAGUID := "00000000-0000-0000-0000-000000000000"
	wantMetadata := `{"fmt":"none","aaguid":"` + wantAAGUID + `","transports":["hybrid","internal","usb","x-future"]}`

	for column, want := range map[string]string{
		"typeof(id)":            "text",
		"length(id)":            "36",
		"user_id":               out.UserID,
		"hex(credential_id)":    strings.ToUpper(hex.EncodeToString(auth.credID)),
		"typeof(credential_id)": "blob",
		"typeof(public_key)":    "blob",
		// UP | UV | BE | BS: AT is not stored.
		"flags":                          "29",
		"typeof(flags)":                  "integer",
		"metadata":                       wantMetadata,
		"typeof(metadata)":               "text",
		"typeof(created_at)":             "integer",
		"json_extract(metadata,'$.fmt')": "none",
	} {
		if gotValue := cred(column); gotValue != want {
			t.Errorf("credentials.%s = %q, want %q", column, gotValue, want)
		}
	}

	// The stored public key is exactly the COSE key the authenticator sent.
	wantKey := coseES256(t, auth.priv.X.FillBytes(make([]byte, 32)), auth.priv.Y.FillBytes(make([]byte, 32)))
	if gotKey := cred("hex(public_key)"); gotKey != strings.ToUpper(hex.EncodeToString(wantKey)) {
		t.Errorf("public_key = %s, want %X", gotKey, wantKey)
	}

	// The first-run state is consumed.
	frExpectStatus(t, "after registration", frAccepted)
}

// TestRegistrationThenLogin proves the account registration created can sign in:
// the stored key, handle and flags are what login needs. A credential that
// registered as backup-eligible must keep that bit at login (section 6.1.3), and
// one that did not must not gain it.
//
//nolint:paralleltest // shares one database
func TestRegistrationThenLogin(t *testing.T) {
	regOpenFirstRun(t)

	pk := registerWith(t, "Admin")

	token := login(t, pk)
	get(t, pathSession, token).expect(t, "GET /api/session", http.StatusOK, "")

	// The session belongs to the account registration created.
	if got := get(t, pathSession, token); !strings.Contains(got.body, `"userId":"`+pk.userID+`"`) {
		t.Errorf("session = %s, want the account %s", got.body, pk.userID)
	}

	// A second login with the same passkey works too: registration left it reusable.
	login(t, pk)

	// An assertion that claims backup eligibility the credential did not register
	// with is refused (the stored BE bit is fixed for the life of the credential).
	assert := pk.assertion()
	assert.flags |= 0x08

	refusal := post(t, pathLoginEnd, assert.sign(t, beginLogin(t), nil).body(t, nil), "")
	refusal.expect(t, "login claiming BE", http.StatusUnauthorized, codeInvalidLogin)
}

// TestRegistrationCredentialIDLengths registers credential ids of every bound
// and checks the BLOB length stored. Bounds are 1 and 1023 (the schema CHECK);
// 0 and 1024 are refused by the verifier before the database.
//
//nolint:paralleltest // shares one database
func TestRegistrationCredentialIDLengths(t *testing.T) {
	tests := []struct {
		name       string
		length     int
		wantStatus int
		wantStored string
	}{
		{"1 byte", 1, http.StatusCreated, "1"},
		{"16 bytes", 16, http.StatusCreated, "16"},
		{"1022 bytes", 1022, http.StatusCreated, "1022"},
		{"1023 bytes (the maximum)", 1023, http.StatusCreated, "1023"},
		{"1024 bytes (one over)", 1024, http.StatusBadRequest, ""},
		{"2000 bytes", 2000, http.StatusBadRequest, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regOpenFirstRun(t)

			options := mustBeginRegistration(t, firstRunSecret, "Alice")
			auth := newAuthenticator()
			auth.credID = randomBytes(tt.length)
			// attestationObject clamps the written length to 1023: write the
			// true one so authData is honest about what follows.
			idLen := uint16(tt.length)
			auth.credIDLen = &idLen

			got := post(t, pathRegisterEnd, auth.finishBody(t, options, firstRunSecret, "Alice"), "")
			if got.status != tt.wantStatus {
				t.Fatalf("finish = %d %s, want %d", got.status, got.body, tt.wantStatus)
			}

			if tt.wantStored != "" {
				expectCount(t, "credentials", "1")

				if gotLen := scalar(t, "SELECT length(credential_id) FROM credentials"); gotLen != tt.wantStored {
					t.Errorf("stored length = %s, want %s", gotLen, tt.wantStored)
				}

				return
			}

			got.expect(t, "finish", http.StatusBadRequest, regCodeCred)
			regExpectNothingWritten(t, tt.name)
		})
	}
}

// ---- begin ------------------------------------------------------------------

// TestRegistrationBegin proves begin is stateless, unique per call and carries
// the options the verifier will accept.
//
//nolint:paralleltest // shares one database
func TestRegistrationBegin(t *testing.T) {
	regOpenFirstRun(t)

	before := count(t, "invitations") + "/" + count(t, "users") + "/" + count(t, "credentials")

	seen := map[string]bool{}

	for i := range 6 {
		got := beginRegistration(t, firstRunSecret, "Alice")
		got.expect(t, "begin", http.StatusOK, "")

		var options creationOptions

		regDecode(t, got, &options)

		pub := options.PublicKey

		if pub.RP.ID != rpID || pub.User.Name != "Alice" || pub.Attestation != "none" {
			t.Errorf("begin %d options = %+v", i, pub)
		}

		if len(pub.PubKeyCredParams) != 1 || pub.PubKeyCredParams[0].Alg != -7 {
			t.Errorf("pubKeyCredParams = %+v, want only ES256", pub.PubKeyCredParams)
		}

		challenge, err := base64.RawURLEncoding.DecodeString(pub.Challenge)
		if err != nil || len(challenge) != 73 || challenge[0] != 1 {
			t.Errorf("challenge = %q (len %d, err %v), want 73 bytes with version 1", pub.Challenge, len(challenge), err)
		}

		handle, err := base64.RawURLEncoding.DecodeString(pub.User.ID)
		if err != nil || len(handle) != 32 {
			t.Errorf("user.id = %q (len %d, err %v), want 32 bytes", pub.User.ID, len(handle), err)
		}

		for _, unique := range []string{"c:" + pub.Challenge, "h:" + pub.User.ID} {
			if seen[unique] {
				t.Errorf("begin repeated %s", unique)
			}

			seen[unique] = true
		}

		// The raw JSON also carries the fixed requirements.
		for _, want := range []string{`"userVerification":"required"`, `"residentKey":"required"`, `"displayName":"Alice"`, `"timeout":300000`} {
			if !strings.Contains(got.body, want) {
				t.Errorf("begin body lacks %s: %s", want, got.body)
			}
		}

		if strings.Contains(got.body, firstRunSecret) {
			t.Error("begin echoed the invitation code")
		}
	}

	after := count(t, "invitations") + "/" + count(t, "users") + "/" + count(t, "credentials")
	if after != before {
		t.Errorf("begin wrote rows: %s -> %s", before, after)
	}
}

// TestRegistrationBeginRefusesInvitations covers every way an invitation code
// can be bad. All unredeemable causes must be the same 403 body: no oracle.
//
//nolint:paralleltest // shares one database
func TestRegistrationBeginRefusesInvitations(t *testing.T) {
	const (
		idA = "00000000-0000-7000-8000-00000000c101"
		idB = "00000000-0000-7000-8000-00000000c102"
	)

	tests := []struct {
		name  string
		setup func(t *testing.T)
		code  string
	}{
		{"unknown well-formed token", func(*testing.T) {}, regUnknownCode},
		{"a token that differs from the secret by one character", func(*testing.T) {}, firstRunSecret[:len(firstRunSecret)-1] + "M"},
		{"the secret's body in lower case", func(*testing.T) {}, strings.ToLower(firstRunSecret)},
		{
			"revoked invitation",
			func(t *testing.T) { t.Helper(); regSeedInvitation(t, idA, regSpareCode, "first_run", 1, "revoked") },
			regSpareCode,
		},
		{
			"expired invitation",
			func(t *testing.T) { t.Helper(); regSeedInvitation(t, idA, regSpareCode, "first_run", 1, "expired") },
			regSpareCode,
		},
		{
			"exhausted invitation (its cap of accounts exist)",
			func(t *testing.T) {
				t.Helper()
				regSeedInvitation(t, idA, regSpareCode, regNoRoleType, 1, "")
				seedUsers(t, idA, 1)
			},
			regSpareCode,
		},
		{
			"first_run invitation once an account exists",
			func(t *testing.T) {
				t.Helper()
				frSeedFirstRunInvitation(t, idA, "", nil)
				seedUser(t, idUserB, roleAdmin)
			},
			firstRunSecret,
		},
	}

	var reference string

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reset(t)
			tt.setup(t)

			got := beginRegistration(t, tt.code, "Alice")
			got.expect(t, "begin", http.StatusForbidden, regCodeInvalid)

			// The body is byte-identical for every cause.
			if reference == "" {
				reference = got.body
			}

			if got.body != reference {
				t.Errorf("body differs between causes (an oracle):\n got  %s\n want %s", got.body, reference)
			}
		})
	}
}

// regTimeStates are the stored time states of an invitation's secret that
// decide whether it can still be redeemed, each as the SQL that sets it. The
// rule is the shared active predicate: not revoked as of now (revoked_at is a
// time, so one scheduled for later has not happened) and expires_at > now (so it
// is expired AT its expires_at, not after). A margin of an hour keeps the
// "later" cases away from the second the request is made in.
func regTimeStates() []struct {
	name       string
	sql        string
	redeemable bool
} {
	return []struct {
		name       string
		sql        string
		redeemable bool
	}{
		{"untouched", "SELECT 1", true},
		{"expires in an hour", "UPDATE secrets SET expires_at = strftime('%s','now') + 3600 WHERE id = ?", true},
		{"expires exactly now", "UPDATE secrets SET expires_at = strftime('%s','now') WHERE id = ?", false},
		{"expired a second ago", "UPDATE secrets SET expires_at = strftime('%s','now') - 1 WHERE id = ?", false},
		{"expires at zero", "UPDATE secrets SET expires_at = 0 WHERE id = ?", false},
		{"expires at a negative time", "UPDATE secrets SET expires_at = -1 WHERE id = ?", false},
		{"revoked a second ago", "UPDATE secrets SET revoked_at = strftime('%s','now') - 1 WHERE id = ?", false},
		{"revoked exactly now", "UPDATE secrets SET revoked_at = strftime('%s','now') WHERE id = ?", false},
		{"revoked in an hour, not yet in force", "UPDATE secrets SET revoked_at = strftime('%s','now') + 3600 WHERE id = ?", true},
	}
}

// regApplyTimeState applies one of regTimeStates to the invitation id.
func regApplyTimeState(t *testing.T, sql, id string) {
	t.Helper()

	if sql == "SELECT 1" {
		return
	}

	seed(t, sql, id)
}

// TestRegistrationBeginHonoursInvitationTimes holds the time rule of an
// invitation at begin, which reads the invitation through invitationQuery: an
// invitation that expires exactly now or was revoked as of now is refused with
// the one opaque 403, and one whose revocation is still scheduled is accepted.
//
//nolint:paralleltest // shares one database
func TestRegistrationBeginHonoursInvitationTimes(t *testing.T) {
	for _, state := range regTimeStates() {
		t.Run(state.name, func(t *testing.T) {
			reset(t)
			regSeedInvitation(t, idInvitationA, regSpareCode, regNoRoleType, 1, "")
			regApplyTimeState(t, state.sql, idInvitationA)

			got := beginRegistration(t, regSpareCode, "Alice")

			if state.redeemable {
				got.expect(t, "begin", http.StatusOK, "")

				return
			}

			got.expect(t, "begin", http.StatusForbidden, regCodeInvalid)
			regExpectNothingWritten(t, "a refused begin")
		})
	}
}

// TestRegistrationFinishHonoursInvitationTimes holds the same rule at finish,
// where the invitation is read again and then insertUserQuery decides in the
// write itself: the invitation is valid when the ceremony begins and its stored
// time state changes before it finishes, so the begin-time read cannot be what
// refuses it. The invitation is of the "member" type, because only a type with
// a role can finish. The refusal is the same opaque 403 as at begin, and a refused
// finish creates no account and no passkey. (The interleaving where the state
// changes between finish's read and its write is the race tests' job.)
//
//nolint:paralleltest // shares one database
func TestRegistrationFinishHonoursInvitationTimes(t *testing.T) {
	for _, state := range regTimeStates() {
		t.Run(state.name, func(t *testing.T) {
			reset(t)
			regSeedInvitation(t, idInvitationA, regNoRoleCode, "member", 1, "")

			body := regPrepareBody(t, regNoRoleCode, "Alice")

			regApplyTimeState(t, state.sql, idInvitationA)

			got := post(t, pathRegisterEnd, body, "")

			if state.redeemable {
				got.expect(t, "finish", http.StatusCreated, "")
				expectCount(t, "users", "1")

				return
			}

			got.expect(t, "finish", http.StatusForbidden, regCodeInvalid)
			regExpectNothingWritten(t, "a refused finish")
		})
	}
}

// TestRegistrationBeginRefusesMalformedCodes: a code that is not an invitation
// token (wrong length, wrong tag, wrong alphabet, not canonical) is refused by
// the parser before any lookup, as 400 invalid_invitation, and nothing is
// written. Tokens of the other kinds are refused here too: a session or an API
// key is not an invitation.
//
//nolint:paralleltest // shares one database
func TestRegistrationBeginRefusesMalformedCodes(t *testing.T) {
	regOpenFirstRun(t)

	prefix := tokenPrefix(tagInvitation)
	body := firstRunSecret[len(prefix):]

	tests := []struct{ name, code string }{
		{"the secret with a character dropped", firstRunSecret[1:]},
		{"the secret with its last character dropped", firstRunSecret[:len(firstRunSecret)-1]},
		{"the secret with a character added", firstRunSecret + "A"},
		{"the secret's body without the prefix", body},
		{"the prefix alone", prefix},
		{"the secret with a space before", " " + firstRunSecret},
		{"the secret with a space after", firstRunSecret + " "},
		{"the secret with a newline after", firstRunSecret + "\n"},
		{"the secret with upper-case prefix", strings.ToUpper(prefix) + body},
		{"the secret's body under the session tag", tokenPrefix(tagSession) + body},
		{"the secret's body under the key tag", tokenPrefix(tagAPIKey) + body},
		{"an unknown tag", "susu_xyz_" + body},
		{"two underscores", "susu__inv_" + body},
		{"a non-canonical last character", prefix + strings.Repeat("A", tokenBodyLen-1) + "B"},
		{"a padding character", firstRunSecret[:len(firstRunSecret)-1] + "="},
		{"a plus in the body", prefix + strings.Repeat("A", tokenBodyLen-2) + "+A"},
		{"a slash in the body", prefix + strings.Repeat("A", tokenBodyLen-2) + "/A"},
		{"the hex of the secret hash", frSecretHashHex()},
		{"the base64 of the secret hash", b64(mustDecodeHex(t, frSecretHashHex()))},
		{"the old shape: a long run of base64url characters", strings.Repeat("A", 256)},
		{"one character", "A"},
		{"3000 characters", strings.Repeat("A", 3000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			beginRegistration(t, tt.code, "Alice").expect(t, "begin", http.StatusBadRequest, regCodeInvalid)
			regExpectNothingWritten(t, tt.name)
		})
	}

	// The refusals did not spend or disturb the first-run invitation.
	options := mustBeginRegistration(t, firstRunSecret, "Alice")
	post(t, pathRegisterEnd, newAuthenticator().finishBody(t, options, firstRunSecret, "Alice"), "").
		expect(t, "the real secret afterwards", http.StatusCreated, "")
}

// TestRegistrationBeginParsesInputs covers the parsers' bounds at the exact
// byte, through the real boundary, for the code and the name.
//
//nolint:paralleltest // shares one database
func TestRegistrationBeginParsesInputs(t *testing.T) {
	regOpenFirstRun(t)

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		// ---- codes: exactly "susu_inv_" and 43 canonical base64url characters ----
		{"empty code", `{"invitationCode":"","name":"A"}`, 400, regCodeInvalid},
		{"missing code", `{"name":"A"}`, 400, regCodeInvalid},
		{"null code", `{"invitationCode":null,"name":"A"}`, 400, regCodeInvalid},
		{"code with a space", `{"invitationCode":"abc def","name":"A"}`, 400, regCodeInvalid},
		{"code with padding", `{"invitationCode":"abcd==","name":"A"}`, 400, regCodeInvalid},
		{"code with +", `{"invitationCode":"ab+cd","name":"A"}`, 400, regCodeInvalid},
		{"code with /", `{"invitationCode":"ab/cd","name":"A"}`, 400, regCodeInvalid},
		{"code with a dot", `{"invitationCode":"ab.cd","name":"A"}`, 400, regCodeInvalid},
		{"code with a newline", `{"invitationCode":"ab\ncd","name":"A"}`, 400, regCodeInvalid},
		{"code with NUL", `{"invitationCode":"ab\u0000cd","name":"A"}`, 400, regCodeInvalid},
		{"code with a non-ASCII letter", `{"invitationCode":"abcé","name":"A"}`, 400, regCodeInvalid},
		{"code with a fullwidth letter", `{"invitationCode":"ａｂｃ","name":"A"}`, 400, regCodeInvalid},
		{"a token of 43 characters is well-formed but unknown", `{"invitationCode":"` + regUnknownCode + `","name":"A"}`, 403, regCodeInvalid},
		{"a token of 42 characters is malformed", `{"invitationCode":"` + regUnknownCode[:len(regUnknownCode)-1] + `","name":"A"}`, 400, regCodeInvalid},
		{"a token of 44 characters is malformed", `{"invitationCode":"` + regUnknownCode + `A","name":"A"}`, 400, regCodeInvalid},
		{"code of 257 bytes is malformed", `{"invitationCode":"` + strings.Repeat("A", 257) + `","name":"A"}`, 400, regCodeInvalid},
		{"code of 3000 bytes is malformed", `{"invitationCode":"` + strings.Repeat("A", 3000) + `","name":"A"}`, 400, regCodeInvalid},
		{"code of 1 byte is malformed", `{"invitationCode":"A","name":"A"}`, 400, regCodeInvalid},
		{"code as a number", `{"invitationCode":123,"name":"A"}`, 400, "invalid_field_type"},
		{"code as an array", `{"invitationCode":["a"],"name":"A"}`, 400, "invalid_field_type"},
		{"code as an object", `{"invitationCode":{},"name":"A"}`, 400, "invalid_field_type"},
		{"code as a bool", `{"invitationCode":true,"name":"A"}`, 400, "invalid_field_type"},

		// ---- request envelope ----
		{"empty body", ``, 400, "empty_body"},
		{"null body", `null`, 200, ""}, // null decodes to the zero value: see the quirk test below
		{"array body", `[]`, 400, "invalid_field_type"},
		{"string body", `"x"`, 400, "invalid_field_type"},
		{"number body", `1`, 400, "invalid_field_type"},
		{"trailing garbage", `{"invitationCode":"` + firstRunSecret + `","name":"A"}x`, 400, "trailing_data"},
		{"two documents", `{"invitationCode":"` + firstRunSecret + `","name":"A"}{}`, 400, "trailing_data"},
		{"unknown member", `{"invitationCode":"` + firstRunSecret + `","name":"A","role":"admin"}`, 400, codeUnknownField},
		{"member in another case", `{"invitationCode":"` + firstRunSecret + `","Name":"A"}`, 400, codeUnknownField},
		{"duplicate code member", `{"invitationCode":"x","invitationCode":"` + firstRunSecret + `","name":"A"}`, 400, "duplicate_field"},
		{"duplicate name member", `{"invitationCode":"` + firstRunSecret + `","name":"A","name":"B"}`, 400, "duplicate_field"},
		{"truncated JSON", `{"invitationCode":"` + firstRunSecret, 400, "invalid_json"},
		{"name as a number", `{"invitationCode":"` + firstRunSecret + `","name":5}`, 400, "invalid_field_type"},
		{"name as null", `{"invitationCode":"` + firstRunSecret + `","name":null}`, 400, regCodeName},
		{"name as an array", `{"invitationCode":"` + firstRunSecret + `","name":["A"]}`, 400, "invalid_field_type"},
		{"name as an object", `{"invitationCode":"` + firstRunSecret + `","name":{"a":1}}`, 400, "invalid_field_type"},
		{"name as a bool", `{"invitationCode":"` + firstRunSecret + `","name":false}`, 400, "invalid_field_type"},
		{"name as a huge number", `{"invitationCode":"` + firstRunSecret + `","name":1e999}`, 400, "invalid_field_type"},
		{"missing name", `{"invitationCode":"` + firstRunSecret + `"}`, 400, regCodeName},
		{"empty object", `{}`, 400, regCodeInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "null body" {
				t.Skip("covered by TestRegistrationNullBodyQuirk")
			}

			got := post(t, pathRegisterBegin, []byte(tt.body), "")
			if got.status != tt.wantStatus || (tt.wantCode != "" && got.errorCode() != tt.wantCode) {
				t.Errorf("begin(%s) = %d %s, want %d %s", tt.body, got.status, got.body, tt.wantStatus, tt.wantCode)
			}
		})
	}

	expectCount(t, "users", "0")
	expectCount(t, "credentials", "0")
}

// TestRegistrationNullBodyQuirk pins what a JSON null body does at begin and
// finish: encoding/json decodes null into the zero value, so the request is
// then judged as an empty one (400 invalid_invitation). It must never succeed.
//
//nolint:paralleltest // shares one database
func TestRegistrationNullBodyQuirk(t *testing.T) {
	regOpenFirstRun(t)

	for _, path := range []string{pathRegisterBegin, pathRegisterEnd} {
		got := post(t, path, []byte("null"), "")
		if got.status != http.StatusBadRequest || got.errorCode() != regCodeInvalid {
			t.Errorf("POST %s null = %d %s, want 400 invalid_invitation", path, got.status, got.body)
		}
	}

	regExpectNothingWritten(t, "null body")
}

// regNameCase is one account name to try at begin and finish.
type regNameCase struct {
	name string
	// raw is the JSON text of the name value, spliced into the body as is, so a
	// case can send invalid UTF-8 or a lone surrogate escape.
	raw string
	// wantBegin is the begin status; wantCode its error code ("" for 200).
	wantBegin int
	wantCode  string
	// wantProfile is the exact users.profile after a successful registration
	// ("" when the name is refused).
	wantProfile string
}

func regNameCases() []regNameCase {
	const (
		ok  = http.StatusOK
		bad = http.StatusBadRequest
	)

	quote := func(s string) string { return `"` + s + `"` }

	two := "é"                  // 2 bytes (NFC)
	three := "€"                // 3 bytes
	four := "😀"                 // 4 bytes
	family := "👨\u200d👩\u200d👧" // ZWJ sequence: contains Cf U+200D
	decomposed := "e\u0301"     // e + combining acute: not NFC

	return []regNameCase{
		{"one ASCII byte", quote("A"), ok, "", `{"name":"A"}`},
		{"128 ASCII bytes (the limit)", quote(strings.Repeat("a", 128)), ok, "", `{"name":"` + strings.Repeat("a", 128) + `"}`},
		{"129 ASCII bytes (one over)", quote(strings.Repeat("a", 129)), bad, regCodeName, ""},
		{"1000 ASCII bytes", quote(strings.Repeat("a", 1000)), bad, regCodeName, ""},
		{"64 two-byte runes (128 bytes)", quote(strings.Repeat(two, 64)), ok, "", `{"name":"` + strings.Repeat(two, 64) + `"}`},
		{"65 two-byte runes (130 bytes)", quote(strings.Repeat(two, 65)), bad, regCodeName, ""},
		{"42 three-byte runes (126 bytes)", quote(strings.Repeat(three, 42)), ok, "", `{"name":"` + strings.Repeat(three, 42) + `"}`},
		{"43 three-byte runes (129 bytes)", quote(strings.Repeat(three, 43)), bad, regCodeName, ""},
		{"32 four-byte runes (128 bytes)", quote(strings.Repeat(four, 32)), ok, "", `{"name":"` + strings.Repeat(four, 32) + `"}`},
		{"33 four-byte runes (132 bytes)", quote(strings.Repeat(four, 33)), bad, regCodeName, ""},
		{"127 ASCII + one two-byte rune (129 bytes)", quote(strings.Repeat("a", 127) + two), bad, regCodeName, ""},
		{"126 ASCII + one two-byte rune (128 bytes)", quote(strings.Repeat("a", 126) + two), ok, "", `{"name":"` + strings.Repeat("a", 126) + two + `"}`},
		{"empty", `""`, bad, regCodeName, ""},
		{"a single space", `" "`, bad, regCodeName, ""},
		{"only whitespace", `"   "`, bad, regCodeName, ""},
		{"only a tab escape", `"\t"`, bad, regCodeName, ""},
		{"ideographic space only", quote("\u3000"), bad, regCodeName, ""},
		{"no-break space only", quote("\u00a0"), bad, regCodeName, ""},
		{"leading and trailing spaces are kept, never trimmed", `"  Alice  "`, ok, "", `{"name":"  Alice  "}`},
		{"inner space", `"Alice Bob"`, ok, "", `{"name":"Alice Bob"}`},
		{"NUL escape", `"a\u0000b"`, bad, regCodeName, ""},
		{"NUL alone", `"\u0000"`, bad, regCodeName, ""},
		{"newline escape", `"a\nb"`, bad, regCodeName, ""},
		{"carriage return escape", `"a\rb"`, bad, regCodeName, ""},
		{"tab escape inside", `"a\tb"`, bad, regCodeName, ""},
		{"DEL", `"a\u007fb"`, bad, regCodeName, ""},
		{"C1 control U+0085", `"a\u0085b"`, bad, regCodeName, ""},
		{"escape U+001B", `"a\u001bb"`, bad, regCodeName, ""},
		{"RLO bidi override", `"a\u202eb"`, bad, regCodeName, ""},
		{"LRE bidi embedding", `"a\u202ab"`, bad, regCodeName, ""},
		{"RLI bidi isolate", `"a\u2067b"`, bad, regCodeName, ""},
		{"zero-width space", `"a\u200bb"`, bad, regCodeName, ""},
		{"zero-width joiner alone", `"a\u200db"`, bad, regCodeName, ""},
		{"zero-width non-joiner", `"a\u200cb"`, bad, regCodeName, ""},
		{"ZWJ emoji sequence (contains a format character)", quote(family), bad, regCodeName, ""},
		{"BOM inside", `"a\ufeffb"`, bad, regCodeName, ""},
		{"BOM at the start", `"\ufeffab"`, bad, regCodeName, ""},
		{"soft hyphen", `"a\u00adb"`, bad, regCodeName, ""},
		{"word joiner", `"a\u2060b"`, bad, regCodeName, ""},
		{"non-NFC (e + combining acute)", quote("caf" + decomposed), bad, regCodeName, ""},
		{"NFC precomposed", quote("café"), ok, "", `{"name":"café"}`},
		{"Hangul jamo sequence (not NFC)", quote("\u1100\u1161"), bad, regCodeName, ""},
		{"Hangul syllable (NFC)", quote("\uac00"), ok, "", `{"name":"` + "\uac00" + `"}`},
		{"U+FFFD replacement char (refused by the body decoder before the name parser)", quote("a\ufffdb"), bad, "invalid_text", ""},
		{"lone high surrogate escape", `"a\ud800b"`, bad, "invalid_text", ""},
		{"lone low surrogate escape", `"a\udc00b"`, bad, "invalid_text", ""},
		{"valid surrogate pair escape", `"\ud83d\ude00"`, ok, "", `{"name":"😀"}`},
		{"reversed surrogate pair escape", `"\ude00\ud83d"`, bad, "invalid_text", ""},
		{"private use character", quote("\ue000"), ok, "", `{"name":"` + "\ue000" + `"}`}, // Co is not Cc/Cf
		{"CJK", quote("山田太郎"), ok, "", `{"name":"山田太郎"}`},
		{"RTL Hebrew without controls", quote("שלום"), ok, "", `{"name":"שלום"}`},
		{"quote and backslash survive", `"a\"b\\c"`, ok, "", `{"name":"a\"b\\c"}`},
		{"slash escape is read as a slash", `"a\/b"`, ok, "", `{"name":"a/b"}`},
		{"HTML-sensitive characters are escaped by Go in the stored JSON", `"<a&b>"`, ok, "", `{"name":"\u003ca\u0026b\u003e"}`},
		{"line separator U+2028 (Zl is not Cc/Cf)", quote("a\u2028b"), ok, "", `{"name":"a\u2028b"}`},
		{"invalid UTF-8 byte 0xff", "\"a\xffb\"", bad, "invalid_text", ""},
		{"invalid UTF-8 lone continuation byte", "\"a\x80b\"", bad, "invalid_text", ""},
		{"invalid UTF-8 overlong NUL (C0 80)", "\"a\xc0\x80b\"", bad, "invalid_text", ""},
		{"invalid UTF-8 encoded surrogate (ED A0 80)", "\"a\xed\xa0\x80b\"", bad, "invalid_text", ""},
		{"invalid UTF-8 truncated sequence at the end", "\"a\xe2\x82\"", bad, "invalid_text", ""},
		{"raw NUL byte in the JSON string", "\"a\x00b\"", bad, "invalid_json", ""},
		{"raw newline byte in the JSON string", "\"a\nb\"", bad, "invalid_json", ""},
		{"raw DEL byte is a legal JSON char but a Cc code point", "\"a\x7fb\"", bad, regCodeName, ""},
	}
}

// TestRegistrationNames drives every name through begin and, when begin
// accepts it, through a complete registration, then reads users.profile back.
// The exact byte limits (128 bytes, never runes) and every refused class are in
// the table.
//
//nolint:paralleltest // shares one database
func TestRegistrationNames(t *testing.T) {
	for _, tt := range regNameCases() {
		t.Run(tt.name, func(t *testing.T) {
			regOpenFirstRun(t)

			begin := post(t, pathRegisterBegin, []byte(`{"invitationCode":"`+firstRunSecret+`","name":`+tt.raw+`}`), "")

			if begin.status != tt.wantBegin || (tt.wantCode != "" && begin.errorCode() != tt.wantCode) {
				t.Fatalf("begin = %d %s, want %d %s", begin.status, begin.body, tt.wantBegin, tt.wantCode)
			}

			// finish takes the same name through the same parser first, so a
			// refused name never reaches the verifier or the database.
			if tt.wantBegin != http.StatusOK {
				finishBody := regFinishWithRawName(t, tt.raw)

				got := post(t, pathRegisterEnd, finishBody, "")
				if got.status != tt.wantBegin || (tt.wantCode != "" && got.errorCode() != tt.wantCode) {
					t.Errorf("finish = %d %s, want %d %s", got.status, got.body, tt.wantBegin, tt.wantCode)
				}

				regExpectNothingWritten(t, tt.name)

				return
			}

			// begin returned the name unchanged in the creation options.
			var options creationOptions

			regDecode(t, begin, &options)

			var wantName string

			err := json.Unmarshal([]byte(tt.raw), &wantName)
			if err != nil {
				t.Fatalf("test name %s: %v", tt.raw, err)
			}

			if options.PublicKey.User.Name != wantName {
				t.Errorf("begin user.name = %q, want %q", options.PublicKey.User.Name, wantName)
			}

			// A complete registration with the raw name.
			auth := newAuthenticator()
			finishBody := regSpliceName(t, auth.finishBody(t, options, firstRunSecret, wantName), tt.raw)

			got := post(t, pathRegisterEnd, finishBody, "")
			if got.status != http.StatusCreated {
				t.Fatalf("finish = %d %s, want 201 (a valid name must never be a 4xx/5xx)", got.status, got.body)
			}

			if profile := scalar(t, "SELECT profile FROM users"); profile != tt.wantProfile {
				t.Errorf("users.profile = %q, want %q", profile, tt.wantProfile)
			}

			if length := scalar(t, "SELECT length(profile) FROM users"); length == "" {
				t.Error("no profile length")
			}

			expectCount(t, "users", "1")
			expectCount(t, "credentials", "1")
		})
	}
}

// regSpliceName replaces the name member of a finish body with raw JSON text.
func regSpliceName(t *testing.T, body []byte, raw string) []byte {
	t.Helper()

	var doc map[string]json.RawMessage

	err := json.Unmarshal(body, &doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	doc["name"] = json.RawMessage(raw)

	// json.Marshal of a RawMessage validates and re-compacts it, which would
	// repair invalid UTF-8; build the object by hand so the bytes go out as is.
	var out bytes.Buffer

	out.WriteByte('{')

	keys := make([]string, 0, len(doc))
	for key := range doc {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	for i, key := range keys {
		if i > 0 {
			out.WriteByte(',')
		}

		out.WriteString(`"` + key + `":`)
		out.Write(doc[key])
	}

	out.WriteByte('}')

	return out.Bytes()
}

// regFinishWithRawName is a finish body whose name is the raw JSON text and
// whose other members are well formed (a stale challenge: only the name is
// under test, and it is parsed first).
func regFinishWithRawName(t *testing.T, raw string) []byte {
	t.Helper()

	options := creationOptions{}
	options.PublicKey.Challenge = b64(randomBytes(73))

	return regSpliceName(t, newAuthenticator().finishBody(t, options, firstRunSecret, "placeholder"), raw)
}

// TestRegistrationWorstCaseNameFitsTheProfileCheck is the type/bound-confusion
// test for names: Go's encoding/json writes '<', '>' and '&' as \u003c (six
// bytes for one), so 128 bytes of '<' are 768 bytes in users.profile, which the
// schema CHECK bounds at 1024. It must register (201), not trip the CHECK (a
// 500 invitation/rejected) or the body cap.
//
//nolint:paralleltest // shares one database
func TestRegistrationWorstCaseNameFitsTheProfileCheck(t *testing.T) {
	for _, char := range []string{"<", ">", "&", "<>&"} {
		t.Run(fmt.Sprintf("128 bytes of %q", char), func(t *testing.T) {
			regOpenFirstRun(t)

			name := strings.Repeat(char, 128/len(char)) + strings.Repeat("<", 128%len(char))
			options := mustBeginRegistration(t, firstRunSecret, name)

			got := post(t, pathRegisterEnd, newAuthenticator().finishBody(t, options, firstRunSecret, name), "")
			got.expect(t, "finish with the worst-case name", http.StatusCreated, "")

			length := scalar(t, "SELECT length(profile) FROM users")
			t.Logf("profile length = %s bytes for %d bytes of %q", length, len(name), char)

			// The profile round-trips to the exact name.
			var profile struct {
				Name string `json:"name"`
			}

			err := json.Unmarshal([]byte(scalar(t, "SELECT profile FROM users")), &profile)
			if err != nil || profile.Name != name {
				t.Errorf("profile name = %q (%v), want %q", profile.Name, err, name)
			}

			if scalar(t, "SELECT length(profile) <= 1024 FROM users") != "1" {
				t.Errorf("profile length %s exceeds the CHECK", length)
			}
		})
	}
}

// ---- finish refusals ---------------------------------------------------------

// regRefusal is a finish request that must be refused and leave nothing.
type regRefusal struct {
	name string
	// build returns the finish body from a begin's options.
	build      func(t *testing.T, options creationOptions) []byte
	wantStatus int
	wantCode   string
}

// regRun begins a fresh ceremony for every row (they must not interfere),
// sends the refusal's body and asserts status, code and an untouched database.
func regRun(t *testing.T, rows []regRefusal) {
	t.Helper()

	for _, tt := range rows {
		t.Run(tt.name, func(t *testing.T) {
			regOpenFirstRun(t)

			options := mustBeginRegistration(t, firstRunSecret, "Alice")
			body := tt.build(t, options)

			got := post(t, pathRegisterEnd, body, "")
			if got.status != tt.wantStatus || (tt.wantCode != "" && got.errorCode() != tt.wantCode) {
				t.Errorf("finish = %d %s, want %d %s", got.status, got.body, tt.wantStatus, tt.wantCode)
			}

			regExpectNothingWritten(t, tt.name)
			expectCount(t, "invitations", "1")
		})
	}
}

// regHonest builds the honest finish body for options.
func regHonest(t *testing.T, options creationOptions) []byte {
	t.Helper()

	return newAuthenticator().finishBody(t, options, firstRunSecret, "Alice")
}

// regWithAuth builds a finish body from an authenticator edit.
func regWithAuth(edit func(*authenticator)) func(*testing.T, creationOptions) []byte {
	return func(t *testing.T, options creationOptions) []byte {
		t.Helper()

		auth := newAuthenticator()
		edit(&auth)

		return auth.finishBody(t, options, firstRunSecret, "Alice")
	}
}

// regWithChallenge builds an honest body whose clientData echoes the given
// challenge bytes instead of the issued ones.
func regWithChallenge(edit func(challenge []byte) []byte) func(*testing.T, creationOptions) []byte {
	return func(t *testing.T, options creationOptions) []byte {
		t.Helper()

		raw, err := base64.RawURLEncoding.DecodeString(options.PublicKey.Challenge)
		if err != nil {
			t.Fatalf("challenge: %v", err)
		}

		forged := options
		forged.PublicKey.Challenge = b64(edit(bytes.Clone(raw)))

		return newAuthenticator().finishBody(t, forged, firstRunSecret, "Alice")
	}
}

// TestRegistrationChallengeRefusals tampers with the signed challenge in every
// region (version byte, expiry bytes, nonce, tag), and sends truncated,
// extended, empty and mis-encoded ones. Every one must be 400 invalid_challenge
// (or invalid_credential for a challenge the verifier cannot even decode) and
// leave nothing behind.
//
// The expiry cannot be exercised end to end: the Worker's clock is the real one
// and the challenge's TTL is five minutes. An expired challenge is therefore
// only reachable with a forged expiry, which the HMAC refuses first. This is
// flagged in the report: expiry itself is covered by the unit tests.
//
//nolint:paralleltest // shares one database
func TestRegistrationChallengeRefusals(t *testing.T) {
	flip := func(index int, mask byte) func([]byte) []byte {
		return func(c []byte) []byte {
			c[index] ^= mask

			return c
		}
	}

	rows := []regRefusal{
		{"version byte flipped", regWithChallenge(flip(0, 0x01)), 400, regCodeChal},
		{"version byte zero", regWithChallenge(func(c []byte) []byte { c[0] = 0; return c }), 400, regCodeChal},
		{"version byte 0xff", regWithChallenge(func(c []byte) []byte { c[0] = 0xff; return c }), 400, regCodeChal},
		{"expiry byte 1 (most significant) flipped", regWithChallenge(flip(1, 0x01)), 400, regCodeChal},
		{"expiry byte 4 flipped", regWithChallenge(flip(4, 0x80)), 400, regCodeChal},
		{"expiry byte 8 (least significant) flipped", regWithChallenge(flip(8, 0x01)), 400, regCodeChal},
		{"expiry set far in the future (forged, tag now wrong)", regWithChallenge(func(c []byte) []byte {
			for i := 1; i <= 8; i++ {
				c[i] = 0x7f
			}

			return c
		}), 400, regCodeChal},
		{"expiry set to zero (forged, tag now wrong)", regWithChallenge(func(c []byte) []byte {
			for i := 1; i <= 8; i++ {
				c[i] = 0
			}

			return c
		}), 400, regCodeChal},
		{"nonce first byte flipped", regWithChallenge(flip(9, 0x01)), 400, regCodeChal},
		{"nonce middle byte flipped", regWithChallenge(flip(25, 0x10)), 400, regCodeChal},
		{"nonce last byte flipped", regWithChallenge(flip(40, 0x01)), 400, regCodeChal},
		{"tag first byte flipped", regWithChallenge(flip(41, 0x01)), 400, regCodeChal},
		{"tag middle byte flipped", regWithChallenge(flip(57, 0x01)), 400, regCodeChal},
		{"tag last byte flipped", regWithChallenge(flip(72, 0x01)), 400, regCodeChal},
		{"every byte flipped", regWithChallenge(func(c []byte) []byte {
			for i := range c {
				c[i] ^= 0xff
			}

			return c
		}), 400, regCodeChal},
		{"truncated by one byte", regWithChallenge(func(c []byte) []byte { return c[:len(c)-1] }), 400, regCodeChal},
		{"truncated to the state only (no tag)", regWithChallenge(func(c []byte) []byte { return c[:41] }), 400, regCodeChal},
		{"truncated to one byte", regWithChallenge(func(c []byte) []byte { return c[:1] }), 400, regCodeChal},
		{"extended by one byte", regWithChallenge(func(c []byte) []byte { return append(c, 0) }), 400, regCodeChal},
		{"extended by a copy of itself", regWithChallenge(func(c []byte) []byte { return append(c, c...) }), 400, regCodeChal},
		{"tag zeroed", regWithChallenge(func(c []byte) []byte {
			for i := 41; i < len(c); i++ {
				c[i] = 0
			}

			return c
		}), 400, regCodeChal},
		// A zero-length challenge is refused by the verifier (empty challenge).
		{"zero-length challenge", regWithChallenge(func([]byte) []byte { return nil }), 400, regCodeCred},
		{"challenge never issued (73 random bytes)", regWithChallenge(func([]byte) []byte { return randomBytes(73) }), 400, regCodeChal},
		{"challenge never issued (16 random bytes)", regWithChallenge(func([]byte) []byte { return randomBytes(16) }), 400, regCodeChal},
		{"challenge never issued (4 KiB of random bytes)", regWithChallenge(func([]byte) []byte { return randomBytes(1000) }), 400, regCodeChal},
		{"challenge from another name", func(t *testing.T, options creationOptions) []byte {
			t.Helper()

			return newAuthenticator().finishBody(t, options, firstRunSecret, "Mallory")
		}, 400, regCodeChal},
		{"challenge from the name with one added space", func(t *testing.T, options creationOptions) []byte {
			t.Helper()

			return newAuthenticator().finishBody(t, options, firstRunSecret, "Alice ")
		}, 400, regCodeChal},
		{"challenge from another (valid) code", func(t *testing.T, options creationOptions) []byte {
			t.Helper()

			// The code must be redeemable for the request to get past the
			// challenge: the order is verifier, challenge, then invitation.
			return newAuthenticator().finishBody(t, options, regSpareCode, "Alice")
		}, 400, regCodeChal},
		{"challenge from the code in another case", func(t *testing.T, options creationOptions) []byte {
			t.Helper()

			return newAuthenticator().finishBody(t, options, strings.ToLower(firstRunSecret), "Alice")
		}, 400, regCodeChal},
	}

	regRun(t, rows)
}

// TestRegistrationChallengeEncodings sends the challenge in clientDataJSON in
// spellings that decode to the same bytes in lenient decoders: only the one
// strict base64url spelling is accepted.
//
//nolint:paralleltest // shares one database
func TestRegistrationChallengeEncodings(t *testing.T) {
	spell := func(edit func(challenge string) string) func(*testing.T, creationOptions) []byte {
		return func(t *testing.T, options creationOptions) []byte {
			t.Helper()

			auth := newAuthenticator()
			origin := auth.origin
			auth.clientData = func(challenge string) []byte {
				return mustJSON(t, map[string]any{
					"type": "webauthn.create", "challenge": edit(challenge), "origin": origin, "crossOrigin": false,
				})
			}

			return auth.finishBody(t, options, firstRunSecret, "Alice")
		}
	}

	rows := []regRefusal{
		{"padded base64 (one = added)", spell(func(c string) string { return c + "=" }), 400, regCodeCred},
		{"padded base64 (== added)", spell(func(c string) string { return c + "==" }), 400, regCodeCred},
		{"standard alphabet + and /", spell(func(c string) string { return strings.NewReplacer("-", "+", "_", "/").Replace(c) + "+/" }), 400, regCodeCred},
		{"line break inside", spell(func(c string) string { return c[:20] + "\n" + c[20:] }), 400, regCodeCred},
		{"carriage return inside", spell(func(c string) string { return c[:20] + "\r" + c[20:] }), 400, regCodeCred},
		{"space inside", spell(func(c string) string { return c[:20] + " " + c[20:] }), 400, regCodeCred},
		{"leading space", spell(func(c string) string { return " " + c }), 400, regCodeCred},
		{"trailing newline", spell(func(c string) string { return c + "\n" }), 400, regCodeCred},
		{"non-zero unused bits in the last character (same bytes in a lenient decoder)", spell(func(c string) string {
			// 73 bytes are 584 bits, in 98 characters of 6 bits: the last
			// character carries 4 unused bits, which an honest encoder
			// writes as zero. The challenge's last character therefore has
			// its low 4 bits clear; setting one gives a spelling Go's
			// lenient decoder reads as the very same bytes.
			alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
			index := strings.IndexByte(alphabet, c[len(c)-1])

			return c[:len(c)-1] + string(alphabet[index|1])
		}), 400, regCodeCred},
		{"challenge as a JSON number", func(t *testing.T, options creationOptions) []byte {
			t.Helper()

			auth := newAuthenticator()
			auth.clientData = func(string) []byte {
				return []byte(`{"type":"webauthn.create","challenge":123,"origin":"` + target.origin + `"}`)
			}

			return auth.finishBody(t, options, firstRunSecret, "Alice")
		}, 400, regCodeCred},
		{"challenge as null", func(t *testing.T, options creationOptions) []byte {
			t.Helper()

			auth := newAuthenticator()
			auth.clientData = func(string) []byte {
				return []byte(`{"type":"webauthn.create","challenge":null,"origin":"` + target.origin + `"}`)
			}

			return auth.finishBody(t, options, firstRunSecret, "Alice")
		}, 400, regCodeCred},
		{"challenge member missing", func(t *testing.T, options creationOptions) []byte {
			t.Helper()

			auth := newAuthenticator()
			auth.clientData = func(string) []byte {
				return []byte(`{"type":"webauthn.create","origin":"` + target.origin + `"}`)
			}

			return auth.finishBody(t, options, firstRunSecret, "Alice")
		}, 400, regCodeCred},
		{"challenge repeated: forged first, genuine second", func(t *testing.T, options creationOptions) []byte {
			t.Helper()

			auth := newAuthenticator()
			auth.clientData = func(challenge string) []byte {
				return []byte(`{"type":"webauthn.create","challenge":"` + b64(randomBytes(73)) + `","challenge":"` + challenge +
					`","origin":"` + target.origin + `"}`)
			}

			return auth.finishBody(t, options, firstRunSecret, "Alice")
		}, 400, regCodeCred},
		{"challenge in another case beside the genuine one", func(t *testing.T, options creationOptions) []byte {
			t.Helper()

			auth := newAuthenticator()
			auth.clientData = func(challenge string) []byte {
				return []byte(`{"type":"webauthn.create","Challenge":"` + b64(randomBytes(73)) + `","challenge":"` + challenge +
					`","origin":"` + target.origin + `"}`)
			}

			return auth.finishBody(t, options, firstRunSecret, "Alice")
		}, 400, regCodeCred},
	}

	regRun(t, rows)
}

// TestRegistrationCrossCeremonyChallenge uses a login challenge for a
// registration (and a registration challenge as a login challenge): the two
// ceremonies derive different keys, so neither opens as the other.
//
//nolint:paralleltest // shares one database
func TestRegistrationCrossCeremonyChallenge(t *testing.T) {
	rows := []regRefusal{
		{"login challenge used for registration", func(t *testing.T, options creationOptions) []byte {
			t.Helper()

			login := beginLogin(t)
			forged := options
			forged.PublicKey.Challenge = login.PublicKey.Challenge

			return newAuthenticator().finishBody(t, forged, firstRunSecret, "Alice")
		}, 400, regCodeChal},
	}

	regRun(t, rows)

	t.Run("registration challenge used for login", func(t *testing.T) {
		pk := newAdmin(t)

		// The first-run code is spent now, so a registration challenge needs a
		// redeemable invitation of its own. begin only reads the invitation, so
		// the role-less type serves.
		regSeedInvitation(t, regFirstRunID, regNoRoleCode, regNoRoleType, 1, "")

		forged := mustBeginRegistration(t, regNoRoleCode, "Eve")

		var asLogin requestOptions

		asLogin.PublicKey.Challenge = forged.PublicKey.Challenge

		got := post(t, pathLoginEnd, pk.assertion().sign(t, asLogin, nil).body(t, nil), "")
		got.expect(t, "login with a registration challenge", http.StatusUnauthorized, codeInvalidLogin)

		if got.session() != "" {
			t.Errorf("a registration challenge logged in: %v", got.setCookies)
		}

		expectCount(t, "sessions", "0")
	})
}

// TestRegistrationPasskeyRefusals sends honest challenges with dishonest
// passkey responses: wrong origin, RP, flags, type, ids and transports.
//
//nolint:paralleltest // shares one database
func TestRegistrationPasskeyRefusals(t *testing.T) {
	cred := regCodeCred

	// flags: UP=1 UV=4 BE=8 BS=16 AT=64 ED=128 RFU1=2 RFU2=32.
	flagRows := func() []regRefusal {
		rows := make([]regRefusal, 0, 10)

		for _, c := range []struct {
			name  string
			flags byte
		}{
			{"UP missing", flagUV | flagAT},
			{"UV missing", flagUP | flagAT},
			{"UP and UV missing", flagAT},
			{"AT missing", flagUP | flagUV},
			{"ED (extension data) set", flagUP | flagUV | flagAT | 0x80},
			{"RFU1 reserved bit set", flagUP | flagUV | flagAT | 0x02},
			{"RFU2 reserved bit set", flagUP | flagUV | flagAT | 0x20},
			{"BS without BE", flagUP | flagUV | flagAT | 0x10},
			{"all bits set", 0xff},
			{"no bits set", 0x00},
		} {
			rows = append(rows, regRefusal{"flags: " + c.name, regWithAuth(func(a *authenticator) { a.flags = c.flags }), 400, cred})
		}

		return rows
	}()

	rows := append([]regRefusal{
		{"wrong origin", regWithAuth(func(a *authenticator) { a.origin = "https://evil.example.com" }), 400, cred},
		{"the API origin instead of the UI origin", regWithAuth(func(a *authenticator) { a.origin = target.apiOrigin }), 400, cred},
		{"origin with a trailing slash", regWithAuth(func(a *authenticator) { a.origin = target.origin + "/" }), 400, cred},
		{"origin in upper case", regWithAuth(func(a *authenticator) { a.origin = strings.ToUpper(target.origin) }), 400, cred},
		{"origin with another port", regWithAuth(func(a *authenticator) { a.origin = "http://localhost:3001" }), 400, cred},
		{"origin with no port", regWithAuth(func(a *authenticator) { a.origin = "http://localhost" }), 400, cred},
		{"origin as a prefix of the allowed one", regWithAuth(func(a *authenticator) { a.origin = target.origin[:len(target.origin)-1] }), 400, cred},
		{"origin with the allowed one as a prefix", regWithAuth(func(a *authenticator) { a.origin = target.origin + ".evil.example" }), 400, cred},
		{"origin with a path", regWithAuth(func(a *authenticator) { a.origin = target.origin + "/path" }), 400, cred},
		{"empty origin", regWithAuth(func(a *authenticator) { a.origin = "" }), 400, cred},
		{"wrong relying party", regWithAuth(func(a *authenticator) { a.rpID = "evil.example.com" }), 400, cred},
		{"relying party in upper case", regWithAuth(func(a *authenticator) { a.rpID = "LOCALHOST" }), 400, cred},
		{"relying party with the port", regWithAuth(func(a *authenticator) { a.rpID = "localhost:3000" }), 400, cred},
		{"relying party empty", regWithAuth(func(a *authenticator) { a.rpID = "" }), 400, cred},
		{"clientData type webauthn.get", regWithAuth(func(a *authenticator) {
			a.clientData = func(c string) []byte {
				return []byte(`{"type":"webauthn.get","challenge":"` + c + `","origin":"` + target.origin + `"}`)
			}
		}), 400, cred},
		{"clientData type empty", regWithAuth(func(a *authenticator) {
			a.clientData = func(c string) []byte {
				return []byte(`{"type":"","challenge":"` + c + `","origin":"` + target.origin + `"}`)
			}
		}), 400, cred},
		{"clientData type missing", regWithAuth(func(a *authenticator) {
			a.clientData = func(c string) []byte {
				return []byte(`{"challenge":"` + c + `","origin":"` + target.origin + `"}`)
			}
		}), 400, cred},
		{"clientData type in upper case", regWithAuth(func(a *authenticator) {
			a.clientData = func(c string) []byte {
				return []byte(`{"type":"WEBAUTHN.CREATE","challenge":"` + c + `","origin":"` + target.origin + `"}`)
			}
		}), 400, cred},
		{"clientData origin missing", regWithAuth(func(a *authenticator) {
			a.clientData = func(c string) []byte {
				return []byte(`{"type":"webauthn.create","challenge":"` + c + `"}`)
			}
		}), 400, cred},
		{"clientData origin as a number", regWithAuth(func(a *authenticator) {
			a.clientData = func(c string) []byte {
				return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":3}`)
			}
		}), 400, cred},
		{"clientData is not JSON", regWithAuth(func(a *authenticator) {
			a.clientData = func(string) []byte { return []byte("not json") }
		}), 400, cred},
		{"clientData is a JSON array", regWithAuth(func(a *authenticator) {
			a.clientData = func(string) []byte { return []byte("[]") }
		}), 400, cred},
		{"clientData is empty", regWithAuth(func(a *authenticator) {
			a.clientData = func(string) []byte { return nil }
		}), 400, cred},
		{"clientData is null", regWithAuth(func(a *authenticator) {
			a.clientData = func(string) []byte { return []byte("null") }
		}), 400, cred},
		{"clientData with a byte order mark", regWithAuth(func(a *authenticator) {
			a.clientData = func(c string) []byte {
				return append([]byte("\xef\xbb\xbf"), []byte(`{"type":"webauthn.create","challenge":"`+c+`","origin":"`+target.origin+`"}`)...)
			}
		}), 400, cred},
		{"clientData with trailing garbage", regWithAuth(func(a *authenticator) {
			a.clientData = func(c string) []byte {
				return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `"}x`)
			}
		}), 400, cred},
		{"clientData with a second document", regWithAuth(func(a *authenticator) {
			a.clientData = func(c string) []byte {
				return []byte(`{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `"}{}`)
			}
		}), 400, cred},
		{"clientData just over 2048 bytes", regWithAuth(func(a *authenticator) {
			a.clientData = func(c string) []byte {
				doc := `{"type":"webauthn.create","challenge":"` + c + `","origin":"` + target.origin + `","pad":"`
				pad := strings.Repeat("a", 2049-len(doc)-2)

				return []byte(doc + pad + `"}`)
			}
		}), 400, cred},
		{"credential id differs from rawId", func(t *testing.T, options creationOptions) []byte {
			t.Helper()

			return regMutate(t, regHonest(t, options), func(doc map[string]any) {
				regCredential(doc)["rawId"] = b64(randomBytes(32))
			})
		}, 400, cred},
		{"credential id differs from the authenticator data's", func(t *testing.T, options creationOptions) []byte {
			t.Helper()

			return regMutate(t, regHonest(t, options), func(doc map[string]any) {
				other := b64(randomBytes(32))
				regCredential(doc)["id"] = other
				regCredential(doc)["rawId"] = other
			})
		}, 400, cred},
		{"credential id padded", func(t *testing.T, options creationOptions) []byte {
			t.Helper()

			return regMutate(t, regHonest(t, options), func(doc map[string]any) {
				regCredential(doc)["id"] = fmt.Sprint(regCredential(doc)["id"]) + "="
			})
		}, 400, cred},
		{"credential id in the standard alphabet", func(t *testing.T, options creationOptions) []byte {
			t.Helper()

			return regMutate(t, regHonest(t, options), func(doc map[string]any) {
				regCredential(doc)["rawId"] = base64.StdEncoding.EncodeToString(randomBytes(31)) + "+/"
			})
		}, 400, cred},
		{"credential id empty", func(t *testing.T, options creationOptions) []byte {
			t.Helper()

			return regMutate(t, regHonest(t, options), func(doc map[string]any) {
				regCredential(doc)["id"] = ""
			})
		}, 400, cred},
		{"credential type is not public-key", func(t *testing.T, options creationOptions) []byte {
			t.Helper()

			return regMutate(t, regHonest(t, options), func(doc map[string]any) {
				regCredential(doc)["type"] = "password"
			})
		}, 400, cred},
		{"credential type missing", func(t *testing.T, options creationOptions) []byte {
			t.Helper()

			return regMutate(t, regHonest(t, options), func(doc map[string]any) {
				delete(regCredential(doc), "type")
			})
		}, 400, cred},
		{"credential type in upper case", func(t *testing.T, options creationOptions) []byte {
			t.Helper()

			return regMutate(t, regHonest(t, options), func(doc map[string]any) {
				regCredential(doc)["type"] = "PUBLIC-KEY"
			})
		}, 400, cred},
		{"attestation format fido-u2f", regWithAuth(func(a *authenticator) {
			a.object = func(authData []byte) []byte {
				return regCBOR(map[string]any{"fmt": "fido-u2f", "attStmt": map[string]any{}, "authData": authData})
			}
		}), 400, cred},
		{"attestation format packed", regWithAuth(func(a *authenticator) {
			a.object = func(authData []byte) []byte {
				return regCBOR(map[string]any{"fmt": "packed", "attStmt": map[string]any{}, "authData": authData})
			}
		}), 400, cred},
		{"attestation format empty", regWithAuth(func(a *authenticator) {
			a.object = func(authData []byte) []byte {
				return regCBOR(map[string]any{"fmt": "", "attStmt": map[string]any{}, "authData": authData})
			}
		}), 400, cred},
		{"attestation format NONE", regWithAuth(func(a *authenticator) {
			a.object = func(authData []byte) []byte {
				return regCBOR(map[string]any{"fmt": "NONE", "attStmt": map[string]any{}, "authData": authData})
			}
		}), 400, cred},
		{"non-empty attStmt", regWithAuth(func(a *authenticator) {
			a.object = func(authData []byte) []byte {
				return regCBOR(map[string]any{"fmt": "none", "attStmt": map[string]any{"x": 1}, "authData": authData})
			}
		}), 400, cred},
		{"attStmt present but a CBOR array", regWithAuth(func(a *authenticator) {
			a.object = func(authData []byte) []byte {
				return regCBOR(map[string]any{"fmt": "none", "attStmt": []any{}, "authData": authData})
			}
		}), 400, cred},
		{"attStmt a CBOR text string", regWithAuth(func(a *authenticator) {
			a.object = func(authData []byte) []byte {
				return regCBOR(map[string]any{"fmt": "none", "attStmt": "x", "authData": authData})
			}
		}), 400, cred},
		{"authData missing in the attestation object", regWithAuth(func(a *authenticator) {
			a.object = func([]byte) []byte {
				return regCBOR(map[string]any{"fmt": "none", "attStmt": map[string]any{}})
			}
		}), 400, cred},
		{"authData too short", regWithAuth(func(a *authenticator) {
			a.object = func(authData []byte) []byte {
				return regCBOR(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData[:50]})
			}
		}), 400, cred},
		{"authData empty", regWithAuth(func(a *authenticator) {
			a.object = func([]byte) []byte {
				return regCBOR(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": []byte{}})
			}
		}), 400, cred},
		{"attestation object is not CBOR", regWithAuth(func(a *authenticator) {
			a.object = func([]byte) []byte { return []byte("not cbor") }
		}), 400, cred},
		{"attestation object is empty", regWithAuth(func(a *authenticator) {
			a.object = func([]byte) []byte { return nil }
		}), 400, cred},
		{"attestation object is a CBOR array", regWithAuth(func(a *authenticator) {
			a.object = func([]byte) []byte { return []byte{0x80} }
		}), 400, cred},
		{"attestation object is CBOR null", regWithAuth(func(a *authenticator) {
			a.object = func([]byte) []byte { return []byte{0xf6} }
		}), 400, cred},
		{"attestation object with trailing bytes", regWithAuth(func(a *authenticator) {
			a.object = func(authData []byte) []byte {
				return append(regCBOR(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData}), 0x00)
			}
		}), 400, cred},
		{"attestation object over 4096 bytes", regWithAuth(func(a *authenticator) {
			a.object = func(authData []byte) []byte {
				return regCBOR(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": append(authData, make([]byte, 4096)...)})
			}
		}), 400, cred},
		{"extensions: clientExtensionResults non-empty", func(t *testing.T, options creationOptions) []byte {
			t.Helper()

			return regMutate(t, regHonest(t, options), func(doc map[string]any) {
				regCredential(doc)["clientExtensionResults"] = map[string]any{"credProps": map[string]any{"rk": true}}
			})
		}, 400, cred},
	}, flagRows...)

	regRun(t, rows)
}

// regCBOR encodes v canonically for the authenticator callbacks, which run
// without the test's own t in scope. An encoding failure is a mistake in the
// test table itself, so it panics.
func regCBOR(v any) []byte {
	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(err)
	}

	out, err := enc.Marshal(v)
	if err != nil {
		panic(err)
	}

	return out
}

// TestRegistrationAcceptedEnvelopeVariants are finish bodies that look unusual
// but are legal, and must register (201): the members the design says are
// ignored, clientExtensionResults empty, and the member order.
//
//nolint:paralleltest // shares one database
func TestRegistrationAcceptedEnvelopeVariants(t *testing.T) {
	tests := []struct {
		name string
		edit func(doc map[string]any)
	}{
		{"clientExtensionResults empty", func(doc map[string]any) { regCredential(doc)["clientExtensionResults"] = map[string]any{} }},
		{"clientExtensionResults null", func(doc map[string]any) { regCredential(doc)["clientExtensionResults"] = nil }},
		{"authenticatorAttachment is carried and ignored", func(doc map[string]any) { regCredential(doc)["authenticatorAttachment"] = "platform" }},
		{"authenticatorAttachment is any string", func(doc map[string]any) { regCredential(doc)["authenticatorAttachment"] = "whatever" }},
		{"response.publicKeyAlgorithm is ignored", func(doc map[string]any) { regResponse(doc)["publicKeyAlgorithm"] = -7 }},
		{"response.publicKeyAlgorithm that disagrees is ignored", func(doc map[string]any) { regResponse(doc)["publicKeyAlgorithm"] = -257 }},
		{"response.publicKey that disagrees is ignored", func(doc map[string]any) { regResponse(doc)["publicKey"] = b64(randomBytes(91)) }},
		{"response.authenticatorData that disagrees is ignored", func(doc map[string]any) { regResponse(doc)["authenticatorData"] = b64(randomBytes(37)) }},
		{"transports omitted", func(doc map[string]any) { delete(regResponse(doc), "transports") }},
		{"transports null", func(doc map[string]any) { regResponse(doc)["transports"] = nil }},
		{"transports empty", func(doc map[string]any) { regResponse(doc)["transports"] = []string{} }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regOpenFirstRun(t)

			options := mustBeginRegistration(t, firstRunSecret, "Alice")
			body := regMutate(t, regHonest(t, options), tt.edit)

			got := post(t, pathRegisterEnd, body, "")
			got.expect(t, "finish", http.StatusCreated, "")
			expectCount(t, "users", "1")
			expectCount(t, "credentials", "1")
		})
	}
}

// TestRegistrationTransports covers the transport hint list at its bounds and
// with hostile entries, and the canonical metadata it is stored as.
//
//nolint:paralleltest // shares one database
func TestRegistrationTransports(t *testing.T) {
	distinct := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = fmt.Sprintf("t%03d", i)
		}

		return out
	}

	tests := []struct {
		name       string
		transports any
		wantStatus int
		wantCode   string
		// wantStored is the exact metadata transports array when registered.
		wantStored string
	}{
		{"none", []any{}, 201, "", `[]`},
		{"one", []any{"usb"}, 201, "", `["usb"]`},
		{"unsorted is sorted", []any{"usb", "ble", "nfc"}, 201, "", `["ble","nfc","usb"]`},
		{"duplicates are removed", []any{"usb", "usb", "usb"}, 201, "", `["usb"]`},
		{"unsorted with duplicates", []any{"b", "a", "b", "a", "c"}, 201, "", `["a","b","c"]`},
		{"case differs: both kept, upper case sorts first", []any{"usb", "USB"}, 201, "", `["USB","usb"]`},
		{"unknown values are kept", []any{"carrier-pigeon"}, 201, "", `["carrier-pigeon"]`},
		{"an entry of 32 bytes", []any{strings.Repeat("x", 32)}, 201, "", `["` + strings.Repeat("x", 32) + `"]`},
		{"an entry of 33 bytes", []any{strings.Repeat("x", 33)}, 400, regCodeCred, ""},
		{"an entry of 1000 bytes", []any{strings.Repeat("x", 1000)}, 400, regCodeCred, ""},
		{"an empty entry", []any{""}, 400, regCodeCred, ""},
		{"an entry with a space is printable ASCII", []any{"a b"}, 201, "", `["a b"]`},
		{"an entry with a quote and a backslash", []any{`a"b\c`}, 201, "", `["a\"b\\c"]`},
		{"an entry with an HTML-sensitive character", []any{"<b>"}, 201, "", `["\u003cb\u003e"]`},
		{"an entry with a control character", []any{"a\x01b"}, 400, regCodeCred, ""},
		{"an entry with a newline", []any{"a\nb"}, 400, regCodeCred, ""},
		{"an entry with DEL", []any{"a\x7fb"}, 400, regCodeCred, ""},
		{"an entry with a non-ASCII letter", []any{"usbé"}, 400, regCodeCred, ""},
		{"an entry with an emoji", []any{"😀"}, 400, regCodeCred, ""},
		{"100 distinct entries (the limit)", distinct(100), 201, "", ""},
		{"101 distinct entries (one over)", distinct(101), 400, "too_many_items", ""},
		{"100 duplicates (the limit)", func() []any {
			out := make([]any, 100)
			for i := range out {
				out[i] = "usb"
			}

			return out
		}(), 201, "", `["usb"]`},
		{"101 duplicates are refused even though they de-duplicate", func() []any {
			out := make([]any, 101)
			for i := range out {
				out[i] = "usb"
			}

			return out
		}(), 400, "too_many_items", ""},
		{"10000 entries exceed the body cap before any bound", func() []any { return distinct(10000) }(), 413, codeBodyTooLarge, ""},
		{"a number entry", []any{5}, 400, "invalid_field_type", ""},
		{"a null entry (decodes to the empty string, which is refused)", []any{nil}, 400, regCodeCred, ""},
		{"an array entry", []any{[]any{"usb"}}, 400, "invalid_field_type", ""},
		{"an object entry", []any{map[string]any{}}, 400, "invalid_field_type", ""},
		{"a bool entry", []any{true}, 400, "invalid_field_type", ""},
		{"transports is a string", "usb", 400, "invalid_field_type", ""},
		{"transports is an object", map[string]any{"a": 1}, 400, "invalid_field_type", ""},
		{"transports is a number", 1, 400, "invalid_field_type", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regOpenFirstRun(t)

			options := mustBeginRegistration(t, firstRunSecret, "Alice")
			body := regMutate(t, regHonest(t, options), func(doc map[string]any) {
				regResponse(doc)["transports"] = tt.transports
			})

			got := post(t, pathRegisterEnd, body, "")
			if got.status != tt.wantStatus || (tt.wantCode != "" && got.errorCode() != tt.wantCode) {
				t.Fatalf("finish = %d %s, want %d %s", got.status, got.body, tt.wantStatus, tt.wantCode)
			}

			if tt.wantStatus != http.StatusCreated {
				regExpectNothingWritten(t, tt.name)

				return
			}

			stored := scalar(t, "SELECT json_extract(metadata, '$.transports') FROM credentials")
			if tt.wantStored != "" && stored != tt.wantStored {
				t.Errorf("stored transports = %s, want %s", stored, tt.wantStored)
			}

			// The metadata stays an array of strings whatever was sent.
			if scalar(t, "SELECT json_type(metadata, '$.transports') FROM credentials") != "array" {
				t.Errorf("metadata.transports is not an array: %s", scalar(t, "SELECT metadata FROM credentials"))
			}
		})
	}
}

// TestRegistrationRequestEnvelope sends malformed finish requests: unknown
// members at every level, repeated keys, wrong types of every field, trailing
// garbage and the body-size cap. None may write anything.
//
//nolint:paralleltest // shares one database
func TestRegistrationRequestEnvelope(t *testing.T) {
	rows := []struct {
		name string
		// build returns the body; raw bodies ignore the honest one.
		build      func(t *testing.T, honest []byte) []byte
		wantStatus int
		wantCode   string
	}{
		{"empty body", func(*testing.T, []byte) []byte { return []byte{} }, 400, "empty_body"},
		{"null body", func(*testing.T, []byte) []byte { return []byte("null") }, 400, regCodeInvalid},
		{"array body", func(*testing.T, []byte) []byte { return []byte("[]") }, 400, "invalid_field_type"},
		{"string body", func(*testing.T, []byte) []byte { return []byte(`"x"`) }, 400, "invalid_field_type"},
		{"number body", func(*testing.T, []byte) []byte { return []byte("1") }, 400, "invalid_field_type"},
		{"empty object", func(*testing.T, []byte) []byte { return []byte("{}") }, 400, regCodeInvalid},
		{"truncated JSON", func(_ *testing.T, honest []byte) []byte { return honest[:len(honest)/2] }, 400, "invalid_json"},
		{"trailing garbage", func(_ *testing.T, honest []byte) []byte { return append(bytes.Clone(honest), 'x') }, 400, "trailing_data"},
		{"trailing second document", func(_ *testing.T, honest []byte) []byte { return append(bytes.Clone(honest), []byte("{}")...) }, 400, "trailing_data"},
		{"leading garbage", func(_ *testing.T, honest []byte) []byte { return append([]byte("x"), honest...) }, 400, "invalid_json"},
		{"UTF-8 byte order mark first", func(_ *testing.T, honest []byte) []byte { return append([]byte("\xef\xbb\xbf"), honest...) }, 400, "invalid_json"},
		{"top-level unknown member role", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { doc["role"] = "admin" })
		}, 400, codeUnknownField},
		{"top-level unknown member userId", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { doc["userId"] = idMissing })
		}, 400, codeUnknownField},
		{"top-level member in another case", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { doc["Name"] = "x" })
		}, 400, codeUnknownField},
		{"credential-level unknown member", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { regCredential(doc)["role"] = "admin" })
		}, 400, codeUnknownField},
		{"response-level unknown member", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { regResponse(doc)["extra"] = "x" })
		}, 400, codeUnknownField},
		{"clientDataJSON member in another case", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) {
				resp := regResponse(doc)
				resp["clientDataJson"] = resp["clientDataJSON"]
				delete(resp, "clientDataJSON")
			})
		}, 400, codeUnknownField},
		{"credential is a string", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { doc["credential"] = "x" })
		}, 400, "invalid_field_type"},
		{"credential is an array", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { doc["credential"] = []any{} })
		}, 400, "invalid_field_type"},
		{"credential is null", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { doc["credential"] = nil })
		}, 400, regCodeCred},
		{"credential missing", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { delete(doc, "credential") })
		}, 400, regCodeCred},
		{"credential empty object", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { doc["credential"] = map[string]any{} })
		}, 400, regCodeCred},
		{"response is a string", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { regCredential(doc)["response"] = "x" })
		}, 400, "invalid_field_type"},
		{"response missing", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { delete(regCredential(doc), "response") })
		}, 400, regCodeCred},
		{"id is a number", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { regCredential(doc)["id"] = 5 })
		}, 400, "invalid_field_type"},
		{"rawId is an array", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { regCredential(doc)["rawId"] = []any{} })
		}, 400, "invalid_field_type"},
		{"type is a number", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { regCredential(doc)["type"] = 1 })
		}, 400, "invalid_field_type"},
		{"clientDataJSON is a number", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { regResponse(doc)["clientDataJSON"] = 1 })
		}, 400, "invalid_field_type"},
		{"attestationObject is an object", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { regResponse(doc)["attestationObject"] = map[string]any{} })
		}, 400, "invalid_field_type"},
		{"attestationObject is null", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { regResponse(doc)["attestationObject"] = nil })
		}, 400, regCodeCred},
		{"publicKeyAlgorithm is a string", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { regResponse(doc)["publicKeyAlgorithm"] = "-7" })
		}, 400, "invalid_field_type"},
		{"name is a number", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { doc["name"] = 5 })
		}, 400, "invalid_field_type"},
		{"invitationCode is a number", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { doc["invitationCode"] = 5 })
		}, 400, "invalid_field_type"},
		{"duplicate top-level key", func(_ *testing.T, honest []byte) []byte {
			return append([]byte(`{"name":"Alice",`), honest[1:]...)
		}, 400, "duplicate_field"},
		{"duplicate credential key", func(_ *testing.T, honest []byte) []byte {
			return bytes.Replace(honest, []byte(`"credential":{`), []byte(`"credential":{"type":"public-key",`), 1)
		}, 400, "duplicate_field"},
		{"duplicate response key", func(_ *testing.T, honest []byte) []byte {
			return bytes.Replace(honest, []byte(`"response":{`), []byte(`"response":{"transports":["usb"],`), 1)
		}, 400, "duplicate_field"},
		{"U+FFFD in the code", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { doc["invitationCode"] = "a\ufffdb" })
		}, 400, "invalid_text"},
		{"invalid UTF-8 inside a member name", func(_ *testing.T, honest []byte) []byte {
			return bytes.Replace(honest, []byte(`"name"`), []byte("\"na\xffme\""), 1)
		}, 400, "invalid_text"},
		{"NUL byte in the body", func(_ *testing.T, honest []byte) []byte {
			return append([]byte{0}, honest...)
		}, 400, "invalid_json"},
		{"body at the 32 KiB cap, padded with spaces, is parsed normally", func(_ *testing.T, honest []byte) []byte {
			return append(bytes.Clone(honest), bytes.Repeat([]byte(" "), 32<<10-len(honest))...)
		}, 201, ""},
		{"body one byte over the 32 KiB cap", func(_ *testing.T, honest []byte) []byte {
			return append(bytes.Clone(honest), bytes.Repeat([]byte(" "), 32<<10+1-len(honest))...)
		}, 413, codeBodyTooLarge},
		{"body of 33 KiB of garbage", func(*testing.T, []byte) []byte { return bytes.Repeat([]byte("x"), 33<<10) }, 413, codeBodyTooLarge},
		{"body of 2 MiB", func(*testing.T, []byte) []byte { return bytes.Repeat([]byte("x"), 2<<20) }, 413, codeBodyTooLarge},
		{"a 32 KiB clientDataJSON member", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { regResponse(doc)["clientDataJSON"] = strings.Repeat("A", 31<<10) })
		}, 400, regCodeCred},
		{"a 4 KiB name", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { doc["name"] = strings.Repeat("a", 4<<10) })
		}, 400, regCodeName},
		{"a 4 KiB id", func(t *testing.T, honest []byte) []byte {
			t.Helper()

			return regMutate(t, honest, func(doc map[string]any) { regCredential(doc)["id"] = strings.Repeat("A", 4<<10) })
		}, 400, regCodeCred},
	}

	for _, tt := range rows {
		t.Run(tt.name, func(t *testing.T) {
			regOpenFirstRun(t)

			options := mustBeginRegistration(t, firstRunSecret, "Alice")
			honest := regHonest(t, options)

			got := post(t, pathRegisterEnd, tt.build(t, honest), "")
			if got.status != tt.wantStatus || (tt.wantCode != "" && got.errorCode() != tt.wantCode) {
				t.Errorf("finish = %d %.300s, want %d %s", got.status, got.body, tt.wantStatus, tt.wantCode)
			}

			if tt.wantStatus == http.StatusCreated {
				expectCount(t, "users", "1")

				return
			}

			regExpectNothingWritten(t, tt.name)
		})
	}
}

// TestRegistrationMethodsAndMedia covers the routes' HTTP contract.
//
//nolint:paralleltest // shares one database
func TestRegistrationMethodsAndMedia(t *testing.T) {
	regOpenFirstRun(t)

	for _, path := range []string{pathRegisterBegin, pathRegisterEnd} {
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			got := send(t, request{method: method, path: path, body: []byte("{}")})
			got.expect(t, method+" "+path, http.StatusMethodNotAllowed, codeMethodNotAllow)
		}

		send(t, request{method: http.MethodPost, path: path, body: []byte("{}"), noType: true}).
			expect(t, "POST "+path+" without a content type", http.StatusUnsupportedMediaType, codeUnsupportedType)
		send(t, request{method: http.MethodPost, path: path, body: []byte("{}"), headers: map[string]string{"Content-Type": "text/plain"}}).
			expect(t, "POST "+path+" as text/plain", http.StatusUnsupportedMediaType, codeUnsupportedType)
		send(t, request{method: http.MethodPost, path: path, body: []byte("{}"), headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}}).
			expect(t, "POST "+path+" as a form", http.StatusUnsupportedMediaType, codeUnsupportedType)
	}

	// A foreign Origin gets no CORS grant: only the UI origin does.
	got := send(t, request{
		method: http.MethodPost, path: pathRegisterBegin,
		body:    mustJSON(t, map[string]string{"invitationCode": firstRunSecret, "name": "A"}),
		headers: map[string]string{"Origin": "https://evil.example"},
	})
	if allow := got.header.Get("Access-Control-Allow-Origin"); allow == "https://evil.example" || allow == "*" {
		t.Errorf("a foreign origin was granted CORS: %q", allow)
	}

	regExpectNothingWritten(t, "methods and media")
}

// ---- interleavings -----------------------------------------------------------

// regPrepared is one racer: a ceremony begun and its finish body built.
type regPrepared struct {
	name string
	body []byte
	auth authenticator
}

func regPrepare(t *testing.T, name string) regPrepared {
	t.Helper()

	options := mustBeginRegistration(t, firstRunSecret, name)
	auth := newAuthenticator()
	auth.priv = newKey(t)

	return regPrepared{name: name, auth: auth, body: auth.finishBody(t, options, firstRunSecret, name)}
}

// regRace posts every body at once, released together, and returns the replies.
func regRace(t *testing.T, bodies [][]byte) []reply {
	t.Helper()

	replies := make([]reply, len(bodies))
	start := make(chan struct{})

	var wg sync.WaitGroup

	for i := range bodies {
		wg.Go(func() {
			<-start

			replies[i] = post(t, pathRegisterEnd, bodies[i], "")
		})
	}

	close(start)
	wg.Wait()

	return replies
}

// TestRegistrationRacingFirstRunFinishes begins N registrations with the
// first-run code, then finishes all of them at once. The conditional insert is
// the single point of acceptance: exactly one 201, exactly one user and one
// credential; every loser is a clean 403 invalid_invitation (its advisory read
// already saw the account) or 409 registration_accept_failed (it lost the
// write); never a 5xx.
//
//nolint:paralleltest // shares one database
func TestRegistrationRacingFirstRunFinishes(t *testing.T) {
	const (
		rounds = 5
		racers = 8
	)

	total := map[string]int{}

	for round := range rounds {
		regOpenFirstRun(t)

		bodies := make([][]byte, racers)

		for i := range racers {
			bodies[i] = regPrepare(t, fmt.Sprintf("Racer %d", i)).body
		}

		replies := regRace(t, bodies)

		winners := 0
		mix := map[string]int{}

		for _, got := range replies {
			key := fmt.Sprintf("%d %s", got.status, got.errorCode())
			mix[key]++
			total[key]++

			switch {
			case got.status == http.StatusCreated:
				winners++
			case got.status == http.StatusForbidden && got.errorCode() == regCodeInvalid:
			case got.status == http.StatusConflict && got.errorCode() == regCodeAccept:
			default:
				t.Errorf("round %d: unexpected loser %d %s", round, got.status, got.body)
			}
		}

		t.Logf("round %d: %v", round, mix)

		if winners != 1 {
			t.Errorf("round %d: %d winners, want exactly 1", round, winners)
		}

		expectCount(t, "users", "1")
		expectCount(t, "credentials", "1")
		expectCount(t, "invitations", "1")

		// The winner's row is complete: role from the invitation.
		if got := scalar(t, "SELECT role FROM users"); got != roleAdmin {
			t.Errorf("round %d: role = %q, want admin", round, got)
		}

		if got := scalar(t, "SELECT count(*) FROM credentials c JOIN users u ON u.id = c.user_id"); got != "1" {
			t.Errorf("round %d: the credential is not attached to the user", round)
		}
	}

	t.Logf("all rounds: %v", total)
}

// TestRegistrationReplayRace sends the SAME finish body twice at once, many
// times over: the user handle and credential id are unique, so exactly one may
// win. The loser must be a clean 4xx.
//
//nolint:paralleltest // shares one database
func TestRegistrationReplayRace(t *testing.T) {
	for round := range 4 {
		regOpenFirstRun(t)

		prepared := regPrepare(t, "Replay")

		replies := regRace(t, [][]byte{prepared.body, prepared.body, prepared.body, prepared.body})

		winners := 0

		for _, got := range replies {
			switch {
			case got.status == http.StatusCreated:
				winners++
			case got.status >= 400 && got.status < 500:
			default:
				t.Errorf("round %d: replay = %d %s, want 201 or a clean 4xx", round, got.status, got.body)
			}
		}

		if winners != 1 {
			t.Errorf("round %d: %d winners for one body, want 1", round, winners)
		}

		expectCount(t, "users", "1")
		expectCount(t, "credentials", "1")
	}
}

// TestRegistrationSequentialReplay replays a finished registration: the second
// attempt must be refused with nothing duplicated.
//
//nolint:paralleltest // shares one database
func TestRegistrationSequentialReplay(t *testing.T) {
	regOpenFirstRun(t)

	prepared := regPrepare(t, "Replay")

	post(t, pathRegisterEnd, prepared.body, "").expect(t, "first finish", http.StatusCreated, "")

	got := post(t, pathRegisterEnd, prepared.body, "")
	if got.status != http.StatusForbidden || got.errorCode() != regCodeInvalid {
		t.Errorf("replayed finish = %d %s, want 403 invalid_invitation", got.status, got.body)
	}

	expectCount(t, "users", "1")
	expectCount(t, "credentials", "1")
}

// TestRegistrationUniqueConstraints exercises the UNIQUE guards through a
// multi-use invitation, where the cap does not stop the second registration and
// only the credential/handle uniqueness can. The invitation type is e2e_no_role
// (the only types with a role are first_run, which is single use), so the Worker
// cannot redeem it: see TestRegistrationInvitationWithoutRole. The constraint
// itself is therefore proved at the database, with the statements registration
// issues, in TestRegistrationBatchConstraints.
//
// What the Worker CAN prove end to end is the first_run path: after the winner,
// a second registration with the same credential id or the same public key is
// refused cleanly (the invitation is spent), never a 5xx.
//
//nolint:paralleltest // shares one database
func TestRegistrationSameCredentialTwice(t *testing.T) {
	tests := []struct {
		name string
		edit func(second *authenticator, first authenticator)
	}{
		{"same credential id", func(second *authenticator, first authenticator) { second.credID = first.credID }},
		{"same public key", func(second *authenticator, first authenticator) { second.priv = first.priv }},
		{"same credential id and key", func(second *authenticator, first authenticator) {
			second.credID = first.credID
			second.priv = first.priv
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regOpenFirstRun(t)

			// Two ceremonies, different handles, begun while the invitation is open.
			optionsA := mustBeginRegistration(t, firstRunSecret, "Alice")
			optionsB := mustBeginRegistration(t, firstRunSecret, "Bob")

			a := newAuthenticator()
			a.priv = newKey(t)

			b := newAuthenticator()
			b.priv = newKey(t)
			tt.edit(&b, a)

			bodies := [][]byte{
				a.finishBody(t, optionsA, firstRunSecret, "Alice"),
				b.finishBody(t, optionsB, firstRunSecret, "Bob"),
			}

			replies := regRace(t, bodies)

			winners := 0

			for _, got := range replies {
				switch got.status {
				case http.StatusCreated:
					winners++
				case http.StatusForbidden, http.StatusConflict:
				default:
					t.Errorf("loser = %d %s, want a clean 403/409", got.status, got.body)
				}
			}

			if winners != 1 {
				t.Errorf("%d winners, want 1", winners)
			}

			expectCount(t, "users", "1")
			expectCount(t, "credentials", "1")
		})
	}
}

// TestRegistrationBatchConstraints proves, against the real database, what the
// registration batch relies on: uniqueness of the user handle, the credential id
// and the public key, and the foreign key from credential to user. These are
// the constraints a multi-use invitation would lean on; no Worker request can
// reach them today (the only invitation type with a role is single use), so the
// statements are tried directly.
//
//nolint:paralleltest // shares one database
func TestRegistrationBatchConstraints(t *testing.T) {
	regOpenFirstRun(t)
	registerWith(t, "Admin")

	const insertCredential = "INSERT INTO credentials (id, credential_id, user_id, public_key, flags, metadata, created_at) " +
		"VALUES (?, ?, ?, ?, 5, '{}', 0)"

	user := scalar(t, "SELECT id FROM users")
	otherUser := "00000000-0000-7000-8000-00000000e301"

	seed(t, "INSERT INTO users (id, user_handle, role, invitation_id, profile, created_at) "+
		"VALUES (?, randomblob(32), 'e2e_none', (SELECT id FROM invitations), '{}', 0)", otherUser)

	existingID := scalar(t, "SELECT hex(credential_id) FROM credentials")
	existingKey := scalar(t, "SELECT hex(public_key) FROM credentials")

	_ = user

	tests := []struct {
		name  string
		query string
		args  []any
		want  bool // refused
	}{
		{"same credential id for another user", insertCredential,
			[]any{idN("0c00", 1), mustDecodeHex(t, existingID), otherUser, randomBytes(77)}, true},
		{"same public key for another user", insertCredential,
			[]any{idN("0c00", 2), randomBytes(32), otherUser, mustDecodeHex(t, existingKey)}, true},
		{"a credential for no user", insertCredential,
			[]any{idN("0c00", 3), randomBytes(32), nil, randomBytes(77)}, true},
		{"a credential for an unknown user", insertCredential,
			[]any{idN("0c00", 4), randomBytes(32), idMissing, randomBytes(77)}, true},
		{"a credential id of 0 bytes", insertCredential,
			[]any{idN("0c00", 5), []byte{}, otherUser, randomBytes(77)}, true},
		{"a credential id of 1024 bytes", insertCredential,
			[]any{idN("0c00", 6), randomBytes(1024), otherUser, randomBytes(77)}, true},
		{"a credential id of 1023 bytes", insertCredential,
			[]any{idN("0c00", 7), randomBytes(1023), otherUser, randomBytes(77)}, false},
		{"a public key of 1025 bytes", insertCredential,
			[]any{idN("0c00", 8), randomBytes(32), otherUser, randomBytes(1025)}, true},
		{"a credential id stored as TEXT", insertCredential,
			[]any{idN("0c00", 9), "text-credential-id", otherUser, randomBytes(77)}, true},
		{"a user handle shared with another account", "INSERT INTO users (id, user_handle, role, invitation_id, profile, created_at) " +
			"VALUES (?, (SELECT user_handle FROM users LIMIT 1), 'e2e_none', (SELECT id FROM invitations), '{}', 0)",
			[]any{idN("0c00", 10)}, true},
		{"a user handle of 65 bytes", "INSERT INTO users (id, user_handle, role, invitation_id, profile, created_at) " +
			"VALUES (?, randomblob(65), 'e2e_none', (SELECT id FROM invitations), '{}', 0)", []any{idN("0c00", 11)}, true},
		{"a profile of 1025 bytes", "INSERT INTO users (id, user_handle, role, invitation_id, profile, created_at) " +
			"VALUES (?, randomblob(32), 'e2e_none', (SELECT id FROM invitations), '{\"name\":\"" + strings.Repeat("a", 1025-10) + "\"}', 0)",
			[]any{idN("0c00", 12)}, true},
		{"a profile of 1024 bytes", "INSERT INTO users (id, user_handle, role, invitation_id, profile, created_at) " +
			"VALUES (?, randomblob(32), 'e2e_none', (SELECT id FROM invitations), '{\"name\":\"" + strings.Repeat("a", 1024-11) + "\"}', 0)",
			[]any{idN("0c00", 13)}, false},
		{"a user for no invitation", "INSERT INTO users (id, user_handle, role, invitation_id, profile, created_at) " +
			"VALUES (?, randomblob(32), 'e2e_none', NULL, '{}', 0)", []any{idN("0c00", 14)}, true},
		{"a user for an unknown invitation", "INSERT INTO users (id, user_handle, role, invitation_id, profile, created_at) " +
			"VALUES (?, randomblob(32), 'e2e_none', '" + idMissing + "', '{}', 0)", []any{idN("0c00", 15)}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := refused(t, tt.query, tt.args...); got != tt.want {
				t.Errorf("refused = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRegistrationRolesComeFromTheInvitation proves a client cannot choose its
// role: the finish body has no role member (unknown_field), and a response
// naming role "admin" under any member is refused or ignored with the account
// still getting the invitation's role.
//
//nolint:paralleltest // shares one database
func TestRegistrationRolesComeFromTheInvitation(t *testing.T) {
	regOpenFirstRun(t)

	options := mustBeginRegistration(t, firstRunSecret, "Alice")
	honest := regHonest(t, options)

	for _, member := range []string{"role", "roles", "type", "invitationType", "isAdmin", "userId", "id"} {
		body := regMutate(t, honest, func(doc map[string]any) { doc[member] = roleAdmin })
		post(t, pathRegisterEnd, body, "").expect(t, "finish with "+member, http.StatusBadRequest, codeUnknownField)
	}

	regExpectNothingWritten(t, "client-chosen role")

	post(t, pathRegisterEnd, honest, "").expect(t, "honest finish", http.StatusCreated, "")

	if got := scalar(t, "SELECT role FROM users"); got != roleAdmin {
		t.Errorf("role = %q", got)
	}
}

// TestRegistrationSecondAccountViaFirstRun proves first_run is single use end to
// end: after the admin exists, begin and finish with the same code are refused,
// whether the ceremony began before or after, and the admin can still log in.
//
//nolint:paralleltest // shares one database
func TestRegistrationSecondAccountViaFirstRun(t *testing.T) {
	regOpenFirstRun(t)

	early := regPrepare(t, "Early")
	admin := registerWith(t, "Admin")

	post(t, pathRegisterEnd, early.body, "").
		expect(t, "finish of a ceremony begun before the admin existed", http.StatusForbidden, regCodeInvalid)
	beginRegistration(t, firstRunSecret, "Late").
		expect(t, "begin after the admin exists", http.StatusForbidden, regCodeInvalid)

	expectCount(t, "users", "1")
	expectCount(t, "credentials", "1")
	frExpectStatus(t, "status", frAccepted)

	if token := login(t, admin); token == "" {
		t.Error("the admin cannot log in")
	}
}

// TestRegistrationOtherInvitationsAreInert seeds invitations of other types and
// states next to the first-run one and proves none lets a registration through:
// only the exact code of a redeemable, role-bearing invitation does.
//
//nolint:paralleltest // shares one database
func TestRegistrationOtherInvitationsAreInert(t *testing.T) {
	regOpenFirstRun(t)

	// An already revoked, expired and exhausted invitation of the first_run type
	// cannot exist beside the live one (the type is unique by construction); use
	// the role-less type for the bystanders.
	regSeedInvitation(t, idInvitationA, regSpareCode, regNoRoleType, 5, "revoked")
	regSeedInvitation(t, idInvitationB, regNoRoleCode, regNoRoleType, 5, "expired")

	for _, code := range []string{regSpareCode, regNoRoleCode} {
		beginRegistration(t, code, "Alice").expect(t, "begin with "+code, http.StatusForbidden, regCodeInvalid)
	}

	// The live one still works.
	registerWith(t, "Admin")
	expectCount(t, "users", "1")
}

// TestRegistrationFirstRunIgnoresTheCap seeds a first_run invitation that allows
// two accounts (num_invites = 2), which only a hand-edited database can hold.
// first_run is additionally bound to "no account exists at all" in the write
// (docs/first_run_design.md, stage 2), so the cap of two must not admit a
// second account: this is the one multi-use shape that has a role, and it
// proves the stage-2 condition is the SQL's, independent of the cap.
//
//nolint:paralleltest // shares one database
func TestRegistrationFirstRunIgnoresTheCap(t *testing.T) {
	reset(t)
	regSeedInvitation(t, regFirstRunID, regSpareCode, "first_run", 2, "")

	// Begin all three while no account exists, against the spare code.
	bodyA := regPrepareBody(t, regSpareCode, "First")
	bodyB := regPrepareBody(t, regSpareCode, "Second")
	bodyC := regPrepareBody(t, regSpareCode, "Third")

	replies := regRace(t, [][]byte{bodyA, bodyB})

	winners := 0

	for _, got := range replies {
		switch got.status {
		case http.StatusCreated:
			winners++
		case http.StatusForbidden, http.StatusConflict:
		default:
			t.Errorf("loser = %d %s, want a clean 403/409", got.status, got.body)
		}
	}

	if winners != 1 {
		t.Errorf("%d winners with a two-account first_run invitation, want 1", winners)
	}

	expectCount(t, "users", "1")
	expectCount(t, "credentials", "1")

	// A later attempt, with the cap of two still not reached, is refused too.
	post(t, pathRegisterEnd, bodyC, "").expect(t, "third registration", http.StatusForbidden, regCodeInvalid)
	expectCount(t, "users", "1")
}

// regPrepareBody begins and builds a finish body for code and name.
func regPrepareBody(t *testing.T, code, name string) []byte {
	t.Helper()

	options := mustBeginRegistration(t, code, name)

	return newAuthenticator().finishBody(t, options, code, name)
}

// TestRegistrationIgnoredIntegerMember is the number type/bound-confusion test.
// response.publicKeyAlgorithm is an int64 in the Go body type and is ignored by
// the verifier (it is a copy of what the attestation object holds). JSON
// numbers cross the JS boundary as float64, so the member is where a number
// above 2^53 or in exponent form would show a confusion: it must either decode
// exactly as an int64 (then be ignored) or be refused as a 400 type error. It
// must never be a 5xx, and it must never change what is stored.
//
// A refused body writes nothing; an accepted one registers the same account an
// honest body would (one user, one credential).
//
//nolint:paralleltest // shares one database
func TestRegistrationIgnoredIntegerMember(t *testing.T) {
	tests := []struct {
		literal    string
		wantStatus int
		wantCode   string
	}{
		{"-7", http.StatusCreated, ""},
		{"0", http.StatusCreated, ""},
		{"-0", http.StatusCreated, ""},
		{"-1", http.StatusCreated, ""},
		{"9007199254740991", http.StatusCreated, ""},
		{"9007199254740992", http.StatusCreated, ""},
		{"9007199254740993", http.StatusCreated, ""},
		{"9223372036854775807", http.StatusCreated, ""},
		{"-9223372036854775808", http.StatusCreated, ""},
		{"9223372036854775808", http.StatusBadRequest, "invalid_field_type"},
		{"-9223372036854775809", http.StatusBadRequest, "invalid_field_type"},
		{"18446744073709551615", http.StatusBadRequest, "invalid_field_type"},
		{"1.0", http.StatusBadRequest, "invalid_field_type"},
		{"-7.0", http.StatusBadRequest, "invalid_field_type"},
		{"1.5", http.StatusBadRequest, "invalid_field_type"},
		{"1e3", http.StatusBadRequest, "invalid_field_type"},
		{"1E3", http.StatusBadRequest, "invalid_field_type"},
		{"1e400", http.StatusBadRequest, "invalid_field_type"},
		{"-1e400", http.StatusBadRequest, "invalid_field_type"},
		{`"-7"`, http.StatusBadRequest, "invalid_field_type"},
		{"true", http.StatusBadRequest, "invalid_field_type"},
		{"[]", http.StatusBadRequest, "invalid_field_type"},
		{"{}", http.StatusBadRequest, "invalid_field_type"},
		{"null", http.StatusCreated, ""},
		{"00", http.StatusBadRequest, "invalid_json"},
		{"+1", http.StatusBadRequest, "invalid_json"},
		{"0x1", http.StatusBadRequest, "invalid_json"},
		{"NaN", http.StatusBadRequest, "invalid_json"},
		{"Infinity", http.StatusBadRequest, "invalid_json"},
		{".5", http.StatusBadRequest, "invalid_json"},
		{"1.", http.StatusBadRequest, "invalid_json"},
	}

	for _, tt := range tests {
		t.Run(tt.literal, func(t *testing.T) {
			regOpenFirstRun(t)

			options := mustBeginRegistration(t, firstRunSecret, "Alice")
			honest := regMutate(t, regHonest(t, options), func(doc map[string]any) { regResponse(doc)["publicKeyAlgorithm"] = 1 })
			body := bytes.Replace(honest, []byte(`"publicKeyAlgorithm":1`), []byte(`"publicKeyAlgorithm":`+tt.literal), 1)

			got := post(t, pathRegisterEnd, body, "")
			if got.status != tt.wantStatus || (tt.wantCode != "" && got.errorCode() != tt.wantCode) {
				t.Fatalf("finish = %d %s, want %d %s", got.status, got.body, tt.wantStatus, tt.wantCode)
			}

			if tt.wantStatus == http.StatusCreated {
				expectCount(t, "users", "1")
				expectCount(t, "credentials", "1")

				return
			}

			regExpectNothingWritten(t, tt.literal)
		})
	}
}
