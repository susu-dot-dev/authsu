package invitations_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/invitations"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// createBody builds a create request body in JSON. Parts that are empty are
// left out, so a field can be missing, and a part that is given is written
// verbatim, so a field can have any value, valid or not.
func createBody(invitationType, numInvites, label, expiresAt string) string {
	var parts []string

	for _, field := range []struct{ name, value string }{
		{"type", invitationType}, {"numInvites", numInvites}, {"label", label}, {"expiresAt", expiresAt},
	} {
		if field.value != "" {
			parts = append(parts, `"`+field.name+`":`+field.value)
		}
	}

	return "{" + strings.Join(parts, ",") + "}"
}

// text is a JSON string literal of s with no escaping, for values the test has
// already written as JSON.
func text(s string) string { return `"` + s + `"` }

// secs formats a Unix time as a JSON number.
func secs(value int64) string { return strconv.FormatInt(value, 10) }

// typed is a create body of the creatable type with the given other fields (see
// createBody).
func typed(numInvites, label, expiresAt string) string {
	return createBody(text(typeCustom), numInvites, label, expiresAt)
}

// invalidCase is a create body that must be refused, and the wire code that
// names why.
type invalidCase struct{ name, body, code string }

// invalidTypes are the refusals of the type: it is a creatable one, never first
// run, and exactly as spelled.
func invalidTypes() []invalidCase {
	const code = invitations.CodeInvalidType

	return []invalidCase{
		{"no type", createBody("", "1", "", ""), code},
		{"empty type", createBody(`""`, "1", "", ""), code},
		{"unknown type", createBody(text("nonsense"), "1", "", ""), code},
		{"workshop is not a type", createBody(text("workshop"), "1", "", ""), code},
		{"first run", createBody(text(store.InvitationFirstRun), "1", "", ""), code},
		{"type in another case", createBody(text("Member"), "1", "", ""), code},
		{"type with a space", createBody(text("member "), "1", "", ""), code},
		{"type with a NUL", createBody(text(`member\u0000`), "1", "", ""), code},
		{"type is a prefix of a creatable one", createBody(text("mem"), "1", "", ""), code},
		{"type is a number", createBody("1", "1", "", ""), codeInvalidFieldType},
	}
}

// invalidNumInvites are the refusals of numInvites: 1 to 10000, a whole JSON
// integer.
func invalidNumInvites() []invalidCase {
	const code = input.CodeInvalidNumInvites

	return []invalidCase{
		{"no numInvites", typed("", "", ""), code},
		{"null numInvites", typed("null", "", ""), code},
		{"zero invites", typed("0", "", ""), code},
		{"negative invites", typed("-1", "", ""), code},
		{"too many invites", typed("10001", "", ""), code},
		{"invites at 2^53", typed("9007199254740992", "", ""), code},
		{"invites at the int64 maximum", typed("9223372036854775807", "", ""), code},
		{"invites beyond int64", typed("9223372036854775808", "", ""), codeInvalidFieldType},
		{"invites with a fraction", typed("1.5", "", ""), codeInvalidFieldType},
		{"invites in exponent form", typed("1e2", "", ""), codeInvalidFieldType},
		{"invites as text", typed(`"3"`, "", ""), codeInvalidFieldType},
	}
}

// invalidLabels are the refusals of the label: display text of at most 256
// characters.
func invalidLabels() []invalidCase {
	const code = input.CodeInvalidLabel

	tooLong := strings.Repeat("é", input.MaxInvitationLabelRunes+1)

	return []invalidCase{
		{"label too long", typed("1", text(tooLong), ""), code},
		{"label of blanks", typed("1", text("   "), ""), code},
		{"label with a NUL", typed("1", text(`a\u0000b`), ""), code},
		{"label with a bidi override", typed("1", text(`a\u202eb`), ""), code},
		{"label not in NFC", typed("1", text(`e\u0301`), ""), code},
		{"label is a number", typed("1", "7", ""), codeInvalidFieldType},
	}
}

// invalidExpiries are the refusals of expiresAt: a whole number of seconds, in
// the future, at most ten years ahead.
func invalidExpiries() []invalidCase {
	const code = input.CodeInvalidExpiresAt

	now := fixedNow().Unix()
	horizon := int64(input.ExpiryHorizon / time.Second)

	return []invalidCase{
		{"expired already", typed("1", "", secs(now-1)), code},
		{"expires now", typed("1", "", secs(now)), code},
		{"expires at the epoch", typed("1", "", "0"), code},
		{"expires before the epoch", typed("1", "", "-1"), code},
		{"expires past the horizon", typed("1", "", secs(now+horizon+1)), code},
		{"expires at 2^53", typed("1", "", "9007199254740992"), code},
		{"expires in milliseconds", typed("1", "", secs(now*1000)), code},
		{"expires as text", typed("1", "", text("tomorrow")), codeInvalidFieldType},
		{"expires with a fraction", typed("1", "", "1.5"), codeInvalidFieldType},
	}
}

// invalidPrecedence are bodies with several wrong fields: the first in the
// order type, numInvites, label, expiresAt is the one reported.
func invalidPrecedence() []invalidCase {
	tooLong := text(strings.Repeat("é", input.MaxInvitationLabelRunes+1))

	return []invalidCase{
		{"type before the rest", createBody(text("x"), "0", tooLong, "1"), invitations.CodeInvalidType},
		{"numInvites before label and expiry", typed("0", tooLong, "1"), input.CodeInvalidNumInvites},
		{"label before expiry", typed("1", tooLong, "1"), input.CodeInvalidLabel},
	}
}

// invalidShapes are bodies that are not a create request at all.
func invalidShapes() []invalidCase {
	return []invalidCase{
		{"unknown field", `{"type":"member","numInvites":1,"role":"admin"}`, codeUnknownField},
		{"a field of a stored invitation", `{"type":"member","numInvites":1,"id":"` + invID + `"}`, codeUnknownField},
		{"repeated field", `{"type":"member","numInvites":1,"numInvites":2}`, "duplicate_field"},
		{"field name in another case", `{"Type":"workshop","numInvites":1}`, codeUnknownField},
		{"empty body", "", "empty_body"},
		{"not JSON", garbage, "invalid_json"},
		{"trailing data", validCreate + validCreate, "trailing_data"},
		{"an array", "[]", codeInvalidFieldType},
		{"a null body", "null", invitations.CodeInvalidType},
		{"label with invalid UTF-8", "{\"type\":\"member\",\"numInvites\":1,\"label\":\"a\xffb\"}", "invalid_text"},
	}
}

// TestCreateRefusesInvalidInput: every refusal is a 400 that comes before
// anything is generated or stored: no entropy is taken, no id is issued, no
// store call is made. Each field has invalid values of its own, and each
// refusal carries that field's code.
func TestCreateRefusesInvalidInput(t *testing.T) {
	t.Parallel()

	tests := slices.Concat(
		invalidTypes(), invalidNumInvites(), invalidLabels(), invalidExpiries(), invalidPrecedence(), invalidShapes())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)

			rec := harn.asAdmin(http.MethodPost, collectionPath, tt.body)

			wantError(t, harn, rec, http.StatusBadRequest, tt.code, tt.code)

			if len(harn.store.calls) != 0 || harn.entropy.taken != 0 || harn.idCalls != 0 {
				t.Errorf("a refused request did work: store %v, entropy %d bytes, %d ids",
					harn.opsCalled(), harn.entropy.taken, harn.idCalls)
			}
		})
	}
}

// TestCreateAcceptsEachCreatableType: member and admin are each accepted and
// stored under their own name.
func TestCreateAcceptsEachCreatableType(t *testing.T) {
	t.Parallel()

	for _, invitationType := range []string{auth.InvitationMember, auth.InvitationAdmin} {
		t.Run(invitationType, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)

			rec := harn.asAdmin(http.MethodPost, collectionPath, createBody(text(invitationType), "1", "", ""))

			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}

			if got := harn.store.calls[0].created.Type; got != invitationType {
				t.Errorf("stored type = %q, want %q", got, invitationType)
			}

			if _, hasRole := auth.RoleForInvitation(invitationType); !hasRole {
				t.Errorf("creatable type %q has no role, so registration would refuse it", invitationType)
			}
		})
	}
}

// validCase is a create body that must be accepted, and the invitation it
// asks for.
type validCase struct {
	name  string
	body  string
	label string
	num   int64
	// expires is the expiry the invitation must be stored and returned with:
	// the one asked for, or the default, input.ExpiryHorizon after now.
	expires int64
}

// validCreates are the shapes a create accepts, at the edge of each field.
func validCreates() []validCase {
	now := fixedNow().Unix()
	horizon := int64(input.ExpiryHorizon / time.Second)
	byDefault := now + horizon
	twoByte := strings.Repeat("é", input.MaxInvitationLabelRunes)
	fourByte := strings.Repeat("😀", input.MaxInvitationLabelRunes)

	return []validCase{
		{"only what is required, so the default expiry", typed("1", "", ""), "", 1, byDefault},
		{"empty label", typed("1", `""`, ""), "", 1, byDefault},
		{"null expiry", typed("1", "", "null"), "", 1, byDefault},
		{"every field", typed("3", text("November workshop"), secs(now+3600)), "November workshop", 3, now + 3600},
		{"most invites", typed("10000", "", ""), "", 10000, byDefault},
		{"expires one second from now", typed("1", "", secs(now+1)), "", 1, now + 1},
		{"expires at the horizon", typed("1", "", secs(now+horizon)), "", 1, now + horizon},
		{"longest label in two-byte characters", typed("1", text(twoByte), ""), twoByte, 1, byDefault},
		{"longest label in four-byte characters", typed("1", text(fourByte), ""), fourByte, 1, byDefault},
		{"label with escapes", typed("1", text(`say \"hi\" \\ \u00e9`), ""), `say "hi" \ é`, 1, byDefault},
	}
}

// stored is the invitation the store must be asked to create for this case, made
// by the same parsers the package uses, so the comparison is of parsed values.
func (tt validCase) stored(t *testing.T, creator string) store.NewInvitation {
	t.Helper()

	label, err := input.ParseInvitationLabel(tt.label)
	if err != nil {
		t.Fatalf("label: %v", err)
	}

	num, err := input.ParseNumInvites(tt.num)
	if err != nil {
		t.Fatalf("numInvites: %v", err)
	}

	expiry, err := input.ParseExpiry(tt.expires, fixedNow())
	if err != nil {
		t.Fatalf("expiresAt: %v", err)
	}

	want := store.NewInvitation{
		ID: newInvID, TokenHash: hashOf(codeOf(sequence(0, secret.BodyBytes))), Type: typeCustom,
		Label: label, NumInvites: num, ExpiresAt: expiry, CreatedBy: creator, CreatedAt: fixedNow(),
	}

	return want
}

// response is the invitation a client must be told of for this case.
func (tt validCase) response(creator string) wireInvitation {
	return wireInvitation{
		ID: newInvID, Type: typeCustom, Label: tt.label, NumInvites: tt.num, Uses: 0, Status: statusActive,
		ExpiresAt: &tt.expires, RevokedAt: nil, CreatedBy: &creator, CreatedAt: fixedNow().Unix(),
	}
}

// TestCreateStoresTheHashAndReturnsTheRow: every valid shape reaches the store
// with the parsed values, the hash of the token, the creating admin and the
// clock; the response is 201 with the row and the token (in "code").
func TestCreateStoresTheHashAndReturnsTheRow(t *testing.T) {
	t.Parallel()

	for _, tt := range validCreates() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			// Another admin than the one the other tests use: the creator is the
			// session's owner, whoever that is.
			const creator = "00000000-0000-7000-8000-0000000000cc"

			rec := harn.do(request{
				method: http.MethodPost, target: collectionPath, body: tt.body,
				cookie: harn.session(creator, auth.RoleAdmin), contentType: "",
			})

			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}

			if len(harn.store.calls) != 1 || harn.store.calls[0].op != opCreate {
				t.Fatalf("store calls = %v, want one create", harn.opsCalled())
			}

			if got := harn.store.calls[0].created; !reflect.DeepEqual(got, tt.stored(t, creator)) {
				t.Errorf("the store was asked to create %+v, want %+v", got, tt.stored(t, creator))
			}

			got := decode[wireCreated](t, rec)
			if got.Code != codeOf(sequence(0, secret.BodyBytes)) ||
				!sameInvitation(got.wireInvitation, tt.response(creator)) {
				t.Errorf("response = %+v, want %+v", got, tt.response(creator))
			}

			if harn.clock.calls != 1 {
				t.Errorf("the clock was read %d times, want once", harn.clock.calls)
			}
		})
	}
}

// TestCreateResponseIsTheWireShape pins the whole body of a create, field by
// field, as a client reads it.
func TestCreateResponseIsTheWireShape(t *testing.T) {
	t.Parallel()

	harn := newHarness(t)
	now := fixedNow().Unix()

	rec := harn.asAdmin(http.MethodPost, collectionPath,
		createBody(text(typeCustom), "3", text("November workshop"), secs(now+3600)))

	want := `{"id":"` + newInvID + `","type":"member","label":"November workshop","numInvites":3,"uses":0,` +
		`"status":"active","expiresAt":` + secs(now+3600) + `,"createdBy":"` + adminID + `","createdAt":` + secs(now) + `,` +
		`"code":"` + codeOf(sequence(0, secret.BodyBytes)) + `"}` + "\n"

	if rec.Code != http.StatusCreated || rec.Body.String() != want {
		t.Errorf("response = %d\n%s\nwant\n%s", rec.Code, rec.Body.String(), want)
	}
}

// TestCreateResponseWithoutAnExpiryHasTheDefault pins the body of a create that
// names no expiry: expiresAt is still present, ten years out.
func TestCreateResponseWithoutAnExpiryHasTheDefault(t *testing.T) {
	t.Parallel()

	harn := newHarness(t)
	now := fixedNow().Unix()

	rec := harn.asAdmin(http.MethodPost, collectionPath, typed("1", "", ""))

	want := `{"id":"` + newInvID + `","type":"member","label":"","numInvites":1,"uses":0,` +
		`"status":"active","expiresAt":` + secs(now+10*365*24*3600) + `,"createdBy":"` + adminID +
		`","createdAt":` + secs(now) + `,"code":"` + codeOf(sequence(0, secret.BodyBytes)) + `"}` + "\n"

	if rec.Code != http.StatusCreated || rec.Body.String() != want {
		t.Errorf("response = %d\n%s\nwant\n%s", rec.Code, rec.Body.String(), want)
	}
}

// TestCreateResponseIsTheStoredRow: the invitation in the response is what the
// database returned, not the request echoed, with its status derived at now.
func TestCreateResponseIsTheStoredRow(t *testing.T) {
	t.Parallel()

	now := fixedNow().Unix()
	stored := storedRow(func(r *store.Invitation) {
		r.ID, r.Type, r.Label, r.NumInvites, r.Uses = "00000000-0000-7000-8000-0000000000dd", typeOther, "from the db", 9, 9
		r.CreatedBy, r.ExpiresAt, r.CreatedAt = new("someone"), now+5, now-7
	})

	harn := newHarness(t)
	harn.store.created = &stored

	rec := harn.asAdmin(http.MethodPost, collectionPath, validCreate)

	got := decode[wireCreated](t, rec)
	want := wireInvitation{
		ID: stored.ID, Type: typeOther, Label: "from the db", NumInvites: 9, Uses: 9, Status: statusExhausted,
		ExpiresAt: new(now + 5), RevokedAt: nil, CreatedBy: new("someone"), CreatedAt: now - 7,
	}

	if rec.Code != http.StatusCreated || !sameInvitation(got.wireInvitation, want) {
		t.Errorf("response = %d %+v, want %+v", rec.Code, got.wireInvitation, want)
	}

	if got.Code != codeOf(sequence(0, secret.BodyBytes)) {
		t.Errorf("code = %q", got.Code)
	}
}

// sameInvitation compares two wire invitations by value, following pointers.
func sameInvitation(a, b wireInvitation) bool {
	return a.ID == b.ID && a.Type == b.Type && a.Label == b.Label && a.NumInvites == b.NumInvites &&
		a.Uses == b.Uses && a.Status == b.Status && a.CreatedAt == b.CreatedAt &&
		equalPtr(a.ExpiresAt, b.ExpiresAt) && equalPtr(a.RevokedAt, b.RevokedAt) && equalPtr(a.CreatedBy, b.CreatedBy)
}

func equalPtr[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}

	return *a == *b
}

// TestCreateShowsTheCodeOnce: the code is in the response exactly once, is the
// base64url of the entropy, and is nowhere in what was stored; each create gets
// its own.
func TestCreateShowsTheCodeOnce(t *testing.T) {
	t.Parallel()

	harn := newHarness(t)
	responses := []*httptest.ResponseRecorder{
		harn.asAdmin(http.MethodPost, collectionPath, validCreate),
		harn.asAdmin(http.MethodPost, collectionPath, validCreate),
	}

	codes := []string{
		codeOf(sequence(0, secret.BodyBytes)), codeOf(sequence(secret.BodyBytes, secret.BodyBytes)),
	}

	if len(codes[0]) != len(tokenPrefix)+secret.BodyLen || codes[0] == codes[1] {
		t.Fatalf("codes = %v", codes)
	}

	for i, rec := range responses {
		wantCodeOnce(t, rec, harn.store.calls[i].created, codes[i])
	}

	if harn.entropy.taken != 2*secret.BodyBytes {
		t.Errorf("took %d entropy bytes, want %d", harn.entropy.taken, 2*secret.BodyBytes)
	}
}

// wantCodeOnce checks that the response carries code exactly once, and that
// what the store was given is its hash and nothing that contains it.
func wantCodeOnce(t *testing.T, rec *httptest.ResponseRecorder, stored store.NewInvitation, code string) {
	t.Helper()

	if got := strings.Count(rec.Body.String(), code); got != 1 {
		t.Errorf("response has the code %d times, want once: %s", got, rec.Body.String())
	}

	if got := decode[wireCreated](t, rec).Code; got != code {
		t.Errorf("response code = %q, want %q", got, code)
	}

	if !bytes.Equal(stored.TokenHash, hashOf(code)) || len(stored.TokenHash) != 32 {
		t.Errorf("stored hash %x", stored.TokenHash)
	}

	if strings.Contains(fmt.Sprintf("%+v", stored), code) || bytes.Contains(stored.TokenHash, []byte(code)) {
		t.Errorf("the store was given the plaintext code: %+v", stored)
	}
}

// TestCreateTokenShape: the code is an invitation token, "susu_inv_" and 43
// base64url characters, hashed whole (prefix included) for the store, and no
// reading of the entropy beyond 32 bytes is made for it.
func TestCreateTokenShape(t *testing.T) {
	t.Parallel()

	harn := newHarness(t)

	rec := harn.asAdmin(http.MethodPost, collectionPath, validCreate)
	got := decode[wireCreated](t, rec)

	if !regexp.MustCompile(`^susu_inv_[A-Za-z0-9_-]{43}$`).MatchString(got.Code) {
		t.Errorf("code = %q, want susu_inv_ and 43 base64url characters", got.Code)
	}

	parsed, err := input.ParseInvitationToken(got.Code)
	if err != nil {
		t.Fatalf("the code does not parse as an invitation token: %v", err)
	}

	sum := secret.Hash(got.Code)
	stored := harn.store.calls[0].created.TokenHash

	if !bytes.Equal(stored, sum[:]) || !bytes.Equal(stored, parsed.Hash()) {
		t.Errorf("stored hash %x, want secret.Hash(code) %x", stored, sum)
	}

	if harn.entropy.taken != secret.BodyBytes {
		t.Errorf("took %d entropy bytes, want %d", harn.entropy.taken, secret.BodyBytes)
	}
}

// TestCreateDefaultExpiry: without expiresAt an invitation expires exactly
// input.ExpiryHorizon after the request's clock reading, counted in whole
// seconds, and that default passes the same parser as a chosen expiry for every
// fraction of a second the clock may carry. A chosen expiry at the horizon is
// accepted and one second past it is refused, whatever the fraction.
func TestCreateDefaultExpiry(t *testing.T) {
	t.Parallel()

	horizon := int64(input.ExpiryHorizon / time.Second)
	tenYears := int64(10 * 365 * 24 * 3600)

	if horizon != tenYears {
		t.Fatalf("the horizon is %d seconds, want ten years of 365 days (%d)", horizon, tenYears)
	}

	for _, fraction := range []time.Duration{0, 1, 500 * time.Millisecond, time.Second - 1} {
		t.Run(fraction.String(), func(t *testing.T) {
			t.Parallel()

			now := fixedNow().Add(fraction)
			wantExpiry := fixedNow().Unix() + tenYears

			harn := newHarness(t)
			harn.clock.now = now

			rec := harn.asAdmin(http.MethodPost, collectionPath, validCreate)
			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}

			created := harn.store.calls[0].created
			if created.ExpiresAt.Unix() != wantExpiry || created.CreatedAt != now {
				t.Errorf("stored expiry %d created %v, want %d and %v",
					created.ExpiresAt.Unix(), created.CreatedAt, wantExpiry, now)
			}

			if got := decode[wireCreated](t, rec); got.ExpiresAt == nil || *got.ExpiresAt != wantExpiry {
				t.Errorf("response expiresAt = %v, want %d", got.ExpiresAt, wantExpiry)
			}

			atHorizon := harn.asAdmin(http.MethodPost, collectionPath, typed("1", "", secs(wantExpiry)))
			pastHorizon := harn.asAdmin(http.MethodPost, collectionPath, typed("1", "", secs(wantExpiry+1)))

			if atHorizon.Code != http.StatusCreated || pastHorizon.Code != http.StatusBadRequest {
				t.Errorf("at the horizon %d, past it %d, want 201 and 400", atHorizon.Code, pastHorizon.Code)
			}
		})
	}
}

// TestCreateExpiryFollowsTheSubSecondClock: the clock's fraction counts, as the
// parser documents: an expiry equal to the current whole second is already in
// the past.
func TestCreateExpiryFollowsTheSubSecondClock(t *testing.T) {
	t.Parallel()

	now := fixedNow().Unix()

	tests := []struct {
		name    string
		expires int64
		status  int
	}{
		{"the current whole second", now, http.StatusBadRequest},
		{"the next second", now + 1, http.StatusCreated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.clock.now = fixedNow().Add(500 * time.Millisecond)

			rec := harn.asAdmin(http.MethodPost, collectionPath, createBody(text(typeCustom), "1", "", secs(tt.expires)))

			if rec.Code != tt.status {
				t.Errorf("status = %d, want %d: %s", rec.Code, tt.status, rec.Body.String())
			}
		})
	}
}

// TestCreateFailsWhenItCannotGenerateAToken: an entropy source that fails or
// gives too little is the service's failure. Nothing is stored, no id is
// issued, and the client sees a bare internal error with no cause.
func TestCreateFailsWhenItCannotGenerateAToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entropy io.Reader
		cause   error
	}{
		{"source fails", failingReader{}, errEntro},
		{"source is empty", bytes.NewReader(nil), io.EOF},
		{"source is one byte short", bytes.NewReader(sequence(0, secret.BodyBytes-1)), io.ErrUnexpectedEOF},
		{"source fails after a partial read", io.MultiReader(bytes.NewReader(sequence(0, 8)), failingReader{}), errEntro},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.deps.Entropy = tt.entropy

			rec := harn.asAdmin(http.MethodPost, collectionPath, validCreate)

			wantError(t, harn, rec, http.StatusInternalServerError, codeInternal, invitations.CodeCodeFailed)

			if !errors.Is(harn.logged[0], tt.cause) {
				t.Errorf("logged %v, want the cause %v", harn.logged[0], tt.cause)
			}

			if len(harn.store.calls) != 0 || harn.idCalls != 0 {
				t.Errorf("a failed token was stored: %v, %d ids", harn.opsCalled(), harn.idCalls)
			}
		})
	}
}

// TestCreateFailsWhenTheStoreDoes: the store's failure is the response and the
// code that was generated is not in it, since there is no invitation for it.
func TestCreateFailsWhenTheStoreDoes(t *testing.T) {
	t.Parallel()

	failures := append(storeFailures(store.CodeInvitationCreateFailed, store.CodeInvitationCreateRejected),
		storeFailure{
			// The store reports a collision as a defect, never as a conflict, so
			// a bare conflict reaching the route is unclassified and not a 409.
			"an unclassified conflict", store.ErrConflict, http.StatusInternalServerError, codeInternal, codeInternal,
		})

	for _, tt := range failures {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			harn := newHarness(t)
			harn.store.err = tt.err

			rec := harn.asAdmin(http.MethodPost, collectionPath, validCreate)

			wantError(t, harn, rec, tt.status, tt.wireCode, tt.logCode)

			if code := codeOf(sequence(0, secret.BodyBytes)); strings.Contains(rec.Body.String(), code) {
				t.Errorf("a failed create returned its token: %s", rec.Body.String())
			}
		})
	}
}
