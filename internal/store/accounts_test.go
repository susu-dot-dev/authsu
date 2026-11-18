//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package store_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/store"
)

const (
	registrationDescription = "registration is temporarily unavailable"
	aaguid                  = "00000000-0000-0000-0000-000000000000"
)

// TestRedeemableInvitationType holds how the invitation lookup is read: the type
// when the code is redeemable, nothing otherwise.
func TestRedeemableInvitationType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		rows  [][]any
		want  string
		found bool
	}{
		{name: "a member invitation", rows: [][]any{row("member")}, want: "member", found: true},
		{name: "the first-run invitation", rows: [][]any{row(store.InvitationFirstRun)}, want: "first_run", found: true},
		{name: "unknown, spent, revoked or expired", rows: nil},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(test.rows...))

			got, found, err := fake.store().RedeemableInvitationType(context.Background(), mustCode(t, "code-1"), now)

			checkErr(t, err, nil)

			if got != test.want || found != test.found {
				t.Errorf("got %q, %v; want %q, %v", got, found, test.want, test.found)
			}
		})
	}
}

// TestRedeemableInvitationTypeDefects holds that a result that is not one text
// column of one row is a defect and never "redeemable".
func TestRedeemableInvitationTypeDefects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rows [][]any
	}{
		{name: "two rows", rows: [][]any{row("a"), row("b")}},
		{name: "type is NULL", rows: [][]any{row(nil)}},
		{name: "type is an integer", rows: [][]any{row(int64(1))}},
		{name: "type is a blob", rows: [][]any{row([]byte("member"))}},
		{name: "a column too many", rows: [][]any{row("member", "extra")}},
		{name: "an empty row", rows: [][]any{row()}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(test.rows...))

			got, found, err := fake.store().RedeemableInvitationType(context.Background(), mustCode(t, "code-1"), now)

			checkErr(t, err, defectOf(store.CodeInvitationCheckRejected))

			if got != "" || found {
				t.Errorf("a defective row returned %q, %v", got, found)
			}
		})
	}
}

// TestRedeemableInvitationTypeStatement pins the conditions that make a code
// redeemable and the arguments in placeholder order. The code is looked up by
// its hash, and the first-run type is an argument.
func TestRedeemableInvitationTypeStatement(t *testing.T) {
	t.Parallel()

	fake := newFake(returning())
	code := mustCode(t, "code-1")

	_, _, err := fake.store().RedeemableInvitationType(context.Background(), code, now)
	checkErr(t, err, nil)

	checkStatements(t, fake, wantStatement{
		fragments: []string{
			"SELECT i.type AS type FROM invitations i",
			"WHERE i.code_hash = ?",
			"AND i.revoked_at IS NULL",
			"AND (i.expires_at IS NULL OR i.expires_at > ?)",
			"AND (SELECT count(*) FROM users u WHERE u.invitation_id = i.id) < i.num_invites",
			"AND (i.type <> ? OR NOT EXISTS (SELECT 1 FROM users))",
		},
		args: []any{code.Hash(), now.Unix(), store.InvitationFirstRun},
	})
}

// TestRedeemableInvitationTypeFailures holds how a failed batch is reported.
func TestRedeemableInvitationTypeFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 1, store.CodeInvitationCheckFailed, store.CodeInvitationCheckRejected, registrationDescription,
		func(s *store.Store) error {
			return lastErr2(s.RedeemableInvitationType(context.Background(), mustCode(t, "code-1"), now))
		})
}

// newAccount returns a complete account to create; a test overrides what it is
// about.
func newAccount(t *testing.T, edit func(*store.NewAccount)) store.NewAccount {
	t.Helper()

	account := store.NewAccount{
		UserID: "user-1", UserHandle: []byte{1, 2, 3}, Role: "admin", Name: mustName(t, "Ann"),
		Code: mustCode(t, "code-1"), InvitationType: "member",
		CredentialRowID: "cred-row-1", CredentialID: []byte{4, 5}, PublicKey: []byte{6, 7, 8}, Flags: 0x45,
		AAGUID: aaguid, Transports: []string{"usb"}, CreatedAt: now,
	}

	if edit != nil {
		edit(&account)
	}

	return account
}

// metadataOf is the credentials.metadata the store writes for transports.
func metadataOf(transports string) string {
	return `{"fmt":"none","aaguid":"` + aaguid + `","transports":` + transports + `}`
}

// TestCreateAccountStatements pins the batch registration writes: the user
// insert carrying the invitation's conditions, then the credential insert
// that fails the batch when the first matched nothing; the JSON columns the
// store builds; and every argument in placeholder order.
//
//nolint:funlen // the case table is the test; splitting it would only scatter the cases
func TestCreateAccountStatements(t *testing.T) {
	t.Parallel()

	userFragments := []string{
		"INSERT INTO users (id, user_handle, role, invitation_id, profile, created_at)",
		"SELECT ?, ?, ?, i.id, ?, ? FROM invitations i",
		"WHERE i.code_hash = ?",
		"AND i.type = ?",
		"AND i.revoked_at IS NULL",
		"AND (i.expires_at IS NULL OR i.expires_at > ?)",
		"AND (SELECT count(*) FROM users u WHERE u.invitation_id = i.id) < i.num_invites",
		"AND (i.type <> ? OR NOT EXISTS (SELECT 1 FROM users))",
	}
	credentialFragments := []string{
		"INSERT INTO credentials (id, credential_id, user_id, public_key, flags, metadata, created_at)",
		"(SELECT id FROM users WHERE user_handle = ?)",
	}

	tests := []struct {
		name     string
		edit     func(*store.NewAccount)
		profile  string
		metadata string
	}{
		{name: "a member with one transport", profile: `{"name":"Ann"}`, metadata: metadataOf(`["usb"]`)},
		{name: "no transports reported is an empty array",
			edit:    func(a *store.NewAccount) { a.Transports = nil },
			profile: `{"name":"Ann"}`, metadata: metadataOf(`[]`)},
		{name: "an empty transport list is an empty array",
			edit:    func(a *store.NewAccount) { a.Transports = []string{} },
			profile: `{"name":"Ann"}`, metadata: metadataOf(`[]`)},
		{name: "several transports keep their order",
			edit:    func(a *store.NewAccount) { a.Transports = []string{"nfc", "ble", "usb"} },
			profile: `{"name":"Ann"}`, metadata: metadataOf(`["nfc","ble","usb"]`)},
		{name: "the name is escaped as JSON",
			edit:    func(a *store.NewAccount) { a.Name = mustName(t, `Ann "<&>" \ O'Neil`) },
			profile: `{"name":"Ann \"\u003c\u0026\u003e\" \\ O'Neil"}`, metadata: metadataOf(`["usb"]`)},
		{name: "a non-ASCII name is kept",
			edit:    func(a *store.NewAccount) { a.Name = mustName(t, "Zoë Ångström") },
			profile: `{"name":"Zoë Ångström"}`, metadata: metadataOf(`["usb"]`)},
		{name: "the first-run type is bound apart from the redeemed type",
			edit:    func(a *store.NewAccount) { a.InvitationType = store.InvitationFirstRun },
			profile: `{"name":"Ann"}`, metadata: metadataOf(`["usb"]`)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			account := newAccount(t, test.edit)
			fake := newFake(applied(2))

			checkErr(t, fake.store().CreateAccount(context.Background(), account), nil)

			created := now.Unix()

			checkStatements(t, fake,
				wantStatement{
					fragments: userFragments,
					args: []any{
						"user-1", []byte{1, 2, 3}, "admin", test.profile, created,
						account.Code.Hash(), account.InvitationType, created, store.InvitationFirstRun,
					},
				},
				wantStatement{
					fragments: credentialFragments,
					args: []any{
						"cred-row-1", []byte{4, 5}, []byte{1, 2, 3}, []byte{6, 7, 8},
						int64(0x45), test.metadata, created,
					},
				},
			)
		})
	}
}

// errEncoder is the failure of the broken JSON encoder.
var errEncoder = errors.New("encoder is broken")

// TestCreateAccountEncodingFailure holds that a JSON column that cannot be
// encoded is a defect and that nothing is written.
func TestCreateAccountEncodingFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		failAt int
	}{
		{name: "the profile", failAt: 1},
		{name: "the credential metadata", failAt: 2},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(applied(2))
			calls := 0

			s := store.NewWithMarshal(fake.exec, func(_ any) ([]byte, error) {
				calls++
				if calls == test.failAt {
					return nil, errEncoder
				}

				return []byte("{}"), nil
			})

			err := s.CreateAccount(context.Background(), newAccount(t, nil))

			checkErr(t, err, defectOf(store.CodeRegistrationAcceptRejected))

			if !errors.Is(err, errEncoder) {
				t.Errorf("error %v lost its cause", err)
			}

			if len(fake.calls) != 0 {
				t.Errorf("exec called %d times after an encoding failure", len(fake.calls))
			}
		})
	}
}

// TestCreateAccountFailures holds that an exhausted invitation, a replay and a
// taken credential (all conflicts) and every other failure come back as
// classified.
func TestCreateAccountFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 2, store.CodeRegistrationAcceptFailed, store.CodeRegistrationAcceptRejected, registrationDescription,
		func(s *store.Store) error { return passErr(s.CreateAccount(context.Background(), newAccount(t, nil))) })
}

// credentialRow is the row CredentialByID reads: id, user_id, public_key,
// flags, user_handle, role.
func credentialRow() []any {
	return row("cred-row-1", "user-1", []byte{1, 2, 3}, int64(0x45), []byte{9, 9}, "member")
}

// TestCredentialByID holds how a passkey row is read, including both ends of the
// flags byte and that no row is an answer and not an error.
func TestCredentialByID(t *testing.T) {
	t.Parallel()

	full := store.Credential{
		ID: "cred-row-1", UserID: "user-1", PublicKey: []byte{1, 2, 3}, Flags: 0x45, UserHandle: []byte{9, 9}, Role: "member",
	}
	flagged := func(flags uint8) store.Credential {
		c := full
		c.Flags = flags

		return c
	}

	tests := []struct {
		name  string
		rows  [][]any
		want  store.Credential
		found bool
	}{
		{name: "a passkey", rows: [][]any{credentialRow()}, want: full, found: true},
		{name: "flags none", rows: [][]any{with(credentialRow(), 3, int64(0))}, want: flagged(0), found: true},
		{name: "flags all", rows: [][]any{with(credentialRow(), 3, int64(255))}, want: flagged(255), found: true},
		{name: "unknown, or its account is revoked", rows: nil},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(test.rows...))

			got, found, err := fake.store().CredentialByID(context.Background(), []byte{4, 5, 6})

			checkErr(t, err, nil)

			if found != test.found || !reflect.DeepEqual(got, test.want) {
				t.Errorf("got %+v, %v; want %+v, %v", got, found, test.want, test.found)
			}
		})
	}
}

// TestCredentialByIDDefects holds that a result that is not the passkey row the
// query promises is a defect: flags outside a byte, a wrong type, NULL in a NOT
// NULL column, or the wrong shape.
func TestCredentialByIDDefects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rows [][]any
	}{
		{name: "two rows", rows: [][]any{credentialRow(), credentialRow()}},
		{name: "flags above a byte", rows: [][]any{with(credentialRow(), 3, int64(256))}},
		{name: "flags negative", rows: [][]any{with(credentialRow(), 3, int64(-1))}},
		{name: "flags a float", rows: [][]any{with(credentialRow(), 3, float64(5))}},
		{name: "id is NULL", rows: [][]any{with(credentialRow(), 0, nil)}},
		{name: "user id is a blob", rows: [][]any{with(credentialRow(), 1, []byte("u"))}},
		{name: "public key is text", rows: [][]any{with(credentialRow(), 2, "key")}},
		{name: "public key is NULL", rows: [][]any{with(credentialRow(), 2, nil)}},
		{name: "user handle is text", rows: [][]any{with(credentialRow(), 4, "handle")}},
		{name: "user handle is NULL", rows: [][]any{with(credentialRow(), 4, nil)}},
		{name: "role is an integer", rows: [][]any{with(credentialRow(), 5, int64(1))}},
		{name: "a column too few", rows: [][]any{credentialRow()[:5]}},
		{name: "a column too many", rows: [][]any{append(credentialRow(), "x")}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(test.rows...))

			got, found, err := fake.store().CredentialByID(context.Background(), []byte{4, 5, 6})

			checkErr(t, err, defectOf(store.CodeCredentialLookupRejected))

			if found || got.ID != "" {
				t.Errorf("a defective row returned %+v, %v", got, found)
			}
		})
	}
}

// TestCredentialByIDStatement pins that the lookup is by the authenticator's
// credential id and refuses a revoked account's passkey.
func TestCredentialByIDStatement(t *testing.T) {
	t.Parallel()

	fake := newFake(returning())

	_, _, err := fake.store().CredentialByID(context.Background(), []byte{4, 5, 6})
	checkErr(t, err, nil)

	checkStatements(t, fake, wantStatement{
		fragments: []string{
			"FROM credentials c JOIN users u ON u.id = c.user_id",
			"WHERE c.credential_id = ?",
			"AND u.revoked_at IS NULL",
			"c.id AS id", "c.user_id AS user_id", "u.user_handle AS user_handle", "u.role AS role",
		},
		args: []any{[]byte{4, 5, 6}},
	})
}

// TestCredentialByIDFailures holds how a failed batch is reported.
func TestCredentialByIDFailures(t *testing.T) {
	t.Parallel()

	runFailures(t, 1, store.CodeCredentialLookupFailed, store.CodeCredentialLookupRejected, loginDescription,
		func(s *store.Store) error { return lastErr2(s.CredentialByID(context.Background(), []byte{1})) })
}

// TestAccountCodes pins the wire codes the operations report.
func TestAccountCodes(t *testing.T) {
	t.Parallel()

	tests := []struct{ got, want string }{
		{store.CodeInvitationCheckFailed, "registration_invitation_check_failed"},
		{store.CodeInvitationCheckRejected, "registration_invitation_check_rejected"},
		{store.CodeRegistrationAcceptFailed, "registration_accept_failed"},
		{store.CodeRegistrationAcceptRejected, "registration_accept_rejected"},
		{store.CodeCredentialLookupFailed, "login_credential_lookup_failed"},
		{store.CodeCredentialLookupRejected, "login_credential_lookup_rejected"},
	}

	for _, test := range tests {
		if test.got != test.want {
			t.Errorf("code %q, want %q", test.got, test.want)
		}
	}
}
