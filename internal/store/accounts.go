package store

import (
	"context"
	"fmt"
	"time"

	"github.com/susu-dot-dev/authsu/internal/input"
)

// Error codes of the account operations. They are stable: clients and
// dashboards may match on them.
const (
	CodeInvitationCheckFailed      = "registration_invitation_check_failed"
	CodeInvitationCheckRejected    = "registration_invitation_check_rejected"
	CodeRegistrationAcceptFailed   = "registration_accept_failed"
	CodeRegistrationAcceptRejected = "registration_accept_rejected"
	CodeCredentialLookupFailed     = "login_credential_lookup_failed"   //nolint:gosec // an error code, not a credential
	CodeCredentialLookupRejected   = "login_credential_lookup_rejected" //nolint:gosec // an error code, not a credential
)

// invitationQuery looks up an invitation for begin and finish. It is a plain
// read: begin uses it as an advisory check, and finish uses it to learn the
// invitation's type so Go can choose the role. Neither relies on it for
// authorisation; insertUserQuery re-checks everything in the write.
//
// The invitation is found by the hash of its token and its kind, through its
// secret, and it is returned only when the secret is active
// (activeSecretPredicate), it is under its cap and, for first run, no account
// exists yet. Otherwise there is no row. The join to invitations is on the id
// and the kind together, as the schema's foreign key is.
//
// Arguments, in order: hash, kind, now, now (unix seconds), first-run type.
const invitationQuery = `
SELECT i.type AS type
FROM secrets s
JOIN invitations i ON i.id = s.id AND i.kind = s.kind
WHERE s.hash = ?
  AND s.kind = ?
  AND ` + activeSecretPredicate + `
  AND (SELECT count(*) FROM users u WHERE u.invitation_id = i.id) < i.num_invites
  AND (i.type <> ? OR NOT EXISTS (SELECT 1 FROM users))`

// RedeemableInvitationType returns the type of the invitation the token names
// when it is redeemable at now: not revoked, not expired, under its cap and, for
// the first-run type, while no account exists. It reports false otherwise, so an
// unknown, spent, revoked or expired token are indistinguishable.
//
// It is advisory: CreateAccount re-checks every condition in its write.
func (s *Store) RedeemableInvitationType(
	ctx context.Context, token input.InvitationToken, now time.Time,
) (string, bool, error) {
	o := op{failed: CodeInvitationCheckFailed, rejected: CodeInvitationCheckRejected,
		description: "registration is temporarily unavailable"}

	unix := now.Unix()

	return find(ctx, s, o,
		Statement{Query: invitationQuery, Args: []any{token.Hash(), KindInvitation, unix, unix, InvitationFirstRun}},
		func(r *row) string { return r.text() })
}

// insertUserQuery creates the account, and is the point of acceptance. Its
// authorisation checks are conditions of the insert itself, so the database
// serialises them: two people finishing at once on a single-use token, or two
// browsers racing to become the first admin, cannot both pass.
//
// The invitation is matched as invitationQuery matches it (hash, kind, active
// secret, cap, first-run rule), with one more condition: it must still have the
// type the caller read. The role is chosen by Go from that type and bound as a
// value, so a type that changed between the read and the write cannot get a role
// chosen for a different one. The client supplies neither.
//
// If no invitation satisfies the conditions the insert matches nothing. A
// conditional insert that matches nothing is not an error, so on its own it
// would not roll the batch back; insertCredentialQuery's required reference to
// the new user is what turns it into a failure.
//
// Arguments, in order: id, user_handle, role, profile, created_at, hash, kind,
// type, now, now (unix seconds), first-run type.
const insertUserQuery = `
INSERT INTO users (id, user_handle, role, invitation_id, profile, created_at)
SELECT ?, ?, ?, i.id, ?, ?
FROM secrets s
JOIN invitations i ON i.id = s.id AND i.kind = s.kind
WHERE s.hash = ?
  AND s.kind = ?
  AND i.type = ?
  AND ` + activeSecretPredicate + `
  AND (SELECT count(*) FROM users u WHERE u.invitation_id = i.id) < i.num_invites
  AND (i.type <> ? OR NOT EXISTS (SELECT 1 FROM users))`

// insertCredentialQuery stores the passkey for the user insertUserQuery just
// created, found by its unique user handle. user_id is NOT NULL and references
// users, so when the user insert matched nothing the subselect is NULL and this
// statement fails, which rolls back the whole batch.
//
// Arguments, in order: id, credential_id, user_handle, public_key, flags,
// metadata, created_at.
//
//nolint:gosec // SQL naming the credentials table, not a credential
const insertCredentialQuery = `
INSERT INTO credentials (id, credential_id, user_id, public_key, flags, metadata, created_at)
VALUES (?, ?, (SELECT id FROM users WHERE user_handle = ?), ?, ?, ?, ?)`

// profile is users.profile.
type profile struct {
	Name string `json:"name"`
}

// credentialMetadata is credentials.metadata: what is written once at
// registration and not needed to authenticate.
type credentialMetadata struct {
	Format     string   `json:"fmt"`
	AAGUID     string   `json:"aaguid"`
	Transports []string `json:"transports"`
}

// attestationFormat is the only attestation registration accepts.
const attestationFormat = "none"

// NewAccount is an account and its first passkey, as registration finishes.
type NewAccount struct {
	// UserID is the new account's id.
	UserID string

	// UserHandle is the WebAuthn user handle, unique per account.
	UserHandle []byte

	// Role is the account's role, chosen from the invitation's type.
	Role string

	// Name is the display name the registrant gave.
	Name input.AccountName

	// Token is the invitation being redeemed, and InvitationType the type the
	// caller read for it with RedeemableInvitationType: the write refuses an
	// invitation that no longer has that type.
	Token          input.InvitationToken
	InvitationType string

	// CredentialRowID is the passkey's row id. CredentialID, PublicKey, Flags,
	// AAGUID (in its canonical text form) and Transports are what the
	// authenticator reported.
	CredentialRowID string
	CredentialID    []byte
	PublicKey       []byte
	Flags           uint8
	AAGUID          string
	Transports      []string

	// CreatedAt is when the account is created, and the time the invitation's
	// expiry is checked against.
	CreatedAt time.Time
}

// CreateAccount creates the account and its passkey in one batch, with the
// invitation's conditions in the write itself (see insertUserQuery).
//
// It returns ErrConflict when the registration cannot stand: the invitation
// was used up, revoked, expired or is not of the type the caller read, the
// first-run invitation met an existing account, or this registration (its
// handle, credential or public key) was already submitted.
func (s *Store) CreateAccount(ctx context.Context, account NewAccount) error {
	o := op{failed: CodeRegistrationAcceptFailed, rejected: CodeRegistrationAcceptRejected,
		description: "registration is temporarily unavailable"}

	// The store owns these columns, so it owns their JSON. A nil transport list
	// is written as [] so the column always holds an array.
	transports := account.Transports
	if transports == nil {
		transports = []string{}
	}

	profileJSON, err := s.marshal(profile{Name: account.Name.String()})
	if err != nil {
		return o.defect(fmt.Errorf("encode profile: %w", err))
	}

	metadataJSON, err := s.marshal(credentialMetadata{
		Format:     attestationFormat,
		AAGUID:     account.AAGUID,
		Transports: transports,
	})
	if err != nil {
		return o.defect(fmt.Errorf("encode credential metadata: %w", err))
	}

	created := account.CreatedAt.Unix()

	_, err = s.run(ctx, o,
		Statement{Query: insertUserQuery, Args: []any{
			account.UserID, account.UserHandle, account.Role, string(profileJSON), created,
			account.Token.Hash(), KindInvitation, account.InvitationType, created, created, InvitationFirstRun,
		}},
		Statement{Query: insertCredentialQuery, Args: []any{
			account.CredentialRowID, account.CredentialID, account.UserHandle, account.PublicKey,
			int64(account.Flags), string(metadataJSON), created,
		}},
	)

	return err
}

// credentialQuery finds the credential an assertion names, joined to its
// account: the key to verify the signature with, the stored flags that
// backup eligibility is checked against, and the user handle the response must
// echo. credential_id is unique, so this is one primary-key-like read.
//
// A credential of a revoked account is not found: login refuses it exactly as
// it refuses an unknown credential, so the response does not say the account
// exists or was revoked.
//
// Arguments: credential_id.
//
//nolint:gosec // SQL naming the credentials table, not a credential
const credentialQuery = `
SELECT c.id AS id, c.user_id AS user_id, c.public_key AS public_key, c.flags AS flags,
       u.user_handle AS user_handle, u.role AS role
FROM credentials c
JOIN users u ON u.id = c.user_id
WHERE c.credential_id = ?
  AND u.revoked_at IS NULL`

// Credential is a passkey with what login needs of its account.
type Credential struct {
	// ID is the credential's row id.
	ID string

	// UserID is the owning account.
	UserID string

	// PublicKey is the COSE key the assertion's signature is verified with.
	PublicKey []byte

	// Flags are the stored credential flags.
	Flags uint8

	// UserHandle is the account's WebAuthn user handle, which the assertion must
	// echo.
	UserHandle []byte

	// Role is the account's role.
	Role string
}

// CredentialByID finds the passkey the authenticator's credential id names. It
// reports false when there is none, or when its account is revoked: a revoked
// account's passkey is indistinguishable from an unknown one.
func (s *Store) CredentialByID(ctx context.Context, credentialID []byte) (Credential, bool, error) {
	o := op{failed: CodeCredentialLookupFailed, rejected: CodeCredentialLookupRejected,
		description: "login is temporarily unavailable"}

	return find(ctx, s, o, Statement{Query: credentialQuery, Args: []any{credentialID}},
		func(r *row) Credential {
			// Struct fields are evaluated in order, which is the column order.
			return Credential{
				ID: r.text(), UserID: r.text(), PublicKey: r.blob(), Flags: r.octet(),
				UserHandle: r.blob(), Role: r.text(),
			}
		})
}
