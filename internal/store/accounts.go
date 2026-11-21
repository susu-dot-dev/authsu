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
// authorisation; CreateAccount's write re-checks everything.
//
// An invitation is found by the hash of its token and its kind, through its
// secret, and it is returned only when the secret is active
// (activeSecretPredicate), it is under its cap and, for first run, no account
// exists yet. Otherwise there is no row. The join to invitations is on the id
// and the kind together, as the schema's foreign key is.
//
// The first-run invitation need not be stored yet: the registration that
// redeems it creates it (see insertFirstRunSecretQuery). So the query also finds
// the first-run type for a token that is the configured first-run secret while
// the database has no invitation and no account, which is exactly when that
// write creates it. The configured secret's hash is NULL when none is
// configured, and a comparison with NULL never holds, so then only a stored
// invitation is found.
//
// Arguments, in order: hash, kind, now, now (unix seconds), first-run type,
// first-run type, hash, configured first-run hash.
const invitationQuery = `
SELECT type FROM (
  SELECT i.type AS type
  FROM secrets s
  JOIN invitations i ON i.id = s.id AND i.kind = s.kind
  WHERE s.hash = ?
    AND s.kind = ?
    AND ` + activeSecretPredicate + `
    AND (SELECT count(*) FROM users u WHERE u.invitation_id = i.id) < i.num_invites
    AND (i.type <> ? OR NOT EXISTS (SELECT 1 FROM users))
  UNION ALL
  SELECT ? AS type
  WHERE ? = ?
    AND NOT EXISTS (SELECT 1 FROM invitations)
    AND NOT EXISTS (SELECT 1 FROM users)
)`

// RedeemableInvitationType returns the type of the invitation the token names
// when it is redeemable at now: not revoked, not expired, under its cap and, for
// the first-run type, while no account exists. It reports false otherwise, so an
// unknown, spent, revoked or expired token are indistinguishable.
//
// firstRun is the configured first-run token, or nil when none is configured. A
// token equal to it is redeemable as the first-run invitation while the
// database has no invitation and no account, though no invitation is stored
// yet: CreateAccount creates it.
//
// It is advisory: CreateAccount re-checks every condition in its write.
func (s *Store) RedeemableInvitationType(
	ctx context.Context, token input.InvitationToken, firstRun *input.InvitationToken, now time.Time,
) (string, bool, error) {
	o := op{failed: CodeInvitationCheckFailed, rejected: CodeInvitationCheckRejected,
		description: "registration is temporarily unavailable"}

	unix := now.Unix()

	return find(ctx, s, o,
		Statement{Query: invitationQuery, Args: []any{
			token.Hash(), KindInvitation, unix, unix, InvitationFirstRun,
			InvitationFirstRun, token.Hash(), configuredHash(firstRun),
		}},
		func(r *row) string { return r.text() })
}

// configuredHash is the hash of the configured first-run token, or nil (SQL
// NULL, which equals nothing) when none is configured.
func configuredHash(firstRun *input.InvitationToken) any {
	if firstRun == nil {
		return nil
	}

	return firstRun.Hash()
}

// insertFirstRunSecretQuery is the first statement of CreateAccount's batch: it
// writes the secret of the first-run invitation, but only when the registering
// token is the configured first-run secret and the database has no invitation
// and no account at all.
//
// The conditions are part of the insert itself, so two registrations racing to
// become the first admin cannot both create it: D1 runs a batch to its end
// before the next one starts, so the second sees the first's invitation and
// inserts nothing. When the conditions do not hold it inserts nothing, which is
// the normal case of every registration after the first.
//
// Secrets of other kinds do not matter to the condition. Sessions and API keys
// exist only for accounts, so while there is no account there are none, and a
// secret of any kind never makes an invitation exist. What this insert must not
// do is leave a secret behind without its invitation, which the next statement
// prevents (see insertFirstRunInvitationQuery).
//
// Arguments, in order: id, kind, hash, expires_at, created_at, hash,
// configured first-run hash.
//
//nolint:gosec // SQL naming the secrets table, not a credential
const insertFirstRunSecretQuery = `
INSERT INTO secrets (id, kind, hash, expires_at, created_at)
SELECT ?, ?, ?, ?, ?
WHERE ? = ?
  AND NOT EXISTS (SELECT 1 FROM invitations)
  AND NOT EXISTS (SELECT 1 FROM users)`

// insertFirstRunInvitationQuery is the second statement of CreateAccount's
// batch: the invitation's own row, written only if the statement before it
// wrote this call's secret. The id is fresh for every call, so a secret with
// this id and kind exists only if the previous statement of this batch inserted
// it, and no other caller's secret can satisfy the condition. The two inserts
// therefore stand or fall together: when the conditions refused the secret
// there is nothing for the invitation to attach to and it is not written, and
// when the secret was written the invitation is, in the same transaction.
//
// created_by is NULL: no account created it. num_invites is 1.
//
// Arguments, in order: id, kind, type, label, the secret's id, the secret's
// kind.
const insertFirstRunInvitationQuery = `
INSERT INTO invitations (id, kind, type, label, num_invites)
SELECT ?, ?, ?, ?, 1
WHERE EXISTS (SELECT 1 FROM secrets WHERE id = ? AND kind = ?)`

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
// The user joins the organization the invitation offers, if it offers one and
// that organization is standard and unrevoked AT THIS WRITE (org_id is a
// subselect, NULL when there is no offer or it fails the condition). The
// organization is a side effect of registration and never a condition of it
// (docs/orgs_design.md, principle 2): a revoked organization leaves org_id NULL
// and the account is created without one. Revoking an organization releases
// its members in a batch of its own, which runs either before this write, when
// the condition fails, or after it, when it finds this user a member and
// releases them, so nobody is left in an organization that no longer works. The
// offer is not consumed: an invitation that admits several people offers the
// organization to each.
//
// If no invitation satisfies the conditions the insert matches nothing. A
// conditional insert that matches nothing is not an error, so on its own it
// would not roll the batch back; insertCredentialQuery's required reference to
// the new user is what turns it into a failure.
//
// Arguments, in order: id, user_handle, role, profile, created_at, organization
// kind, hash, kind, type, now, now (unix seconds), first-run type.
const insertUserQuery = `
INSERT INTO users (id, user_handle, role, invitation_id, profile, created_at, org_id)
SELECT ?, ?, ?, i.id, ?, ?,
       (SELECT o.org_id FROM org_offers o
        JOIN orgs g ON g.id = o.org_id AND g.kind = o.kind
        WHERE o.invitation_id = i.id AND g.kind = ? AND g.revoked_at IS NULL)
FROM secrets s
JOIN invitations i ON i.id = s.id AND i.kind = s.kind
WHERE s.hash = ?
  AND s.kind = ?
  AND i.type = ?
  AND ` + activeSecretPredicate + `
  AND (SELECT count(*) FROM users u WHERE u.invitation_id = i.id) < i.num_invites
  AND (i.type <> ? OR NOT EXISTS (SELECT 1 FROM users))`

// insertOrgAdminQuery is the statement after insertUserQuery: it makes the new
// user an administrator of the organization they joined, when the invitation's
// offer says they join as one. Which organization is not decided again here: it
// is the user's own org_id as the previous statement left it, and it counts only
// if it is the organization of the invitation's offer, the offer's role is the
// administrator's and the organization is still standard and unrevoked. So an
// administrator row exists only for a user who really got that organization:
// a registration whose user insert matched nothing, or whose organization was
// revoked (so org_id is NULL), inserts nothing, and never leaves an
// administrator of an organization they are not in.
//
// The user is matched by id, which is fresh for every call. The invitation is
// the user's own (users.invitation_id), so no other invitation's offer can
// apply.
//
// Arguments, in order: created_at, user id, organization kind, role.
const insertOrgAdminQuery = `
INSERT INTO org_admins (org_id, user_id, created_at)
SELECT u.org_id, u.id, ?
FROM users u
JOIN org_offers o ON o.invitation_id = u.invitation_id AND o.org_id = u.org_id
JOIN orgs g ON g.id = o.org_id AND g.kind = o.kind
WHERE u.id = ?
  AND g.kind = ?
  AND g.revoked_at IS NULL
  AND o.role = ?`

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

// profile is users.profile. Its worst-case size is checked against the
// column's CHECK by schema_test.go.
type profile struct {
	Name  string `json:"name"`
	Email string `json:"email"`
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

	// Email is the email address the registrant gave. It is stored in the
	// profile beside the name.
	Email input.Email

	// Token is the invitation being redeemed, and InvitationType the type the
	// caller read for it with RedeemableInvitationType: the write refuses an
	// invitation that no longer has that type.
	Token          input.InvitationToken
	InvitationType string

	// FirstRun is the configured first-run token, or nil when none is
	// configured. When Token equals it and no invitation or account exists, the
	// write creates the first-run invitation (expiring at FirstRunExpiresAt,
	// labelled FirstRunLabel, with the id FirstRunID) before redeeming it.
	FirstRun          *input.InvitationToken
	FirstRunID        string
	FirstRunLabel     string
	FirstRunExpiresAt time.Time

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
// invitation's conditions in the write itself (see insertUserQuery). When the
// invitation carries an offer to join an organization, the account joins it in
// the same batch, as an administrator too when the offer says so (see
// insertOrgAdminQuery); registration never fails because of the organization.
//
// The batch starts with the first-run invitation's two inserts, which take
// effect only for the configured first-run secret on an empty database (see
// insertFirstRunSecretQuery). They are what lets the first admin register
// without anything having created the invitation beforehand, and they are in
// the same batch as the user insert so the invitation exists exactly when its
// account does: if the user insert matches nothing, the credential insert
// fails and the whole batch, the invitation included, rolls back.
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

	profileJSON, err := s.marshal(profile{Name: account.Name.String(), Email: account.Email.String()})
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
		Statement{Query: insertFirstRunSecretQuery, Args: []any{
			account.FirstRunID, KindInvitation, account.Token.Hash(), account.FirstRunExpiresAt.Unix(), created,
			account.Token.Hash(), configuredHash(account.FirstRun),
		}},
		Statement{Query: insertFirstRunInvitationQuery, Args: []any{
			account.FirstRunID, KindInvitation, InvitationFirstRun, account.FirstRunLabel,
			account.FirstRunID, KindInvitation,
		}},
		Statement{Query: insertUserQuery, Args: []any{
			account.UserID, account.UserHandle, account.Role, string(profileJSON), created, OrgKindStandard,
			account.Token.Hash(), KindInvitation, account.InvitationType, created, created, InvitationFirstRun,
		}},
		Statement{Query: insertOrgAdminQuery, Args: []any{created, account.UserID, OrgKindStandard, OfferRoleAdmin}},
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
