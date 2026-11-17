package login

// credentialQuery finds the credential an assertion names, joined to its
// account: the key to verify the signature with, the stored flags that
// backup eligibility is checked against, and the user handle the response must
// echo. credential_id is unique, so this is one primary-key-like read.
//
// Arguments: credential_id.
//
//nolint:gosec // SQL naming the credentials table, not a credential
const credentialQuery = `
SELECT c.id, c.user_id, c.public_key, c.flags, u.user_handle, u.role
FROM credentials c
JOIN users u ON u.id = c.user_id
WHERE c.credential_id = ?`

// updateFlagsQuery stores the flags an accepted assertion reported. Backup
// state and the verified bit legitimately change over a credential's life, and
// the schema comment on credentials.flags says they are updated on login. It
// runs in the same batch as the session insert, so a replayed login that is
// refused updates nothing.
//
// Arguments: flags, credential row id.
const updateFlagsQuery = `UPDATE credentials SET flags = ? WHERE id = ?`
