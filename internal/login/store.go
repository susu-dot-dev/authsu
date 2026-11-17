package login

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// SQLReader is the Reader backed by a *sql.DB.
type SQLReader struct {
	db *sql.DB
}

// NewSQLReader returns a Reader over db.
func NewSQLReader(db *sql.DB) *SQLReader {
	return &SQLReader{db: db}
}

// CredentialByID implements Reader.
func (r *SQLReader) CredentialByID(ctx context.Context, credentialID []byte) (Credential, bool, error) {
	var (
		cred  Credential
		flags int64
	)

	err := r.db.QueryRowContext(ctx, credentialQuery, credentialID).
		Scan(&cred.ID, &cred.UserID, &cred.PublicKey, &flags, &cred.UserHandle, &cred.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, false, nil
	}

	if err != nil {
		return Credential{}, false, fmt.Errorf("query credential: %w", err)
	}

	// The schema's CHECK keeps flags within a byte, so this cannot truncate.
	cred.Flags = uint8(flags) //nolint:gosec // flags BETWEEN 0 AND 255 is a CHECK on the column

	return cred, true, nil
}
