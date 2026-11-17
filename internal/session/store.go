package session

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SQLReader is the Reader backed by a *sql.DB.
type SQLReader struct {
	db *sql.DB
}

// NewSQLReader returns a Reader over db.
func NewSQLReader(db *sql.DB) *SQLReader {
	return &SQLReader{db: db}
}

// ActiveKey implements Reader.
func (r *SQLReader) ActiveKey(ctx context.Context, kid string, now time.Time) (ActiveKey, bool, error) {
	var (
		key     ActiveKey
		jwk     string
		expires int64
	)

	unix := now.Unix()

	err := r.db.QueryRowContext(ctx, activeKeyQuery, kid, unix, unix).
		Scan(&jwk, &key.UserID, &key.CredentialID, &key.Role, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return ActiveKey{}, false, nil
	}

	if err != nil {
		return ActiveKey{}, false, fmt.Errorf("query session key: %w", err)
	}

	key.JWK = []byte(jwk)
	key.ExpiresAt = time.Unix(expires, 0)

	return key, true, nil
}
