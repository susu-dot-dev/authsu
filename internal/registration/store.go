package registration

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

// RedeemableInvitationType implements Reader.
func (r *SQLReader) RedeemableInvitationType(ctx context.Context, hash []byte, now time.Time) (string, bool, error) {
	var invitationType string

	err := r.db.QueryRowContext(ctx, invitationQuery, hash, now.Unix()).Scan(&invitationType)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}

	if err != nil {
		return "", false, fmt.Errorf("query invitation: %w", err)
	}

	return invitationType, true, nil
}
