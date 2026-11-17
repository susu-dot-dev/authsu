package invitations

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

// List implements Reader.
func (r *SQLReader) List(ctx context.Context) ([]Row, error) {
	rows, err := r.db.QueryContext(ctx, listQuery)
	if err != nil {
		return nil, fmt.Errorf("query invitations: %w", err)
	}

	defer func() { _ = rows.Close() }()

	out := []Row{}

	for rows.Next() {
		row, err := scanRow(rows)
		if err != nil {
			return nil, err
		}

		out = append(out, row)
	}

	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("read invitations: %w", err)
	}

	return out, nil
}

// Get implements Reader.
func (r *SQLReader) Get(ctx context.Context, id string) (Row, error) {
	row, err := scanRow(r.db.QueryRowContext(ctx, getQuery, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Row{}, ErrNotFound
	}

	return row, err
}

// scanner is what *sql.Row and *sql.Rows have in common.
type scanner interface {
	Scan(dest ...any) error
}

// scanRow reads one invitation row. A NULL column is a nil pointer.
func scanRow(from scanner) (Row, error) {
	var (
		row       Row
		expiresAt sql.NullInt64
		revokedAt sql.NullInt64
		createdBy sql.NullString
	)

	err := from.Scan(&row.ID, &row.Type, &row.Label, &row.NumInvites, &row.Uses,
		&expiresAt, &revokedAt, &createdBy, &row.CreatedAt)
	if err != nil {
		return Row{}, fmt.Errorf("scan invitation: %w", err)
	}

	if expiresAt.Valid {
		row.ExpiresAt = &expiresAt.Int64
	}

	if revokedAt.Valid {
		row.RevokedAt = &revokedAt.Int64
	}

	if createdBy.Valid {
		row.CreatedBy = &createdBy.String
	}

	return row, nil
}

// errRowShape is the cause of a returned row that is not an invitation row.
var errRowShape = errors.New("returned row is not an invitation")

// rowColumns is the number of columns in selectColumns.
const rowColumns = 9

// rowOfValues reads one invitation row from the values a batch returned for it,
// in the column order of selectColumns. It is scanRow for the platform's batch
// results, which arrive as plain values and not through database/sql. A NULL
// column is a nil pointer.
func rowOfValues(values []any) (Row, error) {
	if len(values) != rowColumns {
		return Row{}, fmt.Errorf("%w: %d columns, want %d", errRowShape, len(values), rowColumns)
	}

	cols := cursor{values: values, at: 0, err: nil}

	// Struct fields are evaluated in order, which is the column order.
	row := Row{
		ID: cols.text(), Type: cols.text(), Label: cols.text(),
		NumInvites: cols.integer(), Uses: cols.integer(),
		ExpiresAt: cols.optInteger(), RevokedAt: cols.optInteger(), CreatedBy: cols.optText(),
		CreatedAt: cols.integer(),
	}

	return row, cols.err
}

// cursor reads typed values from one returned row, left to right, remembering
// the first column that was not of the type asked for.
type cursor struct {
	values []any
	at     int
	err    error
}

// next returns the value under the cursor and moves on.
func (c *cursor) next() any {
	value := c.values[c.at]
	c.at++

	return value
}

func (c *cursor) fail(value any, want string) {
	if c.err == nil {
		c.err = fmt.Errorf("%w: column %d is %T, want %s", errRowShape, c.at-1, value, want)
	}
}

func (c *cursor) text() string {
	value := c.next()

	text, ok := value.(string)
	if !ok {
		c.fail(value, "text")
	}

	return text
}

func (c *cursor) integer() int64 {
	value := c.next()

	number, ok := value.(int64)
	if !ok {
		c.fail(value, "an integer")
	}

	return number
}

func (c *cursor) optInteger() *int64 {
	if c.values[c.at] == nil {
		c.at++

		return nil
	}

	number := c.integer()

	return &number
}

func (c *cursor) optText() *string {
	if c.values[c.at] == nil {
		c.at++

		return nil
	}

	text := c.text()

	return &text
}
