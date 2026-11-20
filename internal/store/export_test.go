package store

import (
	"context"
)

// This file exposes the unexported helpers to the external test package. It is
// compiled only into tests. Each area that adds helpers to test directly should
// add its own <area>_export_test.go rather than editing this file.

// NewWithMarshal returns a Store whose JSON encoder is marshal.
func NewWithMarshal(exec Exec, marshal func(any) ([]byte, error)) *Store {
	return &Store{exec: exec, marshal: marshal}
}

// helperOp is the operation the exported helpers report their failures as.
func helperOp() op {
	return op{failed: HelperFailed, rejected: HelperRejected, description: HelperDescription}
}

// Codes and description of the operation the helpers below fail as.
const (
	HelperFailed      = "helper_failed"
	HelperRejected    = "helper_rejected"
	HelperDescription = "helper is unavailable"
)

// Run exposes run.
func Run(ctx context.Context, s *Store, statements ...Statement) ([]Result, error) {
	return s.run(ctx, helperOp(), statements...)
}

// ChangedOnce exposes changedOnce.
func ChangedOnce(res Result) (bool, error) { return changedOnce(helperOp(), res) }

// readKinds returns a reader of one row that applies the named column readers
// in order and collects what they return. Optional kinds collect nil or the
// value itself rather than a pointer, so a table can compare them with ==.
func readKinds(kinds []string) func(*row) []any {
	readers := map[string]func(*row) any{
		"text":    func(r *row) any { return r.text() },
		"integer": func(r *row) any { return r.integer() },
		"blob":    func(r *row) any { return r.blob() },
		"octet":   func(r *row) any { return r.octet() },
		"boolean": func(r *row) any { return r.boolean() },
		"timestamp": func(r *row) any {
			return r.timestamp()
		},
		"optText": func(r *row) any {
			if text := r.optText(); text != nil {
				return *text
			}

			return nil
		},
		"optInteger": func(r *row) any {
			if number := r.optInteger(); number != nil {
				return *number
			}

			return nil
		},
	}

	return func(r *row) []any {
		out := make([]any, 0, len(kinds))

		for _, kind := range kinds {
			out = append(out, readers[kind](r))
		}

		return out
	}
}

// DecodeRow decodes values with the column kinds in order: text, optText,
// integer, optInteger, blob, octet, boolean, timestamp.
func DecodeRow(values []any, kinds ...string) ([]any, error) {
	return decode(values, readKinds(kinds))
}

// One exposes one for rows read as kinds.
func One(rows [][]any, kinds ...string) ([]any, error) {
	return one(rows, helperOp(), readKinds(kinds))
}

// All exposes all for rows read as kinds.
func All(rows [][]any, kinds ...string) ([][]any, error) {
	return all(rows, helperOp(), readKinds(kinds))
}

// QueryOne exposes queryOne for a statement whose rows are read as kinds.
func QueryOne(ctx context.Context, s *Store, statement Statement, kinds ...string) ([]any, error) {
	return queryOne(ctx, s, helperOp(), statement, readKinds(kinds))
}

// QueryAll exposes queryAll for a statement whose rows are read as kinds.
func QueryAll(ctx context.Context, s *Store, statement Statement, kinds ...string) ([][]any, error) {
	return queryAll(ctx, s, helperOp(), statement, readKinds(kinds))
}

// Find exposes find for a statement whose row is read as kinds.
func Find(ctx context.Context, s *Store, statement Statement, kinds ...string) ([]any, bool, error) {
	return find(ctx, s, helperOp(), statement, readKinds(kinds))
}

// ErrRowShape is the cause of every row defect.
var ErrRowShape = errRowShape

// AgentsFirstPage exposes the first page's cursor bound.
const AgentsFirstPage = agentsFirstPage

// KeysFirstPage exposes the keys list's first page cursor bound.
const KeysFirstPage = keysFirstPage

// GrantsFirstPage exposes the grants list's first page cursor bound.
const GrantsFirstPage = grantsFirstPage
