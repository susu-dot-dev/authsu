//go:build js && wasm

// Command worker is the Cloudflare Worker entrypoint. It is deliberately
// tiny: it only obtains platform resources that exist solely under js/wasm and
// hands them to internal/app, where all logic lives and is tested.
package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"log"
	"net/http"

	"github.com/syumai/workers-go"
	"github.com/syumai/workers-go/cloudflare"
	"github.com/syumai/workers-go/cloudflare/d1" // also registers the "d1" database/sql driver
	workersfetch "github.com/syumai/workers-go/cloudflare/fetch"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/app"
	"github.com/susu-dot-dev/authsu/internal/fetch"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/store"
)

func main() {
	// sql.Open only records the driver and binding names; the binding is
	// resolved per query, inside a request.
	db, err := sql.Open("d1", "DB")
	if err != nil {
		log.Fatalf("open D1 binding: %v", err)
	}

	workers.Serve(app.NewHandler(app.Platform{
		Exec: batch(db), Getenv: cloudflare.Getenv, Log: logError, Fetch: outbound(),
	}))
}

// outbound returns the outbound HTTP port: the platform's fetch with the
// redirect mode set to manual, so a 3xx comes back to the caller as it is and
// is never followed. Workers has no "error" mode (it throws), and calling the
// client directly, not through an http.Client, keeps Go from following the
// redirect itself. The platform sets no time limit on a subrequest. The
// request's context does: when it ends the binding aborts the fetch and fails
// a pending body read, so the timeout and every other bound are internal/fetch's.
func outbound() fetch.Doer {
	client := workersfetch.NewClient()
	options := &workersfetch.RequestInit{Redirect: workersfetch.RedirectModeManual}

	return func(req *http.Request) (*http.Response, error) {
		return client.Do(&workersfetch.Request{Request: req}, options)
	}
}

// logError writes the full detail of a failed request, including the cause the
// client never sees, to the Worker's log. The code comes first so a log search
// or alert can key on it.
func logError(req httpapi.Request, failure *apierr.Error) {
	log.Printf("request failed: code=%s status=%d method=%s path=%s err=%v",
		failure.Code, failure.Kind.Status(), req.Method, req.Path, failure)
}

// batch returns the database port: D1's batch call, which runs every statement
// as one transaction and rolls the whole batch back if any fails. Every read
// and write goes through it, a read as a one-statement batch. It only converts
// the statement and result types and classifies the failure; the SQL lives in
// internal/store.
func batch(db *sql.DB) store.Exec {
	return func(ctx context.Context, statements ...store.Statement) ([]store.Result, error) {
		converted := make([]d1.Statement, len(statements))
		for i, statement := range statements {
			converted[i] = d1.Statement{Query: statement.Query, Args: statement.Args}
		}

		raw, err := d1.Batch(ctx, db, converted...)
		if err != nil {
			return nil, store.Classify(err)
		}

		results := make([]store.Result, len(raw))
		for i, one := range raw {
			results[i] = store.Result{Changes: one.Meta.Changes, Rows: rowsOf(one.Rows)}
		}

		return results, nil
	}
}

// rowsOf converts the driver's row values to plain values. It returns nil for
// a statement that returned no rows.
func rowsOf(raw [][]driver.Value) [][]any {
	if raw == nil {
		return nil
	}

	rows := make([][]any, len(raw))
	for i, row := range raw {
		rows[i] = make([]any, len(row))
		for j, value := range row {
			rows[i][j] = value
		}
	}

	return rows
}
