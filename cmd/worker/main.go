//go:build js && wasm

// Command worker is the Cloudflare Worker entrypoint. It is deliberately
// tiny: it only obtains platform resources that exist solely under js/wasm and
// hands them to internal/app, where all logic lives and is tested.
package main

import (
	"context"
	"database/sql"
	"log"

	"github.com/syumai/workers-go"
	"github.com/syumai/workers-go/cloudflare"
	"github.com/syumai/workers-go/cloudflare/d1" // also registers the "d1" database/sql driver

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/app"
	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
)

func main() {
	// sql.Open only records the driver and binding names; the binding is
	// resolved per query, inside a request.
	db, err := sql.Open("d1", "DB")
	if err != nil {
		log.Fatalf("open D1 binding: %v", err)
	}

	workers.Serve(app.NewHandler(
		app.Deps{Diagnostics: diagnostics()},
		app.Platform{DB: db, Batch: batch(db), Getenv: cloudflare.Getenv, Log: logError},
	))
}

// logError writes the full detail of a failed request, including the cause the
// client never sees, to the Worker's log. The code comes first so a log search
// or alert can key on it.
func logError(req httpapi.Request, failure *apierr.Error) {
	log.Printf("request failed: code=%s status=%d method=%s path=%s err=%v",
		failure.Code, failure.Kind.Status(), req.Method, req.Path, failure)
}

// batch returns the atomic write function: D1's batch call, which rolls the
// whole batch back if any statement fails. It only converts the statement type
// and classifies the failure; the SQL lives with the feature that issues it.
func batch(db *sql.DB) atomic.Batch {
	return func(ctx context.Context, statements ...atomic.Statement) error {
		converted := make([]d1.Statement, len(statements))
		for i, statement := range statements {
			converted[i] = d1.Statement{Query: statement.Query, Args: statement.Args}
		}

		_, err := d1.Batch(ctx, db, converted...)

		return atomic.Classify(err)
	}
}
