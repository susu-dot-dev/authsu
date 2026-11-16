//go:build js && wasm

// Command worker is the Cloudflare Worker entrypoint. It is deliberately
// tiny: it only obtains platform resources that exist solely under js/wasm and
// hands them to internal/app, where all logic lives and is tested.
package main

import (
	"database/sql"
	"log"

	"github.com/syumai/workers-go"
	"github.com/syumai/workers-go/cloudflare"
	_ "github.com/syumai/workers-go/cloudflare/d1" // registers the "d1" database/sql driver

	"github.com/susu-dot-dev/authsu/internal/app"
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
		app.Platform{DB: db, Getenv: cloudflare.Getenv},
	))
}
