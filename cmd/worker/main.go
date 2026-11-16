//go:build js && wasm

// Command worker is the Cloudflare Worker entrypoint. It is deliberately
// tiny: it only obtains platform resources that exist solely under js/wasm and
// hands them to internal/app, where all logic lives and is tested.
package main

import (
	"github.com/syumai/workers-go"

	"github.com/susu-dot-dev/authsu/internal/app"
)

func main() {
	workers.Serve(app.NewHandler(app.Deps{}))
}
