//go:build debug_routes

package main

import "github.com/susu-dot-dev/authsu/internal/diag"

// diagnostics selects the developer diagnostics routes. INSECURE: only
// compiled with -tags debug_routes.
func diagnostics() diag.Diagnostics { return diag.On{} }
