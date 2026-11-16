//go:build !debug_routes

package main

import "github.com/susu-dot-dev/authsu/internal/diag"

// diagnostics selects no diagnostics routes: the production default.
func diagnostics() diag.Diagnostics { return diag.Off{} }
