module github.com/susu-dot-dev/authsu

go 1.27.4

require github.com/syumai/workers-go v0.36.0

require (
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/telemetry v0.0.0-20261010193011-f71dc92da45e // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.org/x/vuln v1.9.0 // indirect
)

replace github.com/syumai/workers-go => github.com/intentionally-left-nil/workers-go v0.0.0-20261115184608-88d456e75a13

tool golang.org/x/vuln/cmd/govulncheck
