module github.com/susu-dot-dev/authsu

go 1.27.4

require (
	github.com/fxamacker/cbor/v2 v2.10.0
	github.com/susu-dot-dev/japikey_go v0.0.0-20261116153038-f042c31f9150
	github.com/syumai/workers-go v0.36.0
	golang.org/x/text v0.44.0
)

require (
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/telemetry v0.0.0-20261010193011-f71dc92da45e // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.org/x/vuln v1.9.0 // indirect
)

replace github.com/syumai/workers-go => github.com/intentionally-left-nil/workers-go v0.0.0-20261117154858-da5af392ad53

tool golang.org/x/vuln/cmd/govulncheck
