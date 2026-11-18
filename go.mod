module github.com/susu-dot-dev/authsu

go 1.27.4

require (
	github.com/fxamacker/cbor/v2 v2.10.0
	github.com/susu-dot-dev/japikey_go v0.0.0-20261116153038-f042c31f9150
	github.com/syumai/workers-go v0.36.0
	golang.org/x/text v0.44.0
	modernc.org/sqlite v1.62.0
)

require (
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/telemetry v0.0.0-20261010193011-f71dc92da45e // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.org/x/vuln v1.9.0 // indirect
	modernc.org/libc v1.80.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

replace github.com/syumai/workers-go => github.com/intentionally-left-nil/workers-go v0.0.0-20261118063143-b16bd8edf2e7

tool golang.org/x/vuln/cmd/govulncheck
