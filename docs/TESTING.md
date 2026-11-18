# Testing

How tests are written and what gates them. Generic scaffolding: how a specific test works belongs in comments in its test file. The structure being tested is described in [ARCHITECTURE.md](ARCHITECTURE.md); which targets to run, and when, is in [CONTRIBUTING.md](CONTRIBUTING.md).

## Unit tests

- **Test code lives only in `_test.go` files.** Fakes and helpers sit beside the tests that use them; there are no shared test packages. The toolchain never links these into a binary or counts them in coverage, so nothing needs configuring.
- **Consumers define small interfaces** so each package's tests carry a tiny fake of exactly what they need. Duplication across packages is the accepted cost.
- **Tests are table-driven**, with named cases and `t.Run`, in the external test package unless internal access is genuinely needed.
- **One fixtures file per package** (`fixtures_test.go`, or `fixtures_internal_test.go`) holds that package's fakes and builders. A fake records its calls and can be programmed to return any outcome.
- **Tests drive the real boundary.** A feature is tested by building its real routes behind the real route boundary and calling them over `net/http/httptest`, so the declarations are exercised and a handler cannot be tested in a state the boundary would never let it see.
- **Each layer has its own focus:**
  - *parsers*: exhaustive edge cases per primitive, plus a fuzz test per parser asserting that an accepted value round-trips unchanged and a refused one always carries the type's code;
  - *data access*: per operation, the SQL fragments that carry the guards, the exact argument order, decoding of every column type including the defect cases, the mapping of every outcome and error class, and a test that reads `migrations/` and asserts each parser bound fits inside its schema constraint (the real SQL runs only in e2e);
  - *route boundary*: a matrix of credential (session, user key, agent key), role, route and outcome, asserting that the handler is never called and nothing is written when any check fails;
  - *features*: a table per handler (request to status, code, body and store calls), and a route-declaration table asserting each route's method, path, credential and exact access, which is the permission-confusion test.
- **Time, randomness and I/O are injected**, so every branch is reachable from a test.

## Coverage

**100% statement coverage of production code**, enforced by `scripts/covgate` (`make coverage`). Exclusions are explicit: `cmd/worker` and `scripts/` are excluded by the gate, and an individual unreachable statement is marked `// coverage:ignore: <reason>` on the line directly above it. A missing reason or misplaced marker fails the gate, and every honoured ignore is printed in CI. Before using one, refactor to make the branch reachable.

## End-to-end tests

`e2e/`, build tag `e2e`. They drive the real Worker under `wrangler dev` with a simulated D1. They exist for what the host cannot see: TinyGo differences, the D1 driver, real SQLite behaviour, Wrangler wiring, and interleavings of concurrent requests against the real database. The `Makefile` decides the build and the harness only runs it. Dev and e2e use separate state directories. Details are in the harness and test file comments.

- **Behaviour under test is always an HTTP request to the Worker.** The tests also hold a side channel to the Worker's database, in one file (`db_test.go`), with a pure Go SQLite driver opened on the same file the simulated D1 uses. It exists to prepare state (seed rows, empty the tables between tests) and to read state back; it never performs the behaviour being tested, and a test fails the suite if any other file opens a database. It is far faster than shelling out to `wrangler d1 execute`, which is what made the suite slow.
- **Seed only while the Worker is idle.** The simulated D1's own connection does not wait on SQLite's lock, so a seed that lands during a request can fail that request with a busy error. Reads are always safe. Concurrency is therefore inside one test, in the requests: a test seeds, releases its concurrent requests together, waits for all of them, then reads state back.
- **The suite is sliced, and each slice has its own Worker and database.** One Worker serves tests one at a time because they share a database, so the suite is cut into slices that run in parallel, each on its own `wrangler dev`, port and D1 state directory (`shards_test.go`). A slice runs every n-th test in declaration order, which spreads the slow files without a timing table to maintain. Slices share only the read-only `build/`, so a test never needs to know it is sliced and must not rely on another slice's data or on running in the same process as another test.
  - **Locally** `make test-e2e` runs `E2E_SHARDS` slices (default 2) as parallel processes, one state directory each under `E2E_STATE`, output prefixed `[shard n]`; a passing slice prints only its last line unless `-v` is set. `E2E_SHARDS=1` runs everything on one Worker, which is the way to debug an ordering or isolation problem.
  - **In CI** each slice is its own job on its own machine: the workflow sets `E2E_SHARD_INDEX` and `E2E_SHARD_TOTAL` and the harness runs just that slice. A slice can be reproduced locally with the same two variables. See [CI.md](CI.md).
  - **More slices is not always faster.** Each is a Node process plus a workerd, with about 4 seconds of start-up, and the slowest slice sets the wall time. On one 8-core machine 4 slices was about 2.8 times faster than 1, and 6 was no better than 4. A starved machine also makes workerd drop connections, which is why tests that send a far-oversized body accept workerd's own "Network connection lost" 500 as an early refusal (`isEarlyRefusal`) and time out after 30 seconds instead of hanging.
- **Every test starts from a state it creates**, with a reset of the tables and builders from the one fixtures file, so tests depend on neither source order nor each other.
