# Database: migrations and D1 conventions

Conventions for the schema and for talking to D1. Generic scaffolding: the schema itself is in `migrations/`. Where SQL may live in Go is in [ARCHITECTURE.md](ARCHITECTURE.md); procedures for applying migrations to a deployment are in [runbook.md](runbook.md).

- Migrations are plain SQL in `migrations/`, named `NNNN_description.sql` and applied in order by Wrangler. They are **append-only**: one that has landed on `main` is never edited, and a change is a new migration. This applies only once we ship to production; until then every schema change goes into the existing `0001_schema.sql` (see the README).
- **No `CHECK` on open-ended values.** A set of values that grows with the code is validated in Go, because changing a `CHECK` in SQLite means rebuilding the table. `CHECK` is for invariants that will not change.
- **JSON columns are `TEXT`**, not `BLOB`: SQLite's JSONB is an internal format Go cannot write, and the blob path for JSON text is documented as bug compatibility.
- **D1 has no interactive transactions.** Its one atomic primitive is a batch, and the data-access package holds the host-compilable half of it (its batch port, and the classification of constraint failures); a check-then-insert would race, so authorization conditions belong in the write itself. See that package's docs. A batch returns rows keyed by column name, so columns that share a name collapse into one: alias every selected expression.
- **Go code never knows which database it talks to.** The Worker is bound as `DB` in every environment, and the e2e harness applies every migration to a fresh local database, so a broken migration fails CI.
- **Remote migrations are applied by hand.** Neither CI nor Workers Builds applies them. See [runbook.md](runbook.md).
