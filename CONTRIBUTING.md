# Contributing to StateTrack

Thanks for taking the time to contribute. This guide describes how StateTrack
is laid out, how to get a working development environment, and the conventions
the codebase holds itself to. It is written so that a first pull request can be
opened without reading the whole tree first.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md) and to
license your contributions under the project's [Apache License 2.0](LICENSE).

---

## 1. Before you start

- **Read the [README](README.md).** It documents the architecture, the agent
  pipeline, the integrations hub, the AI gateway, the MCP server and the API.
  Most "where does this live?" questions are answered there.
- **[`spec.md`](spec.md)** is the canonical design specification. Where the code
  and the spec disagree, the spec describes the intent — open an issue rather
  than silently changing behaviour.
- **[`docs/enterprise-catalog.md`](docs/enterprise-catalog.md)** is the reference
  for the discovered-application catalog; a change to `catalog.yaml` must be
  reflected there (a drift test enforces this).

## 2. Repository layout

| Path | Module | Purpose |
| --- | --- | --- |
| `pkg/` | `github.com/statetrack/statetrack/pkg` | Shared libraries: `pb` (protobuf), `redact` (secret scrubber), `diff` (Myers + zstd). |
| `agent/` | `.../agent` | The host agent: config, collectors, classification, spool, transport, discovery. |
| `server/` | `.../server` | The control plane: gRPC, storage, integrations, ITSM, AI, MCP, metrics, API. |
| `web/` | npm | React 19 + TypeScript console. |
| `proto/` | — | Canonical gRPC contract. |
| `deploy/`, `scripts/`, `integrations/`, `docs/` | — | Deployment, tooling, provisioned assets and reference docs. |

The Go workspace (`go.work`) composes the three Go modules. All three target
**Go 1.26**.

## 3. Development environment

Prerequisites: **Docker**, **Go 1.26+**, **Node.js 20+**. `protoc` is required
only if you change the protobuf contract.

```bash
# Dependencies + database + demo data
docker compose up -d --wait
make migrate
make seed                 # optional realistic timeline for today

# Backend (gRPC :50051, HTTP :8080, /metrics, /api/v1/mcp)
go run ./server/cmd/statetrack-server

# Console (http://localhost:5173, proxies /api and /metrics to :8080)
npm run dev --prefix web
```

On Windows the equivalent workflow is `scripts/dev.ps1`:

```powershell
.\scripts\dev.ps1 up
.\scripts\dev.ps1 migrate
.\scripts\dev.ps1 seed
.\scripts\dev.ps1 run-server      # demo mode
.\scripts\dev.ps1 run-web         # second shell
```

## 4. The one command to run before pushing

```bash
make check                                  # Linux / macOS / CI
.\scripts\dev.ps1 check                     # Windows
```

`check` runs, and fails on, all of:

1. `gofmt -l pkg agent server` — formatting,
2. `go vet` on all three modules,
3. `go test` on all three modules,
4. a cross-compile of the agent (linux amd64/arm64, windows amd64) and the
   server + `statetrack-mcp`,
5. a drift check that `web/public/integration-assets/` matches `integrations/`.

A change that fails `check` will fail CI, so run it locally first.

### Test layers

| Command | What it covers |
| --- | --- |
| `make test` | Unit tests for `pkg`, `agent`, `server`. |
| `make test-integration` | Tests that need the docker-compose stack (`STATETRACK_TEST_DATABASE_URL`). |
| `make test-race` | `go test -race` in a Linux `golang:1.26` container (the race detector needs cgo; release builds stay `CGO_ENABLED=0`). |
| `make test-e2e` | Linux collector end-to-end tests, unprivileged and privileged. |
| `scripts/e2e_smoke.sh` | Full-stack smoke: stack health → migrations → build → real agent scrubbing, package-burst grouping, Grafana annotation, REST read. |
| `python3 -m unittest discover -s integrations/checkmk -t integrations/checkmk -v` | The Checkmk plugin's stdlib test suite. |

### Focused suites

```bash
go test ./server/internal/mcp/...     # MCP protocol + tool surface
go test ./server/internal/ai/...      # AI gateway, providers, fallback, scrubbing
go test ./agent/internal/discovery/   # catalog + probe engine
go test ./pkg/redact/... ./pkg/diff/...
```

## 5. Code conventions

These are enforced by review and, where possible, by tooling.

- **Formatting.** `gofmt` (Go) and Prettier defaults (TypeScript). `check`
  rejects unformatted Go.
- **Comments explain *why*, not *what*.** The codebase deliberately documents
  the reasoning behind non-obvious decisions — a security property, an ordering
  requirement, a failure mode being engineered against. Match that style: a
  reviewer should learn the constraint you were working under.
- **No secrets in the repo.** Never commit a credential, token or key. `redact`
  exists precisely because raw values must not travel; do not add a field that
  could carry one.
- **Determinism in output.** Tool results, report renderers and metric labels
  must be deterministic (no map iteration in output, no wall-clock timestamps
  beyond the data's own) so transcripts are reproducible and diffs are stable.
- **Closed vocabularies for labels.** Prometheus labels, blast-radius values and
  compliance verdicts are closed sets with a normalization helper; unrecognized
  input folds into an `unknown` bucket rather than minting a new value.
- **Read-only by default.** The Kubernetes RBAC and every probe are
  structurally incapable of mutating what they observe. Do not add a write verb
  or a state mutation to a collector or a probe.

### Frontend conventions

The console follows the rules in [`.cursorrules`](.cursorrules):

- Google Cloud Console / Workspace aesthetic: light-mode first, `#f8fafc`
  background, white cards, `border-slate-200/80`, micro-shadows.
- The fixed color semantics (Google blue `#1a73e8`, red `#d93025`, purple
  `#7c3aed`, amber `#f9ab00`, green `#1e8e3e`, slate neutrals).
- **No** 1,000-line monoliths: decompose into `src/components/`.
- **No** heavyweight charting libraries: use pure SVG / Tailwind flex bars.
- Zero-white-screen discipline: `(items ?? []).map(…)`, error boundaries around
  async widgets, optional chaining on nested data.
- Pages without live tables use strongly typed mocks in `src/api/mockData.ts`
  that match the Go structs, so the page renders immediately.

## 6. Changing the protobuf contract

`proto/` is the source of truth; `pkg/pb` is generated.

```bash
make tools      # install protoc-gen-go / protoc-gen-go-grpc (once)
make proto      # regenerate pkg/pb
```

Commit the regenerated files together with the `.proto` change. A wire-format
change is a compatibility decision — call it out explicitly in the pull
request, and prefer additive fields over renumbering.

## 7. Changing the discovered-application catalog

1. Add or edit an entry in
   [`agent/internal/discovery/catalog.yaml`](agent/internal/discovery/catalog.yaml).
2. Update the coverage tables in
   [`docs/enterprise-catalog.md`](docs/enterprise-catalog.md).
3. If the entry needs a new workload type the console already renders, map it in
   `agent/internal/discovery/workload.go`.
4. Run `go test ./agent/internal/discovery/`. A drift test fails the build if an
   entry is missing from the document, so the manifest and the reference cannot
   silently diverge.

Discovery must never make a network call — that is what makes the catalog work
in an air-gapped estate.

## 8. Changing a provisioned integration asset

The Grafana dashboard, Prometheus rules, Checkmk plugin and Zabbix template live
**once** in `integrations/` (beside the docs describing them).

```bash
.\scripts\dev.ps1 sync-assets          # copy integrations/ → web/public/integration-assets/
.\scripts\dev.ps1 sync-assets -Check   # fail on drift (run by `check`)
```

When you edit the Checkmk plugin, run its unit tests. When you edit the Zabbix
template, note that `TestZabbixTemplateShape` in `server/internal/integrations`
validates its shape and the master/dependent architecture.

## 9. Adding a database migration

- Files are numbered: `server/migrations/00N_name.sql`, applied in filename
  order, **each inside a single transaction**.
- Keep them idempotent (`CREATE TABLE IF NOT EXISTS`, `ON CONFLICT DO NOTHING`)
  so re-running is safe on a database that already has the schema.
- Seed data belongs in the migration only if a fresh install needs it to be
  usable; demo-only data belongs in `statetrack-seed`.
- Comment the *why*: the existing migrations explain the reasoning behind every
  table and index. Follow that pattern.

## 10. Pull request checklist

- [ ] The change is scoped to one concern; unrelated churn is split out.
- [ ] `make check` (or `dev.ps1 check`) passes.
- [ ] New behaviour has a test; a bug fix has a regression test.
- [ ] Documentation is updated (`README.md`, `docs/`, a sub-`README.md`, or the
      relevant `.proto`/`catalog.yaml` companion) if the change is user-visible.
- [ ] No secret, credential, token or key is added to the tree.
- [ ] The commit message says **why**, not just what.

Write the pull request description for a reviewer who has not read the code:
what changed, why, what you verified, and what you deliberately did not do.

## 11. Reporting a security issue

Please **do not** open a public issue for a vulnerability — see
[`SECURITY.md`](SECURITY.md) for the private reporting process.

## 12. Getting help

- Architecture questions: start with the [README](README.md) and
  [`spec.md`](spec.md).
- Integration-specific setup: the sub-`README.md` in `integrations/`.
- Catalog coverage: [`docs/enterprise-catalog.md`](docs/enterprise-catalog.md).
