# Development

Back to the [README](../README.md).

## Requirements

- Go 1.26+. `go.mod` selects the 1.27.4 toolchain; with `GOTOOLCHAIN=auto`, Go downloads it when needed.
- Node.js 24 for the Dashboard (`dashboard/`).
- The [Fetch](https://github.com/Alex-Zechariah-02/fetch) repository checked out as `../fetch` for the stack and browser tests. CI checks it out at `FETCH_REF` in `.github/workflows/ci.yml`.

## Code layout

Each package under `internal/` imports only the packages listed before it. A test enforces the order.

Public packages:

| Package | Purpose |
|---|---|
| `apiward` (root) | Run the gateway inside a Go program ([embedding.md](embedding.md)) |
| `policy` | Policy document types, canonical encoding, offline check |
| `module` | Contract for compile-time modules |

Programs:

| Path | Purpose |
|---|---|
| `cmd/apiward` | The gateway program |
| `cmd/testfixture` | Controlled APIs for the regression tests |
| `examples/embed` | A host program that embeds the gateway |
| `dashboard/` | The Dashboard: React, TypeScript, Vite |

Internal packages, in import order:

| Package | Purpose |
|---|---|
| `internal/fault` | Fault-injection points; active only with the `faultinject` build tag |
| `internal/policy` | Policy types, strict JSON decoding, limits |
| `internal/compile` | Turns a policy into the immutable form requests are decided against |
| `internal/forward` | Sends an admitted request once to its bound upstream |
| `internal/store` | The SQLite database; the only code that runs SQL |
| `internal/audit` | The security log; acknowledges a record only after it is synced to disk |
| `internal/session` | Administrator sessions, in memory only |
| `internal/monitor` | Live views, metrics, traffic summaries, advice, log search |
| `internal/pipeline` | The request pipeline and its built-in checks |
| `internal/controller` | The only code that publishes policy; activation, rollback, overrides |
| `internal/admin` | The Admin API |
| `internal/operator` | The local commands: install, enrol, migrate, backup, restore |
| `internal/openapi` | OpenAPI import and export |
| `internal/gateway` | The gateway program, built from the packages above |
| `internal/issuertest`, `internal/storetest`, `internal/gatewaytest` | Test support only |
| `internal/integration` | End-to-end tests against the real gateway binary |

## Build

```
go build -trimpath -o <out-dir>/apiward ./cmd/apiward
go build -trimpath -o <out-dir>/testfixture ./cmd/testfixture
```

Release build, with the Dashboard inside the binary:

```
cd dashboard && npm ci && npm run build && cd ..
rm -rf internal/adminui/dist && cp -r dashboard/dist internal/adminui/dist
go build -trimpath -tags embedui -o <out-dir>/apiward ./cmd/apiward
```

- `internal/adminui/dist` is ignored by Git.
- `-trimpath` keeps local directory names out of the binary.
- An identical binary needs the same source, toolchain, dependencies, flags, environment and Dashboard build (`npm ci` from `dashboard/package-lock.json`).

## Checks

```
go mod verify
gofmt -l $(git ls-files '*.go')
go vet ./...
go vet -tags faultinject ./...
go test ./... -count=1
```

- `gofmt -l` must print nothing.
- `EAT_PORT_OFFSET` (for example `1000`) moves every test port.
- The regression tests start real gateway and API processes and check each API's own request receipts.
- Tests use synthetic identities and temporary state. No signing key is shipped in source.
- Dashboard checks and browser tests: [../dashboard/README.md](../dashboard/README.md).
