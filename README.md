# APIWard

A lightweight security policy gateway for REST APIs, written in Go.

It checks every request against one policy before forwarding it. One binary: HTTP server, reverse proxy, database and admin Dashboard.

- [Features](#features)
- [Quick start](#quick-start)
- [Build](#build)
- [Run](#run)
- [How it works](#how-it-works)
- [Documentation](#documentation)
- [Tests](#tests)

## Features

- **JWT authentication**: RS256 tokens from your identity provider
- **Role-based access control**, plus an instant blocked-accounts list
- **Rate limiting**: sliding window, per account or per client address
- **Request validation**: JSON body and headers against a JSON Schema
- **Security log**: a request is forwarded only after its record is on disk
- **Default deny**: a request that fails any check never reaches an API
- **Safe policy changes**: a new policy runs on trial and rolls back unless confirmed
- **Dashboard and Admin API**, on a loopback-only listener
- **Per-API options**: path rewrite, host and header conditions, CORS, response headers, address allow lists, TLS to upstreams
- **Signed identity**: upstreams can verify that a request passed the gateway (on by default)
- **OpenAPI** import and export
- **Embeddable** in a Go program; custom checks as compile-time modules
- **No external services**: one SQLite file; Prometheus metrics, `/livez`, `/readyz`

## Quick start

Run the [Fetch](https://github.com/Alex-Zechariah-02/fetch) demonstration: a shop with five APIs behind the gateway.

Requires Go 1.26+ and Node.js 24.

```
git clone https://github.com/Alex-Zechariah-02/apiward
git clone https://github.com/Alex-Zechariah-02/fetch
cd fetch
go run ./cmd/demo up
```

| Open | Address |
|---|---|
| Dashboard | `http://127.0.0.1:9440/` |
| Shop, through the gateway | `http://127.0.0.2:9480/` |
| Metrics | `http://127.0.0.1:9450/metrics` |

## Build

Requires Go 1.26+ (`go.mod` selects the 1.27.4 toolchain).

Gateway only:

```
go build -trimpath -o apiward ./cmd/apiward
```

With the Dashboard inside the binary (also requires Node.js 24):

```
cd dashboard && npm ci && npm run build && cd ..
rm -rf internal/adminui/dist && cp -r dashboard/dist internal/adminui/dist
go build -trimpath -tags embedui -o apiward ./cmd/apiward
```

Container image ([docs/container.md](docs/container.md)):

```
docker build -t apiward:dev .
```

## Run

```
apiward install --config apiward.json --admin <name>
apiward run --config apiward.json
```

1. `install` prints a one-time enrolment secret. Keep it private.
2. Open the Dashboard and choose **First Sign-In with an Enrolment Secret**.
3. Establish the first policy. Until then the gateway forwards nothing.

The settings file is described in [docs/settings.md](docs/settings.md).

| Command | Purpose |
|---|---|
| `run` | Run the gateway |
| `install` | Create the first administrator and the identity key |
| `enrol` | Add or reset an administrator |
| `backup`, `restore` | Back up or restore the database |
| `migrate` | Upgrade a database from an earlier version |
| `health` | Exit 0 when the gateway is ready |
| `jwks` | Print the public key of the signed identity |
| `policy import-openapi` | Make a policy file from an OpenAPI description |
| `policy export-openapi` | Write one API of a policy as OpenAPI |
| `version` | Print the version and compiled-in checks |

- All commands except `version` and `policy` take `--config <file>`.
- Stop the gateway before `install`, `enrol`, `backup`, `restore` or `migrate`.

## How it works

- **Policy**: one document lists upstreams, APIs, operations, roles and permits.
- **Request path**: ingress checks → route → token → roles → rate limit → validation → security log → forward. The first failing stage answers.
- **One version per request**: a request is decided against exactly one policy version and forwarded once.
- **Policy changes**: a new policy is provisional until confirmed; unconfirmed, the previous one returns. Temporary overrides expire by themselves.
- **Identity**: the gateway verifies tokens and never issues them. Upstreams receive the verified account and roles.
- **Listeners**:
  - data: your APIs
  - admin: Dashboard and Admin API, loopback only
  - metrics: Prometheus, `/livez`, `/readyz`
- **Storage**: one SQLite database. Requests read in-memory snapshots, never the database.

## Documentation

| Page | Contents |
|---|---|
| [docs/policy.md](docs/policy.md) | Policy document and policy changes |
| [docs/settings.md](docs/settings.md) | Settings file |
| [docs/openapi.md](docs/openapi.md) | OpenAPI import and export |
| [docs/embedding.md](docs/embedding.md) | Embedding and modules |
| [docs/container.md](docs/container.md) | Container image |
| [docs/development.md](docs/development.md) | Code layout, builds, checks |
| [docs/dashboard.md](docs/dashboard.md) | Dashboard pages and behaviour |
| [dashboard/README.md](dashboard/README.md) | Dashboard build and tests |

## Tests

```
go mod verify
gofmt -l $(git ls-files '*.go')
go vet ./...
go vet -tags faultinject ./...
go test ./... -count=1
```

- `gofmt -l` must print nothing.
- The stack tests need Fetch checked out as `../fetch`.
- `EAT_PORT_OFFSET` (for example `1000`) moves every test port.

## Not covered

The full OWASP API Security Top 10, distributed deployments, Kubernetes, automatic certificates (ACME).

## Licence

Apache-2.0 (`LICENSE`). Third-party components: `THIRD_PARTY_NOTICES`.
