# APIWard

A lightweight security policy gateway for REST APIs, written in Go.

APIWard sits in front of your APIs and checks every request against one shared policy before it is forwarded. It is a single binary with its own HTTP server, reverse proxy, database and admin Dashboard, built on the Go standard library.

- [Features](#features)
- [Quick start](#quick-start)
- [Build from source](#build-from-source)
- [Run](#run)
- [Overview](#overview)
- [Documentation](#documentation)
- [Tests](#tests)

## Features

- **Five security controls** on every request:
  - **JWT authentication**: RS256 tokens from your identity provider, several keys by `kid`, reloadable
  - **Role-based access control**, with an instant blocked-accounts list
  - **Rate limiting**: sliding window, per account or per client address
  - **Request validation**: JSON body and headers against a bounded JSON Schema
  - **Security log**: a request is forwarded only after its record is on disk
- **Default deny.** A request that fails any control never reaches an API.
- **Safe policy changes.** A new policy runs on trial and rolls back by itself unless an administrator confirms it. Temporary overrides expire on their own.
- **Admin Dashboard and Admin API** on a loopback-only listener: policy, history, live events, log search, access checker, advice.
- **Routing extras per API**: path rewrite, host and header conditions, CORS, response headers, address allow lists, TLS and client certificates to upstreams.
- **Signed identity for upstreams**: an optional signed assertion proves a request passed the gateway.
- **OpenAPI import and export** of routes and request schemas.
- **Embeddable**: run it inside a Go program, or add your own checks as compile-time modules.
- **One static binary**, one SQLite file, no external services. Prometheus metrics, `/livez` and `/readyz` included.

## Quick start

The fastest way to see APIWard working is the [Fetch](https://github.com/Alex-Zechariah-02/fetch) demonstration: a small shop with five APIs behind the gateway. You need Go 1.26 or newer and Node.js 24.

```
git clone https://github.com/Alex-Zechariah-02/apiward
git clone https://github.com/Alex-Zechariah-02/fetch
cd fetch
go run ./cmd/demo up
```

Then open:

| | |
|---|---|
| Dashboard | `http://127.0.0.1:9440/` |
| Shop, through the gateway | `http://127.0.0.2:9480/` |
| Metrics | `http://127.0.0.1:9450/metrics` |

The Fetch README lists the demo accounts and commands.

## Build from source

Requirements: Go 1.26 or newer (`go.mod` selects the Go 1.27.4 toolchain). The Dashboard also needs Node.js 24.

Gateway only:

```
go build -trimpath -o gateway ./cmd/gateway
```

Release build, with the Dashboard inside the binary:

```
cd dashboard && npm ci && npm run build && cd ..
rm -rf internal/adminui/dist && cp -r dashboard/dist internal/adminui/dist
go build -trimpath -tags embedui -o gateway ./cmd/gateway
```

Container image (details in [reference/container.md](reference/container.md)):

```
docker build -t apiward:dev .
```

## Run

The gateway reads one JSON settings file ([reference/settings.md](reference/settings.md)).

```
gateway install --config gateway.json --admin <name>    # once: prints a one-time enrolment secret
gateway run --config gateway.json
```

Open the Dashboard, choose **First Sign-In with an Enrolment Secret**, and establish the first policy. Until a policy is published the gateway forwards nothing.

| Command | Purpose |
|---|---|
| `run` | Run the gateway |
| `install`, `enrol` | Create the first administrator; add or reset one |
| `backup`, `restore`, `migrate` | Back up, restore or upgrade the database |
| `health` | Exit 0 when the gateway is ready |
| `jwks` | Print the public key of the identity assertion |
| `policy import-openapi`, `policy export-openapi` | Convert between OpenAPI and a policy file |
| `version` | Version, toolchain and compiled-in controls |

Every command except `version` and the two `policy` commands takes `--config <file>`. `install`, `enrol`, `backup`, `restore` and `migrate` run while the gateway is stopped. `install` and `enrol` print a secret: keep their output private.

## Overview

**One policy.** A policy document lists upstreams, APIs, operations, roles and permits. Each request is decided against exactly one policy version from start to end, then forwarded once, only to the upstream its operation names.

**The pipeline.** Ingress checks, routing, token, roles and blocked accounts, rate limit, body and header validation, security log, forward. The first failing stage answers the request, and the log records which one.

**Changing policy.** Only the gateway's controller publishes a policy. A new policy starts provisional with a confirmation deadline; without confirmation the previous policy returns, also across a restart. A temporary override grants, removes, limits or blocks one thing for up to 24 hours and never weakens token checks, validation or logging.

**Identity.** APIWard verifies tokens and never issues them. Roles come only from verified token claims that the policy defines. Upstreams receive the verified account and roles in `X-Gateway-Subject` and `X-Gateway-Roles`, and optionally in a signed assertion.

**Three listeners.** Data (your APIs; HTTPS with HTTP/2 when given a certificate), admin (Dashboard and Admin API; always loopback, reach it through an SSH tunnel) and metrics (Prometheus, `/livez`, `/readyz`; loopback by default).

**Storage.** One SQLite database holds policy versions, administrators and change history. Requests read immutable in-memory snapshots and never query the database.

## Documentation

| Page | Contents |
|---|---|
| [reference/policy.md](reference/policy.md) | The policy document: operations, conditions, path rewrite, CORS, response headers, address lists, upstreams, capacity limits; policy changes |
| [reference/settings.md](reference/settings.md) | The settings file: listeners, TLS, overload limits, upstream connections, identity assertion, security log |
| [reference/openapi.md](reference/openapi.md) | OpenAPI import and export; moving to or from another gateway |
| [reference/embedding.md](reference/embedding.md) | Running the gateway inside a Go program; compile-time modules |
| [reference/container.md](reference/container.md) | The container image |
| [reference/development.md](reference/development.md) | Architecture, code layout, release builds, checks |
| [dashboard/README.md](dashboard/README.md) | The Dashboard |

## Tests

```
go mod verify
gofmt -l $(git ls-files '*.go')
go vet ./...
go vet -tags faultinject ./...
go test ./... -count=1
```

`gofmt -l` must print nothing. The stack tests need the Fetch repository checked out as `../fetch`. Set `EAT_PORT_OFFSET` (for example `1000`) to move every test port.

## Scope

APIWard does not cover the full OWASP API Security Top 10, distributed deployments, Kubernetes or automatic certificates (ACME).

## Licence

Apache-2.0 (`LICENSE`). Third-party components are listed in `THIRD_PARTY_NOTICES`.
