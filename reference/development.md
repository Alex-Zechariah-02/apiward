# Development

Architecture, code layout, builds and checks. Back to the [README](../README.md).

## How it is built

- The gateway has its own HTTP server and reverse proxy, built on the Go standard library. It serves HTTP/1.0 and HTTP/1.1 in plain text. Each request passes all five controls in one pipeline and then goes only to the API that the policy names, once.
- The project implements the policy model and the five controls itself.
- One SQLite controller stores complete policy versions, roles, permits, independent account blocks, administrators and durable change receipts. Protected requests read immutable snapshots rather than querying the database. The gateway refuses protected admission from state it cannot verify.
- Only the project controller changes the policy in use. The data plane has no administration endpoint.
- A protected admin API listens on a local address only. Administrators sign in with a password and hold explicit permissions. The API reads policy and history, stages and checks complete candidates, and activates, confirms or rolls them back. It also manages temporary overrides, independent account blocks and disk-only key reloads. Read-only checks answer whether a role may call an endpoint (with the request pipeline's own matching and permission code, for the policy in force or a draft), report each built-in limit with its current use and how many tokens each trusted key verified, and give fixed-rule advice: risky settings, unused permissions and alerts. Advice never changes anything.
- The Dashboard's header search by Ref and the live events use an in-memory window of the latest 10,000 API outcomes. A security log search reads the active and rotated audit files, newest first and bounded per page, and exports matching requests as CSV or JSON; it names any log file that has been moved away. Event streams have bounded queues, disclose dropped events and stop with the administrator's session. Traffic summaries and a separate loopback Prometheus listener expose bounded operational measurements without token, subject or address labels.
- Local commands set up the first administrator, add or reset administrators, make and restore checked database backups, and upgrade a database made by an earlier version. A restored backup serves nothing until an administrator confirms a new policy that allows nothing, and a provisional policy in the backup never comes back.
- A web dashboard for administrators (in `dashboard/`) is served by the admin listener itself, so it uses the same sign-in, origin and CSRF checks as the admin API. It shows the confirmed policy, any provisional policy and its deadline, the temporary overrides in force and the change history. It stages and activates new policies, confirms or rolls them back and creates or revokes overrides. It also has pages for the security log search, the access checker, limits and advice, and shows active alerts on its overview. Each change is shown as done only when the gateway's receipt arrives, and a request with no answer is shown as having an unknown outcome.
- [Fetch](https://github.com/Alex-Zechariah-02/fetch), the demonstration application (its own repository), is reached on a second loopback address, so the administrator's session cookie never reaches it. The gateway serves no website of its own: the demo tool serves the shop's built files as one more upstream, and the baseline policy exposes its pages and assets as public `GET` operations of the API `web`, so every request to the shop is checked, rate-limited and audited like an API call. Customers, merchants, riders, support agents and operations staff sign in through Fetch Accounts. Application calls go through the gateway to Inventory, Orders, Reports, Support and Accounts. Business ownership, stock, wallet and order transitions stay in those services.

## Code layout

Each package under `internal/` imports only the packages listed before it; a test enforces the order, and which internal packages each public package may reach.

- `apiward` (repository root): the public package for running the gateway inside a Go program ([embedding.md](embedding.md)).
- `policy`: the public policy document types, canonical encoding and offline check.
- `module`: the public contract for compile-time modules and their bounded per-key table.

- `internal/fault`: the fault-injection points tests use to crash, delay or fail the gateway at exact places. They act only in binaries built with the `faultinject` tag; normal builds compile them to no-ops.
- `internal/policy`: the policy document: its types, strict JSON decoding, and the limits and identifier formats every policy must meet.
- `internal/compile`: turns a policy into an immutable generation (routes, permits, rate rules, body and header schemas) that requests are decided against, readable only through methods; it also owns the trusted clock for deadlines.
- `internal/forward`: sends an admitted request once to the one upstream it is bound to, on a pooled keep-alive connection or a new one, never resending; a missing or non-loopback binding is sent nowhere.
- `internal/store`: the one SQLite database (policy versions, draft changes, temporary rules, blocked accounts, administrators, change receipts); the only code that runs SQL, holding the database exclusively.
- `internal/audit`: the durable security log; an admitted request is acknowledged only after its record is synced to disk, and the writer never deletes a file. A forwarded request has two records with one `request_id`: `request.admitted`, written before forwarding, holds the result of every stage; `request.forwarded`, written after the response, holds the outcome without repeating them (envelope `schema` 8). `gateway.audit_sync_window` (0 to 10 ms, default 0) lets the writer gather more records for one sync when more than one is waiting; every acknowledgement still waits for the sync that covers its record. On one CPU a 2 ms window lowered the 95th-percentile latency at the gateway's saturation rate but raised it at two thirds of that rate, so it is off by default: enable it only on a gateway that runs near saturation, after measuring.
- `internal/session`: administrator sessions, held only in memory as token hashes and bounded in number, and the random tokens the Admin API and operator commands hand out.
- `internal/monitor`: observes without deciding: the window of recent requests and its live views, request metrics, traffic summaries, advice checks, impact previews and the security log search.
- `internal/pipeline`: the data-plane request pipeline and its built-in controls (token verification, roles and blocked accounts, rate limits, body and header validation); it reads published policy but can never publish it, and forwards only a request that passed every stage.
- `internal/controller`: the one authority that changes what is enforced: it publishes policy versions, runs confirmed activation with automatic rollback and temporary rules with their expiry, recovers unfinished changes at startup, and publishes reloaded trust keys and blocked accounts and addresses. Each change is a recorded, audited transition made under one lock; nothing else can publish.
- `internal/admin`: the Admin API: administrator sign-in and sessions, the Host, Origin and CSRF checks, the sign-in throttle, and every status, history, monitoring and change endpoint. It reads the database through read-only methods and asks the controller for every change.
- `internal/operator`: the local operator commands (install, enrol, migrate, backup, restore), run on the host while the gateway is stopped, each holding the deployment lock and recording its changes in the security log.
- `internal/issuertest`: test support only, never imported by production code: an RS256 key generated in memory per test run and the tokens signed with it.
- `internal/storetest`: test support only: a disposable database seeded with a test policy, for the unit tests of packages that open a deployment.
- `internal/gatewaytest`: test support only: the test harness. It builds the gateway, fixture and demo programs, runs each test's gateway as its own process with a disposable deployment, and gives tests clients for the data plane and the Admin API and readers for the security log and the database.
- `internal/openapi`: the offline OpenAPI import and export; it turns a description into a candidate policy, checks it with the compiler, and writes one API of a policy back as a description.
- `internal/gateway`: the gateway itself, which uses the packages above.
- `internal/integration`: end-to-end tests only: each runs the real gateway binary, with the fixture and demo programs, as separate processes through `internal/gatewaytest`; they reach the gateway only through its processes, listeners and files.
- `examples/embed`: a host program that embeds the gateway, using only the public packages.

## Build and test

You need Go 1.26 or newer. `go.mod` selects the Go 1.27.4 toolchain; with `GOTOOLCHAIN=auto`, Go uses or downloads that toolchain when needed. The gateway's programs live in `cmd/`, its code in `internal/`, and the preserved controlled APIs for gateway regression tests in `internal/testfixture`. The Fetch demonstration is its own repository; the gateway's stack and browser tests build its programs from a checkout beside this one (`../fetch`), which CI checks out at the commit named by `FETCH_REF` in `.github/workflows/ci.yml`. Fetch reaches the gateway only through the gateway's programs and public packages. The Dashboard is in `dashboard/`.

- `cmd/gateway` runs the gateway from one strict JSON configuration file. It has the commands `run`, `install`, `enrol`, `backup`, `restore`, `migrate` and `health`, each with `--config <file>`, and the offline `policy import-openapi` and `policy export-openapi` ([openapi.md](openapi.md)). The local commands `install`, `enrol`, `backup`, `restore` and `migrate` run while the gateway is stopped.

```
go build -trimpath -o <out-dir>/gateway.exe ./cmd/gateway
go build -trimpath -o <out-dir>/testfixture.exe ./cmd/testfixture
```

## Building a release

A release binary carries the Dashboard, so one file serves the gateway and its admin interface. Build the Dashboard, copy its build into `internal/adminui/dist` (ignored by Git), then build with the `embedui` tag:

```
cd dashboard && npm ci && npm run build && cd ..
rm -rf internal/adminui/dist && cp -r dashboard/dist internal/adminui/dist
go build -trimpath -tags embedui -o <out-dir>/gateway ./cmd/gateway
```

`-trimpath` keeps local build directory names out of the programs. Reproducing an identical binary also requires the same source, toolchain, dependencies, build flags and environment; a release binary also needs the same Dashboard build, made with `npm ci` from `dashboard/package-lock.json`.

Run the required Go checks from the repository root. In PowerShell, give backend verification its isolated port offset:

```powershell
$env:EAT_PORT_OFFSET='1000'
go mod verify
gofmt -l $(git ls-files '*.go')
go vet ./...
go vet -tags faultinject ./...
go test ./... -count=1
```

`gofmt -l` must print nothing. The Fetch stack tests need the Fetch repository checked out as `../fetch`. The gateway regression tests start real gateway and controlled API processes and check independent request receipts. The Fetch integration test starts all five services and walks the role flows, refusals, policy changes, blocks, keys and resets. Tests use isolated synthetic identities and temporary state: the controlled-test issuer is in memory, while real Accounts tests create private signing files in temporary directories. No application signing key is shipped in source. Race and optional WSL checks have separate evidence; an unrun platform check is not implied by a passing Windows suite.

The dashboard is in `dashboard/` (React and TypeScript, built with Vite). Its browser tests drive a real demonstration made by the Fetch demo tool from `../fetch` (see `../dashboard/README.md`).

## Demonstration

The Fetch repository runs the whole local demonstration, the gateway and this Dashboard included, with one command (`go run ./cmd/demo up` in a Fetch checkout beside this one); its README lists the demo accounts, addresses and commands. The dashboard is then at `http://127.0.0.1:9440/` and the shop at `http://127.0.0.2:9480/`, through the gateway; metrics are at `http://127.0.0.1:9450/metrics`. `EAT_PORT_OFFSET` shifts every port.
