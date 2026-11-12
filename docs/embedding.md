# Embedding and modules

Back to the [README](../README.md).

## Embedding in a Go application

A Go program can run the gateway inside itself instead of beside it. The program serves the gateway's data plane on its own HTTP server; the gateway keeps its Admin API and metrics listeners, its database, its audit log and its start and stop. Every request still passes the full pipeline.

```go
cfg, err := apiward.LoadConfig("apiward.json") // the same file `apiward run` reads
gw, err := apiward.New(cfg, logger)            // takes the deployment lock; binds nothing
err = gw.Start()                               // Admin API and metrics; requests admitted from now on
mux.Handle("/api/", http.StripPrefix("/api", gw)) // policy targets are the paths below /api
server := &http.Server{Addr: ":8080", Handler: mux}
gw.ServerSettings().Apply(server)              // header size and timeouts from the configuration
// ... serve; on shutdown stop the server first, then:
err = gw.Stop(ctx)                             // waits for requests in progress, then closes the audit log
```

- Import `github.com/Alex-Zechariah-02/apiward`. The deployment is installed and its first policy published as for the binary (`apiward install`, then the Dashboard). The configuration's `data.listen` is still required and checked, but an embedded gateway never binds it.
- Before `Start` and from `Stop` on, every request is refused with `503 gateway_unavailable` and recorded. `Start` and `Stop` each run once.
- Errors from `LoadConfig`, `New`, `Start` and `Stop` match exactly one of `ErrConfig`, `ErrLocked`, `ErrStorage`, `ErrListen`, `ErrStarted`, `ErrStopped` or `ErrIncomplete` with `errors.Is`. Refused requests are HTTP responses, never Go errors.
- Apply `ServerSettings` to your server: the gateway cannot enforce header size, timeouts or the connection cap (`data.max_connections`) on a server it does not own.
  - Body limits and every other check stay in the handler.
  - Do not rewrite `RemoteAddr` from client headers before the gateway: address lists and per-address rate limits read it.
- Package `github.com/Alex-Zechariah-02/apiward/policy` holds the policy document types, `Decode`, `Encode` (the canonical form: two policies with the same meaning encode to the same bytes) and `Check`, which answers offline whether a policy would allow a described request (route, access, roles and forwarded path; tokens, rate limits, bodies and blocked accounts need a running gateway).
- `examples/embed` is a runnable host program with its own test.

## Compile-time modules

- A module adds a check to the request pipeline at build time.
- It implements `module.Control` from `github.com/Alex-Zechariah-02/apiward/module` and registers itself from `init` with `module.Register`; a custom binary is a copy of `cmd/apiward` with one blank import per module, built with plain `go build`.
- There is no runtime loading.

- Phases are fixed in code, never configured: `ingress` (after the ingress checks, before a policy is captured), `identity` (after token verification), `authorise` (after roles and blocked accounts), `traffic` (after the rate limit) and `validate` (after body and header validation).
  - Within a phase the built-in control runs first, then modules in ID order.
  - A module cannot skip a later stage and never forwards anything.
- A module's settings are the operation member named by its ID.
  - They are compiled once with the policy; a `Compile` error or panic refuses the draft with `MODULE_FAILED`.
  - A member no module in the build reads is refused with `UNKNOWN_FIELD`, so a policy written for another build never loses a check silently.
  - Ingress modules take no settings.
- A check sees a copy of the method, path, client address, headers (without the bearer token) and the verified subject and roles: no body and no connection.
  - `Refuse` ends the request with a 4xx status and code; `Fail`, a panic or a missing result ends it with `503 gateway_unavailable`.
  - Per-key state goes into a bounded `module.Table`, which refuses new keys when full.
- Each request record holds a `modules` member with every non-built-in module's result (`PASS`, `REJECT`, `FAIL`, `NA` for not configured, `NE` for not reached); a module refusal or failure is recorded at the stage of its phase. `apiward version` and `GET /admin/status` (`build`) list the version, the Go toolchain and every compiled-in control, the five built-ins (`jwt`, `rbac`, `rate`, `body`, `validation`) included; the Dashboard shows them on the Team page.
