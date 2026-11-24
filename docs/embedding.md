# Embedding and modules

Back to the [README](../README.md).

## Embedding in a Go application

A Go program can run the gateway inside itself instead of beside it. The program serves the gateway's data plane on its own HTTP server; the gateway keeps its Admin API and metrics listeners, its database, its audit log and its start and stop. Every request still passes the full pipeline.

```go
cfg, err := apiward.LoadConfig("apiward.json") // the same file `apiward run` reads
gw, err := apiward.New(cfg, logger)            // takes the deployment lock; binds nothing
err = gw.Start()                               // Admin API and metrics; requests admitted from now on
mux.Handle("/api/", http.StripPrefix("/api", gw)) // policy targets are the paths below /api
server := gw.Server(mux)                        // header size, timeouts and protocols from the configuration
server.Addr = ":8080"
// ... serve; on shutdown stop the server first, then:
err = gw.Stop(ctx)                             // waits for requests in progress, then closes the audit log
```

- Import `github.com/Alex-Zechariah-02/apiward`. The deployment is installed and its first policy published as for the binary (`apiward install`, then the Dashboard). The configuration's `data.listen` is still required and checked, but an embedded gateway never binds it.
- Before `Start`, every request is refused with `503 gateway_unavailable` and recorded; once `Stop` has waited for the requests in progress, later ones are refused `503` before the pipeline, since the audit log is closing. `Start` and `Stop` each run once.
- Errors from `LoadConfig`, `New`, `Start` and `Stop` match exactly one of `ErrConfig`, `ErrLocked`, `ErrStorage`, `ErrListen`, `ErrStarted`, `ErrStopped` or `ErrIncomplete` with `errors.Is`. Refused requests are HTTP responses, never Go errors.
- Serve with the server `Server(handler)` returns (`nil` serves the gateway itself): it already carries the configured header size, timeouts and protocols, so set only its address or listener and TLS. Its HTTP/2 protocol errors are counted in `gateway_http2_errors_total`.
- The server's `ConnContext` is also set, so each connection reads one request body at a time; without it an HTTP/2 connection could hold a body per stream. A `ConnContext` of your own must call the one already set.
- `New` refuses the settings only the gateway's own listener applies, naming them: `data.tls`, `data.redirect_http`, `data.max_connections`, `data.max_connections_per_address` and `data.listen_all_interfaces`. Your server owns its TLS, connection limit and addresses.
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
  - A member no module in the build reads is refused with `UNKNOWN_FIELD` naming the member, so a policy written for another build never loses a check silently.
  - A setting must pass the policy's JSON bounds (nesting, value count); it is stored with its object members sorted, so one meaning has one form.
  - Member names inside a setting may use any case and characters (`maxItems`, `$ref`), as inside a schema; repeated names are still refused.
  - Ingress modules take no settings.
- A check sees a copy of the method, path, client address, headers (without the bearer token) and the verified subject and roles: no body and no connection.
  - `Refuse` ends the request with a 4xx status and code; `Fail`, a panic or a missing result ends it with `503 gateway_unavailable`.
  - A `Fail` reason is recorded when it is 1 to 128 bytes of printable ASCII, otherwise as `invalid failure reason`; it never holds request data.
  - The header map is copied once per phase and shared by its checks: a check reads it and never changes it.
  - A phase's checks together are bounded by `data.write_timeout`; a phase that runs past it fails the request.
  - A module that keeps per-key state bounds it itself and fails closed when full; it never keeps mutable package-level state.
- Each request record holds a `modules` member with every non-built-in module's result (`PASS`, `REJECT`, `FAIL`, `NA` for not configured, `NE` for not reached); a module refusal or failure is recorded at the stage of its phase. `apiward version` and `GET /admin/status` (`build`) list the version, the Go toolchain and every compiled-in control, the five built-ins (`jwt`, `rbac`, `rate`, `body`, `validation`) included; the Dashboard shows them on the Team page.
