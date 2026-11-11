# Lightweight Security Policy Gateway for REST APIs

This Go gateway enforces a shared, configurable security policy before requests reach REST APIs. It runs its own HTTP server and reverse proxy using the Go standard library.

## Security controls

The gateway has five security controls:

- **JWT authentication** checks RS256 access tokens with a trusted issuer, audience, expiry, subject and named signing key.
- **Role-based access control** allows or blocks each call by the role of the caller.
- **Rate limiting** counts requests per account or direct client address for each operation over a sliding time window. Public operations use the client address; an IPv6 client is counted by its `/64` (`data.ipv6_rate_prefix`, 48 to 128), so one client cannot escape its limit by rotating addresses inside its own network, while blocked addresses and the security log keep the exact address. A request above the limit gets the answer 429 and goes no further.
- **Request validation** checks the JSON body and selected headers against the operation's bounded JSON Schema. Bodies can include arrays with item schemas and item-count limits. Ambiguous fields and malformed Unicode are rejected.
- **Security event logging** records each security decision in a local file. A request goes to an API only after its record is safely on disk. If the log cannot be written, the gateway stops letting requests through.

Each request uses one policy version from start to end. When one control rejects a request, it never reaches an API. The gateway checks tokens from an outside identity provider and does not issue tokens itself. A token's `kid` selects one of the trusted public keys. Roles come from verified token claims and are kept only when the captured policy defines them. A separate blocked-account list refuses a verified account immediately and survives policy rollback. Public keys can be reloaded from operator files; an invalid reload keeps the current key set.

Policy documents use schema version 4 or 5 and contain roles and permits without per-user membership. Version 5 adds service addresses on other hosts (below); a version 4 document is read exactly as before. Version 3 policies are refused rather than converted automatically. A fresh demonstration creates a version 4 policy.

An API may rewrite the path its upstream receives with `"forward": {"strip_prefix": "/api", "add_prefix": "/v2"}` (either or both): `/api/orders/7` is forwarded as `/v2/orders/7`, and `/api` as `/v2` (`/` when nothing is left). Both prefixes are fixed paths without a trailing `/`, `*`, `%`, `.` or `..` segment, and the strip prefix must lead every target of the API at a segment boundary; otherwise the policy is refused `REWRITE_INVALID`. Routing, access, sign-in, roles, rate limits, validation and the security log all use the path the client sent; the rewrite is applied only when the request is forwarded. The rewritten path is checked again, and a request whose rewritten path is not canonical is refused `400 path_not_canonical`. The security log records `forwarded_path` beside `path` when the two differ.

An operation may carry host and header conditions with `"when": {"hosts": ["api.example.com", "*.example.com"], "headers": [{"name": "X-Version", "value": "2"}]}`: 1 to 16 lower-case host names (exact, or `*.` followed by a domain, which matches any name ending in that domain, never the domain itself) and 1 to 8 headers with exact values; every condition must hold. The request's `Host` is compared without its port and case. A header holds only when the request carries it exactly once with that value, and only names a header schema could declare are allowed. Several operations may share a target and method: the one with the most conditions that hold is selected, else the one without conditions; when none applies the request is answered `404`. Conditions only select an operation, whose own access, sign-in, roles, rate and body rules decide. The compiler refuses two conditioned operations of equal rank that one request could meet (`TARGET_COLLISION`) and a conditioned operation weaker than the unconditioned one beside it (`CONDITION_WEAKER`): allowed where that one is denied, public where it requires sign-in, a role it does not permit, a missing, differently keyed or looser rate rule, a body it refuses or a larger or different one, or a missing header schema. The access checker takes optional `host` and `headers` (an object of names and values) to check such a request; the change preview reports requests to conditioned operations as unknown, since the log keeps neither.

An API may let web pages on other sites call it from a browser with `"cors": {"origins": ["https://shop.example.com"], "methods": ["GET", "POST"], "headers": ["Content-Type"], "expose": ["X-Total"], "credentials": false, "max_age_seconds": 600}`: 1 to 32 exact lower-case origins (`scheme://host[:port]`, no path, no default port) or exactly `["*"]`, which is allowed only without credentials on an API whose operations are all public (otherwise `CORS_WILDCARD_NOT_ALLOWED`); methods of the API's own operations; up to 32 request headers and 16 exposed headers; a preflight cache time of 0 to 86400 seconds (600 by default). The gateway answers a preflight (`OPTIONS` with `Origin` and `Access-Control-Request-Method`) on such an API itself and never forwards it: `204` with the CORS headers when the origin, the method and every requested header are allowed, `204` without them otherwise. Preflights are recorded as `request.preflight` events (decision `allowed` or `refused`, code `cors_preflight` or `cors_refused`) and, when one of the API's public operations has a rate rule, limited per client address by the first such rule on a counter of their own. Every answer for the API, refusals included, carries `Access-Control-Allow-Origin` and `Vary: Origin` for an allowed origin; CORS headers from the upstream are replaced. Browser access never admits a request: every other check applies unchanged.

An API's `"response_headers": {"hsts": true, "nosniff": true, "frame": "deny", "referrer": "no-referrer", "remove": ["Server"]}` adds `Strict-Transport-Security: max-age=31536000` (only on requests received over TLS), `X-Content-Type-Options: nosniff`, `X-Frame-Options` (`deny` or `sameorigin`) and `Referrer-Policy` (`no-referrer` or `strict-origin-when-cross-origin`) when the upstream did not set them, and removes up to 16 named upstream headers (never the gateway's own headers, `Access-Control-*` or the response framing). Gateway refusals always carry `X-Content-Type-Options: nosniff`.

An API's `"allow_addresses": ["10.0.0.0/8", "2001:db8::/32"]` (1 to 256 ranges in canonical CIDR form) admits only those client addresses: others are refused `403 address_not_allowed` before any other check of the operation. A separate blocked address list in the gateway's database refuses a client address at once, before the policy is consulted, with `403 address_blocked`, and survives policy rollback. The Admin API manages it like the blocked accounts: `GET /admin/blocked-addresses`, `PUT /admin/blocked-addresses/{range}` (`{"reason", "expires_at"?}`, an expiry 1 minute to 30 days ahead) and `DELETE /admin/blocked-addresses/{range}`, with `{range}` a URL-encoded canonical CIDR (a single address is `/32` or `/128`; an IPv4-mapped range is stored as IPv4), at most 1,024 entries, recorded in the history as `address.block` and `address.unblock`. The client address is the direct peer of the connection.

An upstream is either `{"id": "orders", "dial": "127.0.0.1:9502"}` (plain HTTP to an address on the gateway's host) or, in schema version 5, `{"id": "orders", "url": "https://orders.internal:8443", "tls": "fetch", "host": "upstream"}`. A `url` is `http://` with a literal IP address, or `https://` with a literal IP address or a lower-case DNS name, with an optional port and nothing after it. `tls` names a TLS profile of the gateway's settings (https only); `host` chooses the `Host` header the upstream receives: `inbound` keeps the client's (the default for http), `upstream` sends the URL's host (the default for https). Loopback, private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`) and shared (`100.64.0.0/10`) addresses are allowed; public addresses only when the settings set `"upstream": {"allow_public_addresses": true}`. Unspecified, link-local (which includes `169.254.169.254`), multicast and broadcast addresses and the cloud metadata addresses `fd00:ec2::254`, `fd20:ce::254`, `100.100.100.200` and `168.63.129.16` are always refused. The address is checked when the policy is saved and again on the resolved address of every connection, just before it is made, so a DNS answer cannot lead elsewhere; a refused connection is answered `502 upstream_unavailable` with the security log reason `destination_refused`, and nothing is sent. Connections use TLS 1.2 or later and HTTP/1.1, verify the certificate for the URL's host against the profile's CA file (or the system roots) and present the profile's client certificate. Upstream connections are kept and reused: up to `upstream.max_idle_per_upstream` idle connections per upstream (default 16; 0 opens a new connection for every request and closes it after the response), each closed after `upstream.idle_conn_timeout` idle (default `30s`, `1s` to `5m`; keep it below the upstream server's own idle timeout). A request is sent once: one that fails on a reused connection is never sent again, and is answered like any exchange that may have reached the upstream (security log reason `outcome_unknown`). TLS sessions to https upstreams are resumed for at most `upstream.tls_session_lifetime` (default `1h`, `1m` to `24h`), with one session cache per TLS profile that a reload replaces; on a resumed session the upstream relies on the client certificate it verified in the first handshake. The settings list the profiles as `"upstream": {"tls_profiles": [{"id": "fetch", "ca_file": "/etc/gateway/fetch-ca.pem", "client_certificate_file": "/etc/gateway/gateway.crt", "client_key_file": "/etc/gateway/gateway.key"}]}` (up to 32; absolute paths; the key is PKCS #8 RSA of at least 2,048 bits or ECDSA P-256 and, on Unix, must not be readable by the group or others). They are read at start and again by `POST /admin/keys/reload`, which keeps the old ones if the new ones are invalid or drop a profile the active policy uses. `GET /admin/tls-profiles` lists them without paths or keys. A policy naming an unknown profile is refused `UNKNOWN_TLS_PROFILE`. Failed TLS connections are logged as `certificate_invalid` or `tls_handshake_failed`, with the address dialled as `upstream_address`.

Upstreams can verify that a request passed the gateway. With `"upstream": {"identity_key": "/etc/gateway/identity.pem"}` (an ECDSA P-256 private key as one PKCS #8 `PRIVATE KEY` PEM block, readable only by its owner; for example `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`), every forwarded request also carries `X-Gateway-Assertion`: a JWT signed with ES256, with `iss` `apiward`, `aud` the API's ID, `sub` and `roles` as in `X-Gateway-Subject` and `X-Gateway-Roles` (both absent on a public operation), `jti` the request ID, `iat`, and `exp` 30 seconds later. Its `kid` is the key's RFC 7638 thumbprint. The public key is a JSON Web Key Set at `GET /.well-known/apiward/jwks.json` on the admin listener (no session needed), and `gateway jwks --config <file>` prints the same set without a running gateway, for the file an upstream on another host reads. An upstream should require exactly one assertion, verify it with that key set accepting only ES256, require its own API ID as `aud`, refuse an expired one allowing a few seconds of clock difference, and take the account from the assertion, not the plain headers. An assertion is not bound to the method, path or body, so whoever can read the connection to an upstream could replay one against the same API for up to 30 seconds: use TLS to upstreams on other hosts. A client's own `X-Gateway-Assertion` is removed like every `X-Gateway-` header. To replace the key, give the upstreams a key set holding the old and new keys, restart the gateway with the new key, then remove the old one from the set. Without the setting nothing is signed.

The data listener serves HTTPS when the settings name certificate files: `"data": {"tls": {"files": {"certificate_file": "/etc/gateway/tls/api.crt", "key_file": "/etc/gateway/tls/api.key"}}}` (absolute paths; chain leaf first; the key as for TLS profiles; the certificate valid when loaded). Overload is bounded on the data listener: at most `data.max_connections` open connections (default 1,024; one more is accepted and closed at once, counted in `gateway_connections_refused_total`) and `data.max_in_flight` requests inside enforcement (default 256; one more is answered `503 overloaded` with `Retry-After: 1` before any token check or body read, and recorded at `INGRESS`). It speaks TLS 1.2 or later with HTTP/2 and HTTP/1.1 chosen by ALPN (`"http2": false` under `data` keeps HTTP/1.1 only; at most 100 concurrent streams and 64 KiB of buffered request body per connection), and upstreams then receive `X-Forwarded-Proto: https` and `Via: 2 gateway` for HTTP/2 requests; upstream connections stay HTTP/1.1. A plain-HTTP data listener serves HTTP/1 only. The files are read again on `SIGHUP` and with every `POST /admin/keys/reload`; a reload that fails keeps the current certificate and writes a `tls.reload_failed` record, and a certificate within 14 days of expiry writes `tls.certificate_expiring` once a day. Automatic certificates (ACME) are not built in: renew the files with a tool such as certbot and reload. `"redirect_http": {"listen": "0.0.0.0:80", "origin": "https://api.example.com"}` under `data` adds a plain HTTP listener that answers every request with `308` to that origin plus the request's path and query; it never forwards, reads no body and counts its answers in `gateway_redirects_total`. A listen address of `0.0.0.0` or `[::]` (every interface) is refused unless `"listen_all_interfaces": true` is set under `data`; the metrics listener leaves loopback only with `"metrics_listen_any": true` under `gateway`. The admin listener always stays on loopback: reach it through an SSH tunnel. The metrics listener also answers `GET /livez` (`200 ok` while the process serves) and `GET /readyz` (`200 ok` only in normal mode with a published policy, when the security log has not failed and the certificate, if any, is valid; else `503 unavailable`); `gateway health --config <file>` asks `/readyz` and exits 0 only when ready.

Capacity ceilings are settings under `limits`, each optional with today's default and a hard maximum: `policy_bytes` (65,536; also the maximum, the database's bound on a stored policy), `apis` (64, up to 256; also bounds upstreams), `operations` (256, up to 4,096), `roles` (64, up to 256), `permits` (4,096, up to 65,536), `rate_counters` (262,144, up to 1,048,576; about 257 bytes of memory each) and `monitor_window` (10,000 recent requests kept for live views, up to 100,000). A policy over a ceiling is refused `LIMIT_EXCEEDED`, so a policy saved under raised settings is refused by a gateway with lower ones. A token carries at most 64 roles whatever the role ceiling. `GET /admin/limits` reports the effective values. The offline commands and the `policy` package check against the defaults.

## Safe policy changes

A policy can pass all checks and still cause problems when it is in use. Administrators can change the shared policy through two workflows:

- **Confirmed Policy Activation.** A new permanent policy starts as provisional and is enforced at once, with a confirmation deadline of 1 second to 24 hours. An administrator confirms it or rolls it back. If nobody confirms it in time, the gateway goes back to the previous policy by itself, also when it was stopped over the deadline. A provisional policy never admits a request after its deadline, even if the rollback runs late. Only one provisional policy can exist at a time, and each one ends exactly once.
- **Temporary Policy Override.** An administrator can give a role one more operation or take one away, raise or lower an operation's rate limit, or block an operation, for 1 second to 24 hours. The change is applied on top of the permanent policy without changing it, and it ends by itself at its expiry time or when it is revoked. It cannot skip token checks or request checks, reduce logging, open a blocked operation or change where requests go. Two overrides cannot change the same thing, and a new permanent policy that would clash with an override is refused. While a provisional policy waits for confirmation, no new override can be made. Rate counts carry over, so an override never gives a fresh quota. A restored backup never brings an old override back.

## Import an OpenAPI description

`gateway policy import-openapi` turns an OpenAPI 3.0 or 3.1 description (JSON, or YAML 1.2) into a new policy file for review. It runs offline: it reads only the files it is given, never fetches a `$ref`, and never activates anything. Stage the result as a draft, trial it and confirm it like any other change.

```
gateway policy import-openapi --spec <file.json|.yaml|.yml> --api <id> --upstream <id>
  --base <policy.json> [--max-body-bytes <n>] [--with-permits] --out <new file> --report <new file>
```

| Flag | Meaning |
|---|---|
| `--spec` | The description, at most 1 MiB; the extension chooses JSON or YAML |
| `--api` | The API to create, or to replace with its operations and the permits that name them |
| `--upstream` | An upstream already in `--base` that serves the API |
| `--base` | The policy to build on, for example the output of `demo policy export` |
| `--max-body-bytes` | Body limit for imported request bodies without `x-apiward-max-bytes`: 1 to 1,048,576, default 16,384 |
| `--with-permits` | Read `x-apiward-roles` into permits, adding missing roles; without it no permit is created |
| `--out`, `--report` | New files; the command never overwrites a file and writes both or neither |

Exit status: `0` every operation mapped; `2` both files written, but some operations were refused or widened (read the report); `1` nothing written (bad flags, unreadable or refused description, an output file exists, or the result does not compile).

**How it maps.** Each path and method becomes one operation `<api>.<operationId>`, allowed, with sign-in required unless the description says `security: []`. No permits are created unless `--with-permits` reads `x-apiward-roles`; grant roles afterwards. A path whose last segment is a parameter (`/orders/{id}`) becomes the prefix `/orders/*`, which also matches deeper paths. Header parameters become the header schema; query, path and cookie parameters are listed as not enforced. A JSON request body becomes a body rule. Schema `$ref`s inside the file are inlined, descriptive keywords (`description`, `example`, `x-…`) are removed, and an object without `additionalProperties` allows extra fields, as OpenAPI does. Every operation is checked by the gateway's own compiler, and the whole result is compiled before anything is written.

**What is refused.** An operation is left out, with a code in the report, when it cannot be expressed exactly: `TRACE` (`METHOD_REFUSED`); a missing or invalid `operationId` (`OPERATION_ID_INVALID`, with a suggestion) or one used twice (`OPERATION_ID_DUPLICATE`); a parameter in the middle of a path (`PATH_TEMPLATE_UNSUPPORTED`); two operations on the same method and target (`TARGET_COLLISION`); API keys, Basic, mutual TLS or optional sign-in (`SECURITY_SCHEME_UNSUPPORTED`); non-JSON bodies (`MEDIA_TYPE_UNSUPPORTED`); a schema keyword the gateway cannot enforce, such as `format`, `pattern` or `oneOf` (`SCHEMA_KEYWORD_UNSUPPORTED`; dropping it would accept more than described); a `$ref` to another file (`EXTERNAL_REF`), a missing one (`REF_INVALID`) or a circular one (`SCHEMA_CYCLE`); a schema deeper than 16 levels or larger than 4,096 values once inlined (`SCHEMA_LIMIT_EXCEEDED`); and anything else the compiler rejects (`COMPILER_REFUSED`, with its code and field). YAML anchors, aliases, merge keys, tags, several documents in one file, duplicate or non-string keys and `.nan`/`.inf` refuse the whole file, naming the line.

**Report.** JSON; every list is always present:

```json
{"spec_version": "3.1.0", "source_format": "yaml", "api": "orders", "operations_in_spec": 8,
 "mapped": [{"method": "GET", "path": "/orders", "operation": "orders.listOrders", "target": "/orders", "auth": "required"}],
 "widened": [{"method": "GET", "path": "/orders/{id}", "operation": "orders.getOrder", "target": "/orders/*", "auth": "required", "note": "matches /orders/<anything>, including deeper paths"}],
 "assumed": [{"operation": "orders.createOrder", "field": "body.max_bytes", "value": 16384}],
 "changed": [{"operation": "orders.updateOrder", "field": "body", "note": "The description allows no body; the gateway refuses a request without one (415 without a JSON Content-Type, else 400 malformed_json)."}],
 "refused": [{"method": "GET", "path": "/orders/{id}/items", "code": "PATH_TEMPLATE_UNSUPPORTED", "message": "A templated segment followed by more segments cannot be expressed."}],
 "needs_permissions": ["orders.listOrders", "orders.getOrder"],
 "scopes_not_mapped": ["orders:read"],
 "not_enforced": [{"operation": "orders.listOrders", "parameter": "page", "in": "query"}],
 "annotations_removed": [{"operation": "orders.createOrder", "field": "#/components/schemas/NewOrder/description"}],
 "removed_operations": ["orders.old"],
 "removed_permits": [{"role": "customer", "operation": "orders.old"}],
 "ignored": ["responses", "servers", "tags"]}
```

`mapped` and `widened` list the imported operations (`note` explains a default they rely on); `assumed` lists values the import chose; `changed` lists behaviour the gateway enforces differently from the description; `refused` entries may add `field` (a JSON Pointer into the description, or the compiler's field) and `suggestion`; `needs_permissions` lists the signed-in operations no role can call yet; `removed_operations` and `removed_permits` are what replacing `--api` took out of the base; `ignored` names description members with no effect on the policy (`servers`, `responses`, `callbacks`, `webhooks`, `links`, `tags`).

**Gateway extensions.** An operation may carry the members the export writes; each is checked, and any other `x-apiward-…` member refuses the operation (`EXTENSION_INVALID`):

| Member | Value | Effect |
|---|---|---|
| `x-apiward-target` | the prefix target the path stands for, such as `/orders/*` for `/orders/{rest}` | the operation is mapped, not widened: the description states that deeper paths match |
| `x-apiward-access` | `allow` or `deny` | the operation's access; absent means `allow` |
| `x-apiward-rate` | `{"algorithm": "sliding-window", "count", "window_seconds", "key"}` | the operation's rate rule, as in a policy |
| `x-apiward-max-bytes` | 1 to 1,048,576 | the body limit; needs a request body |
| `x-apiward-roles` | list of role identifiers | the roles permitted, read only with `--with-permits` |
| `x-apiward-when` | `{"hosts", "headers"}`, as in a policy | the operation's host and header conditions |

At the root, `x-apiward-forward`, `x-apiward-cors`, `x-apiward-response-headers` and `x-apiward-addresses` become the imported API's `forward`, `cors`, `response_headers` and `allow_addresses`, each with exactly the members of the policy's; any other member, or a value of another shape, refuses the description.

## Export a policy as OpenAPI

`gateway policy export-openapi` writes one API of a policy as an OpenAPI 3.1 description (JSON, or YAML by the `--out` extension), for review or for tools that read OpenAPI. Importing that file onto the same policy with `--with-permits` gives the same policy back.

```
gateway policy export-openapi --policy <policy.json> --api <id>
  --out <new file.json|.yaml|.yml> --report <new file> [--with-upstream]
```

Each operation becomes the path and method of its target, with `operationId` = the operation identifier without the `<api>.` prefix. A prefix target `/orders/*` becomes `/orders/{rest}` with `x-apiward-target: /orders/*`. Sign-in required becomes the bearer scheme `apiward`; public becomes `security: []`. A body rule becomes a required `application/json` request body with its schema and `x-apiward-max-bytes`; a header schema becomes header parameters (its root `additionalProperties` is not written, since the gateway checks declared headers only). Access, rate rule and permitted roles go into `x-apiward-access`, `x-apiward-rate` and `x-apiward-roles`; the API's forward rule, browser access, response headers and address allow list go into the root members `x-apiward-forward`, `x-apiward-cors`, `x-apiward-response-headers` and `x-apiward-addresses`, and an operation's conditions into `x-apiward-when`. A description holds one operation per path and method, so a second operation on the same target and method (a conditioned one, after the one without conditions) is not exported and is reported `changed`. The upstream address is written as a server only with `--with-upstream`.

Exit status: `0` the description means exactly what the policy does; `2` both files written, but something differs (read `changed`): a prefix target, which OpenAPI reads as one segment while the gateway also matches deeper paths; an identifier without the `<api>.` prefix, which comes back with it; a target containing `{` or `}`, which is not exported; `1` nothing written. The report lists `exported` (`operation`, `method`, `path`), `changed` (`operation`, `field`, `note`) and `omitted` (what a flag would add).

## Moving to or from another gateway

An API's routes, methods and request schemas move between gateways through standard OpenAPI. Many gateways can export an API as an OpenAPI description, and `gateway policy import-openapi` turns it into a candidate policy (above). In the other direction, `gateway policy export-openapi` writes a description that other gateways' OpenAPI importers can read; they ignore the `x-apiward-*` members.

Sign-in, trusted issuers, roles, rate limits and other gateway-specific settings have no standard form, so they are not translated between products: set them again in the target gateway, and review every imported policy before staging it. Consumers and their credentials stay in the identity provider.

## Embedding in a Go application

A Go program can run the gateway inside itself instead of beside it. The program serves the gateway's data plane on its own HTTP server; the gateway keeps its Admin API and metrics listeners, its database, its audit log and its start and stop. Every request still passes the full pipeline.

```go
cfg, err := apiward.LoadConfig("gateway.json") // the same file `gateway run` reads
gw, err := apiward.New(cfg, logger)            // takes the deployment lock; binds nothing
err = gw.Start()                               // Admin API and metrics; requests admitted from now on
mux.Handle("/api/", http.StripPrefix("/api", gw)) // policy targets are the paths below /api
server := &http.Server{Addr: ":8080", Handler: mux}
gw.ServerSettings().Apply(server)              // header size and timeouts from the configuration
// ... serve; on shutdown stop the server first, then:
err = gw.Stop(ctx)                             // waits for requests in progress, then closes the audit log
```

- Import `github.com/Alex-Zechariah-02/apiward`. The deployment is installed and its first policy published as for the binary (`gateway install`, then the Dashboard). The configuration's `data.listen` is still required and checked, but an embedded gateway never binds it.
- Before `Start` and from `Stop` on, every request is refused with `503 gateway_unavailable` and recorded. `Start` and `Stop` each run once.
- Errors from `LoadConfig`, `New`, `Start` and `Stop` match exactly one of `ErrConfig`, `ErrLocked`, `ErrStorage`, `ErrListen`, `ErrStarted`, `ErrStopped` or `ErrIncomplete` with `errors.Is`. Refused requests are HTTP responses, never Go errors.
- Apply `ServerSettings` to your server: the gateway cannot enforce header size, timeouts or the connection cap (`data.max_connections`) on a server it does not own. Body limits and every other check stay in the handler. Do not rewrite `RemoteAddr` from client headers before the gateway: address lists and per-address rate limits read it.
- Package `github.com/Alex-Zechariah-02/apiward/policy` holds the policy document types, `Decode`, `Encode` (the canonical form: two policies with the same meaning encode to the same bytes) and `Check`, which answers offline whether a policy would allow a described request (route, access, roles and forwarded path; tokens, rate limits, bodies and blocked accounts need a running gateway).
- `examples/embed` is a runnable host program with its own test.

## Compile-time modules

A module adds a check to the request pipeline at build time. It implements `module.Control` from `github.com/Alex-Zechariah-02/apiward/module` and registers itself from `init` with `module.Register`; a custom binary is a copy of `cmd/gateway` with one blank import per module, built with plain `go build`. There is no runtime loading.

- Phases are fixed in code, never configured: `ingress` (after the ingress checks, before a policy is captured), `identity` (after token verification), `authorise` (after roles and blocked accounts), `traffic` (after the rate limit) and `validate` (after body and header validation). Within a phase the built-in control runs first, then modules in ID order. A module cannot skip a later stage and never forwards anything.
- A module's settings are the operation member named by its ID. They are compiled once with the policy; a `Compile` error or panic refuses the draft with `MODULE_FAILED`. A member no module in the build reads is refused with `UNKNOWN_FIELD`, so a policy written for another build never loses a check silently. Ingress modules take no settings.
- A check sees a copy of the method, path, client address, headers (without the bearer token) and the verified subject and roles: no body and no connection. `Refuse` ends the request with a 4xx status and code; `Fail`, a panic or a missing result ends it with `503 gateway_unavailable`. Per-key state goes into a bounded `module.Table`, which refuses new keys when full.
- Each request record holds a `modules` member with every non-built-in module's result (`PASS`, `REJECT`, `FAIL`, `NA` for not configured, `NE` for not reached); a module refusal or failure is recorded at the stage of its phase. `gateway version` and `GET /admin/status` (`build`) list the version, the Go toolchain and every compiled-in control, the five built-ins (`jwt`, `rbac`, `rate`, `body`, `validation`) included; the Dashboard shows them on the Team page.

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

### Code layout

Each package under `internal/` imports only the packages listed before it; a test enforces the order, and which internal packages each public package may reach.

- `apiward` (repository root): the public package for running the gateway inside a Go program (above).
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

- `cmd/gateway` runs the gateway from one strict JSON configuration file. It has the commands `run`, `install`, `enrol`, `backup`, `restore`, `migrate` and `health`, each with `--config <file>`, and the offline `policy import-openapi` and `policy export-openapi` (see above). The local commands `install`, `enrol`, `backup`, `restore` and `migrate` run while the gateway is stopped.

```
go build -trimpath -o <out-dir>/gateway.exe ./cmd/gateway
go build -trimpath -o <out-dir>/testfixture.exe ./cmd/testfixture
```

### Building a release

A release binary carries the Dashboard, so one file serves the gateway and its admin interface. Build the Dashboard, copy its build into `internal/adminui/dist` (ignored by Git), then build with the `embedui` tag:

```
cd dashboard && npm ci && npm run build && cd ..
rm -rf internal/adminui/dist && cp -r dashboard/dist internal/adminui/dist
go build -trimpath -tags embedui -o <out-dir>/gateway ./cmd/gateway
```

A build without the tag needs no Node.js and serves no Dashboard unless `gateway.admin_ui` names a directory of built files. When `admin_ui` is set it is used instead of the embedded build; the start log line `dashboard files` names the source (`directory`, `embedded` or `none`). Either way the Dashboard is served only on the Admin API listener. The page is never cached; the files under `assets/` are cached by the browser for a year (their names change with their content) and the build's gzip copies of the scripts and style sheets are sent as they are, or inflated for a client that does not accept gzip.

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

The dashboard is in `dashboard/` (React and TypeScript, built with Vite). Its browser tests drive a real demonstration made by the Fetch demo tool from `../fetch` (see `dashboard/README.md`).

### Container image

`Dockerfile` builds one image of the gateway with the Dashboard inside. Node.js 24 builds the Dashboard, Go 1.27.4 builds a static `gateway` with the `embedui` tag and cgo off, and the final image is built from `scratch`: the program, plus the certificate authority bundle, `passwd`, `group` and `nsswitch.conf` taken from the distroless static Debian 13 image. It runs as that image's `nonroot` user, UID and GID 65532, and has no shell, time zone data or other system files. Every base image is pinned by digest. In a checkout:

```
docker build -t apiward:dev .
```

`--build-arg REVISION=$(git rev-parse HEAD)` records the commit in the label `org.opencontainers.image.revision`. `docker buildx build --sbom=true --output type=local,dest=<new-folder> .` also writes the image's software bill of materials as `sbom.spdx.json`; it needs the containerd image store or a `docker-container` builder. No image is published to a registry.

The image runs `gateway run --config /etc/apiward/apiward.json`. Mount the settings, keys and certificates read-only at `/etc/apiward`, with every path in the settings under that folder. The only writable folder is `/var/lib/apiward`, so the settings keep the database and the security log there: mount a local named volume or host folder on it, since SQLite's write-ahead log does not work over a network file system (https://www.sqlite.org/wal.html). Key files must belong to UID 65532 and be readable by it alone (mode 600; for example `sudo chown -R 65532:65532 <folder>`): the gateway refuses a key that others can read. Secrets stay in those files, never in environment variables.

Install the first administrator once, before the first start:

```
docker run --rm -v apiward-data:/var/lib/apiward -v "$PWD/apiward:/etc/apiward:ro" apiward:dev install --config /etc/apiward/apiward.json --admin <name>
```

`install` prints a one-time enrolment secret; keep it private. Then start the gateway:

```
docker run -d --name apiward --network host --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --stop-timeout 30 \
  -v apiward-data:/var/lib/apiward -v "$PWD/apiward:/etc/apiward:ro" apiward:dev
```

and in the Dashboard choose **First Sign-In with an Enrolment Secret**, then establish the first policy. The image's health check runs `gateway health`, which asks the metrics listener's `/readyz`, so a new gateway reports unhealthy until its first policy is published. `docker stop` sends `SIGTERM`; give the gateway at least 30 seconds to stop (`--stop-timeout 30`, or `stop_grace_period: 30s` in Compose).

The admin listener always stays on loopback and is never published, so the image runs on the host's network (`--network host`) on Linux with Docker Engine. The Dashboard is then on the host's `127.0.0.1`; from another machine, reach it through `ssh -N -L 9440:127.0.0.1:9440 <user>@<host>` with the same port on both ends, since the browser's `Host` must equal the admin listen address. The listeners use the addresses and ports of the settings: `-p` is ignored with host networking, and no address translation sits in the request path. Docker Desktop offers host networking only as an opt-in setting (version 4.34 or later, Settings > Resources > Network, signed in to Docker), at layer 4 and without binding the host's IP addresses, so it is not the documented setup.

The Fetch repository's `compose.yaml` runs this image beside the Fetch services on one Linux host, with settings its demo tool writes; its README, "Containers", walks through a complete first run.

### Demonstration

The Fetch repository runs the whole local demonstration, the gateway and this Dashboard included, with one command (`go run ./cmd/demo up` in a Fetch checkout beside this one); its README lists the demo accounts, addresses and commands. The dashboard is then at `http://127.0.0.1:9440/` and the shop at `http://127.0.0.2:9480/`, through the gateway; metrics are at `http://127.0.0.1:9450/metrics`. `EAT_PORT_OFFSET` shifts every port.

The gateway rejects a Caddy JSON configuration file and never converts one by itself. Keep the gateway stopped when running local operator commands; a deployment lock prevents two processes from sharing a database. Successful operator commands exit 0; refusals and failures exit 1. `install` and `enrol` print a one-time secret intentionally: keep that output private. On Windows, file modes do not establish confidentiality. Existing deployment and backup directories need operator-managed DACLs. New demonstration directories receive a protected DACL for the current user, SYSTEM and administrators; this does not isolate them from a privileged host administrator.

## Out of scope

The project does not cover the full OWASP API Security Top 10, distributed systems, Kubernetes or new cryptographic methods.
