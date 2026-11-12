# Settings reference

The JSON settings file that `apiward run --config <file>` reads. Upstream TLS profiles, connection reuse and address rules are in [policy.md](policy.md), "Upstreams"; capacity limits in "Capacity limits". Back to the [README](../README.md).

## Data listener

### HTTPS

- The data listener serves HTTPS when the settings name certificate files: `"data": {"tls": {"files": {"certificate_file": "/etc/apiward/tls/api.crt", "key_file": "/etc/apiward/tls/api.key"}}}` (absolute paths; chain leaf first; the key as for TLS profiles; the certificate valid when loaded).

### Overload limits

- Overload is bounded on the data listener: at most `data.max_connections` open connections (default 1,024; one more is accepted and closed at once, counted in `gateway_connections_refused_total`) and `data.max_in_flight` requests inside enforcement (default 256; one more is answered `503 overloaded` with `Retry-After: 1` before any token check or body read, and recorded at `INGRESS`).

### Protocols

- It speaks TLS 1.2 or later with HTTP/2 and HTTP/1.1 chosen by ALPN (`"http2": false` under `data` keeps HTTP/1.1 only; at most 100 concurrent streams and 64 KiB of buffered request body per connection), and upstreams then receive `X-Forwarded-Proto: https` and `Via: 2 gateway` for HTTP/2 requests; upstream connections stay HTTP/1.1.
- HTTP/2 costs CPU: with the Fetch mix it used about 14 % more gateway CPU per request than HTTP/1.1, and a flood of refused requests about twice as much over the same connections; the cost is inside Go's HTTP/2 server, so HTTP/2 stays on by default. Turn it off on a CPU-bound gateway whose clients all speak HTTP/1.1.
- A plain-HTTP data listener serves HTTP/1 only.

### Certificate reload

- The files are read again on `SIGHUP` and with every `POST /admin/keys/reload`; a reload that fails keeps the current certificate and writes a `tls.reload_failed` record, and a certificate within 14 days of expiry writes `tls.certificate_expiring` once a day.
- Automatic certificates (ACME) are not built in: renew the files with a tool such as certbot and reload.

### HTTP redirect

- `"redirect_http": {"listen": "0.0.0.0:80", "origin": "https://api.example.com"}` under `data` adds a plain HTTP listener that answers every request with `308` to that origin plus the request's path and query; it never forwards, reads no body and counts its answers in `gateway_redirects_total`.

### Listen addresses

- A listen address of `0.0.0.0` or `[::]` (every interface) is refused unless `"listen_all_interfaces": true` is set under `data`; the metrics listener leaves loopback only with `"metrics_listen_any": true` under `gateway`.
- The admin listener always stays on loopback: reach it through an SSH tunnel.

### Health endpoints

- The metrics listener also answers `GET /livez` (`200 ok` while the process serves) and `GET /readyz` (`200 ok` only in normal mode with a published policy, when the security log has not failed and the certificate, if any, is valid; else `503 unavailable`); `apiward health --config <file>` asks `/readyz` and exits 0 only when ready.

## Identity assertion for upstreams

### What is signed

- Upstreams can verify that a request passed the gateway.
- With `"upstream": {"identity_key": "/etc/apiward/identity.pem"}` (an ECDSA P-256 private key as one PKCS #8 `PRIVATE KEY` PEM block, readable only by its owner; for example `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`), every forwarded request also carries `X-Gateway-Assertion`: a JWT signed with ES256, with `iss` `apiward`, `aud` the API's ID, `sub` and `roles` as in `X-Gateway-Subject` and `X-Gateway-Roles` (both absent on a public operation), `method` and `path` the request's method and its path as the upstream receives it (after the API's forward rule, decoded, without the query), `jti` the request ID, `iat`, and `exp` 30 seconds later.
- Its `kid` is the key's RFC 7638 thumbprint.

### Public key

- The public key is a JSON Web Key Set at `GET /.well-known/apiward/jwks.json` on the admin listener (no session needed), and `apiward jwks --config <file>` prints the same set without a running gateway, for the file an upstream on another host reads.

### What an upstream must check

- An upstream should require exactly one assertion, verify it with that key set accepting only ES256, require its own API ID as `aud`, require `method` and `path` to equal the method and decoded path of the request it arrived on, refuse an expired one allowing a few seconds of clock difference, and take the account from the assertion, not the plain headers.
- An assertion is not bound to the query or the body, so whoever can read the connection to an upstream could repeat the same method and path there, with a query and body of their choice, until it expires: use TLS to upstreams on other hosts, or have the upstream remember each `jti` until its `exp` and refuse a second use (the gateway never sends one twice).
- A client's own `X-Gateway-Assertion` is removed like every `X-Gateway-` header.

### Replacing the key

- To replace the key, give the upstreams a key set holding the old and new keys, restart the gateway with the new key, then remove the old one from the set.
- Without the setting nothing is signed.

## Dashboard files

- A build without the tag needs no Node.js and serves no Dashboard unless `gateway.admin_ui` names a directory of built files.
- When `admin_ui` is set it is used instead of the embedded build; the start log line `dashboard files` names the source (`directory`, `embedded` or `none`).
- Either way the Dashboard is served only on the Admin API listener.
- The page is never cached; the files under `assets/` are cached by the browser for a year (their names change with their content) and the build's gzip copies of the scripts and style sheets are sent as they are, or inflated for a client that does not accept gzip.

## Security log

- A forwarded request has two records with one `request_id`: `request.admitted`, written before forwarding, holds the result of every stage; `request.forwarded`, written after the response, holds the outcome without repeating them (envelope `schema` 8).
- The log is the file `gateway.audit_log` plus rotated files `<name>.1`, `<name>.2` and so on; a file rotates at `gateway.audit_max_bytes` (4 KiB to 1 GiB, default 64 MiB), and `gateway.audit_max_files` (2 to 1,000, default 8) bounds how many files the log keeps.
- A forwarded request adds about 1.1 KB (both records, measured with the Fetch mix), so the default 512 MiB lasts about 16 minutes at 500 requests per second.
- Sizing: the log lasts budget ÷ (bytes per request × requests per second), where budget = `audit_max_bytes` × `audit_max_files`; size it for the time it takes to move rotated files to an archive, with margin.
- Alert A3 (`GET /admin/alerts`) is raised at 70 % (medium) and 90 % (critical) of the budget, and when, at the active file's recent write rate, the rest lasts less than 1 hour (medium) or 15 minutes (critical); its message states the estimated time to full. The rate is read over the last 1 MiB written to the active file and counts once that file holds 1 MiB. Not raised with `evict_oldest`.
- The same warning in Prometheus: `predict_linear(gateway_audit_bytes[15m], 3600) >= gateway_audit_budget_bytes` fires when the last 15 minutes' growth would fill the log within an hour.
- `gateway.audit_when_full` decides what happens when every file is in use: `"refuse"` (default) deletes nothing: it answers every request it would forward `503 gateway_unavailable` and prints one line to standard error until rotated files are moved away, and records that need no acknowledgement (refusals, forwarding outcomes) are only counted meanwhile, the count written as an `audit.loss` event once there is room; `"evict_oldest"` deletes the oldest rotated file and records an `audit.evicted` event with its name, size, SHA-256 and the times of its first and last records.
- `gateway_audit_bytes` and `gateway_audit_budget_bytes` on the metrics listener show how full the log is, so an alert can fire before it fills; while it is full `/readyz` answers `503`.
- `gateway.audit_sync_window` (0 to 10 ms, default 0) lets the writer gather more records for one sync when more than one is waiting; every acknowledgement still waits for the sync that covers its record.
- On Linux the gateway fills the active file with zero bytes 1 MiB ahead of its records and writes the records in place, so each sync (`fdatasync`) flushes only data; on ext4 this cut the time to make one record durable by more than half (median 2.3 ms to 0.95 ms).
- `gateway.audit_prefill` (default `true`) turns the fill off: set `false` on copy-on-write or memory file systems (btrfs, ZFS, tmpfs), where it saves nothing and writes every byte twice; the log then appends and syncs with `fsync`. Other systems always append.
- While the gateway runs, or after it stops abruptly, the active file ends in up to 1 MiB of zero bytes: its records end at the first zero byte after the last line break. Tools that follow the file size (`tail -f`, `wc -c`, log shippers) see the zeros; read rotated files, or stop at the first zero byte. The gateway removes the zeros at rotation, at a clean stop and at its next start; rotated files are always plain JSON lines.
- On one CPU a 2 ms window lowered the 95th-percentile latency at the gateway's saturation rate but raised it at two thirds of that rate, so it is off by default: enable it only on a gateway that runs near saturation, after measuring.

## Operator commands

- Keep the gateway stopped when running local operator commands; a deployment lock prevents two processes from sharing a database.
- Successful operator commands exit 0; refusals and failures exit 1.
- `install` and `enrol` print a one-time secret intentionally: keep that output private.
- On Windows, file modes do not establish confidentiality: existing deployment and backup directories need operator-managed DACLs.
