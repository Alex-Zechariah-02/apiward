# Settings reference

The JSON settings file that `apiward run --config <file>` reads. Upstream TLS profiles, connection reuse and address rules are in [policy.md](policy.md), "Upstreams"; capacity limits in "Capacity limits". Back to the [README](../README.md).

## The file

- The settings file must be a regular file, not a link, device or directory; it is checked before it is opened and again once open.
- `${NAME}` in any string value is replaced with the environment variable `NAME` (letters, digits and `_`), as in Docker Compose: `"audit_log": "${APIWARD_STATE}/audit.log"`. An unset variable or a `${` that starts no such reference stops the start, naming the setting; `$${` writes a literal `${`.
- `POST /admin/keys/reload` reads the file again with the same checks and applies only `gateway.jwt`, `upstream.allow_public_addresses`, `upstream.tls_profiles` and `upstream.tls_session_lifetime`. Other settings that changed are not applied: the answer's `warnings` and the log line `keys reloaded with settings left for a restart` name them. A file that fails a check, or a reloadable setting that is invalid, is still refused (`422 keys_invalid`).
- The settings file, the token verification keys, the identity key and the TLS files may be symbolic links (a Kubernetes ConfigMap or Secret mount): the link is followed once and its target must be a regular file with the mode required for it. The settings file must not be writable by the group or others and must belong to the gateway's user or root, since it names the database, the audit log and the trusted keys. The database, the audit log and the lock never follow a link.
- `apiward health` reads the settings file alone; `apiward jwks` also reads the identity key. Neither reads the token keys or TLS profile files.

## Start log

- The `listening` line names the data, admin and metrics addresses, the data listener's transport (`http` or `https`) and whether HTTP/2 is on; the `identity assertion` line names the key ID an upstream's key set must hold.
- Each setting that weakens protection is named in a warning: `data.listen_all_interfaces` in use, `gateway.metrics_listen_any` in use, `gateway.health_listen_any` in use, `upstream.allow_public_addresses`, `upstream.unsigned_identity`, `gateway.audit_when_full` (either value), reads added to `gateway.audit_ignore_reads` and a `data.trusted_proxies` entry that covers every address (`0.0.0.0/0` or `::/0`).
- Every diagnostic, of the gateway and of the operator commands, is one JSON line on standard error; after a command-line error the usage text follows as it is.

## Data listener

### HTTPS

- The data listener serves HTTPS when the settings name certificate files: `"data": {"tls": {"files": {"certificate_file": "/etc/apiward/tls/api.crt", "key_file": "/etc/apiward/tls/api.key"}}}` (absolute paths; chain leaf first; the key as for TLS profiles; the certificate valid when loaded).

### Overload limits

- Overload is bounded on the data listener: at most `data.max_connections` open connections (default 1,024; one more is accepted and closed at once, counted in `gateway_connections_refused_total`) and `data.max_in_flight` requests inside enforcement (default 1,024, as Envoy's per-upstream request limit; one more is answered `503 overloaded` with `Retry-After: 1` before any token check, and recorded at `INGRESS`).
- `upstream.max_in_flight_per_upstream` (1 to `data.max_in_flight`, default three quarters of it: 768) bounds the requests in flight to one upstream, so one slow API cannot take every place; one more is answered `503 upstream_busy` with `Retry-After: 1` before admission and recorded at `AUDIT` with reason `upstream_busy` (Envoy's per-cluster circuit breaker, HAProxy's per-server `maxconn`).
- `data.max_connections_per_address` (0 to `data.max_connections`, default 0: off) bounds one client address's open connections; one more is accepted and closed at once, as at `data.max_connections` (nginx `limit_conn`). Behind a proxy every client shares the proxy's address, so leave it off there (the start log warns when set with `data.trusted_proxies`).
- At most 10,000 accounts and 1,024 address ranges can be blocked; one more is refused `LIMIT_EXCEEDED`. `GET /admin/limits` reports both.
- Each request in flight holds about 140 KiB, so the default bounds overload memory to about 140 MiB (reached only when about a thousand requests wait at once, for example behind a stalled upstream); on a host with little memory lower `data.max_in_flight` and `upstream.max_idle_per_upstream` together. With 256 a one-core host refused requests from about 90 % CPU; with 1,024 only past its CPU limit.
- A request body is read completely before the request takes an in-flight place, so a slow upload holds only its own connection: at most `data.max_body_bytes` (default 16 KiB, up to 1 MiB; a larger body is answered `413` at `INGRESS`) within `data.read_timeout`.
- The 16 KiB default is four times the largest Fetch request body; nginx defaults to 1 MiB, Kong and Traefik set no ceiling. Raise it only for APIs whose bodies need it.
- A connection reads one request body at a time, also across its HTTP/2 streams; another upload on the same connection waits its turn.
- Worst-case memory for request bodies is therefore `data.max_connections` × `data.max_body_bytes` (buffers grow as payload bytes arrive, never reserved from `Content-Length` alone): 16 MiB at the defaults, 1 GiB with 1,024 connections and the 1 MiB maximum; lower `data.max_connections` on a small host before raising the body ceiling.
- A response passes to the client as it arrives: the gateway flushes it at least every 100 ms (headers included), and event streams and responses without a length at once.

### Client addresses behind a proxy

- `data.trusted_proxies` lists the load balancers or proxies in front of the gateway, as IP addresses or CIDR prefixes (up to 64; empty by default); an IPv4-mapped prefix such as `::ffff:192.0.2.0/120` is read as the IPv4 prefix it names.
- Only a request whose connection comes from one of them may name its client in `X-Forwarded-For`: the gateway reads the field from the right, skips every trusted proxy, and takes the first other address.
- When every entry is a trusted proxy, the leftmost entry is the client; an entry that is not an IP address stops the reading, and the address read before it is used.
- That client address is used for blocked addresses, `allow_addresses`, address rate keys and the security log. When the peer is a trusted proxy, upstreams receive the validated `X-Forwarded-For` chain with the direct peer appended; from an untrusted peer, client-sent `X-Forwarded-For` headers stay stripped and upstreams receive only the direct peer.
- Without the setting, a client's `X-Forwarded-For` is never trusted.

### Protocols

- A request target may be in absolute form (`GET http://shop.example.com/orders`): the host comes from the target and `Host` is ignored (RFC 9112 section 3.2.2). A target with credentials or a scheme other than `http` or `https` is refused `400`.
- `Upgrade` is ignored, and not forwarded, in an HTTP/1.0 request; in HTTP/1.1 it is refused `400`.
- `OPTIONS` with `Max-Forwards: 0` is answered by the gateway itself (`204`, `Allow` naming the target's methods); a larger value is lowered by one before forwarding, and a value that is not one number is refused `400` (RFC 9110 section 7.6.2).

- HTTP/2 protocol errors (malformed frames, flow-control or stream errors) are counted in `gateway_http2_errors_total`.
- It speaks TLS 1.2 or later with HTTP/2 and HTTP/1.1 chosen by ALPN (`"http2": false` under `data` keeps HTTP/1.1 only; at most 100 concurrent streams and 64 KiB of buffered request body per connection), and upstreams then receive `X-Forwarded-Proto: https` and `Via: 2 gateway` for HTTP/2 requests; upstream connections stay HTTP/1.1.
- HTTP/2 costs CPU: with the Fetch mix it used about 14 % more gateway CPU per request than HTTP/1.1, and a flood of refused requests about twice as much over the same connections; the cost is inside Go's HTTP/2 server, so HTTP/2 stays on by default. Turn it off on a CPU-bound gateway whose clients all speak HTTP/1.1.
- A plain-HTTP data listener serves HTTP/1 only.

### Timeouts

- `data.read_header_timeout` (default 5 s), `data.read_timeout` (10 s), `data.write_timeout` (30 s) and `data.idle_timeout` (5 minutes) each accept 1 s to 10 minutes.
- The defaults are stricter than Traefik's (60 s), Caddy's (1 minute) and Envoy's (none): a slow or stalled client is dropped early, which matters most on a small host.
- A response still being sent when `data.write_timeout` ends is cut off: raise it for long downloads or event streams.

### Certificate reload

- The files are read again on `SIGHUP` and with every `POST /admin/keys/reload`; a reload writes `tls.reloaded` with the new certificate's expiry, one that fails keeps the current certificate and writes a `tls.reload_failed` record, and a certificate within 14 days of expiry writes `tls.certificate_expiring` once a day.
- Automatic certificates (ACME) are not built in: renew the files with a tool such as certbot and reload.

### HTTP redirect

- `"redirect_http": {"listen": "0.0.0.0:80", "origin": "https://api.example.com"}` under `data` adds a plain HTTP listener that answers every request with `308` to that origin plus the request's path and query; it never forwards, reads no body and counts its redirects in `gateway_redirects_total`.
- It uses the data listener's `read_header_timeout`, `write_timeout` and header limit, answers `400` to a target that is not a path (such as `OPTIONS *`), and keeps at most `data.max_connections` open connections.

### Listen addresses

- A listen address of `0.0.0.0` or `[::]` (every interface) is refused unless `"listen_all_interfaces": true` is set under `data`; the metrics listener leaves loopback only with `"metrics_listen_any": true` under `gateway`.
- `gateway.health_listen` (optional, unset by default) binds a listener that serves `GET /livez` and `GET /readyz` alone, so a load balancer can read readiness without `/metrics` reaching its network; it leaves loopback only with `"health_listen_any": true`. The metrics listener keeps serving both. The `health` command probes it when it is set.
- No two listeners may share an address and port; `0.0.0.0` covers every IPv4 address and `[::]` every address, so a listener on either conflicts with one on the same port.
- The admin listener always stays on loopback: reach it through an SSH tunnel.
- The admin and metrics listeners each keep at most 64 open connections, and the redirect listener `data.max_connections`; one more is closed at once and counted in `gateway_listener_connections_refused_total{listener="admin"|"metrics"|"redirect"}`.
- If the metrics or redirect listener fails, only that listener stops (logged as `listener stopped`); the data plane keeps serving, and health checks against a stopped metrics listener fail. A data listener failure stops the gateway.

### Health endpoints

- The metrics listener also answers `GET /livez` (`200 ok` while the process serves) and `GET /readyz` (`200 ok` only in normal mode with a published policy, when the security log has not failed and the certificate, if any, is valid; else `503 unavailable`); `apiward health --config <file>` asks `/readyz` and exits 0 only when ready.
- Health and metrics share one listener, so moving it off loopback publishes `/metrics` too, without authentication or TLS, as Envoy's admin port, a Traefik entry point with metrics and Caddy's admin endpoint do. Allow only the scraper and the load balancer by firewall; the start log warns.

## Identity assertion for upstreams

### What is signed

- Upstreams can verify that a request passed the gateway; the gateway signs by default.
- The key is `upstream.identity_key`, or `identity.pem` beside `gateway.database` when that setting is absent: an Ed25519 or ECDSA P-256 private key as one PKCS #8 `PRIVATE KEY` PEM block, readable only by its owner. The key's type fixes the algorithm: Ed25519 signs `EdDSA` (RFC 8037), P-256 signs `ES256`.
- `upstream.retiring_identity_key` (optional, absolute path) names a second PEM `PUBLIC KEY` (Ed25519 or ECDSA P-256) published in `GET /.well-known/apiward/jwks.json` and `apiward jwks` during a rotation and never used to sign. Both `upstream.identity_key` and `upstream.retiring_identity_key` reload live on `POST /admin/keys/reload`.
- `apiward install` creates an Ed25519 key when the file is missing and keeps a key already there; `openssl genpkey -algorithm ED25519` makes one by hand. A deployment with a P-256 key keeps signing `ES256` until the key is replaced; give the upstreams a key set with both keys first.
- `install` refuses an existing database before it writes any key. An installed deployment whose key file is lost needs that file restored: a new key has a new key ID, which its upstreams do not trust.
- Without the key file the gateway refuses to start, naming the file.
- `"upstream": {"unsigned_identity": true}` turns signing off: upstreams then receive only the plain headers, and the start log says so. It cannot be combined with `identity_key` or `retiring_identity_key`.
- Signed or not, an upstream must accept requests only from the gateway (client certificates or a firewall), as NIST SP 800-207 requires of a policy enforcement point.
- Every forwarded request carries `X-Gateway-Assertion`: a JWT signed with `EdDSA` or `ES256` (by the key's type), with `iss` `apiward`, `aud` the API's ID, `sub` and `roles` as in `X-Gateway-Subject` and `X-Gateway-Roles` (both absent on a public operation), `method` and `path` the request's method and its path as the upstream receives it (after the API's forward rule, decoded, without the query), `jti` the request ID, `iat`, and `exp` 30 seconds later.
- Its `kid` is the key's RFC 7638 thumbprint.

### Public key

- The public key is a JSON Web Key Set at `GET /.well-known/apiward/jwks.json` on the admin listener (no session needed), and `apiward jwks --config <file>` prints the same set without a running gateway, for the file an upstream on another host reads.

### What an upstream must check

- An upstream should require exactly one assertion, verify it with that key set, taking the algorithm from the key the `kid` names (`EdDSA` for an `OKP` Ed25519 key, `ES256` for a P-256 key) and refusing a token whose `alg` differs (RFC 8725 section 3.1), require its own API ID as `aud`, require `method` and `path` to equal the method and decoded path of the request it arrived on, refuse an expired one allowing a few seconds of clock difference, and take the account from the assertion, not the plain headers.
- An assertion is not bound to the query or the body, so whoever can read the connection to an upstream could repeat the same method and path there, with a query and body of their choice, until it expires: use TLS to upstreams on other hosts, or have the upstream remember each `jti` until its `exp` and refuse a second use (the gateway never sends one twice).
- A client's own `X-Gateway-Assertion` is removed like every `X-Gateway-` header.

### Replacing the key

- To replace the key, give the upstreams a key set holding the old and new keys, restart the gateway with the new key, then remove the old one from the set.

## Dashboard files

- A build without the tag needs no Node.js and serves no Dashboard unless `gateway.admin_ui` names a directory of built files.
- When `admin_ui` is set it is used instead of the embedded build; the start log line `dashboard files` names the source (`directory`, `embedded` or `none`).
- Either way the Dashboard is served only on the Admin API listener.
- An administrator session ends after `gateway.admin_idle_timeout` without a request (default `15m`) and at the latest `gateway.admin_session_lifetime` after sign-in (default `8h`); each accepts `1s` to `24h`.
- One administrator holds at most `gateway.admin_sessions` sessions (default `8`, `1` to `64`); a further sign-in ends that administrator's oldest session.
- At most 1,024 sessions are live at once across all administrators, a memory bound; one more sign-in is answered `503 session_limit`. Sessions are kept in memory, so a restart ends them all.
- A directory is read so that no name or link in it leads to a file outside it.
- The page is never stored (`Cache-Control: no-store`); the files under `assets/` are cached by the browser for a year (their names change with their content) and the build's gzip copies of the scripts and style sheets are sent as they are, or inflated while they are sent for a client that does not accept gzip. A weight that is not a valid `q` value refuses its encoding.

- `upstream.idle_conn_timeout` (default 30 s) must stay below each upstream server's own idle timeout, so the gateway, not the upstream, closes an idle connection; otherwise a request written just as the upstream closes the connection fails (it is never resent).

## Security log

- A forwarded request has two records with one `request_id`: `request.admitted`, written before forwarding, holds the result of every stage; `request.forwarded`, written after the response, holds the outcome without repeating them (envelope `schema` 9).
- The log is the file `gateway.audit_log` plus rotated files named by the UTC time they were rotated (`audit-2026-11-19T08-22-33.123.log` for `audit.log`), so names never repeat; a file rotates at `gateway.audit_max_bytes` (4 KiB to 1 GiB, default 64 MiB).
- After each rotation a background task compresses the rotated file (gzip, `.log.gz`) into the archive folder, records `audit.archived` and only then deletes the original. It never runs on the request path. `gzip -dc` reads an archived file.
- `gateway.audit_archive` (absolute path, default `archive` beside `audit_log`) may be on another disk; `gateway.audit_archive_max_bytes` (64 MiB to 16 TiB, default 10 GiB) bounds it by size only, with no age limit; `gateway.audit_compress` (default `true`) set `false` moves files uncompressed.
- `gateway.audit_max_files` × `gateway.audit_max_bytes` (default 8 × 64 MiB) bounds the log folder: the active file plus rotated files not yet archived.
- `gateway.audit_when_full` (default `"evict_oldest"`): when the archive or the log folder exceeds its bound, the oldest file is deleted after an `audit.evicted` record of it (name, size, SHA-256, first and last record times) is saved. `"refuse"` deletes nothing: archiving stops at the archive's bound, the log folder fills, and the gateway then answers every request it would forward `503 gateway_unavailable` until files are moved away. Both values are named in a warning at start.
- Disk pressure: every 10 s the gateway reads the free space of the log and archive disks; below `gateway.audit_min_free_percent` (1 to 50, default 10) it evicts the oldest files on that disk early, each recorded first, until there is room again (refuse mode alerts only).
- Reserve: `gateway.audit_reserve_bytes` (1 MiB to 1 GiB, default 64 MiB) is split between `<name>.reserve` (general writes, budget minus 1 MiB) and `audit.evict.reserve` (1 MiB, used only to write `audit.evicted` records while admissions are refused for want of space; at the 1 MiB minimum each file is 512 KiB). Both are filled and synced at start and remade once the disk has room; `gateway_audit_reserve_bytes` reports their sum.
- If the archive folder fails (full, missing, unmounted, no permission), files are compressed in the log folder instead, the oldest evicted there, alert A3 is raised, and the files move to the archive once it works again.
- Sizing (measured, 750 requests/s with refusals, WSL 2): the gateway writes about 0.92 MiB/s (about 1.2 kB per request); a 64 MiB file compresses to about 6 MiB (ratio 10.6) in about 0.43 s of one core, so the default 10 GiB archive holds about 1,700 files, about 33 hours at that rate. Archive size = hours × 3,600 × requests/s × 1.2 kB ÷ 10.6.
- `gateway.audit_client_address` (default `"full"`) decides how client addresses are recorded: `"full"`, `"prefix"` (IPv4 /24, IPv6 /48) or `"hash"` (`hmac:` and 32 hex digits, HMAC-SHA-256 with the key in `gateway.audit_address_key`, an absolute path to a file of at least 32 bytes readable only by its owner). Only the record changes: rate limits and blocked addresses still use the whole address, and accounts are never masked. A masked address weakens forensics, so it stays off unless privacy rules ask for it.
- `gateway_audit_bytes` and `gateway_audit_budget_bytes` show the log folder against its bound; `gateway_audit_archive_bytes`, `gateway_audit_archive_budget_bytes`, `gateway_audit_archive_ok`, `gateway_audit_pending_files`, `gateway_audit_free_bytes{disk="log"|"archive"}`, `gateway_audit_reserve_bytes` and `gateway_audit_pressure_evictions_total` show the archive and the disks; while the log refuses records `/readyz` answers `503`.
- Alert A3 also reports an archive folder that cannot be written (critical), a disk below its free-space threshold (medium) or below the reserve (critical), and more than two rotated files waiting to be archived (medium).
- A write refused because the file system has no space (`ENOSPC`, or `EDQUOT` for a quota) first uses the reserve. Without one, the gateway answers `503 gateway_unavailable` instead of forwarding, retries once a second, and resumes once a write and its sync succeed, recording `audit.recovered` with reason `storage_space`.
- A failed sync or any other write error replaces the active file without a restart: the batch is refused, the suspect file is kept as a rotated file, a new file starts under a new run ID, and `audit.recovered` (reason `sync_failed`) names the suspect file and the end of its last synced batch, with the lost records counted. After a failed sync the system may have dropped written data, so nothing later in that file proves durable (the reason PostgreSQL stops on a failed `fsync`). The gateway refuses requests only while no new file can be written, retried once a second; `gateway_audit_sync_recoveries_total` counts the replacements.
- `gateway_audit_save_seconds` is how long each request waited for its admission record to be saved; `gateway_audit_slow_saves_total` counts waits over 100 ms, logged at most once a minute. A save that takes longer than `gateway.audit_timeout` (default 2 s) refuses the request.
- A change the database could not complete is recorded as `transition.failed` (reason `STORE_ERROR`) and counted in `gateway_control_store_failures_total`.
- Every authenticated Admin API read writes an `admin.read` record (also the read-only `POST` requests: access check, impact preview, temporary rule check), except successful `GET` reads of the paths in `gateway.audit_ignore_reads` (default `["/admin/status", "/admin/traffic", "/admin/events"]`, the reads the Dashboard repeats every second; at most 32 paths, each beginning with `/admin/`; `[]` records every read). Refused reads and every change are always recorded. Paths added beyond the default are named in a warning at start. Every record kind: [logs.md](logs.md).
- A search lists a rotated file as missing when the `audit.rotated` record at the head of the next file names it and neither folder holds it (plain or compressed); the oldest file's predecessor is not checked, and a file evicted while older files remained leaves an empty `<name>.evicted` marker so it is not listed.
- Files named `<name>.1`, `<name>.2` by earlier versions, and uncompressed rotated files an earlier version left, are compressed and archived at start, oldest first.
- `gateway.audit_sync_window` (0 to 10 ms, default 0) lets the writer gather more records for one sync when more than one is waiting; every acknowledgement still waits for the sync that covers its record.
- On Linux the gateway fills the active file with zero bytes 1 MiB ahead of its records and writes the records in place, so each sync (`fdatasync`) flushes only data; on ext4 this cut the time to make one record durable by more than half (median 2.3 ms to 0.95 ms).
- `gateway.audit_prefill` (default `true`) turns the fill off: set `false` on copy-on-write or memory file systems (btrfs, ZFS, tmpfs), where it saves nothing and writes every byte twice; the log then appends and syncs with `fsync`. Other systems always append.
- While the gateway runs, or after it stops abruptly, the active file ends in up to 1 MiB of zero bytes: its records end at the first zero byte after the last line break. Tools that follow the file size (`tail -f`, `wc -c`, log shippers) see the zeros; read rotated files, or stop at the first zero byte. The gateway removes the zeros at rotation, at a clean stop and at its next start; rotated files are always plain JSON lines.
- On one CPU a 2 ms window lowered the 95th-percentile latency at the gateway's saturation rate but raised it at two thirds of that rate, so it is off by default: enable it only on a gateway that runs near saturation, after measuring.

## Operator commands

- The database keeps the newest `gateway.history_keep` policy versions (100 to 100,000, default 1,000). Publishing a version deletes, in the same transaction, the versions older than those and the history only they need: their trials, finished temporary rules, drafts and recorded changes. A row in use is never deleted: the policy in force, a trial's undo target, the base of an active temporary rule, a change whose security-log record is not yet written.
- At most 100 unused drafts (staged or withdrawn, never tried) are kept: staging another deletes the oldest unused one and its recorded changes, once their security-log records are written.
- After a blocked-list change the newest `gateway.history_keep` changes that published no version are kept with their recorded answers; older ones whose security-log records are written are deleted.
- A deleted version can no longer be rolled back to or restored, History no longer lists it, and a request key from a deleted change is decided as a new request. The security log files remain the full record of every change.
- `apiward audit verify --jwks <key set file> <files…>` checks the security log's chain and signed checkpoints: give the files oldest first: the archive's files, then the log folder's rotated files, each sorted by name, the active file last (`.log.gz` files are read directly). It prints its report as JSON, with `anchored_files` naming rotated files where a run was anchored at its first signed checkpoint and `missing_files` naming files the next file's rotation record names that were neither given nor evicted, and exits 0 only when nothing was found altered or missing; a run starting mid-file-set without a verifiable checkpoint reports one problem while still checking later records, and a compressed file whose content does not match the SHA-256 in its header is reported as altered. It reads no settings file.
- Restore runs SQLite's full integrity check on the backup and the quick check on the copy it puts in place.
- A path conflict in the settings or a command's files names both settings and both paths.
- Keep the gateway stopped when running local operator commands; a deployment lock prevents two processes from sharing a database.
- Successful operator commands exit 0; refusals and failures exit 1.
- `install` and `enrol` print a one-time secret intentionally: keep that output private.
- On Windows, file modes do not establish confidentiality: existing deployment and backup directories need operator-managed DACLs.
