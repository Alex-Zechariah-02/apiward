# Policy reference

The policy document and how it changes. Back to the [README](../README.md).

## Controls and identity

- Each request uses one policy version from start to end.
- When one control rejects a request, it never reaches an API.
- The gateway checks tokens from an outside identity provider and does not issue tokens itself.
- A token's `kid` selects one of the trusted public keys.
- Roles come from verified token claims and are kept only when the captured policy defines them.
- A separate blocked-account list refuses a verified account immediately and survives policy rollback.
- Public keys can be reloaded from operator files; an invalid reload keeps the current key set.

## Schema versions

- Policy documents use schema version 4 or 5 and contain roles and permits without per-user membership.
- Version 5 adds service addresses on other hosts ("Upstreams" below); a version 4 document is read exactly as before.
- Version 3 policies are refused rather than converted automatically.

## Path rewrite

- An API may rewrite the path its upstream receives with `"forward": {"strip_prefix": "/api", "add_prefix": "/v2"}` (either or both): `/api/orders/7` is forwarded as `/v2/orders/7`, and `/api` as `/v2` (`/` when nothing is left).
- Both prefixes are fixed paths without a trailing `/`, `*`, `%`, `.` or `..` segment, and the strip prefix must lead every target of the API at a segment boundary; otherwise the policy is refused `REWRITE_INVALID`.
- Routing, access, sign-in, roles, rate limits, validation and the security log all use the path the client sent; the rewrite is applied only when the request is forwarded.
- The rewritten path is checked again, and a request whose rewritten path is not canonical is refused `400 path_not_canonical`.
- The security log records `forwarded_path` beside `path` when the two differ.

## Host and header conditions

### Conditions

- An operation may carry host and header conditions with `"when": {"hosts": ["api.example.com", "*.example.com"], "headers": [{"name": "X-Version", "value": "2"}]}`: 1 to 16 lower-case host names (exact, or `*.` followed by a domain, which matches any name ending in that domain, never the domain itself) and 1 to 8 headers with exact values; every condition must hold.
- The request's `Host` is compared without its port and case.
- A header holds only when the request carries it exactly once with that value, and only names a header schema could declare are allowed.

### Which operation is selected

- Several operations may share a target and method: the one with the most conditions that hold is selected, else the one without conditions; when none applies the request is answered `404`.
- Conditions only select an operation, whose own access, sign-in, roles, rate and body rules decide.

### Checks

- The compiler refuses two conditioned operations of equal rank that one request could meet (`TARGET_COLLISION`) and a conditioned operation weaker than the unconditioned one beside it (`CONDITION_WEAKER`): allowed where that one is denied, public where it requires sign-in, a role it does not permit, a missing, differently keyed or looser rate rule, a body it refuses or a larger or different one, or a missing header schema.
- The access checker takes optional `host` and `headers` (an object of names and values) to check such a request; the change preview reports requests to conditioned operations as unknown, since the log keeps neither.

## Browser access (CORS)

### Setting

- An API may let web pages on other sites call it from a browser with `"cors": {"origins": ["https://shop.example.com"], "methods": ["GET", "POST"], "headers": ["Content-Type"], "expose": ["X-Total"], "credentials": false, "max_age_seconds": 600}`: 1 to 32 exact lower-case origins (`scheme://host[:port]`, no path, no default port) or exactly `["*"]`, which is allowed only without credentials on an API whose operations are all public (otherwise `CORS_WILDCARD_NOT_ALLOWED`); methods of the API's own operations; up to 32 request headers and 16 exposed headers; a preflight cache time of 0 to 86400 seconds (600 by default).

### Preflight requests

- The gateway answers a preflight (`OPTIONS` with `Origin` and `Access-Control-Request-Method`) on such an API itself and never forwards it: `204` with the CORS headers when the origin, the method and every requested header are allowed, `204` without them otherwise.
- Preflights are recorded as `request.preflight` events (decision `allowed` or `refused`, code `cors_preflight` or `cors_refused`) and, when one of the API's public operations has a rate rule, limited per client address by the first such rule on a counter of their own.
- The API's address allow list and preflight rate rule apply to every preflight on its paths, also one whose requested method has no operation.

### Responses

- Every answer for the API, refusals included, carries `Access-Control-Allow-Origin` and `Vary: Origin` for an allowed origin; CORS headers from the upstream are replaced.
- Browser access never admits a request: every other check applies unchanged.

## Response headers

An API's `"response_headers": {"hsts": true, "nosniff": true, "frame": "deny", "referrer": "no-referrer", "remove": ["Server"]}` adds `Strict-Transport-Security: max-age=31536000` (only on requests received over TLS), `X-Content-Type-Options: nosniff`, `X-Frame-Options` (`deny` or `sameorigin`) and `Referrer-Policy` (`no-referrer` or `strict-origin-when-cross-origin`) when the upstream did not set them, and removes up to 16 named upstream headers (never the gateway's own headers, `Access-Control-*` or the response framing). Gateway refusals always carry `X-Content-Type-Options: nosniff`.

## Address lists

### Allow list of an API

- An API's `"allow_addresses": ["10.0.0.0/8", "2001:db8::/32"]` (1 to 256 ranges in canonical CIDR form) admits only those client addresses: others are refused `403 address_not_allowed` before any other check of the operation.

### Blocked addresses

- A separate blocked address list in the gateway's database refuses a client address at once, before the policy is consulted, with `403 address_blocked`, and survives policy rollback.
- The Admin API manages it like the blocked accounts: `GET /admin/blocked-addresses`, `PUT /admin/blocked-addresses/{range}` (`{"reason", "expires_at"?}`, an expiry 1 minute to 30 days ahead) and `DELETE /admin/blocked-addresses/{range}`, with `{range}` a URL-encoded canonical CIDR (a single address is `/32` or `/128`; an IPv4-mapped range is stored as IPv4), at most 1,024 entries, recorded in the history as `address.block` and `address.unblock`.
- The client address is the direct peer of the connection.

## Upstreams

### Address forms

- An upstream is either `{"id": "orders", "dial": "127.0.0.1:9502"}` (plain HTTP to an address on the gateway's host) or, in schema version 5, `{"id": "orders", "url": "https://orders.internal:8443", "tls": "fetch", "host": "upstream"}`.
- A `url` is `http://` with a literal IP address, or `https://` with a literal IP address or a lower-case DNS name, with an optional port and nothing after it.
- `tls` names a TLS profile of the gateway's settings (https only); `host` chooses the `Host` header the upstream receives: `inbound` keeps the client's (the default for http), `upstream` sends the URL's host (the default for https).

### Allowed addresses

- Loopback, private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`) and shared (`100.64.0.0/10`) addresses are allowed; public addresses only when the settings set `"upstream": {"allow_public_addresses": true}`.
- Unspecified, link-local (which includes `169.254.169.254`), multicast and broadcast addresses and the cloud metadata addresses `fd00:ec2::254`, `fd20:ce::254`, `100.100.100.200` and `168.63.129.16` are always refused.
- The address is checked when the policy is saved and again on the resolved address of every connection, just before it is made, so a DNS answer cannot lead elsewhere; a refused connection is answered `502 upstream_unavailable` with the security log reason `destination_refused`, and nothing is sent.

### TLS

- Connections use TLS 1.2 or later and HTTP/1.1, verify the certificate for the URL's host against the profile's CA file (or the system roots) and present the profile's client certificate.

### Connection reuse

- Upstream connections are kept and reused: up to `upstream.max_idle_per_upstream` idle connections per upstream (default 16; 0 opens a new connection for every request and closes it after the response), each closed after `upstream.idle_conn_timeout` idle (default `30s`, `1s` to `5m`; keep it below the upstream server's own idle timeout).
- A request is sent once: one that fails on a reused connection is never sent again, and is answered like any exchange that may have reached the upstream (security log reason `outcome_unknown`).
- TLS sessions to https upstreams are resumed for at most `upstream.tls_session_lifetime` (default `1h`, `1m` to `24h`), with one session cache per TLS profile that a reload replaces; on a resumed session the upstream relies on the client certificate it verified in the first handshake.

### TLS profiles

- The settings list the profiles as `"upstream": {"tls_profiles": [{"id": "fetch", "ca_file": "/etc/apiward/fetch-ca.pem", "client_certificate_file": "/etc/apiward/gateway.crt", "client_key_file": "/etc/apiward/gateway.key"}]}` (up to 32; absolute paths; the key is PKCS #8 RSA of at least 2,048 bits or ECDSA P-256 and, on Unix, must not be readable by the group or others).
- They are read at start and again by `POST /admin/keys/reload`, which keeps the old ones if the new ones are invalid or drop a profile the active policy uses.
- `GET /admin/tls-profiles` lists them without paths or keys.
- A policy naming an unknown profile is refused `UNKNOWN_TLS_PROFILE`.
- Failed TLS connections are logged as `certificate_invalid` or `tls_handshake_failed`, with the address dialled as `upstream_address`.

## Capacity limits

- Capacity ceilings are settings under `limits`, each optional with today's default and a hard maximum: `policy_bytes` (65,536; also the maximum, the database's bound on a stored policy), `apis` (64, up to 256; also bounds upstreams), `operations` (256, up to 4,096), `roles` (64, up to 256), `permits` (4,096, up to 65,536), `rate_counters` (262,144, up to 1,048,576; about 257 bytes of memory each) and `monitor_window` (10,000 recent requests kept for live views, up to 100,000).
- A policy over a ceiling is refused `LIMIT_EXCEEDED`, so a policy saved under raised settings is refused by a gateway with lower ones.
- A token carries at most 64 roles whatever the role ceiling.
- `GET /admin/limits` reports the effective values.
- The offline commands and the `policy` package check against the defaults.

## Changing a policy

Administrators change the policy through two workflows.

### Confirmed Policy Activation

- A new permanent policy starts as provisional and is enforced at once, with a confirmation deadline of 1 second to 24 hours.
- An administrator confirms it or rolls it back.
- If nobody confirms it in time, the gateway goes back to the previous policy by itself, also when it was stopped over the deadline.
- A provisional policy never admits a request after its deadline, even if the rollback runs late.
- Only one provisional policy can exist at a time, and each one ends exactly once.

### Temporary Policy Override

- An administrator can give a role one more operation or take one away, raise or lower an operation's rate limit, or block an operation, for 1 second to 24 hours.
- The change is applied on top of the permanent policy without changing it, and it ends by itself at its expiry time or when it is revoked.
- It cannot skip token checks or request checks, reduce logging, open a blocked operation or change where requests go.
- Two overrides cannot change the same thing, and a new permanent policy that would clash with an override is refused.
- While a provisional policy waits for confirmation, no new override can be made.
- Rate counts carry over, so an override never gives a fresh quota.
- A restored backup never brings an old override back.
