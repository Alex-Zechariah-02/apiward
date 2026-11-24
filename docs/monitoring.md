# Monitoring

What the gateway reports about its own traffic: the metrics listener, the Admin API's monitoring reads and the window of recent requests they come from. Security log records: [logs.md](logs.md). Listener settings: [settings.md](settings.md).

## Metrics

- `GET /metrics` on the metrics listener answers in the Prometheus text format.
- `gateway_requests_total{api, operation, decision, code, module}` counts each request's outcome.
- `decision` is one of `allowed`, `refused`, `failed` (the gateway's own error) and `upstream_failed` (the service gave no complete answer).
- `code` is the outcome code the client was answered, or a module's refusal code; free text never becomes a label.
- A module failure is counted with `code="gateway_unavailable"` and `module` naming the module.
- At most 4,096 request series are kept; later new series are counted with `unknown` labels and their requests in `gateway_metric_series_dropped_total`.
- `gateway_request_duration_seconds{api}` is a histogram of the whole request time, buckets 0.1 ms to 10 s.
- `apiward_gateway_overhead_seconds{api}` is the gateway's own time of a forwarded request (the whole time minus the upstream's); `apiward_upstream_seconds{api}` the upstream's, from sending the request to its response headers.
- Both have buckets 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.1, 1 and 10 seconds; requests that never reached an upstream are not in them.
- `gateway_recent_requests` is the number of requests the window of recent requests holds; `gateway_window_oldest_seconds` the age of its oldest.
- `gateway_live_views` is the number of open live views (at most 8).
- Label values are escaped as the text format requires; invalid UTF-8 is replaced.

## Window of recent requests

- The gateway keeps the last `limits.monitor_window` requests (default 10,000) in memory for the live views, the traffic summary, the refusal-spike alert and the impact preview.
- At high rates the window covers less time: at 1,000 requests a second, 10,000 requests are about 10 seconds.

## Admin API reads

- `GET /admin/health` needs no session; it answers `{"state"}` with `200` in normal, bootstrap and recovery mode, and `503` with `"unavailable"` otherwise.
- `GET /admin/traffic?window=60|300|3600` summarises the window's requests; `covers_from` and `complete` say from when the answer holds every request.
- When the window has dropped requests from inside the time asked for, `complete` is `false` and `covers_from` is the oldest request kept; the Dashboard draws the seconds before it as no data.
- `previous` (the window before) is `null` when the gateway no longer holds all of it.
- `GET /admin/events` lists recent requests, newest first, filtered by `ref`, `subject`, `operation` and `decision` (any of the four decisions); `GET /admin/events/stream` streams them (Server-Sent Events).
- Each request view carries `upstream` (the service it was bound to) and `forwarded_path` (the path sent, only when the endpoint's forward rule changed it); both are `null` when absent.
- A live view checks its session at least once a second while requests arrive and every 15 seconds while idle; a sign-out or revocation ends it at once.
- `GET /admin/policy` sends an `ETag`; a request with `If-None-Match` naming it is answered `304` without the document.
- `GET /admin/alerts` raises A1 (refusal spike) only when the window still holds every request of the 16 minutes the rule compares; after the window dropped requests from that time, A1 is withheld.
- In library mode (a host program serves the data plane) `GET /admin/advice` lists W6 (severity `info`): the gateway cannot confirm the host's transport is HTTPS.
- `GET /admin/advice` keeps a summary of the active security log file's part already read and reads only what was written since; a rotation, a shorter file or a new gateway start reads the file again.
- `gateway_upstream_connections_idle`, `gateway_upstream_dials_total` and `gateway_upstream_reuses_total` show the upstream connection pool: idle connections now, and connections dialled and reused since the start.
- `gateway_listener_failures_total` counts metrics and redirect listeners that stopped on an error; the data plane keeps serving.
- `gateway_audit_records_lost_total`, `gateway_audit_evictions_total` and `gateway_blocked_addresses` count refused audit records written in loss records, security log files evicted (each after its `audit.evicted` record), and the blocked address ranges; the security log's archive, disk and save-wait metrics are in [settings.md](settings.md#security-log).
- `gateway_audit_chain_batches_total` counts `audit.chain` records written since start; `gateway_audit_last_checkpoint_timestamp_seconds` is the Unix time of the last signed checkpoint (`0` before the first). Copy the signed checkpoint itself off the host from `audit_checkpoint` in `GET /admin/status` ([logs.md](logs.md#tamper-evidence)).
