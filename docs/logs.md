# Security log

What the gateway records, when a record is waited for, and how to read the log. Settings: [settings.md](settings.md#security-log).

## Files

- The active file is `gateway.audit_log`; a rotated file is named by the UTC time it was rotated, to the millisecond (`audit-2026-11-19T08-22-33.123.log` for `audit.log`), so names sort by age and never repeat.
- Rotated files are compressed to `<name>.gz` in the archive folder (`gateway.audit_archive`), in 1 MiB gzip members; `gzip -dc` reads one, and its gzip header comment holds the first and last record times and the SHA-256 of the uncompressed content.
- Each line is one JSON record with `schema`, `event_id`, `time`, `seq` and `kind`, plus the fields of its kind.
- `seq` numbers one run's records in file order, rising by one; records refused for lack of room leave no gap and are counted in `audit.loss`.
- A record never exceeds 64 KiB: one that would is replaced by `audit.unwritable` with its request ID, decision and status, `target` its kind and `reason` `too_large`.
- The active file is kept at mode `0600`, also when an existing file had a wider mode; new, renamed and deleted file names are synced to disk with their directory.
- Records never hold tokens, passwords, cookies or request bodies.
- **Waited for**: the gateway goes on only after the record is on disk; when it cannot be written, the action is refused.
- **Queued**: the record is written with the next batch; a record that finds no room is counted, and the count is written as `audit.loss`.

## Request records

| Kind | Written when | Record |
|---|---|---|
| `request.admitted` | A request passed every check, before it is forwarded | Waited for |
| `request.forwarded` | The upstream exchange ended | Queued |
| `request.rejected` | A check refused the request, or enforcement failed | Queued |
| `request.preflight` | The gateway answered an `OPTIONS` request itself: a browser preflight, or one with `Max-Forwards: 0` (code `max_forwards`) | Queued |

- An admission record's `AUDIT` stage reads `PASS`: it is written only when that stage passes.
- An admission whose record is not on disk within `gateway.audit_timeout` is answered `503` and recorded as `request.rejected` at `AUDIT` with reason `audit_timeout`. If the writer had not yet taken the admission record, it is withdrawn and never written; otherwise the rejection follows it and supersedes it (same `request_id`).
- `request.forwarded` also holds `upstream_ms`: the time from sending the request upstream to its response headers (monotonic clock). `duration_ms` minus `upstream_ms` is the gateway's own share.
- A request record holds the request ID, method, path, client address, policy version, operation, API, account, roles, the result of each check, status, error code and duration.
- A recorded method is cut at 32 bytes and a path at 256 (`path_truncated` marks the path).
- A request whose identity assertion would exceed 4,096 bytes (a very long path or many roles) is refused `400` at `BIND` with reason `assertion_too_large`, since upstreams may refuse a longer header.
- A failure inside the gateway while forwarding is recorded as `request.forwarded` with decision `failed` and code `internal_error`, answered `500` when nothing was sent yet.
- Refusals before any policy applies (overload, oversized or malformed requests, tunnels, upgrades) write no request record; they are counted per reason and address in `audit.ingress_summary` once a minute.
- Policy refusals (`401`, `403`, `429`) and unauthenticated route or canonical-path refusals (`404` or `405` at `ROUTE`, `400` at `CANONICAL`, and `400` at `ROUTE` for an invalid `Max-Forwards`) and refused CORS preflights are recorded in full up to 60 per client address per minute; further ones from that address in the same minute are counted in the same summary under `<stage>/<reason>/<operation>`, with exact counts, so a flood cannot push older records out of the log. Other refusals, admissions and outcomes are always recorded in full.

## Administrator records

| Kind | Written when | Record |
|---|---|---|
| `admin.authenticated` | Sign-in succeeded, before the session is handed out | Waited for |
| `admin.logout` | Sign-out | Queued |
| `admin.read` | An authenticated read, including the read-only POST requests (access check, impact preview, temporary rule check) | Queued |
| `admin.rejected` | A request without a valid session was refused, or the gateway could not answer it | Queued |
| `admin.denied` | A signed-in administrator's request was refused | Queued |

- `gateway.audit_ignore_reads` leaves out successful reads of the paths the Dashboard repeats ([settings.md](settings.md#security-log)).
- A refusal record names its reason: for example `bad_credentials`, `locked`, `throttled`, `csrf`, `permission`; `store`, `audit`, `busy` and `log` mean a part of the gateway failed.

## Change records

| Kind | Written when | Record |
|---|---|---|
| `transition.intent` | Before any change is committed to the database | Waited for |
| `transition.committed` | A change without a new policy version was committed (draft change, enrolment, password) | Waited for |
| `transition.published` | A change published a new policy version | Waited for |
| `cpa.activated`, `cpa.confirmed`, `cpa.rolled_back`, `cpa.timed_out` | A policy went on trial, was kept, was undone, or its trial ended | Waited for |
| `tpo.created`, `tpo.revoked`, `tpo.expired` | A temporary rule began, was revoked or ended | Waited for |
| `account.block`, `account.unblock`, `address.block`, `address.unblock`, `keys.reload` | A blocked-list change or a key reload took effect | Waited for |
| `transition.rejected`, `cpa.rejected`, `tpo.rejected` | A change was refused (reason `UNAVAILABLE` while the gateway stops or has no database) | Queued |
| `tpo.validated` | A temporary rule passed its check without being created | Queued |
| `transition.failed` | The database could not complete a change | Waited for after an intent, else queued |
| `controller.reconciled` | The gateway reconciled its stored state at start | Queued |
| `controller.unavailable` | The gateway stopped accepting protected requests; `reason` is the state code, `error` the detail | Queued |

- Temporary rules and a trial whose times run out by the same check end together: each keeps its own `transition.intent` and outcome record (`tpo.expired`, `cpa.timed_out`), and every outcome names the one policy generation published for them all.
- At start, an outcome whose record is missing is written again under its own kind with reason `reconciled`.
- So a `transition.intent` without an outcome record means the change was not committed: every committed change has its outcome record once the gateway has started again.
- The state codes of `controller.unavailable`, also the `state` of `GET /admin/status`: `store_unavailable`, `audit_reconcile_failed` (the audit log refused a record the controller needs; retried until it is recorded), `clock_regression` (reset offline with `apiward recover-clock --config <file>` after fixing the host clock), `rollback_target_invalid`, `deadline_mismatch`, `transition_incomplete`, `policy_invalid`, or the stored mode that serves no policy. The detail stays in the log and the gateway's own output.

## Gateway and operator records

| Kind | Written when | Record |
|---|---|---|
| `gateway.started` | The gateway opened its deployment with these settings, before any listener binds (a bind that then fails is reported on stderr, with no further record): `file` names the settings file, `sha256` its digest | Queued |
| `gateway.key` | At start, once per key in force: `target` the key ID, `reason` `verification` (a token key, `sha256` its fingerprint) or `assertion` (the identity key, whose ID is its thumbprint) | Queued |
| `tls.reloaded` | A listener certificate reload succeeded; `expires_at` is the new certificate's expiry | Queued |
| `tls.reload_failed` | A listener certificate reload failed; the old certificate stays | Queued |
| `tls.certificate_expiring` | Daily while the listener certificate expires within 14 days | Queued |
| `operator.backup` | `apiward backup` wrote a backup | Waited for |
| `operator.clock_reset` | `apiward recover-clock` reset `high_water` (`old_high_water`, `new_high_water`, `ended_transitions`) | Waited for |
| `audit.rotated` | The active file was rotated | With its batch |
| `audit.archived` | A rotated file was compressed and moved (`file`, `bytes` and `sha256` of the uncompressed file, `archived_bytes`, `first_record`, `last_record`, `target` `archive` or `live`) | Before the original is deleted |
| `audit.evicted` | The oldest file was deleted (`file`, `bytes` and `sha256` as stored, `first_record`, `last_record`, `reason` `archive_budget`, `log_budget` or `disk_pressure`, `target`); uses `audit.evict.reserve` when the log has no space | Before the deletion |
| `audit.loss` | Records were dropped for lack of room since the last batch | With its batch |
| `audit.recovered` | At start, the last record of the active file had been cut off (`file`, `offset`); with reason `storage_space`, writing resumed after the file system had no space (`duration_ms` how long, `lost` the records counted meanwhile); with reason `sync_failed` or `rotation_failed`, the active file was replaced (`file` the suspect file, `offset` the end of its last synced batch) | Queued |
| `audit.chain` | Every written batch: `sha256` is the chain head after the batch | Ends its batch |
| `audit.checkpoint` | Once a minute and at each rotation: `sha256` the chain head, `target` the identity key ID, `signature` its signature | With its batch |
| `audit.closed` | A clean stop; nothing follows it but its chain record | Last |
| `request.outcome_unknown` | At a start after an unclean stop, once per admission without an outcome in the last `data.read_header_timeout` + `data.write_timeout` before the stop (`reason` `unclean_stop`) | Queued |
| `audit.reconciled` | After the `request.outcome_unknown` records, with their count in `counts.outcome_unknown` | Queued |
| `audit.unwritable` | A record would exceed 64 KiB; it stands in for that record | In its place |
| `audit.ingress_summary` | Refusals before any policy applied were counted | Once a minute |

- Operator commands (`install`, `enrol`, `disable`, `migrate`, `restore`) write `transition.intent` and `transition.committed` around their change; `recover-clock` writes `transition.intent` and `operator.clock_reset`.

## Tamper evidence

- Each batch extends a SHA-256 chain: the head is SHA-256 of the previous head and the batch's bytes, starting from zero at each start of the gateway, and the batch ends with `audit.chain` naming it.
- `audit.checkpoint` signs the head with the identity key (the key upstreams verify assertions with) once a minute and at rotation.
- `apiward audit verify --jwks <key set> <files…>` recomputes the chain over the files, oldest first, and checks every checkpoint; it names each record altered, added or removed, each compressed file whose content does not match its header's SHA-256, and each missing file. With keys, every run needs at least one verifiable checkpoint (otherwise one problem, including a run younger than its first checkpoint), and an `audit.evicted` record explains a missing file only when a verified checkpoint of its run covers it. When a run's earlier files are not given, it anchors the run at the first file's signed checkpoint (listed in `anchored_files`), or reports one problem when that batch has no verifiable checkpoint while still checking later records. Records after the last chain record of an unclean stop, or of a file replaced after a failed sync, are reported as unchained, not as altered.
- `GET /admin/status` returns the latest signed checkpoint in `audit_checkpoint` (or `null` before the first checkpoint or under `upstream.unsigned_identity`); copy checkpoints off the host regularly. `gateway_audit_chain_batches_total` and `gateway_audit_last_checkpoint_timestamp_seconds` on the metrics listener track chain progress.
- Limit: anyone with root on the host holds the identity key and can rewrite and re-sign the tail; only heads or checkpoints copied off the host bound that.

## Reading the log

- The files are plain JSON lines: `jq` or any log shipper reads them.
- `GET /admin/security-log` (permission `read_history`) searches the request records of the active, rotated and archived files, newest first, by request ID, account, operation, decision and time.
- `format=csv` or `format=json` exports up to 10,000 rows within 256 MiB of reading; the CSV escapes values a spreadsheet would run as formulas.
- Searches and exports read the files one at a time and stop when the client leaves.
- `GET /admin/alerts` reads the active file's last 1 MiB for its write rate; `GET /admin/advice` reads tracked permission use from the database instead of scanning log files.
- The Dashboard's Security Log page uses these endpoints; its live views read the gateway's memory, not the files.
- `gateway_audit_bytes` and `gateway_audit_budget_bytes` on the metrics listener show how full the log is.
- `gateway_key_reload_failures_total` counts key reloads refused because the keys or the settings beside them were invalid.
- `gateway_admin_failures_total{reason}` counts Admin API requests the gateway could not answer itself: `store`, `audit`, `busy`, `log`, `streams` (every live-view slot in use).
- `/readyz` answers `503` while the log refuses records: it has failed, has no space, is replacing its file, or is full under `refuse`.
