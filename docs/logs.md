# Security log

What the gateway records, when a record is waited for, and how to read the log. Settings: [settings.md](settings.md#security-log).

## Files

- The active file is `gateway.audit_log`; rotated files are named `<file>.1`, `<file>.2` and so on, the highest number the newest.
- Each line is one JSON record with `schema`, `event_id`, `time`, `seq` and `kind`, plus the fields of its kind.
- Records never hold tokens, passwords, cookies or request bodies.
- **Waited for**: the gateway goes on only after the record is on disk; when it cannot be written, the action is refused.
- **Queued**: the record is written with the next batch; a record that finds no room is counted, and the count is written as `audit.loss`.

## Request records

| Kind | Written when | Record |
|---|---|---|
| `request.admitted` | A request passed every check, before it is forwarded | Waited for |
| `request.forwarded` | The upstream exchange ended | Queued |
| `request.rejected` | A check refused the request, or enforcement failed | Queued |
| `request.preflight` | A browser preflight was answered | Queued |

- A request record holds the request ID, method, path, client address, policy version, operation, API, account, roles, the result of each check, status, error code and duration.
- Refusals before any policy applies (overload, oversized or malformed requests, tunnels, upgrades) write no request record; they are counted per reason and address in `audit.ingress_summary` once a minute.

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
| `transition.rejected`, `cpa.rejected`, `tpo.rejected` | A change was refused | Queued |
| `tpo.validated` | A temporary rule passed its check without being created | Queued |
| `transition.failed` | The database could not complete a change | Queued |
| `controller.reconciled` | The gateway reconciled its stored state at start | Queued |
| `controller.unavailable` | The gateway stopped accepting protected requests | Queued |

- At start, an outcome whose record is missing is written again under its own kind with reason `reconciled`.

## Gateway and operator records

| Kind | Written when | Record |
|---|---|---|
| `tls.reload_failed` | A listener certificate reload failed; the old certificate stays | Queued |
| `tls.certificate_expiring` | Daily while the listener certificate expires within 14 days | Queued |
| `operator.backup` | `apiward backup` wrote a backup | Waited for |
| `audit.rotated` | The active file was rotated | With its batch |
| `audit.evicted` | A full log under `evict_oldest` deleted its oldest file (name, size, SHA-256, first and last record) | Before the deletion |
| `audit.loss` | Records were dropped for lack of room since the last batch | With its batch |
| `audit.recovered` | At start, the last record of the active file had been cut off | Queued |
| `audit.ingress_summary` | Refusals before any policy applied were counted | Once a minute |

- Operator commands (`install`, `enrol`, `migrate`, `restore`) write `transition.intent` and `transition.committed` around their change.

## Reading the log

- The files are plain JSON lines: `jq` or any log shipper reads them.
- `GET /admin/security-log` (permission `read_history`) searches the request records of the active and rotated files, newest first, by request ID, account, operation, decision and time.
- `format=csv` or `format=json` exports up to 10,000 rows within 256 MiB of reading; the CSV escapes values a spreadsheet would run as formulas.
- Searches, exports and the unused-permission advice read the files one at a time and stop when the client leaves.
- `GET /admin/advice` reads the files for unused permissions; `GET /admin/alerts` reads the active file's last 1 MiB for its write rate.
- The Dashboard's Security Log page uses these endpoints; its live views read the gateway's memory, not the files.
- `gateway_audit_bytes` and `gateway_audit_budget_bytes` on the metrics listener show how full the log is.
- `gateway_admin_failures_total{reason}` counts Admin API requests the gateway could not answer itself: `store`, `audit`, `busy`, `log`.
- `/readyz` answers `503` while the log has failed or is full.
