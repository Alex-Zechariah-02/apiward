# APIWard Dashboard

The administrator web console for APIWard: React and TypeScript, served by the gateway's admin listener at `/`. It holds no authority: the Admin API checks and decides every action. Pages and behaviour: [docs/dashboard.md](../docs/dashboard.md).

## Pages

| Group | Pages |
|---|---|
| Monitor | Overview, Live Traffic, APIs; request details in a side panel |
| Policy | Policy (Designer: Canvas, Form, JSON), Roles, Changes, Temporary Rules, Blocking |
| Admin | History, Policy as Code, Team, My Account |

## Requirements

- Node.js 24 and npm 11
- Browser tests: Go, Git, Google Chrome, and the Fetch repository at `../fetch`

## Build

```sh
npm ci
npm run check   # type checks the application and the tests
npm run build   # writes dist/
```

- Serve it: set the settings' `gateway.admin_ui` to the absolute path of `dist/`, or embed it in the binary ([docs/development.md](../docs/development.md)).

## Develop

- `npm run dev` serves `http://localhost:5173/` and proxies `/admin` to a running gateway's admin listener at `127.0.0.1:9440` (rewrites `Host` and `Origin`).
- The proxy is development only: not in the production build, not test evidence.

## Browser tests

```powershell
$env:EAT_PORT_OFFSET='1000'
$env:E2E_BACKEND_SOURCE='worktree'
npm run build
npm run e2e
```

- One file or test: `npx playwright test e2e/<file>.spec.ts [-g "<test name>"]`.
- Run one browser suite at a time: its demonstrations own the backend ports.
- Each spec file starts its own gateway, Fetch services and Fetch Accounts through the Fetch demo tool, and builds the state its tests read.

| Variable | Effect |
|---|---|
| `E2E_BACKEND_SOURCE` | `head` (default): backend built from an isolated export of `HEAD`; `worktree`: snapshot of the current `cmd/`, `internal/`, `go.mod`, `go.sum` (refused if it changes while copying) |
| `EAT_PORT_OFFSET` | Shifts every backend port, the short-session gateway and the development proxy target |
| `E2E_DEV_PORT` | Development server port (default 5173) |
| `E2E_APP_DIST` | Existing Dashboard build to serve instead of `dist/` |
| `WEBSITE_DIST` | Built Fetch shop to use instead of building `../fetch/client` |
| `E2E_EVIDENCE` | File for JSON-lines evidence: backend source, statuses, receipts, event fields; never secrets |
| `E2E_SHOTS` | Folder for screenshots; pages taller than 16,000 px are saved as viewport images with a scroll manifest |
