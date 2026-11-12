# Dashboard

The administrator Dashboard: a React and TypeScript single-page application that the admin listener serves at `/`, on the same origin as the Admin API. Build and test steps: [dashboard/README.md](../dashboard/README.md).

## Authority

- The Dashboard holds no authority of its own.
- The Admin API authenticates administrators and checks their permissions, the session's CSRF token and the request's `Origin` and `Host` on every call.
- The Admin API decides every change; the Dashboard shows what it returns and sends what the administrator confirms.
- Hiding an action the administrator lacks permission for is a convenience; the server still refuses it.

## Monitor

- **Overview:** the policy in force; a change on trial with its countdown, **Undo change** and **Review and keep**; temporary rules in force; traffic in a chosen window; why requests were refused; the latest refusals with the deciding check; figures per API; a timeline of policy changes.
- A new or restored installation is told how to establish its first policy.
- Every page warns at the top while the gateway is not accepting requests.
- A Getting Started guide ticks off the first steps (a policy in force, a first trial, a trial kept or undone) from what the gateway reports, and hides itself once all are done; **Hide this guide** removes it sooner; My Account shows it again.
- **Live Traffic:** every request as the gateway decides it, streamed; pause for inspection; filters for changes only (anything but reads) or refusals only; keeps the latest 1,000 requests and draws the newest 200 that match.
- **Request details:** every request row on Overview, Live Traffic and the Security Log opens the request in a side panel at the page's own address plus `?ref=`; Back closes it.
- The panel shows arrival time, method and path, response, policy version and account; each check passed, the deciding check and those never reached; the full reason; the Ref to copy.
- The **Search** box in every page header opens a full Ref the same way, opens the Security Log on an account or endpoint ID (never placed in the address), and finds a draft change ("change 12"), a temporary rule ("rule 3") or a version ("version 4").
- **APIs:** each API's endpoints, who may call them, rate limits and bodies, traffic figures, and each endpoint's request rules in words with the exact schema under More Details.

## Policy

- **Policy:** the Policy Designer (below); "Versions and tables" opens the policy in force as tables and every version, each of which can start a draft change.
- **Roles:** what each role can do under the policy in force, in plain sentences, with any temporary rule that changes it and the accounts seen with it in recent requests; read only.
- **Changes:** the guided way a change goes live.
  - A draft starts on the Policy page or from the active version; pasting or loading a whole JSON document is under **Advanced**.
  - Saving a draft change runs the gateway's own compiler over the whole document.
  - The review lists the differences member by member.
  - An impact preview replays recent requests to show which would now be decided differently.
  - The change goes on trial with a deadline and is undone by itself unless someone keeps it.
  - Before a trial starts, its dialog says what the change adds, changes and removes.
  - A draft that denies every request or removes a whole API is confirmed by typing "deny all" or the API's ID; a first policy by typing "deny all".
  - Past trials are listed with how each ended.
- **Temporary Rules:** allow or restrict something for a fixed lifetime, checked with the gateway before the rule is added; incident quick actions such as freezing ordering for 10 minutes.
- **Blocking:** block an account instantly, unblock it, and see the accounts and roles in recent traffic. A block is not a policy change: undoing a change never lifts it.

## Admin

- **History:** every administrative transition, filtered by area, outcome and administrator, read page by page or all at once.
- **Policy as Code:** the policy in force as one JSON document to copy or download, and the Admin API requests a script uses to read it and to save a draft change from a file.
- **Team:** administrators and their permissions; trusted token signing keys, with a reload from the operator's settings; the running build (version, Go toolchain, every compiled-in control with its phase). Adding an administrator stays an operator command (`apiward enrol`).
- **My Account:** session details, your permissions in plain words, the gateway's address, password change.

## Common behaviour

- Changes, Temporary Rules, Blocking, Roles and APIs share one list toolbar: a **Filter** box over rows already read (sends nothing), the row count ("2 of 5 roles"; a paged list says "loaded"), and the list's main action.
- **Add a Temporary Rule** opens a step-by-step form that ends on a review and the usual confirmation.
- The sidebar starts wide with group names, the environment ("Local gateway" when served from this computer) and its address; narrowing it to icons is one click and remembered in the browser.
- Controls move briefly when their state changes; with the operating system's reduced motion, only colour and opacity change.
- A notification bar names what changed between status reads: a trial starting or ending, temporary rules added or ended, signing keys reloaded, a security log that cannot be written. It makes no requests of its own.
- A notice stays until dismissed or another page opens; a problem stays on every page until dismissed.
- Every change is confirmed in a dialog that states its consequence.
- A change whose answer is lost is reported as an unknown outcome and never resent by itself; an explicit resend reuses its idempotency key, so the gateway applies it at most once.
- Every refusal, warning and unknown outcome has a plain title, what to do next, and a collapsed **More Details** with the exact error code, HTTP status, field and IDs, each copyable.
- "Refused", "Applied, but …" and "No answer from the gateway" stay distinct.

## Sign-in and storage

- Sign-in uses a password; first sign-in uses an operator-issued enrolment secret.
- The session is an HttpOnly, `Secure`, `SameSite=Strict`, host-only cookie that page scripts cannot read.
- Browser storage holds only display choices: the appearance (`gateway.theme`), the sidebar (`gateway.sidebar`) and the time zone (`gateway.timezone`).

## Policy Designer

- Edit one draft in Canvas, Form or JSON. Boxes show roles, endpoints, APIs and service addresses; arrows show permissions and routing.
- The checks on an endpoint stay in the gateway's enforcement order, with the same names as Live Traffic.
- The Form tab offers every editing option by keyboard.
- **Templates** prepares a common change in the draft: limit sign-in attempts, read-only access for a role to an API, remove a role's access to an API, or a tighter rate limit on an endpoint. It only edits the unsaved draft and says what it changed.
- **Step by Step** walks through three edits (give a role access, change a rate limit, add an endpoint), each ending on a review; **Apply to the Draft** only edits the unsaved draft.
- **Connect an API** opens in a side drawer from the Policy page, its empty canvas, the APIs page or the Getting Started guide. Steps: service address, API, endpoints, roles, rate limits and, optionally, a JSON Schema for each write endpoint's request body; the review lists what the draft gains; **Add to the Draft** only edits the unsaved draft.
- The gateway's compiler checks the result, schemas included, when the draft is saved.
- The draft stays in the signed-in page's memory across pages and ends with the session.
- **Save Draft Change** asks the gateway to check and store the whole document; the change continues on the Changes page. A save with no answer remains an unknown outcome; only an explicit identical resend reuses its request key.
- The in-force and on-trial modes are read-only. Live markers show temporary permissions, removals, rates, endpoint denial and changes on trial without rewriting the draft.
- Trace explains the selected document and sends no request; it does not apply temporary rules or decide actual access.

## Serving

- Set the settings' `gateway.admin_ui` to the absolute path of `dist/`, or build the binary with `-tags embedui` ([development.md](development.md)).
- The gateway serves `index.html` and the flat `assets/` directory, nothing else.
- Each script and style sheet is stored only as a gzip copy (`.js.gz`, `.css.gz`), sent as is to a browser that accepts gzip and inflated for one that does not.
- The page is never cached; `assets/` files are cached for a year, so each is named after its content (the build does this).
- Content policy: `default-src 'none'`; scripts, styles, images, fonts and connections from its own origin only. The build puts no script or style into the page and calls only relative Admin API paths.
- Fonts: Hanken Grotesk and Geist Mono, two files of the build, registered with the CSS Font Loading API before the page renders; SIL Open Font License 1.1 notices in `dashboard/src/fonts/`.
