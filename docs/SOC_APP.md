# SOC web app (v4.3.0 – v5.0.0)

React 19 + Vite 8 + strict TypeScript, React Router 7, TanStack Query 5. Source in `dashboard/`.
The build is served by FastAPI at **`/app`** (`/` redirects there).

```bash
cd dashboard && npm ci && npm run build      # -> dashboard/dist, served at http://localhost:8000/app
npm run dev                                   # Vite dev server on :5173, proxies /api and /ws to :8000
npm run lint && npm run typecheck && npm test # ESLint, tsc, Vitest
npm run e2e                                   # Playwright against the real FastAPI app (temp DB, mocked LLM)
```

## Pages
- **Login** (v4.3.0): exchanges an API key for a server-side session. The key is never stored in the browser.
- **Overview** (v4.3.0): open incidents, pending approvals, mean time to contain, false-positive
  rate, open-by-severity chart, CERT-In countdowns, recent incidents, model/LLM health.
- **Incidents** (v4.3.0): filter (status, minimum severity, include replays), sort, paginate. State lives in the URL.
- **Incident detail** (v4.3.1) `/app/incidents/:id`:
  - Lifecycle buttons. Analysts see only triage/investigating; containment opens a dialog asking
    for a justification.
  - MD/PDF export.
  - CERT-In countdown, plus a report draft and "mark reported" for admins.
  - **AI analyst panel** labelled "AI recommendation — review before acting". It shows
    provenance: source model or rules, cached, degraded reason, output-policy corrections,
    instruction-like telemetry count. "Run analysis" calls `POST /api/incidents/{id}/analyze`;
    replays always use the rule analyst. The analyst never changes severity and never proposes
    or executes anything.
  - Aggregated telemetry.
  - Suggested playbooks. Steps run per role; "Request action" only *proposes*.
  - Linked actions with rollback state, notes, and the full hash-chained timeline with its
    verification status.
- **Approvals** (v4.3.1, admin nav) `/app/approvals`:
  - Pending actions, with estimated blast radius, reversibility, rollback TTL and the linked
    incident.
  - Approve, or reject with a reason, both through a confirmation dialog.
  - Active time-boxed blocks with a live rollback countdown. Extend 10 min or make permanent;
    both need a reason.
  - Analysts who open the URL get a read-only view, and the server returns 403 on any action.
- **Live updates** (v4.3.1): one WebSocket per tab to `/ws/incidents`, authenticated by the
  session cookie. Same-origin handshakes only: the `Origin` must match `Host`, so another site
  can't ride the cookie. Reconnects with exponential backoff (1 s up to a 30 s cap). Each event
  refreshes the affected queries. The status chip shows Live / Connecting / Offline (polling),
  and pages keep polling as a fallback.

- **Live feed** (v4.5.0) `/app/live`: the `/ws/dashboard` stream (scored flows, burst alerts,
  enforced drops, campaigns) over the session cookie, same-origin only. Filter by type, attacks
  only, or search IP/label; pause holds incoming events and resume flushes them. The list is
  windowed: only visible rows are in the DOM, and the last 2,000 events are kept.
- **Replay** (v4.5.0) `/app/replay`: pick a stored scenario and speed. The result shows each
  stage and links to the new replay incident. Proposals from a replay go to a dry-run queue only.
- **AI analyst** (v4.5.0) `/app/analyst`: read-only chat (`/api/chat`), optionally scoped to an
  incident, with the incident's stored-analysis provenance alongside. Requests to block or
  approve get the safety refusal.
- **Settings & health** (v4.5.0) `/app/settings`: release, environment, package versions, model
  artifacts, analyst model chain (key present yes/no only), IR settings. Read-only; no secrets.
- **Legacy dashboard**: removed in v5.0.0. `/dashboard` and `/legacy` redirect (308) to `/app/`.
  Its JSON endpoints and the `/ws/dashboard` stream remain; the live feed uses them.

## Security model
| Control | How |
|---|---|
| Session | `POST /api/session/login` → opaque id in `ddos_session` cookie: **HttpOnly, Secure, SameSite=Strict, Path=/**. Server-side store; new id on every login (rotation); 30 min idle / 8 h absolute expiry (`DDOS_SESSION_IDLE_S`, `DDOS_SESSION_ABSOLUTE_S`); role re-checked against the configured keys on every request, so revoking a key ends its sessions. Login rate-limited per client (`DDOS_LOGIN_RATE_PER_MIN`, default 10). |
| CSRF | Synchroniser token returned by login / `GET /api/session`, kept in JS memory only, sent as `X-CSRF-Token` on POST/PUT/PATCH/DELETE. Missing or wrong token on a cookie-authenticated mutation → **403**. Header-key clients (CLI/scripts) are unaffected: their key is not an ambient credential. |
| RBAC | Same roles as v4.2.0 (`src/api/rbac.py`). The session resolves to analyst or admin. Admin-only controls are hidden in the UI **and** enforced server-side. `/actions/approve` and `/actions/reject` accept an admin session plus CSRF token; an analyst session gets 403, the same as an analyst key. `approve()` is still called only from `approve_action_endpoint` (the AST test checks this). |
| CSP | `/app*` and `/api/*`: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`. No `unsafe-inline` / `unsafe-eval`. The build emits only external JS/CSS; charts use SVG attributes, not inline styles. |
| Other headers | `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy` (camera/mic/geo/payment/usb off), `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin`; HSTS in production/staging. |
| Rendering | All server strings are rendered as React text. ESLint (`no-restricted-syntax`) fails the build on `dangerouslySetInnerHTML`, `innerHTML` or a `style` attribute. Playwright checks that an `<img onerror>` incident title renders as text. |
| CORS | Same-origin only by default (was `*`). List extra origins in `DDOS_CORS_ORIGINS` if a separate client needs it. |
| SPA mount | Files are served only from inside `dashboard/dist` (resolved-path check). Unknown client routes get `index.html`; `/api/*` is never shadowed; missing assets → 404. |

## Accessibility and layout (checked by Playwright on every page)
- axe-core (WCAG 2.0/2.1 A + AA tags): **0 serious or critical** violations on all 8 page types.
- No CSP violations in the console. No horizontal scroll at 375 px. No running animations under
  `prefers-reduced-motion: reduce`. Approvals can be done keyboard-only, and dialogs focus their
  reason field.
- Screenshots in `docs/img/` (`SCREENSHOTS=1 npx playwright test`) are captured from the e2e run.

## Design
Dark theme. Accents: cyan `#22d3ee`, violet `#818cf8`, amber `#ffba08`. **Red only for
severity 5 (critical)**, enforced by a unit test. Visible focus rings and a skip link.
`prefers-reduced-motion` is respected, and there is no horizontal scroll at 375 px
(Playwright-checked).

## CI
`.github/workflows/webapp.yml` runs `npm ci`, lint, typecheck, Vitest, build,
`npm audit --audit-level=high --omit=dev`, then Playwright (Chromium) against the real API.
CodeQL already scans `javascript-typescript`. Dependabot watches `dashboard/`.
