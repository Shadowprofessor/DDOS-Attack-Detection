# SOC web app (v4.3.0)

React 19 + Vite 8 + strict TypeScript, React Router 7, TanStack Query 5. Source in `dashboard/`.
The build is served by FastAPI at **`/app`**. The legacy `/dashboard` is unchanged until v4.5.0.

```bash
cd dashboard && npm ci && npm run build      # -> dashboard/dist, served at http://localhost:8000/app
npm run dev                                   # Vite dev server on :5173, proxies /api and /ws to :8000
npm run lint && npm run typecheck && npm test # ESLint, tsc, Vitest
npm run e2e                                   # Playwright against the real FastAPI app (temp DB, mocked LLM)
```

## Pages in this release
- **Login**: exchanges an API key for a server-side session. The key is never stored in the browser.
- **Overview**: open incidents, pending approvals, mean time to contain, false-positive rate,
  open-by-severity chart, CERT-In countdowns, recent incidents, model/LLM health.
- **Incidents**: filter (status, minimum severity, include replays), sort (time / severity),
  pagination. State lives in the URL.

Incident detail, approvals, the AI panel and live updates arrive in v4.3.1. Live feed, replay,
chat and settings arrive in v4.5.0.

## Security model
| Control | How |
|---|---|
| Session | `POST /api/session/login` → opaque id in `ddos_session` cookie: **HttpOnly, Secure, SameSite=Strict, Path=/**. Server-side store; new id on every login (rotation); 30 min idle / 8 h absolute expiry (`DDOS_SESSION_IDLE_S`, `DDOS_SESSION_ABSOLUTE_S`); role re-checked against the configured keys on every request, so revoking a key ends its sessions. Login rate-limited per client (`DDOS_LOGIN_RATE_PER_MIN`, default 10). |
| CSRF | Synchroniser token returned by login / `GET /api/session`, kept in JS memory only, sent as `X-CSRF-Token` on POST/PUT/PATCH/DELETE. Missing or wrong token on a cookie-authenticated mutation → **403**. Header-key clients (CLI/scripts) are unaffected: their key is not an ambient credential. |
| RBAC | Unchanged from v4.2.0 (`src/api/rbac.py`); the session resolves to the same analyst/admin role. Admin-only controls will be hidden in the UI **and** enforced server-side. |
| CSP | `/app*` and `/api/*`: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`. No `unsafe-inline` / `unsafe-eval`. The build emits only external JS/CSS; charts use SVG attributes, not inline styles. |
| Other headers | `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy` (camera/mic/geo/payment/usb off), `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin`; HSTS in production/staging. |
| Rendering | All server strings are rendered as React text. ESLint (`no-restricted-syntax`) fails the build on `dangerouslySetInnerHTML`, `innerHTML` or a `style` attribute. Playwright checks that an `<img onerror>` incident title renders as text. |
| CORS | Same-origin only by default (was `*`). List extra origins in `DDOS_CORS_ORIGINS` if a separate client needs it. |
| SPA mount | Files are served only from inside `dashboard/dist` (resolved-path check). Unknown client routes get `index.html`; `/api/*` is never shadowed; missing assets → 404. |

## Design
Dark theme. Accents: cyan `#22d3ee`, violet `#818cf8`, amber `#ffba08`. **Red only for
severity 5 (critical)**, enforced by a unit test. Visible focus rings and a skip link.
`prefers-reduced-motion` is respected, and there is no horizontal scroll at 375 px
(Playwright-checked).

## CI
`.github/workflows/webapp.yml` runs `npm ci`, lint, typecheck, Vitest, build,
`npm audit --audit-level=high --omit=dev`, then Playwright (Chromium) against the real API.
CodeQL already scans `javascript-typescript`. Dependabot watches `dashboard/`.
