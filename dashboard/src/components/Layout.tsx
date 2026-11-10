import { NavLink, Outlet } from "react-router";
import { useQueryClient } from "@tanstack/react-query";
import { isAdmin, logout, useAuth } from "../auth/store";
import { useLiveStatus, useLiveUpdates } from "../live/useLive";
import { LoginPage } from "../pages/Login";

export function Layout() {
  const auth = useAuth();
  const qc = useQueryClient();
  useLiveUpdates(auth.status === "authenticated");
  const live = useLiveStatus();

  if (auth.status === "unknown") {
    return (
      <main className="center" aria-busy="true">
        <p className="muted">Loading…</p>
      </main>
    );
  }
  if (auth.status === "anonymous") return <LoginPage />;

  const onLogout = async () => {
    await logout();
    qc.clear();
  };

  return (
    <div className="shell">
      <a className="skip" href="#main">Skip to content</a>
      <header className="topbar">
        <span className="brand">DDoS SOC</span>
        <nav aria-label="Primary">
          <NavLink to="/overview">Overview</NavLink>
          <NavLink to="/incidents">Incidents</NavLink>
          {isAdmin(auth) && <NavLink to="/approvals">Approvals</NavLink>}
        </nav>
        <span className={`live live-${live}`} role="status" aria-live="polite">
          {live === "live" ? "Live" : live === "connecting" ? "Connecting…" : "Offline (polling)"}
        </span>
        <span className="who">
          <span className={`role role-${auth.role}`}>{auth.role}</span>
          <button type="button" className="btn ghost" onClick={onLogout}>
            Log out
          </button>
        </span>
      </header>
      <main id="main" tabIndex={-1}>
        <Outlet />
      </main>
    </div>
  );
}
