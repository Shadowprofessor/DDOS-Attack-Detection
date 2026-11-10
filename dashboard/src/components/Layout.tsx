import { NavLink, Outlet } from "react-router";
import { useQueryClient } from "@tanstack/react-query";
import { logout, useAuth } from "../auth/store";
import { LoginPage } from "../pages/Login";

export function Layout() {
  const auth = useAuth();
  const qc = useQueryClient();

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
        </nav>
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
