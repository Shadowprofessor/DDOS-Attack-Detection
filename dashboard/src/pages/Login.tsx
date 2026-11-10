import { useState, type FormEvent } from "react";
import { ApiError } from "../api/client";
import { login } from "../auth/store";

export function LoginPage() {
  const [key, setKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(key.trim());
      setKey("");
    } catch (err) {
      setError(err instanceof ApiError && err.status === 429 ? "Too many attempts. Wait a minute." : "Invalid API key.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="center">
      <form className="card login" onSubmit={onSubmit} aria-labelledby="login-title">
        <h1 id="login-title">DDoS SOC</h1>
        <p className="muted">Sign in with your analyst or admin API key. The key is exchanged for a session and never stored in the browser.</p>
        <label htmlFor="api-key">API key</label>
        <input
          id="api-key"
          type="password"
          autoComplete="current-password"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          minLength={8}
          required
        />
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        <button type="submit" className="btn primary" disabled={busy || key.trim().length < 8}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </main>
  );
}
