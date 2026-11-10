// Minimal external store for the current session (role + CSRF token), in memory only.
import { useSyncExternalStore } from "react";
import { api, json, setCsrfToken, type Role, type SessionInfo } from "../api/client";

export interface AuthState {
  status: "unknown" | "anonymous" | "authenticated";
  role: Role | null;
  actor: string | null;
}

let state: AuthState = { status: "unknown", role: null, actor: null };
const listeners = new Set<() => void>();

function set(next: AuthState): void {
  state = next;
  listeners.forEach((l) => l());
}

export function getAuth(): AuthState {
  return state;
}

export function subscribe(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

export function useAuth(): AuthState {
  return useSyncExternalStore(subscribe, getAuth, getAuth);
}

function accept(s: SessionInfo): void {
  setCsrfToken(s.csrf_token);
  set({ status: "authenticated", role: s.role, actor: s.actor });
}

export function clearAuth(): void {
  setCsrfToken(null);
  set({ status: "anonymous", role: null, actor: null });
}

/** Restore an existing session after a reload (cookie is sent automatically). */
export async function restore(): Promise<void> {
  try {
    accept(await api<SessionInfo>("/api/session"));
  } catch {
    clearAuth();
  }
}

export async function login(apiKey: string): Promise<void> {
  accept(await api<SessionInfo>("/api/session/login", { method: "POST", body: json({ api_key: apiKey }) }));
}

export async function logout(): Promise<void> {
  try {
    await api<void>("/api/session/logout", { method: "POST" });
  } finally {
    clearAuth();
  }
}

export const isAdmin = (s: AuthState): boolean => s.role === "admin";
