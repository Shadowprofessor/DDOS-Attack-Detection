import { afterEach, describe, expect, it, vi } from "vitest";
import { getCsrfToken } from "../api/client";
import { clearAuth, getAuth, isAdmin, login, logout, restore } from "./store";

function respond(status: number, body?: unknown) {
  return new Response(body === undefined ? null : JSON.stringify(body), { status });
}

afterEach(() => {
  vi.unstubAllGlobals();
  clearAuth();
});

describe("auth store", () => {
  it("login keeps role + CSRF in memory only", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => respond(200, { role: "admin", actor: "admin:ab12", csrf_token: "c1" })));
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    await login("some-api-key");
    expect(getAuth()).toEqual({ status: "authenticated", role: "admin", actor: "admin:ab12" });
    expect(isAdmin(getAuth())).toBe(true);
    expect(getCsrfToken()).toBe("c1");
    expect(setItem).not.toHaveBeenCalled();
  });

  it("failed login leaves the user anonymous", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => respond(401, { detail: "Invalid API key." })));
    clearAuth();
    await expect(login("wrong-key-1")).rejects.toThrow();
    expect(getAuth().status).toBe("anonymous");
  });

  it("restore without a session goes anonymous; with one, authenticated", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => respond(401, { detail: "No active session." })));
    await restore();
    expect(getAuth().status).toBe("anonymous");
    vi.stubGlobal("fetch", vi.fn(async () => respond(200, { role: "analyst", actor: "analyst:cd34", csrf_token: "c2" })));
    await restore();
    expect(getAuth().role).toBe("analyst");
    expect(isAdmin(getAuth())).toBe(false);
  });

  it("logout clears state even if the server call fails", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => respond(200, { role: "analyst", actor: "a", csrf_token: "c3" })));
    await login("some-api-key");
    vi.stubGlobal("fetch", vi.fn(async () => respond(500, {})));
    await expect(logout()).rejects.toThrow();
    expect(getAuth().status).toBe("anonymous");
    expect(getCsrfToken()).toBeNull();
  });
});
