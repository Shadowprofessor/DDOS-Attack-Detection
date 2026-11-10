import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, setCsrfToken } from "./client";

function mockFetch(status: number, body: unknown) {
  const fn = vi.fn(async () => new Response(body === undefined ? null : JSON.stringify(body), { status }));
  vi.stubGlobal("fetch", fn);
  return fn;
}

afterEach(() => {
  vi.unstubAllGlobals();
  setCsrfToken(null);
});

describe("api client", () => {
  it("refuses non-/api paths (no open redirect / cross-origin use)", async () => {
    await expect(api("https://evil.example/x")).rejects.toThrow();
    await expect(api("/app/x")).rejects.toThrow();
  });

  it("sends same-origin credentials and no CSRF header on GET", async () => {
    const f = mockFetch(200, { ok: 1 });
    setCsrfToken("tok");
    await api("/api/x");
    const [, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.credentials).toBe("same-origin");
    expect(new Headers(init.headers).has("X-CSRF-Token")).toBe(false);
  });

  it("adds the CSRF token on state-changing requests", async () => {
    const f = mockFetch(201, { id: "INC-1" });
    setCsrfToken("tok-123");
    await api("/api/incidents", { method: "post", body: "{}" });
    const [, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    const h = new Headers(init.headers);
    expect(h.get("X-CSRF-Token")).toBe("tok-123");
    expect(h.get("Content-Type")).toBe("application/json");
    expect(init.method).toBe("POST");
  });

  it("maps error bodies to ApiError with the server detail only", async () => {
    mockFetch(403, { detail: "Insufficient privileges: admin role required." });
    const err = await api("/api/x").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(403);
    expect((err as ApiError).message).toBe("Insufficient privileges: admin role required.");
  });

  it("summarises 422 validation lists instead of echoing them", async () => {
    mockFetch(422, { detail: [{ loc: ["body", "x"], msg: "bad", input: "<script>" }] });
    const err = (await api("/api/x").catch((e: unknown) => e)) as ApiError;
    expect(err.message).toBe("Invalid input.");
  });

  it("returns undefined for 204", async () => {
    mockFetch(204, undefined);
    await expect(api("/api/session/logout", { method: "POST" })).resolves.toBeUndefined();
  });
});
