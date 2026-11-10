import { defineConfig, devices } from "@playwright/test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { ADMIN_KEY, ANALYST_KEY } from "./e2e/keys";

// E2E runs the REAL FastAPI app (serving dashboard/dist) with throwaway keys and a temp DB.
// LLM is never called (no NVIDIA_API_KEY): the analyst falls back to rules.
const PORT = Number(process.env.E2E_PORT ?? 8765);
const work = mkdtempSync(join(tmpdir(), "ddos-e2e-"));

export default defineConfig({
  testDir: "e2e",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: `${process.env.PYTHON ?? "python"} -m uvicorn src.api.app:app --host 127.0.0.1 --port ${PORT}`,
    cwd: resolve(import.meta.dirname, ".."),
    url: `http://localhost:${PORT}/health`,
    timeout: 180_000,
    reuseExistingServer: false,
    env: {
      DDOS_API_KEYS: ANALYST_KEY,
      DDOS_ADMIN_KEYS: ADMIN_KEY,
      DDOS_IR_DATABASE_URL: `sqlite:///${join(work, "ir.db").replace(/\\/g, "/")}`,
      DDOS_PENDING_ACTIONS_PATH: join(work, "actions.json"),
      DDOS_DEV_KEY_FILE: join(work, ".dev-keys"),
      // scheduler ON: approved blocks get a real rollback countdown (default TTL 600 s)
      DDOS_IR_SCHEDULER: "on",
      DDOS_LOGIN_RATE_PER_MIN: "100",
      NVIDIA_API_KEY: "",
    },
  },
});
