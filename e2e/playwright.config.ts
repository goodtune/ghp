import { defineConfig } from "@playwright/test";

const baseURL = process.env.GHP_BASE_URL || "http://localhost:8080";

export default defineConfig({
  testDir: "./tests",
  outputDir: "./test-results",
  timeout: 30_000,
  retries: 0,
  use: {
    baseURL,
    headless: true,
    screenshot: "on",
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { browserName: "chromium" },
    },
  ],
  reporter: [
    ["list"],
    ["json", { outputFile: "./test-results/results.json" }],
    ["html", { open: "never" }],
  ],
});
