import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.GHP_BASE_URL || "http://localhost:8080";

// Optionally restrict to a single browser via PLAYWRIGHT_BROWSER (chromium |
// firefox | webkit). When unset, all three projects run.
const onlyBrowser = process.env.PLAYWRIGHT_BROWSER;

const allProjects = [
  {
    name: "chromium",
    use: { ...devices["Desktop Chrome"] },
  },
  {
    name: "firefox",
    use: { ...devices["Desktop Firefox"] },
  },
  {
    name: "webkit",
    use: { ...devices["Desktop Safari"] },
  },
];

export default defineConfig({
  testDir: "./tests",
  outputDir: "./test-results",
  timeout: 30_000,
  retries: 0,
  workers: 1,
  use: {
    baseURL,
    headless: true,
    screenshot: "on",
    trace: "retain-on-failure",
  },
  projects: onlyBrowser
    ? allProjects.filter((p) => p.name === onlyBrowser)
    : allProjects,
  reporter: [
    ["list"],
    ["json", { outputFile: "./test-results/results.json" }],
    ["html", { open: "never" }],
  ],
});
