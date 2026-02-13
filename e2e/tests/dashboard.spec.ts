import { test, expect } from "@playwright/test";
import { loginTestUser } from "./helpers";

test.describe("Dashboard", () => {
  test.beforeEach(async ({ context }) => {
    await loginTestUser(context);
  });

  test("renders dashboard with user info", async ({ page }, testInfo) => {
    await page.goto("/");

    await expect(page).toHaveTitle("ghp — Dashboard");

    // Header shows the username.
    await expect(page.locator("header")).toContainText("testuser");

    // Header shows the role.
    await expect(page.locator("header")).toContainText("user");

    // Sign out button is present.
    await expect(
      page.locator('button:has-text("Sign out")')
    ).toBeVisible();

    await testInfo.attach("dashboard-overview", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });

  test("shows Create Token section with form fields", async ({ page }) => {
    await page.goto("/");

    // The create token section heading exists.
    await expect(
      page.locator('h2:has-text("Create Token")')
    ).toBeVisible();

    // Form fields are present.
    await expect(page.locator("#repo")).toBeVisible();
    await expect(page.locator("#scopes")).toBeVisible();
    await expect(page.locator("#duration")).toBeVisible();
    await expect(page.locator("#session")).toBeVisible();

    // Create Token button.
    await expect(
      page.locator('button:has-text("Create Token")')
    ).toBeVisible();
  });

  test("shows Active Tokens section", async ({ page }) => {
    await page.goto("/");

    await expect(
      page.locator('h2:has-text("Active Tokens")')
    ).toBeVisible();

    // Initially shows "No tokens found".
    await expect(page.locator("#token-list")).toContainText("No tokens found");
  });

  test("shows Audit Log section", async ({ page }) => {
    await page.goto("/");

    await expect(
      page.locator('h2:has-text("Audit Log")')
    ).toBeVisible();
  });

  test("duration dropdown has expected options", async ({ page }) => {
    await page.goto("/");

    const options = page.locator("#duration option");
    await expect(options).toHaveCount(4);

    const values = await options.evaluateAll((els) =>
      els.map((el) => (el as HTMLOptionElement).value)
    );
    expect(values).toEqual(["8h", "24h", "48h", "168h"]);

    // 24h is selected by default.
    await expect(page.locator("#duration")).toHaveValue("24h");
  });
});
