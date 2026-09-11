import { test, expect } from "@playwright/test";
import {
  loginTestUser,
  ensureAppExists,
  createAppViaAPI,
  listAppsViaAPI,
  deleteAppViaAPI,
} from "./helpers";

test.describe("Dashboard - no apps configured", () => {
  test.beforeEach(async ({ context }) => {
    // Login as admin to clean up apps, then login as regular user.
    const admin = await loginTestUser(context, {
      username: "dashboard-admin-cleanup",
      role: "admin",
    });
    const apps = await listAppsViaAPI(admin.sessionToken);
    for (const app of apps) {
      await deleteAppViaAPI(admin.sessionToken, app.id);
    }
    await loginTestUser(context, { username: "dashboard-no-apps" });
  });

  test("hides token sections when no apps exist", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // The no-apps message should be visible.
    await expect(page.locator("#no-apps-message")).toBeVisible();
    await expect(page.locator("#no-apps-message")).toContainText(
      "No apps have been configured"
    );

    // Token creation and listing should be hidden.
    await expect(page.locator("#create-token-section")).toBeHidden();
    await expect(page.locator("#active-tokens-section")).toBeHidden();
  });
});

test.describe("Dashboard", () => {
  test.beforeEach(async ({ context }) => {
    await ensureAppExists(context);
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

    // Web component form fields are present.
    await expect(page.locator("ghp-repo-select")).toBeVisible();
    await expect(page.locator("ghp-permission-select")).toBeVisible();
    await expect(page.locator("#duration")).toBeVisible();
    await expect(page.locator("#session")).toBeVisible();

    // Create Token button.
    await expect(
      page.locator('button:has-text("Create Token")')
    ).toBeVisible();
  });

  test("shows Active Tokens section", async ({ context, page }) => {
    // Use a unique user so tokens from other tests don't interfere.
    await loginTestUser(context, { username: "dashboard-empty-tokens" });
    await page.goto("/");

    await expect(
      page.locator('h2:has-text("Active Tokens")')
    ).toBeVisible();

    // Initially shows "No tokens found".
    await expect(page.locator("#token-list")).toContainText("No tokens found");
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

test.describe("Dashboard - multi-app selection", () => {
  let adminToken: string;

  test.beforeEach(async ({ context }) => {
    // Login as admin to set up apps.
    const admin = await loginTestUser(context, {
      username: "dashboard-multiapp-admin",
      role: "admin",
    });
    adminToken = admin.sessionToken;

    // Clean up existing apps.
    const apps = await listAppsViaAPI(adminToken);
    for (const app of apps) {
      await deleteAppViaAPI(adminToken, app.id);
    }
  });

  test("requires app selection before showing token form with multiple apps", async ({
    context,
    page,
  }) => {
    // Create two apps.
    await createAppViaAPI(adminToken, {
      name: "Production App",
      app_id: 71001,
      is_default: true,
    });
    await createAppViaAPI(adminToken, {
      name: "Staging App",
      app_id: 71002,
    });

    // Login as regular user and load dashboard.
    await loginTestUser(context, { username: "multiapp-user" });
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // App selector should be visible.
    await expect(page.locator("#app-list-section")).toBeVisible();
    await expect(page.locator("#app-list")).toContainText("Production App");
    await expect(page.locator("#app-list")).toContainText("Staging App");

    // Token form should be hidden until an app is selected.
    await expect(page.locator("#create-token-section")).toBeHidden();
    await expect(page.locator("#active-tokens-section")).toBeHidden();

    // Click on an app card.
    await page.locator('.app-card:has-text("Production App")').click();

    // Token form should now be visible.
    await expect(page.locator("#create-token-section")).toBeVisible();
    await expect(page.locator("#active-tokens-section")).toBeVisible();

    // The selected card should be highlighted.
    await expect(
      page.locator('.app-card:has-text("Production App")')
    ).toHaveClass(/selected/);
  });

  test("auto-selects and shows form with single app", async ({
    context,
    page,
  }) => {
    await createAppViaAPI(adminToken, {
      name: "Only App",
      app_id: 72001,
      is_default: true,
    });

    await loginTestUser(context, { username: "singleapp-user" });
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // App list should be hidden (auto-selected).
    await expect(page.locator("#app-list-section")).toBeHidden();

    // Token form should be visible directly.
    await expect(page.locator("#create-token-section")).toBeVisible();
    await expect(page.locator("#active-tokens-section")).toBeVisible();
  });
});
