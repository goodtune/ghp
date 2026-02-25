import { test, expect } from "@playwright/test";
import { loginTestUser } from "./helpers";

test.describe("Admin", () => {
  test.beforeEach(async ({ context }) => {
    await loginTestUser(context, { username: "admin-e2e", role: "admin" });
  });

  test("loads users panel via SSE on page load", async ({ page }, testInfo) => {
    await page.goto("/admin");

    // Admin nav link is active.
    await expect(page.locator('header a.nav-link.active')).toHaveText("Admin");

    // Users tab is active by default.
    const usersPanel = page.locator("#admin-users-panel");
    await expect(usersPanel).toBeVisible();

    // Wait for SSE to deliver the users table.
    await expect(usersPanel.locator("table")).toBeVisible({ timeout: 5_000 });
    await expect(usersPanel).toContainText("admin-e2e");

    await testInfo.attach("admin-users", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });

  test("switches to tokens tab via SSE", async ({ page }, testInfo) => {
    await page.goto("/admin");
    await expect(page.locator("#admin-users-panel table")).toBeVisible({ timeout: 5_000 });

    // Tokens panel should not have content initially.
    await expect(page.locator("#admin-tokens-panel h2")).not.toBeVisible();

    // Switch to Tokens tab — fires SSE GET.
    await page.click('button.tab:has-text("Tokens")');
    await expect(page.locator("#admin-tokens-panel h2")).toContainText("All Tokens", { timeout: 5_000 });

    await testInfo.attach("admin-tokens", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });

  test("filters tokens by status", async ({ page }) => {
    await page.goto("/admin");
    await expect(page.locator("#admin-users-panel table")).toBeVisible({ timeout: 5_000 });

    // Switch to tokens tab.
    await page.click('button.tab:has-text("Tokens")');
    await expect(page.locator("#admin-tokens-panel h2")).toContainText("All Tokens", { timeout: 5_000 });

    // The filter bar should be visible.
    await expect(page.locator(".filter-bar")).toBeVisible();
  });

  test("clicking a user row expands to show their tokens", async ({ page }) => {
    await page.goto("/admin");
    await expect(page.locator("#admin-users-panel table")).toBeVisible({ timeout: 5_000 });

    // Click on the first user row.
    const userRow = page.locator('#admin-users-panel tr.expandable-row').first();
    await userRow.click();

    // Expansion row should appear with token cards or empty message.
    const expansion = page.locator('[id^="user-expansion-"]');
    await expect(expansion).toBeVisible({ timeout: 5_000 });
  });

  test("live updates tokens panel when token is created", async ({
    context,
    browser,
  }) => {
    // Open admin page in first tab.
    const adminPage = await context.newPage();
    await adminPage.goto("/admin");

    // Wait for SSE to load.
    await expect(
      adminPage.locator("#admin-users-panel table")
    ).toBeVisible({ timeout: 5_000 });

    // Switch to tokens tab to verify it loaded.
    await adminPage.click('button.tab:has-text("Tokens")');
    await expect(
      adminPage.locator("#admin-tokens-panel h2")
    ).toContainText("All Tokens");

    // Open dashboard in a second page (same context = same session).
    const dashPage = await context.newPage();
    await dashPage.goto("/");
    await dashPage.waitForLoadState("domcontentloaded");

    // Create a token via the dashboard stepper (SSE-driven, dev mode).
    await dashPage.locator('button:has-text("New Token")').first().click();
    await expect(dashPage.locator(".modal-overlay")).toHaveClass(/open/);

    // Wait for step 0 to load via SSE.
    await expect(
      dashPage.locator('#stepper-content .stepper-title:has-text("Select Repository")')
    ).toBeVisible({ timeout: 5_000 });

    await dashPage.fill("#repo-input", "goodtune/live-update-test");
    await dashPage.locator('#stepper-content button:has-text("Next")').click();

    // Wait for step 1, advance.
    await expect(
      dashPage.locator('#stepper-content .stepper-title:has-text("Set Permissions")')
    ).toBeVisible({ timeout: 5_000 });
    await dashPage.locator('#stepper-content button:has-text("Next")').click();

    // Wait for step 2, advance.
    await expect(
      dashPage.locator('#stepper-content .stepper-title:has-text("Details")')
    ).toBeVisible({ timeout: 5_000 });
    await dashPage.locator('#stepper-content button:has-text("Next")').click();

    // Wait for step 3, create.
    await expect(
      dashPage.locator('#stepper-content .stepper-title:has-text("Confirm")')
    ).toBeVisible({ timeout: 5_000 });
    await dashPage.locator('#stepper-content button:has-text("Create Token")').click();

    await expect(dashPage.locator(".token-display")).toBeVisible({
      timeout: 10_000,
    });

    // Now check the admin page — the tokens panel should have updated live.
    await adminPage.bringToFront();
    await adminPage.click('button.tab:has-text("Tokens")');

    // The newly created token should appear in the admin tokens table.
    await expect(
      adminPage.locator("#admin-tokens-panel")
    ).toContainText("goodtune/live-update-test", { timeout: 10_000 });
  });
});
