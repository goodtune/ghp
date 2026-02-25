import { test, expect } from "@playwright/test";
import { loginTestUser } from "./helpers";

test.describe("Dashboard", () => {
  test.beforeEach(async ({ context }) => {
    await loginTestUser(context);
  });

  test("renders dashboard with user info", async ({ page }, testInfo) => {
    await page.goto("/");

    await expect(page).toHaveTitle("ghp — Dashboard");

    // Header shows the user avatar.
    await expect(page.locator("header .avatar")).toBeVisible();

    // Sign out button is present.
    await expect(
      page.locator('button:has-text("Sign out")')
    ).toBeVisible();

    await testInfo.attach("dashboard-overview", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });

  test("shows empty state when no tokens exist", async ({
    context,
    page,
  }) => {
    await loginTestUser(context, { username: "dashboard-empty-user" });
    await page.goto("/");

    // Empty state message is visible.
    await expect(page.locator(".empty-state")).toContainText(
      "No tokens yet"
    );

    // Empty state has a New Token button.
    await expect(
      page.locator('.empty-state button:has-text("New Token")')
    ).toBeVisible();

    // The section-header should NOT have a New Token button when empty.
    await expect(
      page.locator('.section-header button:has-text("New Token")')
    ).not.toBeVisible();
  });

  test("New Token button opens stepper modal and loads step 0 via SSE", async ({ page }) => {
    await page.goto("/");

    // Click the New Token button (in empty state or header).
    await page.locator('button:has-text("New Token")').first().click();

    // Modal overlay should be visible.
    await expect(page.locator(".modal-overlay")).toHaveClass(/open/);

    // Step 0 content should load via SSE.
    await expect(
      page.locator('#stepper-content .stepper-title:has-text("Select Repository")')
    ).toBeVisible({ timeout: 5_000 });

    // Stepper dots should be visible.
    await expect(page.locator(".stepper-dot")).toHaveCount(4);
  });

  test("stepper modal can be closed", async ({ page }) => {
    await page.goto("/");

    // Open the modal.
    await page.locator('button:has-text("New Token")').first().click();
    await expect(page.locator(".modal-overlay")).toHaveClass(/open/);

    // Close via the X button.
    await page.locator(".stepper-close").click();

    // Modal should no longer have the open class.
    await expect(page.locator(".modal-overlay")).not.toHaveClass(/open/);
  });

  test("duration dropdown has expected options in stepper", async ({
    page,
  }) => {
    await page.goto("/");

    // Open stepper and navigate to step 2 (Details) via SSE.
    await page.locator('button:has-text("New Token")').first().click();

    // Wait for step 0, fill repo, advance.
    await expect(
      page.locator('#stepper-content .stepper-title:has-text("Select Repository")')
    ).toBeVisible({ timeout: 5_000 });
    await page.fill("#repo-input", "goodtune/duration-test");
    await page.locator('#stepper-content button:has-text("Next")').click();

    // Wait for step 1, advance.
    await expect(
      page.locator('#stepper-content .stepper-title:has-text("Set Permissions")')
    ).toBeVisible({ timeout: 5_000 });
    await page.locator('#stepper-content button:has-text("Next")').click();

    // Wait for step 2.
    await expect(
      page.locator('#stepper-content .stepper-title:has-text("Details")')
    ).toBeVisible({ timeout: 5_000 });

    const options = page.locator("#duration option");
    await expect(options).toHaveCount(4);

    const values = await options.evaluateAll((els) =>
      els.map((el) => (el as HTMLOptionElement).value)
    );
    expect(values).toEqual(["8h", "24h", "48h", "168h"]);
  });

  test("admin user sees Admin link in header", async ({ context, page }) => {
    await loginTestUser(context, { username: "admin-test", role: "admin" });
    await page.goto("/");

    await expect(page.locator('a:has-text("Admin")')).toBeVisible();
  });
});
