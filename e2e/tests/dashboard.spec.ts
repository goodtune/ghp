import { test, expect } from "@playwright/test";
import { loginTestUser, waitForDatastar } from "./helpers";

test.describe("Dashboard", () => {
  test("renders dashboard with header and nav", async ({ page, context }, testInfo) => {
    await loginTestUser(context);
    await page.goto("/dashboard/");

    await expect(page).toHaveTitle("Dashboard — GitHub Proxy");

    // Header shows the avatar with username as alt text.
    const header = page.locator("header.header");
    await expect(header.locator('img.header-avatar[alt="testuser"]')).toBeVisible();
    await expect(header.locator('a:has-text("Sign out")')).toBeVisible();

    // Navigation links.
    await expect(header.locator('a:has-text("Dashboard")')).toBeVisible();

    await testInfo.attach("dashboard-overview", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });

  test("shows empty state when user has no tokens", async ({ page, context }) => {
    await loginTestUser(context, { username: "dashboard-empty-user" });
    await page.goto("/dashboard/");
    await waitForDatastar(page);

    await expect(page.locator(".empty-state")).toBeVisible();
    await expect(page.locator(".empty-state")).toContainText("No tokens yet");
    await expect(page.locator('.empty-state button:has-text("New Token")')).toBeVisible();
  });

  test("admin user sees Admin nav link", async ({ page, context }) => {
    await loginTestUser(context, { username: "dash-admin", role: "admin" });
    await page.goto("/dashboard/");

    await expect(page.locator('header a:has-text("Admin")')).toBeVisible();
  });

  test("non-admin user does not see Admin nav link", async ({ page, context }) => {
    await loginTestUser(context, { username: "dash-regular", role: "user" });
    await page.goto("/dashboard/");

    await expect(page.locator('header a:has-text("Admin")')).not.toBeVisible();
  });
});
