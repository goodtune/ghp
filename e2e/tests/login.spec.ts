import { test, expect } from "@playwright/test";

test.describe("Login page", () => {
  test("renders the login page with branding", async ({ page }, testInfo) => {
    await page.goto("/login");

    // Check page title.
    await expect(page).toHaveTitle("ghp — Login");

    // Check branding elements.
    await expect(page.locator("h1")).toHaveText("ghp");
    await expect(page.locator("p")).toContainText(
      "GitHub Proxy for Autonomous Coding Agents"
    );

    await testInfo.attach("login-page", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });

  test("displays the build version beneath the login form", async ({
    page,
  }) => {
    await page.goto("/login");

    // The version string helps managers identify which image is deployed.
    // In dev/CI builds the version defaults to "dev".
    const version = page.locator(".version");
    await expect(version).toBeVisible();
    await expect(version).toContainText("version");
  });

  test("has a Sign in with GitHub button linking to OAuth", async ({
    page,
  }) => {
    await page.goto("/login");

    const signInBtn = page.locator('a.btn:has-text("Sign in with GitHub")');
    await expect(signInBtn).toBeVisible();
    await expect(signInBtn).toHaveAttribute("href", "/auth/github");
  });

  test("unauthenticated root redirects to login", async ({ page }) => {
    await page.goto("/");

    // Should redirect to /login.
    await expect(page).toHaveURL(/\/login$/);
  });
});
