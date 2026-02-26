import { test, expect } from "@playwright/test";

test.describe("Login page", () => {
  test("renders the login page with branding", async ({ page }, testInfo) => {
    await page.goto("/login");

    // Check page title.
    await expect(page).toHaveTitle("ghp — Login");

    // Check branding elements.
    await expect(page.locator("h1")).toHaveText("GitHub Proxy");
    await expect(page.locator("p")).toContainText(
      "Scoped tokens for coding agents"
    );

    await testInfo.attach("login-page", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });

  test("has a sign in button", async ({ page }) => {
    await page.goto("/login");

    // In dev mode, shows dev login form. In production, shows GitHub OAuth link.
    const devLogin = page.locator('button:has-text("Sign in (dev)")');
    const oauthLogin = page.locator('a:has-text("Sign in with GitHub")');
    await expect(devLogin.or(oauthLogin)).toBeVisible();
  });

  test("unauthenticated root redirects to login", async ({ page }) => {
    await page.goto("/");

    // Should redirect to /login.
    await expect(page).toHaveURL(/\/login$/);
  });
});
