import { test, expect } from "@playwright/test";

test.describe("Login page", () => {
  test("renders the login page with branding", async ({ page }, testInfo) => {
    await page.goto("/login/");

    await expect(page).toHaveTitle("Sign in — GitHub Proxy");

    await expect(page.locator("h1.login-heading")).toHaveText("GitHub Proxy");
    await expect(page.locator("p.login-subtitle")).toContainText(
      "Scoped tokens for coding agents"
    );

    // Mascot image is visible.
    await expect(page.locator("img.login-mascot")).toBeVisible();

    await testInfo.attach("login-page", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });

  test("has a Sign in with GitHub button linking to OAuth", async ({
    page,
  }) => {
    await page.goto("/login/");

    const signInBtn = page.locator('a.login-btn:has-text("Sign in with GitHub")');
    await expect(signInBtn).toBeVisible();
    await expect(signInBtn).toHaveAttribute("href", "/auth/github");
  });

  test("unauthenticated root redirects to dashboard then login", async ({ page }) => {
    await page.goto("/");

    // Root → /dashboard/ → /login/ (unauthenticated).
    await expect(page).toHaveURL(/\/login\/$/);
  });

  test("shows dev login form when in dev mode", async ({ page }) => {
    await page.goto("/login/");

    const devForm = page.locator("#dev-login-form");
    await expect(devForm).toBeVisible();

    await expect(devForm.locator('input[name="username"]')).toBeVisible();
    await expect(devForm.locator('select[name="role"]')).toBeVisible();
    await expect(devForm.locator('button[type="submit"]')).toHaveText("Dev Login");
  });

  test("dev login form signs in and redirects to dashboard", async ({ page }, testInfo) => {
    await page.goto("/login/");

    await page.fill('#dev-login-form input[name="username"]', "e2e-devlogin");
    await page.selectOption('#dev-login-form select[name="role"]', "admin");
    await page.click('#dev-login-form button[type="submit"]');

    // Should redirect to dashboard.
    await expect(page).toHaveURL(/\/dashboard\/$/);
    await expect(page).toHaveTitle("Dashboard — GitHub Proxy");

    await testInfo.attach("after-dev-login", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });
});
