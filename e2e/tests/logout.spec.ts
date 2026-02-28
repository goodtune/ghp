import { test, expect } from "@playwright/test";
import { loginTestUser } from "./helpers";

test.describe("Logout", () => {
  test("sign out link goes to confirmation page", async ({
    page,
    context,
  }, testInfo) => {
    await loginTestUser(context);
    await page.goto("/dashboard/");

    await expect(page).toHaveTitle("Dashboard — GitHub Proxy");

    await testInfo.attach("before-logout", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });

    // Click Sign out link in header.
    await page.click('header a:has-text("Sign out")');

    // Should be on the logout confirmation page.
    await expect(page).toHaveURL(/\/logout\/$/);
    await expect(page.locator('button[type="submit"]')).toContainText("Sign Out");

    await testInfo.attach("logout-confirm", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });

    // Confirm logout.
    await page.click('button:has-text("Sign Out")');

    // Should redirect to login page.
    await expect(page).toHaveURL(/\/login\/$/);
    await expect(page).toHaveTitle("Sign in — GitHub Proxy");

    await testInfo.attach("after-logout", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });
});
