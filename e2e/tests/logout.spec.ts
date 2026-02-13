import { test, expect } from "@playwright/test";
import { loginTestUser } from "./helpers";

test.describe("Logout", () => {
  test("sign out button logs user out and redirects to login", async ({
    page,
    context,
  }, testInfo) => {
    await loginTestUser(context);
    await page.goto("/");

    // Verify we're on the dashboard.
    await expect(page).toHaveTitle("ghp — Dashboard");

    await testInfo.attach("before-logout", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });

    // Click Sign out.
    await page.click('button:has-text("Sign out")');

    // Should end up on the login page.
    await expect(page).toHaveURL(/\/login$/);
    await expect(page).toHaveTitle("ghp — Login");

    await testInfo.attach("after-logout", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });
});
