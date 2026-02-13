import { test, expect } from "@playwright/test";
import { loginTestUser } from "./helpers";

test.describe("Token management", () => {
  test.beforeEach(async ({ context }) => {
    await loginTestUser(context);
  });

  test("can create a token via the form", async ({ page }, testInfo) => {
    await page.goto("/");

    // Fill in the form.
    await page.fill("#repo", "goodtune/myproject");
    await page.fill("#scopes", "contents:read,pulls:write");
    await page.selectOption("#duration", "24h");
    await page.fill("#session", "playwright-test-session");

    await testInfo.attach("token-form-filled", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });

    // Click Create Token.
    await page.click('button:has-text("Create Token")');

    // The new token display should become visible.
    const tokenDisplay = page.locator("#new-token");
    await expect(tokenDisplay).toBeVisible();

    // The token value should start with ghp_.
    const tokenValue = page.locator("#token-value");
    await expect(tokenValue).toContainText("ghp_");

    // The warning message should be shown.
    await expect(tokenDisplay).toContainText(
      "This token will only be shown once"
    );

    await testInfo.attach("token-created", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });

  test("created token appears in the Active Tokens list", async ({
    page,
  }) => {
    await page.goto("/");

    // Create a token first.
    await page.fill("#repo", "goodtune/testproject");
    await page.fill("#scopes", "contents:read");
    await page.fill("#session", "e2e-list-test");
    await page.click('button:has-text("Create Token")');

    // Wait for the token display.
    await expect(page.locator("#new-token")).toBeVisible();

    // The token list should now contain our token details.
    const tokenList = page.locator("#token-list");
    await expect(tokenList).toContainText("goodtune/testproject");
    await expect(tokenList).toContainText("Active");
  });

  test("can revoke a token", async ({ context, page }, testInfo) => {
    // Use a unique user so tokens from other tests don't interfere.
    await loginTestUser(context, { username: "revoke-test-user" });
    await page.goto("/");

    // Create a token.
    await page.fill("#repo", "goodtune/revoke-test");
    await page.fill("#scopes", "issues:write");
    await page.click('button:has-text("Create Token")');
    await expect(page.locator("#new-token")).toBeVisible();

    // Accept the confirmation dialog.
    page.on("dialog", (dialog) => dialog.accept());

    // Click Revoke — there should be exactly one since this is a fresh user.
    const revokeBtn = page.locator(
      '#token-list button:has-text("Revoke")'
    );
    await expect(revokeBtn).toBeVisible();
    await revokeBtn.click();

    // After revoking, the token should show as Revoked.
    await expect(page.locator("#token-list")).toContainText("Revoked");

    await testInfo.attach("token-revoked", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });

  test("shows validation when required fields are missing", async ({
    page,
  }) => {
    await page.goto("/");

    // Accept the alert dialog.
    page.on("dialog", async (dialog) => {
      expect(dialog.message()).toContain("required");
      await dialog.accept();
    });

    // Try to create without filling required fields.
    await page.click('button:has-text("Create Token")');
  });
});
