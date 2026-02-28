import { test, expect } from "@playwright/test";
import { loginTestUser, waitForDatastar } from "./helpers";

test.describe("Token wizard", () => {
  test.beforeEach(async ({ context }) => {
    await loginTestUser(context);
  });

  test("New Token button opens wizard modal with step 1", async ({ page }, testInfo) => {
    await page.goto("/dashboard/");
    await waitForDatastar(page);

    // Click New Token (from empty state).
    await page.click('button:has-text("New Token")');

    // Modal should open with step 1.
    const modal = page.locator("#modal-content");
    await expect(modal).toContainText("Select Repository");
    await expect(modal.locator('input[name="repository"]')).toBeVisible();

    await testInfo.attach("wizard-step1", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });

  test("full wizard flow creates a token", async ({ page }, testInfo) => {
    await page.goto("/dashboard/");
    await waitForDatastar(page);

    // Step 1: open wizard and enter repository.
    await page.click('button:has-text("New Token")');
    const modal = page.locator("#modal-content");
    await expect(modal).toContainText("Select Repository");

    await page.fill('input[name="repository"]', "goodtune/myproject");
    await page.click('#modal-content button[type="submit"]', { force: true });

    // Step 2: permissions.
    await expect(modal).toContainText("Set Permissions", { timeout: 10000 });

    await testInfo.attach("wizard-step2", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });

    // Select a permission and submit (force click since form may be tall).
    await page.selectOption('#modal-content select[name="perm_contents"]', "read");
    await page.click('#modal-content button[type="submit"]', { force: true });

    // Step 3: duration.
    await expect(modal).toContainText("Duration", { timeout: 10000 });
    await page.click('#modal-content button[type="submit"]', { force: true });

    // Step 4: confirm.
    await expect(modal).toContainText("Confirm", { timeout: 10000 });
    await expect(modal).toContainText("goodtune/myproject");

    await testInfo.attach("wizard-step4-confirm", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });

    // Click Create Token.
    await page.click('#modal-content button:has-text("Create Token")', { force: true });

    // Token display should appear.
    await expect(modal.locator(".token-display")).toBeVisible({ timeout: 10000 });
    const tokenInput = modal.locator("input.token-value");
    const tokenValue = await tokenInput.inputValue();
    expect(tokenValue).toMatch(/^ghx_/);
    await expect(modal).toContainText("only be shown once");

    await testInfo.attach("token-created", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });

    // Close the modal and verify token card appears on dashboard.
    await page.click('#modal-content .modal-close', { force: true });
    await page.waitForLoadState("networkidle");
    await expect(page.locator(".token-card")).toBeVisible({ timeout: 10000 });
    await expect(page.locator(".token-card")).toContainText("goodtune/myproject");
  });

  test("wizard back button navigates to previous step", async ({ page }) => {
    await page.goto("/dashboard/");
    await waitForDatastar(page);

    // Open wizard and go to step 2.
    await page.click('button:has-text("New Token")');
    const modal = page.locator("#modal-content");
    await page.fill('input[name="repository"]', "org/repo");
    await page.click('#modal-content button[type="submit"]', { force: true });
    await expect(modal).toContainText("Set Permissions", { timeout: 10000 });

    // Click Back.
    await page.click('#modal-content button:has-text("Back")', { force: true });

    // Should be back on step 1 with the repository preserved.
    await expect(modal).toContainText("Select Repository", { timeout: 10000 });
  });
});

test.describe("Token revoke", () => {
  test("can revoke a token via the card", async ({ context, page }, testInfo) => {
    await loginTestUser(context, { username: "revoke-e2e-user" });
    await page.goto("/dashboard/");
    await waitForDatastar(page);

    // Create a token first via the wizard.
    await page.click('button:has-text("New Token")');
    const modal = page.locator("#modal-content");
    await page.fill('input[name="repository"]', "goodtune/revoke-test");
    await page.click('#modal-content button[type="submit"]', { force: true });
    await expect(modal).toContainText("Set Permissions", { timeout: 10000 });
    await page.click('#modal-content button[type="submit"]', { force: true }); // step 2 → 3
    await expect(modal).toContainText("Duration", { timeout: 10000 });
    await page.click('#modal-content button[type="submit"]', { force: true }); // step 3 → 4
    await expect(modal).toContainText("Confirm", { timeout: 10000 });
    await page.click('#modal-content button:has-text("Create Token")', { force: true });
    await expect(page.locator("#modal-content .token-display")).toBeVisible({ timeout: 10000 });

    // Close modal and reload.
    await page.click('#modal-content .modal-close', { force: true });
    await page.waitForLoadState("networkidle");

    // Wait for dashboard to show token card.
    await expect(page.locator(".token-card")).toBeVisible({ timeout: 10000 });
    await waitForDatastar(page);

    // Click Revoke on the token card.
    await page.click('.token-card button:has-text("Revoke")', { force: true });

    // Revoke confirmation modal should appear.
    await expect(modal).toContainText("ghx_", { timeout: 10000 });

    await testInfo.attach("revoke-confirm", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });

    // Confirm revoke.
    await page.click('#modal-content button:has-text("Confirm Revoke")', { force: true });

    // Page should reload showing revoked status.
    await page.waitForLoadState("networkidle");
    await expect(page.locator(".token-card .status-revoked")).toBeVisible({ timeout: 10000 });

    await testInfo.attach("token-revoked", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });
});
