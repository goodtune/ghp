import { test, expect } from "@playwright/test";
import { loginTestUser } from "./helpers";

/**
 * Walk through the stepper to create a token.
 * Assumes the modal is already open and step 0 is loading via SSE.
 * In dev mode, uses the text input for repo and default permissions.
 */
async function createTokenViaStepper(
  page: any,
  opts: { repo: string; session?: string }
) {
  // Wait for step 0 to load via SSE.
  await expect(
    page.locator('#stepper-content .stepper-title:has-text("Select Repository")')
  ).toBeVisible({ timeout: 5_000 });

  // Step 0: Set repo via text input (dev mode) and advance.
  await page.fill("#repo-input", opts.repo);
  await page.locator('#stepper-content button:has-text("Next")').click();

  // Wait for step 1 to load via SSE.
  await expect(
    page.locator('#stepper-content .stepper-title:has-text("Set Permissions")')
  ).toBeVisible({ timeout: 5_000 });

  // Step 1: Permissions — dev mode shows defaults, just advance.
  await page.locator('#stepper-content button:has-text("Next")').click();

  // Wait for step 2 to load via SSE.
  await expect(
    page.locator('#stepper-content .stepper-title:has-text("Details")')
  ).toBeVisible({ timeout: 5_000 });

  // Step 2: Details — fill session if provided, then advance.
  if (opts.session) {
    await page.fill("#session", opts.session);
  }
  await page.locator('#stepper-content button:has-text("Next")').click();

  // Wait for step 3 to load via SSE.
  await expect(
    page.locator('#stepper-content .stepper-title:has-text("Confirm")')
  ).toBeVisible({ timeout: 5_000 });

  // Step 3: Confirm & Create.
  await page.locator('#stepper-content button:has-text("Create Token")').click();
}

test.describe("Token management", () => {
  test.beforeEach(async ({ context }) => {
    await loginTestUser(context);
  });

  test("can create a token via the stepper", async ({ page }, testInfo) => {
    await page.goto("/");
    await page.waitForLoadState("domcontentloaded");

    // Open the stepper modal.
    await page.locator('button:has-text("New Token")').first().click();
    await expect(page.locator(".modal-overlay")).toHaveClass(/open/);

    await createTokenViaStepper(page, {
      repo: "goodtune/myproject",
      session: "playwright-test-session",
    });

    // The token display should appear in the confirm step.
    const tokenDisplay = page.locator(".token-display");
    await expect(tokenDisplay).toBeVisible({ timeout: 10_000 });

    // The token value should start with ghx_.
    await expect(tokenDisplay).toContainText("ghx_");

    // The warning message should be shown.
    await expect(page.locator(".token-warning")).toContainText(
      "This token will only be shown once"
    );

    await testInfo.attach("token-created", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });

  test("created token appears as a card on the dashboard", async ({
    context,
    page,
  }) => {
    await loginTestUser(context, { username: "token-card-user" });
    await page.goto("/");
    await page.waitForLoadState("domcontentloaded");

    // Open stepper and create a token.
    await page.locator('button:has-text("New Token")').first().click();

    await createTokenViaStepper(page, {
      repo: "goodtune/testproject",
      session: "e2e-card-test",
    });

    await expect(page.locator(".token-display")).toBeVisible({ timeout: 10_000 });

    // Close modal and reload to see the token card.
    await page.reload();
    await page.waitForLoadState("domcontentloaded");

    // Token card should be present.
    const tokenCard = page.locator(".token-card").first();
    await expect(tokenCard).toBeVisible();
    await expect(tokenCard).toContainText("goodtune/testproject");
  });

  test("can revoke a token", async ({ context, page }, testInfo) => {
    await loginTestUser(context, { username: "revoke-test-user" });
    await page.goto("/");
    await page.waitForLoadState("domcontentloaded");

    // Create a token first.
    await page.locator('button:has-text("New Token")').first().click();

    await createTokenViaStepper(page, {
      repo: "goodtune/revoke-test",
    });

    await expect(page.locator(".token-display")).toBeVisible({ timeout: 10_000 });

    // Reload to see the token card with revoke button.
    await page.reload();
    await page.waitForLoadState("domcontentloaded");

    // Accept the confirmation dialog.
    page.on("dialog", (dialog) => dialog.accept());

    // Click Revoke on the token card.
    const revokeBtn = page.locator('.token-card button:has-text("Revoke")');
    await expect(revokeBtn).toBeVisible();
    await revokeBtn.click();

    // After revoking via SSE, the card should update (no more revoke button).
    await expect(revokeBtn).not.toBeVisible({ timeout: 10_000 });

    await testInfo.attach("token-revoked", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });

  test("dashboard updates live after token creation without reload", async ({
    context,
    page,
  }, testInfo) => {
    const uniqueUser = `live-dash-${Date.now()}`;
    await loginTestUser(context, { username: uniqueUser });
    await page.goto("/");
    await page.waitForLoadState("domcontentloaded");

    // Initially should show empty state.
    await expect(page.locator(".empty-state")).toBeVisible();

    // Create a token via the stepper.
    await page.locator('button:has-text("New Token")').first().click();
    await expect(page.locator(".modal-overlay")).toHaveClass(/open/);

    await createTokenViaStepper(page, {
      repo: "goodtune/live-dash-test",
    });

    // Token display should appear.
    await expect(page.locator(".token-display")).toBeVisible({ timeout: 10_000 });

    // Close the modal.
    await page.locator(".stepper-close").click();
    await expect(page.locator(".modal-overlay")).not.toHaveClass(/open/);

    // The dashboard should now show the token card WITHOUT reload.
    const tokenCard = page.locator(".token-card").first();
    await expect(tokenCard).toBeVisible({ timeout: 5_000 });
    await expect(tokenCard).toContainText("goodtune/live-dash-test");

    // The empty state should be gone.
    await expect(page.locator(".empty-state")).not.toBeVisible();

    await testInfo.attach("live-dash-update", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });

  test("section-header shows New Token button only when tokens exist", async ({
    context,
    page,
  }) => {
    // Fresh user with no tokens.
    await loginTestUser(context, { username: "header-btn-test" });
    await page.goto("/");

    // Section-header should NOT have the button.
    await expect(
      page.locator('.section-header button:has-text("New Token")')
    ).not.toBeVisible();

    // Empty state SHOULD have the button.
    await expect(
      page.locator('.empty-state button:has-text("New Token")')
    ).toBeVisible();
  });
});
