import { test, expect } from "@playwright/test";
import { loginTestUser } from "./helpers";

/** Inject a repository into the ghp-repo-select component and select it. */
async function selectRepo(page: any, repo: string) {
  await page.evaluate((r: string) => {
    const el = document.getElementById("repo-select") as any;
    el.repos = [r];
    el.value = r;
  }, repo);
}

/** Select a permission level inside the ghp-permission-select component. */
async function selectPermission(
  page: any,
  perm: string,
  level: string
) {
  await page.evaluate(
    ({ p, l }: { p: string; l: string }) => {
      const el = document.getElementById("perm-select") as any;
      const sel = el.shadowRoot.querySelector(
        `[data-perm="${p}"]`
      ) as HTMLSelectElement;
      if (sel) {
        sel.value = l;
        sel.dispatchEvent(new Event("change"));
      }
    },
    { p: perm, l: level }
  );
}

test.describe("Token management", () => {
  test.beforeEach(async ({ context }) => {
    await loginTestUser(context);
  });

  test("can create a token via the form", async ({ page }, testInfo) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Set repo and permissions via the web components.
    await selectRepo(page, "goodtune/myproject");
    await selectPermission(page, "contents", "read");

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

    // The token value should start with ghx_.
    const tokenValue = page.locator("#token-value");
    await expect(tokenValue).toContainText("ghx_");

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
    await page.waitForLoadState("networkidle");

    // Create a token first.
    await selectRepo(page, "goodtune/testproject");
    await selectPermission(page, "contents", "read");
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
    await page.waitForLoadState("networkidle");

    // Create a token.
    await selectRepo(page, "goodtune/revoke-test");
    await selectPermission(page, "issues", "write");
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
