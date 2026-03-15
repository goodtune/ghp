import { test, expect, type Page } from "@playwright/test";
import { loginTestUser, ensureAppExists } from "./helpers";

/** Inject repositories into the ghp-repo-select component and select them (multi mode). */
async function selectRepos(page: Page, repos: string[]) {
  await page.evaluate((r: string[]) => {
    const el = document.getElementById("repo-select") as any;
    el.repos = r;
    el.value = r;
  }, repos);
}

/** Select a permission level inside the ghp-permission-select component. */
async function selectPermission(page: Page, perm: string, level: string) {
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

/** Return the permission keys currently rendered inside the ghp-permission-select shadow DOM. */
async function getRenderedPermissions(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const el = document.getElementById("perm-select") as any;
    const selects = el.shadowRoot.querySelectorAll("select[data-perm]");
    return Array.from(selects).map((s: any) => s.dataset.perm as string);
  });
}

test.describe("Token management", () => {
  test.beforeEach(async ({ context }) => {
    await ensureAppExists(context);
    await loginTestUser(context);
  });

  test("can create an open-scoped token (no repos, no permissions)", async ({
    page,
  }, testInfo) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Do NOT select any repository or permission — open-scoped by default.
    await page.selectOption("#duration", "24h");
    await page.fill("#session", "playwright-open-scoped");

    await testInfo.attach("open-scoped-form", {
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

    // The token list should show (open) for repos and scopes.
    const tokenList = page.locator("#token-list");
    await expect(tokenList).toContainText("(open)");

    await testInfo.attach("open-scoped-created", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });

  test("can create a scoped token with repository and permissions", async ({
    page,
  }, testInfo) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Set repos (multi mode) and permissions via the web components.
    await selectRepos(page, ["goodtune/myproject"]);
    await selectPermission(page, "contents", "read");

    await page.selectOption("#duration", "24h");
    await page.fill("#session", "playwright-scoped-session");

    await testInfo.attach("scoped-form-filled", {
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

    await testInfo.attach("scoped-token-created", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });

  test("can create a token with multiple repositories", async ({
    page,
  }, testInfo) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Select multiple repos.
    await selectRepos(page, [
      "goodtune/project-a",
      "goodtune/project-b",
    ]);
    await selectPermission(page, "contents", "read");

    await page.fill("#session", "playwright-multi-repo");

    await page.click('button:has-text("Create Token")');

    const tokenDisplay = page.locator("#new-token");
    await expect(tokenDisplay).toBeVisible();

    // Both repos should appear in the token list.
    const tokenList = page.locator("#token-list");
    await expect(tokenList).toContainText("goodtune/project-a");
    await expect(tokenList).toContainText("goodtune/project-b");

    await testInfo.attach("multi-repo-created", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });

  test("created token appears in the Active Tokens list", async ({
    page,
  }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Create an open-scoped token.
    await page.fill("#session", "e2e-list-test");
    await page.click('button:has-text("Create Token")');

    // Wait for the token display.
    await expect(page.locator("#new-token")).toBeVisible();

    // The token list should now contain our token details.
    const tokenList = page.locator("#token-list");
    await expect(tokenList).toContainText("Active");
  });

  test("can revoke a token", async ({ context, page }, testInfo) => {
    // Use a unique user so tokens from other tests don't interfere.
    await loginTestUser(context, { username: "revoke-test-user" });
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Create an open-scoped token.
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

  test("repo select uses multi mode", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Verify the repo-select is in multi mode.
    const mode = await page.evaluate(() => {
      const el = document.getElementById("repo-select") as any;
      return el.getAttribute("mode");
    });
    expect(mode).toBe("multi");
  });

  test("form labels indicate optional fields", async ({ page }) => {
    await page.goto("/");

    // Labels should indicate repos and permissions are optional.
    await expect(page.locator(".create-form")).toContainText("optional");
  });

  test("permission select loads from API and shows available scopes", async ({
    page,
  }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Default permissions (no GitHub OAuth token for test users) should
    // include pull_requests (not the old "pulls" key).
    const perms = await getRenderedPermissions(page);
    expect(perms).toContain("pull_requests");
    expect(perms).not.toContain("pulls");
    expect(perms).toContain("contents");
    expect(perms).toContain("issues");
  });

  test("permission select respects API-returned scope restrictions", async ({
    page,
  }) => {
    // Mock the permissions API to return a limited set (read-only contents + metadata).
    await page.route("/api/github/permissions", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          contents: "read",
          pull_requests: "read",
          metadata: "read",
        }),
      });
    });

    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const perms = await getRenderedPermissions(page);

    // Only the mocked permissions should be rendered.
    // Note: metadata is rendered as a disabled <select> without data-perm,
    // so getRenderedPermissions() won't include it — verify it separately.
    expect(perms).toContain("contents");
    expect(perms).toContain("pull_requests");
    expect(perms).not.toContain("issues");
    expect(perms).not.toContain("actions");
    expect(perms).not.toContain("checks");

    // Verify metadata row is present (rendered with a disabled select).
    const metadataRow = await page.evaluate(() => {
      const el = document.getElementById("perm-select") as any;
      return el.shadowRoot.querySelector("select[disabled]") !== null;
    });
    expect(metadataRow).toBe(true);
  });

  test("can create a scoped token with pull_requests permission", async ({
    page,
  }, testInfo) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    await selectRepos(page, ["goodtune/myproject"]);
    await selectPermission(page, "pull_requests", "read");

    await page.selectOption("#duration", "8h");
    await page.fill("#session", "playwright-pull-requests");

    await page.click('button:has-text("Create Token")');

    const tokenDisplay = page.locator("#new-token");
    await expect(tokenDisplay).toBeVisible();

    const tokenValue = page.locator("#token-value");
    await expect(tokenValue).toContainText("ghx_");

    await testInfo.attach("pull-requests-token-created", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });
});
