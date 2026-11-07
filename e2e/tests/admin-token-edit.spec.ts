import { test, expect, type Page } from "@playwright/test";
import { ensureAppExists, loginTestUser } from "./helpers";

// Admin token scope edit (#350): the edit row uses <ghp-permission-select>,
// validates client-side with the server's rules, and renders server
// rejections in the form.

async function createToken(page: Page, session: string, scopes: string) {
  const resp = await page.request.post("/api/tokens", {
    data: { duration: "24h", scopes, session_id: session },
  });
  expect(resp.ok(), await resp.text()).toBeTruthy();
  const list = await page.request.get("/api/tokens?all=true");
  expect(list.ok()).toBeTruthy();
  const tokens = await list.json();
  const tok = tokens.find((t: any) => t.session_id === session && !t.revoked_at);
  expect(tok).toBeTruthy();
  return tok.id as string;
}

async function openEditRow(page: Page, id: string) {
  await page.goto("/admin");
  await page.waitForLoadState("networkidle");
  await page.locator(`button[data-edit-token="${id}"]`).click();
  await expect(page.locator("#edit-token-row")).toBeVisible();
}

function selectLevel(page: Page, perm: string, level: string) {
  return page
    .locator("#edit-token-scopes")
    .locator(`select[data-perm="${perm}"]`)
    .selectOption(level);
}

test.describe("Admin - token scope edit", () => {
  test.beforeEach(async ({ context }) => {
    await ensureAppExists(context);
    await loginTestUser(context, { username: "admin-token-edit", role: "admin" });
  });

  test("edit row pre-populates the permission selector and shows JSON", async ({
    page,
  }) => {
    const id = await createToken(page, `edit-prepop-${Date.now()}`, "contents:read,issues:write");
    await openEditRow(page, id);

    const sel = page.locator("#edit-token-scopes");
    await expect(sel.locator('select[data-perm="contents"]')).toHaveValue("read");
    await expect(sel.locator('select[data-perm="issues"]')).toHaveValue("write");
    await expect(sel.locator('select[data-perm="metadata"]')).toHaveValue("");
    // The selector offers canonical names only.
    await expect(sel.locator('select[data-perm="pulls"]')).toHaveCount(0);

    const json = page.locator("#edit-token-scopes-json");
    await expect(json).toBeHidden();
    await page.locator("#edit-token-scopes-json-toggle").click();
    await expect(json).toBeVisible();
    await expect(json).toContainText('"contents": "read"');
    await expect(json).toContainText('"issues": "write"');
  });

  test("successful edit saves the selected scopes", async ({ page }) => {
    const id = await createToken(page, `edit-ok-${Date.now()}`, "contents:read");
    await openEditRow(page, id);

    await selectLevel(page, "contents", "write");
    await selectLevel(page, "pull_requests", "read");

    const patch = page.waitForRequest(
      (r) => r.method() === "PATCH" && r.url().endsWith(`/api/tokens/${id}`)
    );
    await page.locator('#edit-token-row button:has-text("Save")').click();
    const body = (await patch).postDataJSON();
    expect(body.scopes).toEqual({ contents: "write", pull_requests: "read" });

    await expect(page.locator("#edit-token-row")).toHaveCount(0);
    const row = page.locator(`tr[data-token-id="${id}"]`);
    await expect(row).toContainText('"contents":"write"');
    await expect(row).toContainText('"pull_requests":"read"');
  });

  test("server rejection renders in the form error element", async ({ page }) => {
    const id = await createToken(page, `edit-reject-${Date.now()}`, "contents:read");
    await openEditRow(page, id);

    const message = 'unknown scope permission "pulls" (valid permissions: actions, contents)';
    await page.route(`**/api/tokens/${id}`, async (route) => {
      if (route.request().method() !== "PATCH") return route.fallback();
      await route.fulfill({
        status: 400,
        contentType: "application/json",
        body: JSON.stringify({ message }),
      });
    });

    await selectLevel(page, "issues", "read");
    await page.locator('#edit-token-row button:has-text("Save")').click();

    const err = page.locator("#edit-token-error");
    await expect(err).toBeVisible();
    await expect(err).toContainText(message);
    // The row stays open so the operator can correct the entry.
    await expect(page.locator("#edit-token-row")).toBeVisible();
  });

  test("server rejects a crafted PATCH with a legacy alias", async ({ page }) => {
    const id = await createToken(page, `edit-alias-${Date.now()}`, "contents:read");
    const resp = await page.request.patch(`/api/tokens/${id}`, {
      data: { scopes: { pulls: "write" } },
    });
    expect(resp.status()).toBe(400);
    expect((await resp.json()).message).toContain('unknown scope permission "pulls"');
  });

  test("legacy entries are flagged and removed on save", async ({ page }) => {
    const id = await createToken(page, `edit-legacy-${Date.now()}`, "contents:read");
    await page.goto("/admin");
    await page.waitForLoadState("networkidle");
    // Simulate a token stored before validation existed by rewriting the
    // button's data attribute; the server no longer accepts such entries.
    await page
      .locator(`button[data-edit-token="${id}"]`)
      .evaluate((el) =>
        el.setAttribute("data-token-scopes", JSON.stringify({ contents: "read", pulls: "write" }))
      );
    await page.locator(`button[data-edit-token="${id}"]`).click();

    const warn = page.locator("#edit-token-scopes-warning");
    await expect(warn).toBeVisible();
    await expect(warn).toContainText("pulls:write");

    // Changing the permissions drops the invalid entry.
    await selectLevel(page, "issues", "read");
    const patch = page.waitForRequest(
      (r) => r.method() === "PATCH" && r.url().endsWith(`/api/tokens/${id}`)
    );
    await page.locator('#edit-token-row button:has-text("Save")').click();
    expect((await patch).postDataJSON().scopes).toEqual({ contents: "read", issues: "read" });
  });

  test("repos-only edit omits scopes from the PATCH", async ({ page }) => {
    const id = await createToken(page, `edit-repos-${Date.now()}`, "contents:read");
    await openEditRow(page, id);
    let body: any = null;
    await page.route(`**/api/tokens/${id}`, async (route) => {
      if (route.request().method() !== "PATCH") return route.fallback();
      body = route.request().postDataJSON();
      await route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
    });
    await page.locator("#edit-token-row textarea").fill("acme/widgets");
    await page.locator('#edit-token-row button:has-text("Save")').click();
    await expect(page.locator("#edit-token-row")).toHaveCount(0);
    expect(body.repositories).toEqual(["acme/widgets"]);
    expect("scopes" in body).toBe(false);
  });

  test("all-invalid stored scopes cannot be widened to open-scoped by default", async ({
    page,
  }) => {
    const id = await createToken(page, `edit-allbad-${Date.now()}`, "contents:read");
    await page.goto("/admin");
    await page.waitForLoadState("networkidle");
    const btn = page.locator(`button[data-edit-token="${id}"]`);
    // Simulate a stored deny-all scope set that the server no longer accepts.
    const openStale = async () => {
      await btn.evaluate((el) => el.setAttribute("data-token-scopes", JSON.stringify({ pulls: "write" })));
      await btn.click();
    };
    await openStale();

    let body: any = null;
    await page.route(`**/api/tokens/${id}`, async (route) => {
      if (route.request().method() !== "PATCH") return route.fallback();
      body = route.request().postDataJSON();
      await route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
    });

    // Repos-only save keeps the stored (deny-all) scopes untouched.
    await page.locator("#edit-token-row textarea").fill("acme/widgets");
    await page.locator('#edit-token-row button:has-text("Save")').click();
    await expect(page.locator("#edit-token-row")).toHaveCount(0);
    expect("scopes" in body).toBe(false);

    // Saving with no permission selected still never sends {}: the stored
    // deny-all entry is kept unless the admin clears scopes explicitly.
    await openStale();
    await expect(page.locator("#edit-token-scopes-warning")).toContainText("pulls:write");
    await page.locator('#edit-token-row button:has-text("Save")').click();
    await expect(page.locator("#edit-token-row")).toHaveCount(0);
    expect(body.scopes).toBeUndefined();

    await openStale();
    await page.locator("#edit-token-clear-scopes").check();
    await page.locator('#edit-token-row button:has-text("Save")').click();
    await expect(page.locator("#edit-token-row")).toHaveCount(0);
    expect(body.scopes).toEqual({});
  });

  test("explicit clear sends empty scopes", async ({ page }) => {
    const id = await createToken(page, `edit-clear-${Date.now()}`, "contents:read");
    await openEditRow(page, id);
    await selectLevel(page, "contents", "");
    await page.locator('#edit-token-row button:has-text("Save")').click();
    await expect(page.locator("#edit-token-error")).toContainText(
      "This would remove all scopes and make the token open-scoped"
    );

    await page.locator("#edit-token-clear-scopes").check();
    const patch = page.waitForRequest(
      (r) => r.method() === "PATCH" && r.url().endsWith(`/api/tokens/${id}`)
    );
    await page.locator('#edit-token-row button:has-text("Save")').click();
    expect((await patch).postDataJSON().scopes).toEqual({});
    await expect(page.locator(`tr[data-token-id="${id}"]`)).toContainText("(open)");
  });

  test("metadata is capped at read", async ({ page }) => {
    const id = await createToken(page, `edit-meta-${Date.now()}`, "contents:read");
    await openEditRow(page, id);
    const opts = page.locator("#edit-token-scopes").locator('select[data-perm="metadata"] option');
    await expect(opts).toHaveCount(2);
  });
});

test.describe("Admin - token scope client-side validation", () => {
  test.beforeEach(async ({ context }) => {
    await loginTestUser(context, { username: "admin-token-edit", role: "admin" });
  });

  test("validateScopes applies the server's rules", async ({ page }) => {
    await page.goto("/admin");
    await page.waitForLoadState("networkidle");
    const results = await page.evaluate(() => {
      const v = (window as any).validateScopes as (s: object) => string;
      return {
        ok: v({ contents: "read", pull_requests: "write" }),
        empty: v({}),
        alias: v({ pulls: "write" }),
        level: v({ contents: "admin" }),
      };
    });
    expect(results.ok).toBe("");
    expect(results.empty).toBe("");
    expect(results.alias).toContain('unknown permission "pulls"');
    expect(results.level).toContain('invalid level "admin" for "contents"');
  });
});
