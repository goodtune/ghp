import { test, expect, request } from "@playwright/test";
import { createHmac } from "node:crypto";
import {
  loginTestUser,
  createAppViaAPI,
  deleteAppViaAPI,
  listAppsViaAPI,
} from "./helpers";

const BASE_URL = process.env.GHP_BASE_URL || "http://localhost:8080";

async function webhookStatus(sessionToken: string) {
  const ctx = await request.newContext({
    baseURL: BASE_URL,
    extraHTTPHeaders: { Authorization: `Bearer ${sessionToken}` },
  });
  const resp = await ctx.get("/api/webhooks/status");
  const body = await resp.json();
  await ctx.dispose();
  return body;
}

test.describe("Admin - Webhooks", () => {
  let sessionToken: string;

  test.beforeEach(async ({ context }) => {
    const login = await loginTestUser(context, {
      username: "admin-webhooks-test",
      role: "admin",
    });
    sessionToken = login.sessionToken;
    for (const app of await listAppsViaAPI(sessionToken)) {
      await deleteAppViaAPI(sessionToken, app.id);
    }
  });

  test("app form takes a webhook secret and the table shows it", async ({
    page,
  }) => {
    await page.goto("/admin");
    await page.waitForLoadState("networkidle");

    await page.click('summary:has-text("Add App")');
    await expect(page.locator("#app-webhook-secret")).toBeVisible();
    await page.fill("#app-name", "Hooked App");
    await page.fill("#app-github-id", "99077");
    await page.fill(
      "#app-private-key",
      "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA PRIVATE KEY-----"
    );
    await page.fill("#app-webhook-secret", "e2e-webhook-secret");
    await page.click("#create-app-btn");

    const row = page.locator("#apps-list tr", { hasText: "Hooked App" });
    await expect(row).toBeVisible();
    await expect(row).toContainText("Secret set");

    const apps = await listAppsViaAPI(sessionToken);
    const created = apps.find((a) => a.name === "Hooked App") as
      | { id: string; has_webhook_secret?: boolean }
      | undefined;
    expect(created?.has_webhook_secret).toBe(true);
  });

  test("apps without a secret are marked and can be given one inline", async ({
    page,
  }) => {
    const app = await createAppViaAPI(sessionToken, {
      name: "Plain App",
      app_id: 99078,
    });
    await page.goto("/admin");
    await page.waitForLoadState("networkidle");

    const row = page.locator("#apps-list tr", { hasText: "Plain App" });
    await expect(row).toContainText("No secret");

    await row.locator('[data-edit-app]').click();
    const editRow = page.locator("#edit-app-row");
    await expect(editRow).toBeVisible();
    const secretInput = editRow.locator('input[type="password"]').nth(1);
    await secretInput.fill("rotated");
    await editRow.locator('button:has-text("Save")').click();
    await expect(
      page.locator("#apps-list tr", { hasText: "Plain App" })
    ).toContainText("Secret set");

    const apps = await listAppsViaAPI(sessionToken);
    const updated = apps.find((a) => a.id === app.id) as
      | { has_webhook_secret?: boolean }
      | undefined;
    expect(updated?.has_webhook_secret).toBe(true);
  });

  test("webhooks panel reflects server state and shows deliveries", async ({
    page,
  }) => {
    const status = await webhookStatus(sessionToken);
    await page.goto("/admin");
    await page.waitForLoadState("networkidle");

    const section = page.locator("#webhooks-section");
    if (!status.enabled) {
      await expect(section).toBeHidden();
      return;
    }

    await expect(section).toBeVisible();
    await expect(page.locator("#webhooks-status")).toContainText(
      status.ingress_path
    );

    // Register an app with a secret and post a signed delivery to the
    // ingress exactly as GitHub would.
    const secret = "e2e-delivery-secret";
    await createAppViaAPI(sessionToken, {
      name: "Delivery App",
      app_id: 99079,
      webhook_secret: secret,
    });
    const payload = JSON.stringify({
      action: "opened",
      repository: { name: "ghp", owner: { login: "goodtune" } },
      sender: { login: "octocat" },
    });
    const signature =
      "sha256=" + createHmac("sha256", secret).update(payload).digest("hex");
    const delivery = `e2e-${Date.now()}`;
    const anon = await request.newContext({ baseURL: BASE_URL });
    const resp = await anon.post(status.ingress_path, {
      headers: {
        "Content-Type": "application/json",
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": delivery,
        "X-GitHub-Hook-ID": "1",
        "X-GitHub-Hook-Installation-Target-Type": "integration",
        "X-GitHub-Hook-Installation-Target-ID": "99079",
        "X-Hub-Signature-256": signature,
      },
      data: payload,
    });
    expect(resp.status()).toBe(202);
    const ack = await resp.json();
    expect(ack.subject).toContain(".pull_request.opened.goodtune.ghp");

    // A bad signature is rejected and never stored.
    const bad = await anon.post(status.ingress_path, {
      headers: {
        "Content-Type": "application/json",
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": `${delivery}-bad`,
        "X-GitHub-Hook-Installation-Target-Type": "integration",
        "X-GitHub-Hook-Installation-Target-ID": "99079",
        "X-Hub-Signature-256": "sha256=" + "0".repeat(64),
      },
      data: payload,
    });
    expect(bad.status()).toBe(401);
    await anon.dispose();

    await page.click("#webhooks-refresh-btn");
    const deliveryRow = page.locator("#webhooks-deliveries tr", {
      hasText: "goodtune/ghp",
    });
    await expect(deliveryRow.first()).toBeVisible();
    await expect(deliveryRow.first()).toContainText("pull_request");
    await expect(deliveryRow.first()).toContainText("Delivery App");

    await deliveryRow.first().locator("[data-view-delivery]").click();
    await expect(page.locator("#delivery-payload-row")).toContainText(
      '"sender"'
    );
  });
});
