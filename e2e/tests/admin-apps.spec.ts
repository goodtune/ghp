import { test, expect, request } from "@playwright/test";
import {
  loginTestUser,
  createAppViaAPI,
  deleteAppViaAPI,
  listAppsViaAPI,
} from "./helpers";

const BASE_URL = process.env.GHP_BASE_URL || "http://localhost:8080";

test.describe("Admin - Multi-App Management", () => {
  let sessionToken: string;

  test.beforeEach(async ({ context }) => {
    // Login as admin for all tests in this group.
    const login = await loginTestUser(context, {
      username: "admin-apps-test",
      role: "admin",
    });
    sessionToken = login.sessionToken;

    // Clean up any apps left over from previous test runs.
    const apps = await listAppsViaAPI(sessionToken);
    for (const app of apps) {
      await deleteAppViaAPI(sessionToken, app.id);
    }
  });

  test("admin page shows Apps section with empty state", async ({ page }) => {
    await page.goto("/admin");
    await page.waitForLoadState("networkidle");

    // The Apps section heading should be visible.
    await expect(page.locator('h2:has-text("Apps")')).toBeVisible();

    // Empty state message should appear when no apps exist.
    await expect(page.locator("#apps-list")).toContainText("No apps configured");

    // Token sections should be hidden when no apps exist.
    await expect(page.locator("#agent-token-section")).toBeHidden();
    await expect(page.locator("#all-tokens-section")).toBeHidden();
  });

  test("can create an app and form collapses after", async ({
    page,
  }, testInfo) => {
    await page.goto("/admin");
    await page.waitForLoadState("networkidle");

    const addAppDetails = page.locator('details:has(summary:has-text("Add App"))');

    // Expand the "Add App" collapsible.
    await page.click('summary:has-text("Add App")');
    await expect(addAppDetails).toHaveAttribute("open", "");

    // Fill in the form fields.
    await page.fill("#app-name", "E2E Test App");
    await page.fill("#app-github-id", "99001");
    await page.fill("#app-client-id", "Iv1.e2etest");
    await page.fill(
      "#app-private-key",
      "-----BEGIN RSA PRIVATE KEY-----\ne2e-test-key\n-----END RSA PRIVATE KEY-----"
    );
    await page.check("#app-is-default");

    // Click Create App.
    await page.click("#create-app-btn");

    // Wait for the apps list to update with the new app.
    await expect(page.locator("#apps-list")).toContainText("E2E Test App");
    await expect(page.locator("#apps-list")).toContainText("99001");
    await expect(page.locator("#apps-list")).toContainText("Default");

    // The Add App form should have collapsed.
    await expect(addAppDetails).not.toHaveAttribute("open", "");

    await testInfo.attach("app-created-form-collapsed", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });

  test("token sections appear after creating an app", async ({
    page,
  }) => {
    // Create an app via API.
    await createAppViaAPI(sessionToken, {
      name: "Unlock Tokens App",
      app_id: 66001,
      is_default: true,
    });

    await page.goto("/admin");
    await page.waitForLoadState("networkidle");

    // Token sections should now be visible.
    await expect(page.locator("#agent-token-section")).toBeVisible();
    await expect(page.locator("#all-tokens-section")).toBeVisible();
  });

  test("can edit an app via inline edit form", async ({ page }, testInfo) => {
    await createAppViaAPI(sessionToken, {
      name: "Original Name",
      app_id: 67001,
      is_default: false,
    });

    await page.goto("/admin");
    await page.waitForLoadState("networkidle");

    // Click the Edit button.
    await page.locator('#apps-list button:has-text("Edit")').click();

    // The edit form row should appear.
    const editRow = page.locator("#edit-app-row");
    await expect(editRow).toBeVisible();

    // Change the app name.
    const nameInput = editRow.locator('input[type="text"]').first();
    await nameInput.fill("Updated Name");

    await testInfo.attach("edit-form-filled", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });

    // Click Save.
    await editRow.locator('button:has-text("Save")').click();

    // The table should update with the new name.
    await expect(page.locator("#apps-list")).toContainText("Updated Name");
    // Edit row should be gone after reload.
    await expect(page.locator("#edit-app-row")).toBeHidden();
  });

  test("edit form cancel closes without saving", async ({ page }) => {
    await createAppViaAPI(sessionToken, {
      name: "Keep This Name",
      app_id: 67002,
    });

    await page.goto("/admin");
    await page.waitForLoadState("networkidle");

    await page.locator('#apps-list button:has-text("Edit")').click();
    await expect(page.locator("#edit-app-row")).toBeVisible();

    // Click Cancel.
    await page.locator('#edit-app-row button:has-text("Cancel")').click();
    await expect(page.locator("#edit-app-row")).toBeHidden();

    // Name should be unchanged.
    await expect(page.locator("#apps-list")).toContainText("Keep This Name");
  });

  test("agent token fields hidden until app selected with multiple apps", async ({
    page,
  }) => {
    // Create two apps, neither is default.
    await createAppViaAPI(sessionToken, {
      name: "App One",
      app_id: 68001,
    });
    await createAppViaAPI(sessionToken, {
      name: "App Two",
      app_id: 68002,
    });

    await page.goto("/admin");
    await page.waitForLoadState("networkidle");

    // The agent token section should be visible but fields hidden.
    await expect(page.locator("#agent-token-section")).toBeVisible();
    await expect(page.locator("#agent-token-fields")).toBeHidden();

    // Select an app.
    await page.locator("#app-select").selectOption({ index: 1 });

    // Fields should now be visible.
    await expect(page.locator("#agent-token-fields")).toBeVisible();
  });

  test("created app appears in the apps table with correct details", async ({
    page,
  }) => {
    // Create an app via API first.
    await createAppViaAPI(sessionToken, {
      name: "API Created App",
      app_id: 77001,
      is_default: true,
    });

    await page.goto("/admin");
    await page.waitForLoadState("networkidle");

    const appsList = page.locator("#apps-list");
    await expect(appsList).toContainText("API Created App");
    await expect(appsList).toContainText("77001");
    await expect(appsList).toContainText("Default");

    // Verify the table has a Delete button.
    await expect(
      appsList.locator('button:has-text("Delete")')
    ).toBeVisible();
  });

  test("can delete an app via the admin UI", async ({ page }, testInfo) => {
    // Create an app to delete.
    await createAppViaAPI(sessionToken, {
      name: "App To Delete",
      app_id: 88001,
    });

    await page.goto("/admin");
    await page.waitForLoadState("networkidle");

    // Verify app is visible.
    await expect(page.locator("#apps-list")).toContainText("App To Delete");

    // Accept the confirmation dialog.
    page.on("dialog", (dialog) => dialog.accept());

    // Click the Delete button.
    await page.locator('#apps-list button:has-text("Delete")').click();

    // The apps list should show the empty state.
    await expect(page.locator("#apps-list")).toContainText(
      "No apps configured"
    );

    await testInfo.attach("app-deleted", {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });

  test("multiple apps appear in the apps table", async ({ page }) => {
    // Create two apps.
    await createAppViaAPI(sessionToken, {
      name: "First App",
      app_id: 11001,
      is_default: true,
    });
    await createAppViaAPI(sessionToken, {
      name: "Second App",
      app_id: 11002,
    });

    await page.goto("/admin");
    await page.waitForLoadState("networkidle");

    const appsList = page.locator("#apps-list");
    await expect(appsList).toContainText("First App");
    await expect(appsList).toContainText("Second App");
    await expect(appsList).toContainText("11001");
    await expect(appsList).toContainText("11002");

    // Only the first app should be marked as default.
    const defaultBadges = appsList.locator(".badge-active");
    await expect(defaultBadges).toHaveCount(1);
  });

  test("app selector is hidden when only one app exists", async ({
    page,
  }) => {
    // Create a single app.
    await createAppViaAPI(sessionToken, {
      name: "Solo App",
      app_id: 22001,
      is_default: true,
    });

    await page.goto("/admin");
    await page.waitForLoadState("networkidle");

    // The app selector should be hidden (auto-selected).
    const appSelectParent = page.locator("#app-select").locator("..");
    await expect(appSelectParent).toBeHidden();
  });

  test("app selector appears when multiple apps exist", async ({ page }) => {
    // Create two apps, one as default.
    await createAppViaAPI(sessionToken, {
      name: "App Alpha",
      app_id: 33001,
      is_default: true,
    });
    await createAppViaAPI(sessionToken, {
      name: "App Beta",
      app_id: 33002,
    });

    await page.goto("/admin");
    await page.waitForLoadState("networkidle");

    // The app selector should be visible.
    const appSelect = page.locator("#app-select");
    await expect(appSelect).toBeVisible();

    // It should have 3 options: placeholder + 2 apps.
    const options = appSelect.locator("option");
    await expect(options).toHaveCount(3);

    // The default app should include "(default)" in its label.
    await expect(appSelect).toContainText("App Alpha (default)");
    await expect(appSelect).toContainText("App Beta");
  });

  test("app selector auto-selects the default app", async ({ page }) => {
    await createAppViaAPI(sessionToken, {
      name: "Non-Default App",
      app_id: 44001,
    });
    const defaultApp = await createAppViaAPI(sessionToken, {
      name: "Default App",
      app_id: 44002,
      is_default: true,
    });

    await page.goto("/admin");
    await page.waitForLoadState("networkidle");

    // The app selector should have the default app pre-selected.
    const selectedValue = await page.locator("#app-select").inputValue();
    expect(selectedValue).toBe(defaultApp.id);
  });
});

test.describe("Admin - App API endpoints", () => {
  let sessionToken: string;

  test.beforeEach(async ({ context }) => {
    const login = await loginTestUser(context, {
      username: "admin-api-test",
      role: "admin",
    });
    sessionToken = login.sessionToken;

    // Clean up.
    const apps = await listAppsViaAPI(sessionToken);
    for (const app of apps) {
      await deleteAppViaAPI(sessionToken, app.id);
    }
  });

  test("GET /api/apps returns empty array when no apps exist", async () => {
    const ctx = await request.newContext({
      baseURL: BASE_URL,
      extraHTTPHeaders: { Authorization: `Bearer ${sessionToken}` },
    });
    const resp = await ctx.get("/api/apps");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toEqual([]);
    await ctx.dispose();
  });

  test("POST /api/apps creates an app and returns it", async () => {
    const ctx = await request.newContext({
      baseURL: BASE_URL,
      extraHTTPHeaders: { Authorization: `Bearer ${sessionToken}` },
    });
    const resp = await ctx.post("/api/apps", {
      data: {
        name: "API Test App",
        app_id: 55001,
        private_key: "test-key-pem",
        client_id: "Iv1.apitest",
        is_default: true,
      },
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.name).toBe("API Test App");
    expect(body.app_id).toBe(55001);
    expect(body.is_default).toBe(true);
    expect(body.id).toBeTruthy();
    expect(body.created_at).toBeTruthy();
    await ctx.dispose();
  });

  test("GET /api/apps/{id} returns app details", async () => {
    const app = await createAppViaAPI(sessionToken, {
      name: "Fetch Me",
      app_id: 55002,
    });
    const ctx = await request.newContext({
      baseURL: BASE_URL,
      extraHTTPHeaders: { Authorization: `Bearer ${sessionToken}` },
    });
    const resp = await ctx.get(`/api/apps/${app.id}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.name).toBe("Fetch Me");
    expect(body.app_id).toBe(55002);
    await ctx.dispose();
  });

  test("DELETE /api/apps/{id} removes the app", async () => {
    const app = await createAppViaAPI(sessionToken, {
      name: "Delete Me",
      app_id: 55003,
    });
    const ctx = await request.newContext({
      baseURL: BASE_URL,
      extraHTTPHeaders: { Authorization: `Bearer ${sessionToken}` },
    });

    const delResp = await ctx.delete(`/api/apps/${app.id}`);
    expect(delResp.status()).toBe(200);

    // Verify it's gone.
    const getResp = await ctx.get(`/api/apps/${app.id}`);
    expect(getResp.status()).toBe(404);
    await ctx.dispose();
  });

  test("POST /api/apps rejects missing required fields", async () => {
    const ctx = await request.newContext({
      baseURL: BASE_URL,
      extraHTTPHeaders: { Authorization: `Bearer ${sessionToken}` },
    });

    // Missing name.
    const resp1 = await ctx.post("/api/apps", {
      data: { app_id: 55004, private_key: "key" },
    });
    expect(resp1.status()).toBe(400);

    // Missing app_id.
    const resp2 = await ctx.post("/api/apps", {
      data: { name: "No ID", private_key: "key" },
    });
    expect(resp2.status()).toBe(400);

    // Missing private_key.
    const resp3 = await ctx.post("/api/apps", {
      data: { name: "No Key", app_id: 55004 },
    });
    expect(resp3.status()).toBe(400);

    await ctx.dispose();
  });

  test("app API endpoints require admin role", async ({ context }) => {
    // Login as regular user.
    const { sessionToken: userToken } = await loginTestUser(context, {
      username: "regular-user-app-test",
      role: "user",
    });

    const ctx = await request.newContext({
      baseURL: BASE_URL,
      extraHTTPHeaders: { Authorization: `Bearer ${userToken}` },
    });

    const resp = await ctx.get("/api/apps");
    expect(resp.status()).toBe(403);
    await ctx.dispose();
  });
});
