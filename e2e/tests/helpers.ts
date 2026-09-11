import { type BrowserContext, request } from "@playwright/test";

const BASE_URL = process.env.GHP_BASE_URL || "http://localhost:8080";

/**
 * Authenticate a test user via the dev-mode /auth/test-login endpoint.
 * Sets the session cookie on the browser context so subsequent page
 * navigations are authenticated.
 */
export async function loginTestUser(
  context: BrowserContext,
  opts: { username?: string; role?: string } = {}
): Promise<{ sessionToken: string; username: string; userId: string }> {
  const apiContext = await request.newContext({ baseURL: BASE_URL });
  const resp = await apiContext.post("/auth/test-login", {
    data: {
      username: opts.username || "testuser",
      role: opts.role || "user",
    },
  });

  if (!resp.ok()) {
    throw new Error(
      `Test login failed: ${resp.status()} ${await resp.text()}`
    );
  }

  const body = await resp.json();

  // Set the session cookie on the browser context.
  const url = new URL(BASE_URL);
  await context.addCookies([
    {
      name: "ghp_session",
      value: body.session_token,
      domain: url.hostname,
      path: "/",
      httpOnly: true,
      sameSite: "Lax",
    },
  ]);

  await apiContext.dispose();

  return {
    sessionToken: body.session_token,
    username: body.username,
    userId: body.user_id,
  };
}

// Cached admin session to avoid repeated /auth/test-login calls.
let cachedAdminToken: string | null = null;
let appEnsured = false;

/**
 * Ensure at least one app exists (for tests that need token features).
 * Caches the result so we only hit /auth/test-login once.
 * On auth failure, retries with a fresh admin token.
 */
export async function ensureAppExists(
  _context: BrowserContext
): Promise<{ adminToken: string; appId: string }> {
  for (let attempt = 0; attempt < 2; attempt++) {
    const adminToken = await getAdminToken(attempt > 0);
    try {
      const apps = await listAppsViaAPI(adminToken);
      if (apps.length > 0) {
        appEnsured = true;
        return { adminToken, appId: apps[0].id };
      }
      if (appEnsured) {
        // Apps were deleted by another test — create a new one.
      }
      const app = await createAppViaAPI(adminToken, {
        name: "Default Test App",
        app_id: 90001,
        is_default: true,
      });
      appEnsured = true;
      return { adminToken, appId: app.id };
    } catch (e) {
      if (attempt === 0) {
        // Token might be stale — clear cache and retry.
        cachedAdminToken = null;
        continue;
      }
      throw e;
    }
  }
  throw new Error("ensureAppExists: unreachable");
}

/**
 * Login as admin via the API (without setting browser cookies).
 * Caches the session token across calls.
 */
async function getAdminToken(forceRefresh = false): Promise<string> {
  if (cachedAdminToken && !forceRefresh) return cachedAdminToken;
  const ctx = await request.newContext({ baseURL: BASE_URL });
  const resp = await ctx.post("/auth/test-login", {
    data: { username: "helper-admin", role: "admin" },
  });
  if (!resp.ok()) {
    throw new Error(
      `Admin login failed: ${resp.status()} ${await resp.text()}`
    );
  }
  const body = await resp.json();
  await ctx.dispose();
  cachedAdminToken = body.session_token;
  return cachedAdminToken;
}

/**
 * Create an app via the API.
 */
export async function createAppViaAPI(
  sessionToken: string,
  app: {
    name: string;
    app_id: number;
    private_key?: string;
    is_default?: boolean;
  }
): Promise<{ id: string; name: string; app_id: number; is_default: boolean }> {
  const ctx = await request.newContext({
    baseURL: BASE_URL,
    extraHTTPHeaders: { Authorization: `Bearer ${sessionToken}` },
  });
  const resp = await ctx.post("/api/apps", {
    data: {
      name: app.name,
      app_id: app.app_id,
      private_key:
        app.private_key ||
        "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
      is_default: app.is_default ?? false,
    },
  });
  if (!resp.ok()) {
    throw new Error(
      `createAppViaAPI failed: ${resp.status()} ${await resp.text()}`
    );
  }
  const body = await resp.json();
  await ctx.dispose();
  return body;
}

/**
 * Delete an app via the API.
 */
export async function deleteAppViaAPI(
  sessionToken: string,
  appId: string
): Promise<void> {
  const ctx = await request.newContext({
    baseURL: BASE_URL,
    extraHTTPHeaders: { Authorization: `Bearer ${sessionToken}` },
  });
  await ctx.delete(`/api/apps/${appId}`);
  await ctx.dispose();
}

/**
 * List apps via the API.
 */
export async function listAppsViaAPI(
  sessionToken: string
): Promise<any[]> {
  const ctx = await request.newContext({
    baseURL: BASE_URL,
    extraHTTPHeaders: { Authorization: `Bearer ${sessionToken}` },
  });
  const resp = await ctx.get("/api/apps");
  if (!resp.ok()) {
    await ctx.dispose();
    throw new Error(
      `listAppsViaAPI failed: ${resp.status()}`
    );
  }
  const body = await resp.json();
  await ctx.dispose();
  return Array.isArray(body) ? body : [];
}
