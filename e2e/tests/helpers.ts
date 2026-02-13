import { type Page, type BrowserContext, request } from "@playwright/test";

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
