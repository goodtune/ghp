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

/**
 * Wait for Datastar to be loaded and initialized on the page.
 * Datastar loads as an ES module, so we need to wait for it
 * to process all data-* attributes before interacting with them.
 */
export async function waitForDatastar(page: Page): Promise<void> {
  // Wait for the Datastar module script to finish loading.
  await page.waitForFunction(() => {
    // Datastar sets window.ds when it initializes.
    if ((window as any).ds) return true;
    // Fallback: check if any data-on-click element has been processed
    // by verifying the script element exists and the module has loaded.
    const script = document.querySelector('script[type="module"][src*="datastar"]');
    return !!script;
  }, { timeout: 5000 }).catch(() => {});
  // Give Datastar a moment to bind all event handlers after module load.
  await page.waitForTimeout(300);
}
