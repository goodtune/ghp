import { test, expect, request } from "@playwright/test";
import { loginTestUser } from "./helpers";

const BASE_URL = process.env.GHP_BASE_URL || "http://localhost:8080";

test.describe("Auth API", () => {
  test("GET /auth/status returns unauthenticated without session", async () => {
    const ctx = await request.newContext({ baseURL: BASE_URL });
    const resp = await ctx.get("/auth/status");

    expect(resp.status()).toBe(401);
    const body = await resp.json();
    expect(body.authenticated).toBe(false);
    await ctx.dispose();
  });

  test("GET /auth/status returns authenticated with session", async ({
    context,
  }) => {
    const { sessionToken } = await loginTestUser(context);

    const ctx = await request.newContext({
      baseURL: BASE_URL,
      extraHTTPHeaders: {
        Authorization: `Bearer ${sessionToken}`,
      },
    });
    const resp = await ctx.get("/auth/status");

    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.authenticated).toBe(true);
    expect(body.username).toBe("testuser");
    await ctx.dispose();
  });

  test("GET /auth/github redirects to GitHub OAuth", async () => {
    const ctx = await request.newContext({
      baseURL: BASE_URL,
      maxRedirects: 0,
    });

    const resp = await ctx.get("/auth/github");

    // Should be a redirect (307).
    expect(resp.status()).toBe(307);
    const location = resp.headers()["location"];
    expect(location).toContain("github.com/login/oauth/authorize");
    await ctx.dispose();
  });

  test("POST /auth/logout clears session", async ({ context }) => {
    const { sessionToken } = await loginTestUser(context);

    const ctx = await request.newContext({
      baseURL: BASE_URL,
      extraHTTPHeaders: {
        Cookie: `ghp_session=${sessionToken}`,
      },
    });

    // Logout.
    const logoutResp = await ctx.post("/auth/logout");
    expect(logoutResp.status()).toBe(200);

    // Check status — session should be gone.
    const statusResp = await ctx.get("/auth/status");
    // After logout the cookie was cleared, so this returns 401.
    expect(statusResp.status()).toBe(401);
    await ctx.dispose();
  });

  test("API endpoints require authentication", async () => {
    const ctx = await request.newContext({ baseURL: BASE_URL });

    const endpoints = [
      { method: "GET" as const, path: "/api/tokens" },
      { method: "GET" as const, path: "/api/audit" },
    ];

    for (const ep of endpoints) {
      const resp = await ctx.fetch(ep.path, { method: ep.method });
      expect(resp.status()).toBe(401);
    }

    await ctx.dispose();
  });
});
