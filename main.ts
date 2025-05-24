/// <reference types="@cloudflare/workers-types" />
/// <reference lib="es2021" />
//@ts-check
import { DORM, createClient } from "dormroom";

export { DORM };
export interface Env {
  X_CLIENT_ID: string;
  X_CLIENT_SECRET: string;
  X_REDIRECT_URI: string;
  LOGIN_REDIRECT_URI: string;
  DORM_NAMESPACE: DurableObjectNamespace<DORM>;
}

export const html = (strings: TemplateStringsArray, ...values: any[]) => {
  return strings.reduce(
    (result, str, i) => result + str + (values[i] || ""),
    "",
  );
};

// CORS headers for responses
function getCorsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}

async function generateRandomString(length: number): Promise<string> {
  const randomBytes = new Uint8Array(length);
  crypto.getRandomValues(randomBytes);
  return Array.from(randomBytes, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

async function generateCodeChallenge(codeVerifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const base64 = btoa(String.fromCharCode(...new Uint8Array(digest)));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Helper to extract cookie value
function getCookieValue(
  cookieString: string | null,
  name: string,
): string | null {
  if (!cookieString) return null;
  const matches = cookieString.match(new RegExp(`${name}=([^;]+)`));
  return matches ? decodeURIComponent(matches[1]) : null;
}

const ROOT_DB_NAME = "db:root";

const migrations = {
        // initial version
        1: [
    `
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      name TEXT,
      profile_image_url TEXT,
      access_token TEXT NOT NULL,
      refresh_token TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    `,
  ],
      }

export default {
  fetch: async (request: Request, env: Env, ctx: ExecutionContext) => {
    // Deconstruct Cookies
    const url = new URL(request.url);
    const method = request.method;
    const cookie = request.headers.get("Cookie");
    const xAccessToken = getCookieValue(cookie, "x_access_token");
    const userId = getCookieValue(cookie, "x_user_id");
    const accessToken = xAccessToken || url.searchParams.get("apiKey");

    // Handle CORS preflight requests
    if (method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: getCorsHeaders(),
      });
    }

    // Initialize DORM client for user database
    const dbName = url.pathname.startsWith("/admin/")
      ? url.pathname.split("/")[2]
      : undefined;
    const prefix = `/admin/${dbName}`;

    // Initialize DORM client for user database
    const client = createClient({
      doNamespace: env.DORM_NAMESPACE,
      version: "v2", // Version prefix for migrations
      migrations,
      ctx, // Pass execution context for waitUntil
      name: dbName || userId || ROOT_DB_NAME,
      mirrorName:
        dbName !== ROOT_DB_NAME
          ? ROOT_DB_NAME
          : userId
            ? ROOT_DB_NAME
            : undefined,
    });

    // Handle DB middleware requests (for exploring the DB)
    const middlewareResponse = await client.middleware(request, {
      prefix,
      secret: env.X_CLIENT_SECRET,
    });
    if (middlewareResponse) return middlewareResponse;

    // X Login routes
    if (url.pathname === "/login") {
      const scope = url.searchParams.get("scope");
      const state = await generateRandomString(16);
      const codeVerifier = await generateRandomString(43);
      const codeChallenge = await generateCodeChallenge(codeVerifier);

      const Location = `https://x.com/i/oauth2/authorize?response_type=code&client_id=${
        env.X_CLIENT_ID
      }&redirect_uri=${encodeURIComponent(
        env.X_REDIRECT_URI,
      )}&scope=${encodeURIComponent(
        scope || "users.read follows.read tweet.read offline.access",
      )}&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256`;

      const headers = new Headers(getCorsHeaders());

      headers.append("Location", Location);

      headers.append(
        "Set-Cookie",
        `x_oauth_state=${state}; HttpOnly; Path=/; Secure; SameSite=Lax; Max-Age=600`,
      );
      headers.append(
        "Set-Cookie",
        `x_code_verifier=${codeVerifier}; HttpOnly; Path=/; Secure; SameSite=Lax; Max-Age=600`,
      );

      return new Response("Redirecting", {
        status: 307,
        headers,
      });
    }

    // X OAuth callback route
    if (url.pathname === "/callback") {
      const urlState = url.searchParams.get("state");
      const code = url.searchParams.get("code");
      const cookieString = request.headers.get("Cookie") || "";

      const stateCookie = getCookieValue(cookieString, "x_oauth_state");
      const codeVerifier = getCookieValue(cookieString, "x_code_verifier");

      // Validate state and code verifier
      if (
        !urlState ||
        !stateCookie ||
        urlState !== stateCookie ||
        !codeVerifier
      ) {
        return new Response(
          `Invalid state or missing code verifier. Session validation failed.`,
          {
            status: 400,
            headers: getCorsHeaders(),
          },
        );
      }

      try {
        // Exchange code for access token
        const tokenResponse = await fetch(
          "https://api.twitter.com/2/oauth2/token",
          {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
              Authorization: `Basic ${btoa(
                `${env.X_CLIENT_ID}:${env.X_CLIENT_SECRET}`,
              )}`,
            },
            body: new URLSearchParams({
              code: code || "",
              redirect_uri: env.X_REDIRECT_URI,
              grant_type: "authorization_code",
              code_verifier: codeVerifier,
            }),
          },
        );

        if (!tokenResponse.ok) {
          throw new Error(
            `Twitter API responded with ${
              tokenResponse.status
            }: ${await tokenResponse.text()}`,
          );
        }

        const tokenData: any = await tokenResponse.json();
        const { access_token, refresh_token } = tokenData;

        // Fetch user data to store in the database
        const userResponse = await fetch(
          "https://api.x.com/2/users/me?user.fields=profile_image_url",
          {
            headers: {
              Authorization: `Bearer ${access_token}`,
              "Content-Type": "application/json",
            },
          },
        );

        if (!userResponse.ok) {
          throw new Error(
            `X API error: ${userResponse.status} ${await userResponse.text()}`,
          );
        }

        const userData: any = await userResponse.json();
        const { id, name, username, profile_image_url } = userData.data;

        if (!id) {
          throw new Error(`X API error: no ID found`);
        }

        // Create a client for this specific user
        const userClient = createClient({
          doNamespace: env.DORM_NAMESPACE,
          version: "v2",
          migrations,
          ctx,
          name: String(id),
          mirrorName: ROOT_DB_NAME,
        });

        // Check if user exists in database
        const existingUser = await userClient.exec(
          "SELECT * FROM users WHERE id = ?",
          id
        ).one().catch(() => null);

        if (existingUser) {
          // Update existing user
          await userClient.exec(
            "UPDATE users SET access_token = ?, refresh_token = ?, name = ?, profile_image_url = ?, last_login = ? WHERE id = ?",
            access_token,
            refresh_token || null,
            name,
            profile_image_url,
            new Date().toISOString(),
            id
          );
        } else {
          // Create new user
          await userClient.exec(
            "INSERT INTO users (id, username, name, profile_image_url, access_token, refresh_token) VALUES (?, ?, ?, ?, ?, ?)",
            id,
            username,
            name,
            profile_image_url,
            access_token,
            refresh_token || null
          );
        }

        const headers = new Headers({
          ...getCorsHeaders(),
          Location: url.origin + (env.LOGIN_REDIRECT_URI || "/"),
        });

        // Set access token cookie and clear temporary cookies
        headers.append(
          "Set-Cookie",
          `x_access_token=${encodeURIComponent(
            access_token,
          )}; HttpOnly; Path=/; Secure; SameSite=Lax; Max-Age=34560000`,
        );
        headers.append(
          "Set-Cookie",
          `x_user_id=${encodeURIComponent(
            id,
          )}; HttpOnly; Path=/; Secure; SameSite=Lax; Max-Age=34560000`,
        );
        headers.append(
          "Set-Cookie",
          `x_oauth_state=; Max-Age=0; Path=/`,
        );
        headers.append(
          "Set-Cookie",
          `x_code_verifier=; Max-Age=0; Path=/`,
        );

        return new Response("Redirecting", {
          status: 307,
          headers,
        });
      } catch (error) {
        return new Response(
          html`
            <!DOCTYPE html>
            <html lang="en">
              <head>
                <title>Login Failed</title>
              </head>
              <body>
                <h1>X Login Failed</h1>
                <p>
                  ${error instanceof Error ? error.message : "Unknown error"}
                </p>
                <a href="/">Return to homepage</a>
              </body>
            </html>
          `,
          {
            status: 500,
            headers: {
              "Content-Type": "text/html",
              "Set-Cookie": `x_oauth_state=; Max-Age=0; Path=/, x_code_verifier=; Max-Age=0; Path=/`,
              ...getCorsHeaders(),
            },
          },
        );
      }
    }

    // Logout route
    if (url.pathname === "/logout") {
      // Update last_login in the database if we have the user ID
      if (userId) {
        await client.exec(
          "UPDATE users SET last_login = ? WHERE id = ?",
          new Date().toISOString(),
          userId
        );
      }

      const headers = new Headers({
        Location: "/",
        ...getCorsHeaders(),
      });

      headers.append(
        "Set-Cookie",
        "x_access_token=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax",
      );
      headers.append(
        "Set-Cookie",
        "x_user_id=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax",
      );

      return new Response("Logging out...", { status: 302, headers });
    }

    // Dashboard route - show user profile if logged in
    if (url.pathname === "/dashboard") {
      if (!accessToken || !userId) {
        // Redirect to login if no access token
        return new Response("Redirecting to login...", {
          status: 302,
          headers: {
            Location: "/login",
            ...getCorsHeaders(),
          },
        });
      }

      // Try to get user data from database with matching access_token
      const userData = await client.exec(
        "SELECT * FROM users WHERE id = ? AND access_token = ?",
        userId,
        accessToken
      ).one().catch(() => null);

      if (!userData) {
        return new Response("Redirecting to login...", {
          status: 302,
          headers: { Location: "/login", ...getCorsHeaders() },
        });
      }

      return new Response(
        html`
          <!DOCTYPE html>
          <html>
            <head>
              <title>X User Dashboard</title>
              <style>
                body { font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }
                img { border-radius: 50%; }
                .profile { display: flex; gap: 20px; align-items: center; }
                .btn { display: inline-block; padding: 8px 16px; background: #1DA1F2; color: white; 
                       text-decoration: none; border-radius: 4px; margin-right: 10px; }
                .btn-logout { background: #E0245E; }
              </style>
            </head>
            <body>
              <h1>X Dashboard</h1>
              <div class="profile">
                <img src="${userData.profile_image_url}" width="64" height="64" alt="Profile">
                <div>
                  <h2>${userData.name}</h2>
                  <p>@${userData.username}</p>
                </div>
              </div>
              <p>Last login: ${new Date(userData.last_login).toLocaleString()}</p>
              <div>
                <a href="/" class="btn">Home</a>
                <a href="/logout" class="btn btn-logout">Logout</a>
              </div>
            </body>
          </html>
        `,
        {
          headers: {
            "content-type": "text/html",
            ...getCorsHeaders(),
          },
        },
      );
    }

    // Default route
    if (url.pathname === "/" || url.pathname === "") {
      return new Response(
        html`
          <!DOCTYPE html>
          <html>
            <head>
              <title>X OAuth Demo</title>
              <style>
                body { font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }
                .btn { display: inline-block; padding: 10px 20px; background: #1DA1F2; color: white; 
                       text-decoration: none; border-radius: 4px; }
              </style>
            </head>
            <body>
              <h1>X OAuth Demo</h1>
              <p>Simple X/Twitter OAuth implementation with DORM SQLite storage</p>
              <a href="/login" class="btn">Login with X</a>
            </body>
          </html>
        `,
        {
          headers: {
            "content-type": "text/html",
            ...getCorsHeaders(),
          },
        },
      );
    }

    return new Response("Not found", { status: 404 });
  },
};
