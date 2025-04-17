import { DORM, createClient, DBConfig } from "dormroom/DORM";
export { DORM };

// Database configuration for X Login users
const dbConfig: DBConfig = {
  statements: [
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
  version: "v1",
  authSecret: "x-login-secret-key", // Change in production
};

export interface Env {
  X_CLIENT_ID: string;
  X_CLIENT_SECRET: string;
  X_REDIRECT_URI: string;
  LOGIN_REDIRECT_URI: string;
  X_LOGIN_DO: DurableObjectNamespace;
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

export default {
  fetch: async (request: Request, env: Env, ctx: ExecutionContext) => {
    // Initialize DORM client for user database
    const client = createClient(env.X_LOGIN_DO, dbConfig);
    const url = new URL(request.url);
    const method = request.method;

    // Handle CORS preflight requests
    if (method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: getCorsHeaders(),
      });
    }

    // Handle DB middleware requests (for exploring the DB)
    const middlewareResponse = await client.middleware(request, {
      prefix: "/api/db",
      secret: dbConfig.authSecret,
    });
    if (middlewareResponse) return middlewareResponse;

    // Extract access token from cookies or query params
    const cookie = request.headers.get("Cookie");
    const xAccessToken = getCookieValue(cookie, "x_access_token");
    const accessToken = xAccessToken || url.searchParams.get("apiKey");

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
        status: 302,
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

        // Store or update user in database
        const existingUserResult = await client.select("users", { id });

        if (
          existingUserResult.ok &&
          existingUserResult.json &&
          existingUserResult.json.length > 0
        ) {
          // Update existing user with new tokens and login time
          await client.update(
            "users",
            {
              access_token,
              refresh_token: refresh_token || null,
              name,
              profile_image_url,
              last_login: new Date().toISOString(),
            },
            { id },
          );
        } else {
          // Create new user
          await client.insert("users", {
            id,
            username,
            name,
            profile_image_url,
            access_token,
            refresh_token: refresh_token || null,
          });
        }

        const headers = new Headers({
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
        headers.append("Set-Cookie", `x_oauth_state=; Max-Age=0; Path=/`);
        headers.append("Set-Cookie", `x_code_verifier=; Max-Age=0; Path=/`);

        return new Response("Redirecting", {
          status: 307,
          headers: {
            ...headers,
            ...getCorsHeaders(),
          },
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
                <script>
                  setTimeout(() => (window.location.href = "/"), 5000);
                </script>
                <p>Redirecting to homepage in 5 seconds...</p>
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
      const userId = getCookieValue(cookie, "x_user_id");

      // Update last_login in the database if we have the user ID
      if (userId) {
        await client.update(
          "users",
          { last_login: new Date().toISOString() },
          { id: userId },
        );
      }

      const headers = new Headers({
        Location: "/",
        "Set-Cookie": [
          "x_access_token=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax",
          "x_user_id=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax",
        ].join(", "),
        ...getCorsHeaders(),
      });

      return new Response("Logging out...", { status: 302, headers });
    }

    // Dashboard route - show user profile if logged in
    if (url.pathname === "/dashboard") {
      if (!accessToken) {
        // Redirect to login if no access token
        return new Response("Redirecting to login...", {
          status: 302,
          headers: {
            Location: "/login",
            ...getCorsHeaders(),
          },
        });
      }

      try {
        // Get user ID from cookie
        const userId = getCookieValue(cookie, "x_user_id");
        let userData;

        // Try to get user data from database first
        if (userId) {
          const dbUserResult = await client.select("users", { id: userId });
          if (
            dbUserResult.ok &&
            dbUserResult.json &&
            dbUserResult.json.length > 0
          ) {
            userData = dbUserResult.json[0];
          }
        }

        // If not found in DB or no userId cookie, fetch from API
        if (!userData) {
          const userResponse = await fetch(
            "https://api.x.com/2/users/me?user.fields=profile_image_url",
            {
              headers: {
                Authorization: `Bearer ${accessToken}`,
                "Content-Type": "application/json",
              },
            },
          );

          if (!userResponse.ok) {
            throw new Error(
              `X API error: ${
                userResponse.status
              } ${await userResponse.text()}`,
            );
          }

          const apiUserData: any = await userResponse.json();
          userData = {
            id: apiUserData.data.id,
            name: apiUserData.data.name,
            username: apiUserData.data.username,
            profile_image_url: apiUserData.data.profile_image_url,
          };
        }

        return new Response(
          html`
            <!DOCTYPE html>
            <html lang="en" class="bg-slate-900">
              <head>
                <meta charset="utf8" />
                <script src="https://cdn.tailwindcss.com"></script>
                <title>X User Dashboard</title>
                <style>
                  @import url("https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap");
                  body {
                    font-family: "Inter", sans-serif;
                  }
                </style>
              </head>
              <body class="text-slate-100">
                <main class="max-w-6xl mx-auto px-4 py-16">
                  <div class="text-center mb-20">
                    <h1
                      class="text-5xl font-bold mb-6 bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent"
                    >
                      X Dashboard
                    </h1>

                    <div
                      class="max-w-md mx-auto bg-slate-800 rounded-xl p-6 mb-8"
                    >
                      <div class="flex items-center gap-4">
                        <img
                          src="${userData.profile_image_url}"
                          alt="Profile"
                          class="w-16 h-16 rounded-full"
                        />
                        <div class="text-left">
                          <h2 class="text-xl font-semibold">
                            ${userData.name}
                          </h2>
                          <p class="text-slate-400">@${userData.username}</p>
                        </div>
                      </div>
                    </div>

                    <div class="flex justify-center gap-4">
                      <a
                        href="/"
                        class="bg-blue-500 hover:bg-blue-600 px-6 py-3 rounded-lg font-medium transition-colors"
                      >
                        Home
                      </a>
                      <a
                        href="/logout"
                        class="border border-blue-500 text-blue-500 px-6 py-3 rounded-lg font-medium hover:bg-blue-500/10 transition-colors"
                      >
                        Logout
                      </a>
                    </div>
                  </div>
                </main>
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
      } catch (error) {
        // If error accessing profile, clear cookies and redirect to login
        return new Response(
          html`
            <!DOCTYPE html>
            <html lang="en">
              <head>
                <title>Dashboard Error</title>
              </head>
              <body>
                <h1>Error Loading Dashboard</h1>
                <p>
                  ${error instanceof Error ? error.message : "Unknown error"}
                </p>
                <p>Your session may have expired. Please login again.</p>
                <script>
                  setTimeout(() => (window.location.href = "/login"), 3000);
                </script>
              </body>
            </html>
          `,
          {
            status: 401,
            headers: {
              "content-type": "text/html",
              "Set-Cookie": [
                "x_access_token=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax",
                "x_user_id=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax",
              ].join(", "),
              ...getCorsHeaders(),
            },
          },
        );
      }
    }

    // API route to get current user
    if (url.pathname === "/api/me") {
      if (!accessToken) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: {
            "Content-Type": "application/json",
            ...getCorsHeaders(),
          },
        });
      }

      try {
        const userId = getCookieValue(cookie, "x_user_id");
        let userData;

        // Try to get from database first
        if (userId) {
          const dbUserResult = await client.select("users", { id: userId });
          if (
            dbUserResult.ok &&
            dbUserResult.json &&
            dbUserResult.json.length > 0
          ) {
            userData = dbUserResult.json[0];

            // Don't expose tokens in API response
            delete userData.access_token;
            delete userData.refresh_token;
          }
        }

        // If not in DB, fetch from X API
        if (!userData) {
          const userResponse = await fetch(
            "https://api.x.com/2/users/me?user.fields=profile_image_url",
            {
              headers: {
                Authorization: `Bearer ${accessToken}`,
                "Content-Type": "application/json",
              },
            },
          );

          if (!userResponse.ok) {
            throw new Error(`X API error: ${userResponse.status}`);
          }

          const apiData: any = await userResponse.json();
          userData = apiData.data;
        }

        return new Response(JSON.stringify(userData), {
          headers: {
            "Content-Type": "application/json",
            ...getCorsHeaders(),
          },
        });
      } catch (error) {
        return new Response(
          JSON.stringify({
            error: "Failed to fetch user data",
            message: error instanceof Error ? error.message : "Unknown error",
          }),
          {
            status: 500,
            headers: {
              "Content-Type": "application/json",
              ...getCorsHeaders(),
            },
          },
        );
      }
    }

    // Home page
    return new Response(
      html`
        <!DOCTYPE html>
        <html lang="en" class="bg-black">
          <head>
            <meta charset="utf8" />
            <meta
              name="viewport"
              content="width=device-width, initial-scale=1"
            />
            <script src="https://cdn.tailwindcss.com"></script>
            <title>X Login Demo - X OAuth 2.0 Implementation with DORM</title>
            <style>
              @import url("https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap");
              body {
                font-family: "Inter", sans-serif;
              }
              .x-gradient {
                background: linear-gradient(135deg, #000000 0%, #1d1d1d 100%);
              }
              .x-border {
                border: 1px solid rgba(255, 255, 255, 0.1);
              }
            </style>
          </head>

          <body class="text-white">
            <main class="min-h-screen x-gradient">
              <div class="max-w-5xl mx-auto px-4 py-16">
                <!-- Hero Section -->
                <div class="text-center mb-20">
                  <div class="mb-8">
                    <svg
                      viewBox="0 0 24 24"
                      class="w-12 h-12 mx-auto"
                      fill="currentColor"
                    >
                      <path
                        d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"
                      />
                    </svg>
                  </div>
                  <h1 class="text-5xl font-bold mb-4">
                    X Login Demo with DORM
                  </h1>
                  <p class="text-xl text-gray-400 mb-8">
                    Secure OAuth 2.0 Implementation with PKCE for X/Twitter with
                    SQLite Storage
                  </p>
                  <div class="flex justify-center gap-4">
                    <a
                      id="login"
                      href="${accessToken ? "/dashboard" : "/login"}"
                      class="bg-white text-black hover:bg-gray-200 px-8 py-4 rounded-full font-bold text-lg transition-colors flex items-center gap-2"
                    >
                      ${accessToken ? "Go to Dashboard" : "Login with X"}
                    </a>
                    <a
                      href="https://github.com/janwilmake/xlogin"
                      target="_blank"
                      class="x-border hover:bg-white/10 px-8 py-4 rounded-full font-medium transition-colors flex items-center gap-2"
                    >
                      <svg
                        class="w-5 h-5"
                        fill="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          fill-rule="evenodd"
                          d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
                          clip-rule="evenodd"
                        />
                      </svg>
                      View Source
                    </a>
                  </div>
                </div>

                <!-- Features Grid -->
                <div class="grid md:grid-cols-3 gap-8 mb-20">
                  <div
                    class="x-border rounded-xl p-6 hover:bg-white/5 transition-colors"
                  >
                    <div class="text-blue-400 mb-4">
                      <svg
                        class="w-8 h-8"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          stroke-linecap="round"
                          stroke-linejoin="round"
                          stroke-width="2"
                          d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"
                        />
                      </svg>
                    </div>
                    <h3 class="text-xl font-bold mb-2">Secure OAuth 2.0</h3>
                    <p class="text-gray-400">
                      PKCE implementation with encrypted cookies and CSRF
                      protection
                    </p>
                  </div>

                  <div
                    class="x-border rounded-xl p-6 hover:bg-white/5 transition-colors"
                  >
                    <div class="text-blue-400 mb-4">
                      <svg
                        class="w-8 h-8"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          stroke-linecap="round"
                          stroke-linejoin="round"
                          stroke-width="2"
                          d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"
                        />
                      </svg>
                    </div>
                    <h3 class="text-xl font-bold mb-2">
                      User Profiles in SQLite
                    </h3>
                    <p class="text-gray-400">
                      Store X profiles in DORM SQLite database for fast access
                    </p>
                  </div>

                  <div
                    class="x-border rounded-xl p-6 hover:bg-white/5 transition-colors"
                  >
                    <div class="text-blue-400 mb-4">
                      <svg
                        class="w-8 h-8"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          stroke-linecap="round"
                          stroke-linejoin="round"
                          stroke-width="2"
                          d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                        />
                      </svg>
                    </div>
                    <h3 class="text-xl font-bold mb-2">
                      Cloudflare Integration
                    </h3>
                    <p class="text-gray-400">
                      Edge-first implementation with DORM SQLite database for
                      state management
                    </p>
                  </div>
                </div>

                <!-- Footer -->
                <div
                  class="text-center text-gray-500 border-t border-white/10 pt-12"
                >
                  <p class="text-sm">
                    Built with ❤️ using Cloudflare Workers and DORM. Not
                    affiliated with X Corp.
                  </p>
                </div>
              </div>
            </main>
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
  },
};
