import { DORM, createClient, DBConfig } from "dormroom/DORM";
export { DORM };
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
    const client = createClient(env.X_LOGIN_DO, {
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
      authSecret: env.X_CLIENT_SECRET,
    });
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
      prefix: "/admin",
      secret: env.X_CLIENT_SECRET,
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
        `x_oauth_state=${state}; HttpOnly; Domain=xymake.com; Path=/; Secure; SameSite=Lax; Max-Age=600`,
      );
      headers.append(
        "Set-Cookie",
        `x_code_verifier=${codeVerifier}; HttpOnly; Domain=xymake.com; Path=/; Secure; SameSite=Lax; Max-Age=600`,
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
          ...getCorsHeaders(),
          Location: url.origin + (env.LOGIN_REDIRECT_URI || "/"),
        });

        // Set access token cookie and clear temporary cookies
        headers.append(
          "Set-Cookie",
          `x_access_token=${encodeURIComponent(
            access_token,
          )}; HttpOnly; Domain=xymake.com; Path=/; Secure; SameSite=Lax; Max-Age=34560000`,
        );
        headers.append(
          "Set-Cookie",
          `x_user_id=${encodeURIComponent(
            id,
          )}; HttpOnly; Domain=xymake.com; Path=/; Secure; SameSite=Lax; Max-Age=34560000`,
        );
        headers.append(
          "Set-Cookie",
          `x_oauth_state=; Domain=xymake.com; Max-Age=0; Path=/`,
        );
        headers.append(
          "Set-Cookie",
          `x_code_verifier=; Domain=xymake.com; Max-Age=0; Path=/`,
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
              "Set-Cookie": `x_oauth_state=; Domain=xymake.com; Max-Age=0; Path=/, x_code_verifier=; Max-Age=0; Domain=xymake.com; Path=/`,
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
        ...getCorsHeaders(),
      });

      headers.append(
        "Set-Cookie",
        "x_access_token=; Max-Age=0; Domain=xymake.com; Path=/; HttpOnly; Secure; SameSite=Lax",
      );
      headers.append(
        "Set-Cookie",
        "x_user_id=; Max-Age=0; Domain=xymake.com; Path=/; HttpOnly; Secure; SameSite=Lax",
      );

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

    return new Response("Not found", { status: 404 });
  },
};
