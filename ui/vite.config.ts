import path from "node:path";
import fs from "node:fs";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

const here = path.dirname(fileURLToPath(import.meta.url));

function normalizeBase(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) {
    return "/";
  }
  if (trimmed === "./") {
    return "./";
  }
  if (trimmed.endsWith("/")) {
    return trimmed;
  }
  return `${trimmed}/`;
}

export default defineConfig(() => {
  const envBase = process.env.OPENCLAW_CONTROL_UI_BASE_PATH?.trim();
  const base = envBase ? normalizeBase(envBase) : "./";
  return {
    base,
    publicDir: path.resolve(here, "public"),
    plugins: [
      {
        name: "openclaw-dev-user-api",
        configureServer(server) {
          const userFile = path.resolve(here, "..", "database", "user.json");
          const sessionsFile = path.resolve(here, "..", "database", "sessions.json");
          server.middlewares.use(async (req, res, next) => {
            if (!req.url || !req.url.startsWith("/api/user")) {
              return next();
            }

            try {
              if (req.method === "GET") {
                // GET 必须带 Authorization: Bearer <token>
                const auth = (req.headers && (req.headers.authorization || req.headers.Authorization)) || "";
                const match = String(auth).trim().match(/^Bearer\s+(.+)$/i);
                if (!match) {
                  res.statusCode = 401;
                  res.end("Unauthorized");
                  return;
                }
                const token = match[1];
                let sessions: any = {};
                if (fs.existsSync(sessionsFile)) {
                  try {
                    sessions = JSON.parse(await fs.promises.readFile(sessionsFile, "utf8") || "{}");
                  } catch {
                    sessions = {};
                  }
                }
                const session = sessions[token];
                if (!session || session.active !== true) {
                  res.statusCode = 401;
                  res.end("Unauthorized");
                  return;
                }
                res.statusCode = 200;
                res.setHeader("Content-Type", "application/json");
                res.end(JSON.stringify({ username: session.username }));
                return;
              }

              if (req.method === "POST") {
                // 登录：验证凭据后创建 session.json
                let body = "";
                for await (const chunk of req) {
                  body += chunk;
                }
                const creds = body ? JSON.parse(body) : {};
                if (!fs.existsSync(userFile)) {
                  res.statusCode = 404;
                  res.end("No user");
                  return;
                }
                const stored = JSON.parse(await fs.promises.readFile(userFile, "utf8") || "{}");
                // Validate credentials. Support client-side SHA-256 passwordHash or plaintext password for compatibility.
                let valid = false;
                if (stored.username === creds.username) {
                  if (typeof creds.passwordHash === "string" && creds.passwordHash) {
                    // Hash stored plaintext password and compare
                    try {
                      const storedPw = String(stored.password ?? "");
                      const hash = crypto.createHash("sha256").update(storedPw, "utf8").digest("hex");
                      if (hash === creds.passwordHash) {
                        valid = true;
                      }
                    } catch {
                      valid = false;
                    }
                  } else if (typeof creds.password === "string") {
                    if (stored.password === creds.password) {
                      valid = true;
                    }
                  }
                }
                if (valid) {
                  // 生成随机 token，并写入 sessions.json（支持多会话）
                  const token = crypto.randomBytes(24).toString("hex");
                  const newSession = { username: stored.username, createdAt: Date.now(), active: true, token };
                  let sessions = {};
                  if (fs.existsSync(sessionsFile)) {
                    try {
                      sessions = JSON.parse(await fs.promises.readFile(sessionsFile, "utf8") || "{}");
                    } catch {
                      sessions = {};
                    }
                  }
                  sessions[token] = newSession;
                  await fs.promises.writeFile(sessionsFile, JSON.stringify(sessions, null, 2), "utf8");
                  res.statusCode = 200;
                  res.setHeader("Content-Type", "application/json");
                  res.end(JSON.stringify({ ok: true, token }));
                } else {
                  res.statusCode = 401;
                  res.end("Unauthorized");
                }
                return;
              }

              if (req.method === "DELETE") {
                // 注销：删除对应 token 的会话（sessions.json 中移除对应键）
                const auth = (req.headers && (req.headers.authorization || req.headers.Authorization)) || "";
                const match = String(auth).trim().match(/^Bearer\s+(.+)$/i);
                if (!match) {
                  res.statusCode = 401;
                  res.end("Unauthorized");
                  return;
                }
                const token = match[1];
                try {
                  let sessions = {};
                  if (fs.existsSync(sessionsFile)) {
                    try {
                      sessions = JSON.parse(await fs.promises.readFile(sessionsFile, "utf8") || "{}");
                    } catch {
                      sessions = {};
                    }
                  }
                  if (sessions && sessions[token]) {
                    delete sessions[token];
                    await fs.promises.writeFile(sessionsFile, JSON.stringify(sessions, null, 2), "utf8");
                  }
                  res.statusCode = 204;
                  res.end();
                } catch (err) {
                  res.statusCode = 500;
                  res.end(String(err));
                }
                return;
              }
            } catch (err) {
              res.statusCode = 500;
              res.end(String(err));
              return;
            }

            return next();
          });
        },
      },
    ],
    optimizeDeps: {
      include: ["lit/directives/repeat.js"],
    },
    build: {
      outDir: path.resolve(here, "../dist/control-ui"),
      emptyOutDir: true,
      sourcemap: true,
      // Keep CI/onboard logs clean; current control UI chunking is intentionally above 500 kB.
      chunkSizeWarningLimit: 1024,
    },
    server: {
      host: true,
      port: 5173,
      strictPort: true,
    },
  };
});
