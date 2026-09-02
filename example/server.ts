import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";

import { getMigrations } from "better-auth/db/migration";
import { toNodeHandler } from "better-auth/node";

import { createExampleAuth } from "./auth.js";

const exampleRoot = dirname(fileURLToPath(import.meta.url));

export async function startExampleServer(options: Readonly<{
  authOrigin?: string;
  betterAuthSecret: string;
  port?: number;
  publishableKey: string;
  siteSecretKey: string;
}>) {
  const database = new DatabaseSync(":memory:");
  let closePromise: Promise<void> | undefined;
  let authHandler: ReturnType<typeof toNodeHandler> | undefined;
  const server = createServer((request, response) => {
    void (async () => {
      try {
        const host = request.headers.host;
        if (!host) throw new Error("Missing host");
        const url = new URL(request.url ?? "/", `http://${host}`);
        if (request.method === "GET" && url.pathname === "/") {
          response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
          response.end(readFileSync(join(exampleRoot, "index.html")));
          return;
        }
        if (request.method === "GET" && url.pathname === "/client.js") {
          response.writeHead(200, {
            "cache-control": "no-store",
            "content-type": "application/javascript; charset=utf-8",
          });
          response.end(readFileSync(join(exampleRoot, "dist", "client.js")));
          return;
        }
        if (request.method === "GET" && url.pathname === "/config.json") {
          response.writeHead(200, { "content-type": "application/json; charset=utf-8" });
          response.end(JSON.stringify({ publishableKey: options.publishableKey }));
          return;
        }
        if (url.pathname.startsWith("/api/auth/")) {
          if (!authHandler) throw new Error("Authentication unavailable");
          await authHandler(request, response);
          return;
        }
        response.writeHead(404).end("Not found");
      } catch {
        response.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
        response.end("Internal server error");
      }
    })();
  });
  const close = () =>
    (closePromise ??= new Promise<void>((resolveClose, rejectClose) => {
      server.close((error) => (error ? rejectClose(error) : resolveClose()));
      server.closeAllConnections();
      database.close();
    }));

  try {
    await new Promise<void>((resolveListen, rejectListen) => {
      server.once("error", rejectListen);
      server.listen(options.port ?? 0, "127.0.0.1", () => {
        server.off("error", rejectListen);
        resolveListen();
      });
    });
    const address = server.address();
    if (typeof address !== "object" || address === null) {
      throw new Error("Loopback listener has no TCP address");
    }
    const origin = `http://127.0.0.1:${address.port}`;
    const authOrigin = options.authOrigin ?? origin;
    const auth = createExampleAuth({
      baseURL: authOrigin,
      betterAuthSecret: options.betterAuthSecret,
      database,
      siteSecretKey: options.siteSecretKey,
    });
    authHandler = toNodeHandler(auth);
    await (await getMigrations(auth.options)).runMigrations();
    return { close, origin };
  } catch (error) {
    await close().catch(() => undefined);
    throw error;
  }
}

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = process.env.PORT === undefined ? 3000 : Number(process.env.PORT);
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    throw new Error("PORT must be a valid TCP port");
  }
  const example = await startExampleServer({
    betterAuthSecret: required("BETTER_AUTH_SECRET"),
    port,
    publishableKey: required("SWITCHFROG_PUBLISHABLE_KEY"),
    siteSecretKey: required("SWITCHFROG_SITE_SECRET_KEY"),
  });
  const stop = () =>
    void example.close().catch(() => {
      process.exitCode = 1;
    });
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  console.log(example.origin);
}
