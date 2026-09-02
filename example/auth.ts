import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";
import type { DatabaseSync } from "node:sqlite";

import { switchfrog } from "@switchfrog/better-auth";

export function createExampleAuth(options: Readonly<{
  baseURL: string;
  betterAuthSecret: string;
  database: DatabaseSync;
  siteSecretKey: string;
}>) {
  return betterAuth({
    basePath: "/api/auth",
    baseURL: options.baseURL,
    database: options.database,
    emailAndPassword: { enabled: true },
    plugins: [organization(), switchfrog({ siteSecretKey: options.siteSecretKey })],
    secret: options.betterAuthSecret,
  });
}
