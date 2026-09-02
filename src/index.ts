import type { BetterAuthPlugin } from "better-auth";
import {
  APIError,
  createAuthEndpoint,
  sensitiveSessionMiddleware,
} from "better-auth/api";
import { z } from "zod";

import { computeIdentityDigest } from "./identity-digest";

const identifyBody = z
  .object({
    sessionToken: z.string().trim().min(1).max(8192),
    expectedIdentityDigest: z.string().regex(/^[0-9a-f]{64}$/),
  })
  .strict();

export function switchfrog(
  options: Readonly<{ siteSecretKey: string }>,
): BetterAuthPlugin {
  const siteSecretKey = options.siteSecretKey.trim();
  if (!siteSecretKey.startsWith("sf_sk_") || siteSecretKey.length === 6) {
    throw new TypeError("siteSecretKey must be a Switchfrog Site secret key");
  }

  return {
    id: "switchfrog",
    endpoints: {
      identifySession: createAuthEndpoint(
        "/switchfrog/identify",
        {
          method: "POST",
          body: identifyBody,
          requireHeaders: true,
          use: [sensitiveSessionMiddleware],
        },
        async (ctx) => {
          const { session, user } = ctx.context.session;
          const activeOrganizationId = (
            session as typeof session & { activeOrganizationId?: unknown }
          ).activeOrganizationId;
          const accountId =
            typeof activeOrganizationId === "string" &&
            activeOrganizationId.trim().length > 0
              ? activeOrganizationId
              : null;

          if (accountId !== null) {
            let member: unknown = null;
            try {
              member = await ctx.context.adapter.findOne({
                model: "member",
                where: [
                  { field: "userId", value: user.id },
                  { field: "organizationId", value: accountId },
                ],
              });
            } catch {
              // Membership that cannot be freshly confirmed is not authority.
            }
            if (!member) {
              throw new APIError("FORBIDDEN", {
                message: "Active organization membership could not be confirmed",
              });
            }
          }

          const identityDigest = await computeIdentityDigest(user.id, accountId);
          if (identityDigest !== ctx.body.expectedIdentityDigest) {
            throw APIError.from("PRECONDITION_FAILED", {
              code: "SWITCHFROG_IDENTITY_CHANGED",
              message: "Better Auth identity changed",
            });
          }

          let response: Response;
          try {
            response = await fetch("https://api.switchfrog.com/v1/identify", {
              method: "POST",
              headers: {
                authorization: `Bearer ${siteSecretKey}`,
                "content-type": "application/json",
              },
              body: JSON.stringify({
                sessionToken: ctx.body.sessionToken,
                userId: user.id,
                ...(accountId === null ? {} : { accountId }),
              }),
              redirect: "error",
              signal: AbortSignal.timeout(5000),
            });
          } catch {
            throw new APIError("BAD_GATEWAY", {
              message: "Switchfrog identity association failed",
            });
          }

          const body: unknown = await response.json().catch(() => null);
          if (
            response.status === 409 &&
            typeof body === "object" &&
            body !== null &&
            "error" in body &&
            body.error === "session_reinit_required"
          ) {
            throw APIError.from("CONFLICT", {
              code: "SWITCHFROG_SESSION_REINIT_REQUIRED",
              message: "Switchfrog session reinitialization required",
            });
          }
          if (
            response.status !== 200 ||
            typeof body !== "object" ||
            body === null ||
            !("status" in body) ||
            body.status !== "accepted"
          ) {
            throw new APIError("BAD_GATEWAY", {
              message: "Switchfrog identity association failed",
            });
          }

          return { status: "accepted" as const };
        },
      ),
    },
  } satisfies BetterAuthPlugin;
}
