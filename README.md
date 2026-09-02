# Switchfrog for Better Auth

`@switchfrog/better-auth` automatically starts Switchfrog browser observation and associates an authenticated Better Auth user and active organization with the current Switchfrog session.

The npm package is not published yet. To try the integration now, [run the example](#run-the-example). After publication, install it with:

```sh
pnpm add @switchfrog/better-auth
```

Better Auth >=1.6.29 and <2 is supported.

## Server

Configure the server plugin beside your other Better Auth plugins:

```ts
import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";
import { switchfrog } from "@switchfrog/better-auth";

export const auth = betterAuth({
  plugins: [
    organization(),
    switchfrog({
      siteSecretKey: process.env.SWITCHFROG_SITE_SECRET_KEY!,
    }),
  ],
});
```

`siteSecretKey` is a Site secret key. Keep it on the server and set `SWITCHFROG_SITE_SECRET_KEY` in the server environment.

## Client

Configure the client plugin once:

```ts
import { createAuthClient } from "better-auth/client";
import { organizationClient } from "better-auth/client/plugins";
import { switchfrogClient } from "@switchfrog/better-auth/client";

export const authClient = createAuthClient({
  plugins: [
    organizationClient(),
    switchfrogClient({
      publishableKey: "sf_pk_your_publishable_key",
    }),
  ],
});
```

`publishableKey` is browser-visible and begins with `sf_pk_`.

## Run the example

The runnable [example](./example) uses Better Auth email and password sign-in with organizations.

Clone this repository and open its root:

```sh
git clone https://github.com/switchfrog/switchfrog-better-auth.git
cd switchfrog-better-auth
pnpm install --frozen-lockfile
cp .env.example .env
```

Set the three values, then run `pnpm dev`.

## Verify

Install Chromium, then run the package checks:

```sh
pnpm exec playwright install chromium
pnpm verify
```

## Production canary

**Warning:** This sends synthetic identity and session traffic to production. Run it only against an approved, isolated canary origin.

Set these four gate variables with your approved canary configuration, then run `pnpm smoke:canary`:

- `SWITCHFROG_BETTER_AUTH_CANARY=production`
- `SWITCHFROG_CANARY_ORIGIN`
- `SWITCHFROG_PUBLISHABLE_KEY`
- `SWITCHFROG_SITE_SECRET_KEY`

## Runtime behavior

The client loads `https://api.switchfrog.com/sdk/v1.js` at runtime instead of bundling it. After an error-free initial Better Auth session read, Switchfrog starts observation. An anonymous session stays anonymous until login associates the current Switchfrog session with the authenticated identity.

The client calls `reset()` on logout or when the user or active organization changes or is removed. A normal session refresh does not reset the session.

The browser does not supply identity. The server derives the user and active organization from the authoritative Better Auth session, checks current membership, and then associates the identity. Identity labels Switchfrog telemetry. It does not authorize application actions.

Switchfrog failures do not change Better Auth authentication, session state, redirects, sign-in, sign-out, or organization selection.

## Content security policy

For a restrictive Content Security Policy, allow `https://api.switchfrog.com` in `script-src` and `connect-src`. If you define `script-src-elem`, allow it there too.

## Contributing

This repository is published from Switchfrog's canonical source. [Open an issue](https://github.com/switchfrog/switchfrog-better-auth/issues) to report a bug or ask an installation question. We don't accept pull requests from outside collaborators. Published commits and releases remain permanent public references.
