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

## Optional consent control

See the [consent guide](https://docs.switchfrog.com/guides/consent) for CMP provider recipes.

Set `waitForConsent: true` when your consent management platform (CMP) controls this deployment:

```ts
switchfrogClient({
  publishableKey: "sf_pk_your_publishable_key",
  waitForConsent: true,
});
```

Configure the wait before any installer can start Switchfrog. The adapter loads the hosted script, but does not read its identity cache, hash identity, start collection, or associate a user while held. Better Auth continues its own authentication and session requests.

After the hosted SDK has loaded, use the same client in your CMP bridge:

```ts
const client = window.Switchfrog.init("sf_pk_your_publishable_key");

async function applyCollectionPermission(allowed: boolean) {
  if (allowed) await client.optIn();
  else await client.optOut();
}
```

Install your CMP's continuing change listener and apply its current decision on every page, including a saved decision. Call `applyCollectionPermission` with that decision when the SDK becomes available; reread it after any asynchronous script loading. The omitted init option above reuses the adapter's held client. A saved SDK approval does not release a new page configured with `waitForConsent: true`.

`optOut()` blocks immediately, aborts pending association requests, and clears the adapter's identity cache. `optIn()` starts collection and asks Better Auth to reread the current session. An already signed-in user is associated with the new Switchfrog session without logging in again. Auth results captured during the hold are discarded. `reset()` handles identity changes and does not grant permission.

The SDK remembers withdrawal and coordinates tabs when localStorage works. If storage fails, the current page still enforces its choice in memory, but persistence and deletion across pages cannot be guaranteed. Keep the initial wait and apply your CMP's current decision on every page. The adapter's digest cache is only a synchronization hint; it cannot grant permission or supply identity.

Use the current hosted SDK in every installer. A runtime missing the consent methods must be upgraded and the page reloaded. Omitting `waitForConsent` preserves automatic startup, subject to a saved withdrawal. Explicitly conflicting initialization options throw a setup error. If the script download itself must wait, delay loading the integration through your CMP too.

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

Open `/?consent-demo` to try the optional consent bridge. The permission selector starts with no decision and keeps Switchfrog held. Select **Allow** to start, **Deny or withdraw** to stop, then **Allow** again to reassociate the current signed-in user. This selector demonstrates CMP wiring; it is not a CMP or consent evidence. The ordinary example URL keeps automatic startup.

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
