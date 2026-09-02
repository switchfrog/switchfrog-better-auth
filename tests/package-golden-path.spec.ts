import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  constants,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import test, { type TestContext } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  chromium,
  expect,
  request as playwrightRequest,
  type APIRequestContext,
  type Browser,
  type BrowserContext,
  type Page,
  type Request as PlaywrightRequest,
} from "@playwright/test";

type VerifierConfiguration = Readonly<{
  inputTarball?: string;
  mode: VerificationMode;
  outputTarball?: string;
  version: string;
}>;

type VerificationMode =
  | Readonly<{ kind: "hermetic" }>
  | Readonly<{
      kind: "production";
      origin: string;
      publishableKey: string;
      siteSecretKey: string;
    }>;

type PackageManifest = Readonly<{
  dependencies: Readonly<Record<string, string>>;
  devDependencies: Readonly<Record<string, string>>;
  engines: Readonly<Record<string, string>>;
  packageManager: string;
  peerDependencies: Readonly<Record<string, string>>;
  version: string;
}>;

type NpmPackResult = Readonly<{
  filename: string;
  files: readonly Readonly<{ path: string }>[];
}>;

type VerifiedConsumer = Readonly<{
  consumerRoot: string;
  tarballBytes: Buffer;
}>;

type IdentityCall = Readonly<{
  accountId?: string;
  accepted: boolean;
  authorizationMatches: boolean;
  contentTypeMatches: boolean;
  sessionFingerprint: string;
  status: number;
  userId: string;
}>;

type PendingGate = Readonly<{
  promise: Promise<void>;
  release(): void;
}>;

type LifecycleResources = {
  apiRequestContext?: APIRequestContext;
  browser?: Browser;
  context?: BrowserContext;
  example?: Readonly<{ close(): Promise<void>; origin: string }>;
  pendingGate?: PendingGate;
};

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const packageManifest = JSON.parse(
  readFileSync(join(packageRoot, "package.json"), "utf8"),
) as PackageManifest;
const expectedPackedFiles = [
  "LICENSE",
  "README.md",
  "dist/client.d.ts",
  "dist/client.js",
  "dist/identity-digest.d.ts",
  "dist/identity-digest.js",
  "dist/index.d.ts",
  "dist/index.js",
  "package.json",
] as const;
const expectedPackedArchiveMembers = expectedPackedFiles
  .map((path) => `package/${path}`)
  .sort();
const exampleFiles = [
  "auth.ts",
  "client.ts",
  "index.html",
  "server.ts",
  "tsconfig.json",
  "tsdown.config.mjs",
] as const;
const packageBuildSourceFiles = [
  "LICENSE",
  "README.md",
  "package.json",
  "pnpm-lock.yaml",
  "tsconfig.json",
  "tsdown.config.ts",
  "src/client.ts",
  "src/identity-digest.ts",
  "src/index.ts",
] as const;
const verifierConfiguration = readConfiguration(process.env);

test("ordinary lifecycle events select hermetic mode without reading canary values", () => {
  const canaryNames = new Set([
    "SWITCHFROG_BETTER_AUTH_CANARY",
    "SWITCHFROG_CANARY_ORIGIN",
    "SWITCHFROG_PUBLISHABLE_KEY",
    "SWITCHFROG_SITE_SECRET_KEY",
  ]);

  for (const lifecycleEvent of [undefined, "verify", "verify:package", "test"]) {
    const environment = new Proxy<NodeJS.ProcessEnv>(
      { npm_lifecycle_event: lifecycleEvent },
      {
        get(target, property, receiver) {
          if (typeof property === "string" && canaryNames.has(property)) {
            throw new Error("ordinary verification read a canary value");
          }
          return Reflect.get(target, property, receiver) as string | undefined;
        },
      },
    );

    assert.deepEqual(readConfiguration(environment).mode, { kind: "hermetic" });
  }
});

test("production canary mode requires exact opaque configuration", () => {
  const validEnvironment = {
    npm_lifecycle_event: "smoke:canary",
    SWITCHFROG_BETTER_AUTH_CANARY: "production",
    SWITCHFROG_CANARY_ORIGIN: "https://canary.example",
    SWITCHFROG_PUBLISHABLE_KEY: "sf_pk_liveABC123",
    SWITCHFROG_SITE_SECRET_KEY: "sf_sk_liveXYZ789",
  } satisfies NodeJS.ProcessEnv;
  assert.deepEqual(readConfiguration(validEnvironment).mode, {
    kind: "production",
    origin: "https://canary.example",
    publishableKey: "sf_pk_liveABC123",
    siteSecretKey: "sf_sk_liveXYZ789",
  });

  const invalidValues = [
    ["SWITCHFROG_BETTER_AUTH_CANARY", ""],
    ["SWITCHFROG_BETTER_AUTH_CANARY", "production "],
    ["SWITCHFROG_BETTER_AUTH_CANARY", "Production"],
    ["SWITCHFROG_CANARY_ORIGIN", " https://canary.example"],
    ["SWITCHFROG_CANARY_ORIGIN", "https://one.example\nhttps://two.example"],
    ["SWITCHFROG_CANARY_ORIGIN", "http://canary.example"],
    ["SWITCHFROG_CANARY_ORIGIN", "https://user:password@canary.example"],
    ["SWITCHFROG_CANARY_ORIGIN", "https://canary.example/path"],
    ["SWITCHFROG_CANARY_ORIGIN", "https://canary.example?query=true"],
    ["SWITCHFROG_CANARY_ORIGIN", "https://canary.example#fragment"],
    ["SWITCHFROG_CANARY_ORIGIN", "https://api.switchfrog.com"],
    ["SWITCHFROG_CANARY_ORIGIN", "https://api.switchfrog.com."],
    ["SWITCHFROG_CANARY_ORIGIN", "https://api.switchfrog.com..."],
    ["SWITCHFROG_PUBLISHABLE_KEY", ""],
    ["SWITCHFROG_PUBLISHABLE_KEY", " sf_pk_liveABC123"],
    ["SWITCHFROG_PUBLISHABLE_KEY", "sf_pk_liveABC123\nextra"],
    ["SWITCHFROG_PUBLISHABLE_KEY", "sf_pk_replace_me"],
    ["SWITCHFROG_PUBLISHABLE_KEY", "sf_pk_..."],
    ["SWITCHFROG_PUBLISHABLE_KEY", "sf_sk_liveABC123"],
    ["SWITCHFROG_SITE_SECRET_KEY", ""],
    ["SWITCHFROG_SITE_SECRET_KEY", " sf_sk_liveXYZ789"],
    ["SWITCHFROG_SITE_SECRET_KEY", "sf_sk_liveXYZ789\nextra"],
    ["SWITCHFROG_SITE_SECRET_KEY", "sf_sk_replace_me"],
    ["SWITCHFROG_SITE_SECRET_KEY", "sf_sk_..."],
    ["SWITCHFROG_SITE_SECRET_KEY", "sf_pk_liveXYZ789"],
  ] as const;

  for (const [name, suppliedValue] of invalidValues) {
    const invalidEnvironment = { ...validEnvironment, [name]: suppliedValue };
    assert.throws(
      () => readConfiguration(invalidEnvironment),
      (error) => {
        assert.ok(error instanceof Error);
        for (const value of Object.values(invalidEnvironment)) {
          if (value && value !== "smoke:canary") {
            assert.equal(error.message.includes(value), false);
          }
        }
        return true;
      },
      name,
    );
  }
});

test("server fetch never falls through for unexpected Switchfrog URLs", async () => {
  const modes: readonly VerificationMode[] = [
    { kind: "hermetic" },
    {
      kind: "production",
      origin: "https://canary.example",
      publishableKey: "sf_pk_liveABC123",
      siteSecretKey: "sf_sk_liveXYZ789",
    },
  ];

  for (const mode of modes) {
    let originalFetchReached = false;
    const fetcher = createServerFetch(
      mode,
      (async () => {
        originalFetchReached = true;
        return new Response();
      }) as typeof fetch,
      [],
    );

    await assert.rejects(
      fetcher("https://api.switchfrog.com/v1/unexpected"),
      /unexpected Switchfrog server request/,
    );
    assert.equal(originalFetchReached, false);
  }
});

test(
  "HTTPS bridge preserves cookies, aborts unknown paths, and delays stale identify",
  { timeout: 30_000 },
  async (context) => {
    let sessionCookieReachedLoopback = false;
    let identifyReachedLoopback = false;
    let unknownReachedLoopback = false;
    let server: ReturnType<typeof createServer> | undefined;
    let browser: Browser | undefined;
    let browserContext: BrowserContext | undefined;
    let requestContext: APIRequestContext | undefined;
    const gate = createPendingGate();
    const cleanupErrors: unknown[] = [];
    context.after(async () => {
      await cleanup(cleanupErrors, () => gate.release());
      await cleanup(cleanupErrors, () =>
        browserContext?.unrouteAll({ behavior: "wait" }),
      );
      await cleanup(cleanupErrors, () => requestContext?.dispose());
      await cleanup(cleanupErrors, () => browserContext?.close());
      await cleanup(cleanupErrors, () => browser?.close());
      await cleanup(cleanupErrors, () => {
        const activeServer = server;
        return activeServer?.listening
          ? activeServer[Symbol.asyncDispose]()
          : undefined;
      });
      finishVerification({ kind: "hermetic" }, undefined, cleanupErrors);
    });

    server = createServer((request, response) => {
      request.resume();
      if (request.method === "GET" && request.url === "/") {
        response.writeHead(200, { "content-type": "text/html" }).end("bridge");
        return;
      }
      if (request.method === "POST" && request.url === "/api/auth/sign-up/email") {
        response
          .writeHead(200, {
            "content-type": "application/json",
            "set-cookie":
              "better-auth.session_token=bridge-session; Path=/; HttpOnly; Secure; SameSite=Lax",
          })
          .end("{}");
        return;
      }
      if (request.method === "GET" && request.url === "/api/auth/get-session") {
        sessionCookieReachedLoopback =
          request.headers.cookie?.includes(
            "better-auth.session_token=bridge-session",
          ) === true;
        response
          .writeHead(200, { "content-type": "application/json" })
          .end("{}");
        return;
      }
      if (
        request.method === "POST" &&
        request.url === "/api/auth/switchfrog/identify"
      ) {
        identifyReachedLoopback = true;
        response.writeHead(412).end();
        return;
      }
      unknownReachedLoopback = true;
      response.writeHead(404).end();
    });
    const bridgeServer = server;
    await new Promise<void>((resolveListen, rejectListen) => {
      bridgeServer.once("error", rejectListen);
      bridgeServer.listen(0, "127.0.0.1", resolveListen);
    });
    const address = bridgeServer.address();
    assert.ok(typeof address === "object" && address !== null);
    const loopbackOrigin = `http://127.0.0.1:${address.port}`;
    browser = await chromium.launch();
    const activeBrowser = browser;
    browserContext = await activeBrowser.newContext({ serviceWorkers: "block" });
    const activeBrowserContext = browserContext;
    requestContext = await playwrightRequest.newContext();
    const activeRequestContext = requestContext;
    const gatedStatuses: number[] = [];
    let identifyWasGated = false;

    await installCanaryBridge(
      activeBrowserContext,
      activeRequestContext,
      "https://canary.example",
      loopbackOrigin,
      (request) => {
        if (
          new URL(request.url()).pathname ===
          "/api/auth/switchfrog/identify"
        ) {
          identifyWasGated = true;
          return true;
        }
        return false;
      },
      gate,
      gatedStatuses,
    );
    const page = await activeBrowserContext.newPage();
    await page.goto("https://canary.example");
    assert.equal(
      await page.evaluate(async () =>
        (
          await fetch("/api/auth/sign-up/email", {
            body: "{}",
            headers: { "content-type": "application/json" },
            method: "POST",
          })
        ).ok,
      ),
      true,
    );
    assert.equal(
      (await activeBrowserContext.cookies("https://canary.example")).some(
        (cookie) => cookie.name === "better-auth.session_token",
      ),
      true,
      "bridge response did not set the browser cookie",
    );
    await page.evaluate(() => fetch("/api/auth/get-session"));
    assert.equal(sessionCookieReachedLoopback, true);
    assert.equal(
      await page.evaluate(() =>
        fetch("/unknown").then(
          () => false,
          () => true,
        ),
      ),
      true,
    );
    assert.equal(unknownReachedLoopback, false);

    const identify = page.evaluate(() =>
      fetch("/api/auth/switchfrog/identify", {
        body: "{}",
        headers: { "content-type": "application/json" },
        method: "POST",
      }).then((response) => response.status),
    );
    await waitForCondition(() => identifyWasGated, "bridge identify gate");
    assert.equal(identifyReachedLoopback, false);
    gate.release();
    assert.equal(await identify, 412);
    assert.equal(identifyReachedLoopback, true);
    assert.deepEqual(gatedStatuses, [412]);
  },
);

test("rejects a relative input tarball path", () => {
  assert.throws(
    () =>
      readConfiguration({
        SWITCHFROG_BETTER_AUTH_INPUT_TARBALL: "package.tgz",
      }),
    /INPUT_TARBALL must be absolute/,
  );
});

test("rejects a relative output tarball path", () => {
  assert.throws(
    () =>
      readConfiguration({
        SWITCHFROG_BETTER_AUTH_OUTPUT_TARBALL: "package.tgz",
      }),
    /OUTPUT_TARBALL must be absolute/,
  );
});

test("rejects one path as both input and output", () => {
  const tarball = join(tmpdir(), "switchfrog-better-auth-input.tgz");

  assert.throws(
    () =>
      readConfiguration({
        SWITCHFROG_BETTER_AUTH_INPUT_TARBALL: tarball,
        SWITCHFROG_BETTER_AUTH_OUTPUT_TARBALL: tarball,
      }),
    /input and output tarballs must differ/,
  );
});

test("rejects cleanup outside an owned verifier root", () => {
  assert.throws(
    () => assertOwnedTempRoot(tmpdir()),
    /refusing to remove an unowned temporary path/,
  );
});

test("cleanup records each failure without skipping later steps", async () => {
  const calls: string[] = [];
  const errors: unknown[] = [];

  await cleanup(errors, async () => {
    calls.push("first");
    throw new Error("first cleanup failed");
  });
  await cleanup(errors, async () => {
    calls.push("second");
    throw new Error("second cleanup failed");
  });
  await cleanup(errors, () => {
    calls.push("third");
  });

  assert.deepEqual(calls, ["first", "second", "third"]);
  assert.deepEqual(
    errors.map((error) => (error as Error).message),
    ["first cleanup failed", "second cleanup failed"],
  );
});

test("a cleanup failure never masks the primary verifier failure", () => {
  const primaryFailure = new Error("primary failure");

  assert.throws(
    () =>
      finishVerification(
        { kind: "hermetic" },
        primaryFailure,
        [new Error("cleanup failure")],
      ),
    (error) => error === primaryFailure,
  );
});

test("cleanup-only failures are reported together", () => {
  const cleanupErrors = [new Error("first"), new Error("second")];

  assert.throws(
    () => finishVerification({ kind: "hermetic" }, undefined, cleanupErrors),
    (error) =>
      error instanceof AggregateError &&
      error.message === "package verifier cleanup failed" &&
      error.errors[0] === cleanupErrors[0] &&
      error.errors[1] === cleanupErrors[1],
  );
});

test("production verifier failures are opaque", async (context) => {
  const mode: VerificationMode = {
    kind: "production",
    origin: "https://private-canary.example",
    publishableKey: "sf_pk_private",
    siteSecretKey: "sf_sk_private",
  };
  const privateTarball = join(tmpdir(), "private-canary-package.tgz");

  await assert.rejects(
    verifyPackedPackage(context, {
      inputTarball: privateTarball,
      mode,
      version: packageManifest.devDependencies["better-auth"]!,
    }),
    (error) => {
      assert.ok(error instanceof Error);
      assert.equal(error.message, "production canary failed");
      assert.equal(error.cause, undefined);
      assert.equal(String(error).includes(mode.origin), false);
      assert.equal(String(error).includes(privateTarball), false);
      return true;
    },
  );

  assert.throws(
    () =>
      finishVerification(mode, undefined, [new Error("private cleanup")]),
    (error) => {
      assert.ok(error instanceof Error);
      assert.equal(error.message, "production canary failed");
      assert.equal(error.cause, undefined);
      return true;
    },
  );
});

test("production output failures are opaque", () => {
  const mode: VerificationMode = {
    kind: "production",
    origin: "https://private-canary.example",
    publishableKey: "sf_pk_private",
    siteSecretKey: "sf_sk_private",
  };

  assert.throws(
    () =>
      finishVerification(mode, undefined, [], {
        bytes: Buffer.from("private archive"),
        path: packageRoot,
      }),
    (error) => {
      assert.ok(error instanceof Error);
      assert.equal(error.message, "production canary failed");
      assert.equal(error.cause, undefined);
      assert.equal(String(error).includes(packageRoot), false);
      assert.equal(String(error).includes("EEXIST"), false);
      return true;
    },
  );
});

test("production observer consumes only one expected stale 412 resource error", () => {
  const listeners = new Map<string, (event: unknown) => void>();
  const page = {
    on(event: string, listener: (value: unknown) => void) {
      listeners.set(event, listener);
      return this;
    },
  } as unknown as Page;
  const errors: string[] = [];
  const gatedStatuses = [412];
  const expectedStaleUrl =
    "https://private-canary.example/api/auth/switchfrog/identify";
  const staleResourceError = (url: string) => ({
    location: () => ({ url }),
    text: () =>
      "Failed to load resource: the server responded with a status of 412 (Precondition Failed)",
    type: () => "error",
  });

  observePage(page, errors, true, gatedStatuses, expectedStaleUrl);
  listeners.get("console")!(
    staleResourceError("https://private-canary.example/unrelated"),
  );
  listeners.get("console")!(staleResourceError(expectedStaleUrl));
  listeners.get("console")!(staleResourceError(expectedStaleUrl));
  listeners.get("pageerror")!(new Error("unexpected page error"));
  assert.deepEqual(errors, [
    "browser console error",
    "browser console error",
    "browser page error",
  ]);
});

test("parses npm pack JSON after lifecycle output", () => {
  assert.deepEqual(
    parseNpmPackOutput(
      '> @switchfrog/better-auth@0.1.0 prepack\n> pnpm build\n[{"filename":"package.tgz","files":[]}]\n',
    ),
    [{ filename: "package.tgz", files: [] }],
  );
});

test("rejects extra and duplicate package archive members before extraction", () => {
  const tempRoot = mkdtempSync(join(tmpdir(), "switchfrog-better-auth-"));
  const fixtureRoot = join(tempRoot, "archive-fixture");
  const packageFixtureRoot = join(fixtureRoot, "package");

  try {
    for (const path of expectedPackedFiles) {
      const filePath = join(packageFixtureRoot, path);
      mkdirSync(dirname(filePath), { recursive: true });
      writeFileSync(filePath, path);
    }
    writeFileSync(join(fixtureRoot, "unexpected.txt"), "unexpected");

    const extraMemberTarball = createTestTarball(
      tempRoot,
      fixtureRoot,
      "extra-member.tgz",
      [...expectedPackedArchiveMembers, "unexpected.txt"],
    );
    assert.throws(
      () => extractPackedPackage(tempRoot, extraMemberTarball),
      /package archive inventory must be exact/,
    );
    assert.equal(existsSync(join(tempRoot, "extracted")), false);

    const duplicateMemberTarball = createTestTarball(
      tempRoot,
      fixtureRoot,
      "duplicate-member.tgz",
      [...expectedPackedArchiveMembers, expectedPackedArchiveMembers[0]!],
    );
    assert.throws(
      () => extractPackedPackage(tempRoot, duplicateMemberTarball),
      /package archive inventory must be exact/,
    );
    assert.equal(existsSync(join(tempRoot, "extracted")), false);
  } finally {
    assertOwnedTempRoot(tempRoot);
    rmSync(tempRoot, { force: true, recursive: true });
  }
});

test("shared store discovery preserves PNPM_HOME without forwarding credentials", () => {
  const tempRoot = mkdtempSync(join(tmpdir(), "switchfrog-better-auth-"));
  const previousHome = process.env.PNPM_HOME;
  const previousToken = process.env.NODE_AUTH_TOKEN;
  try {
    writeFileSync(
      join(tempRoot, "package.json"),
      JSON.stringify({ packageManager: packageManifest.packageManager }),
    );
    process.env.PNPM_HOME = join(tempRoot, "pnpm");
    process.env.NODE_AUTH_TOKEN = "sentinel-not-a-credential";
    assert.equal(findSharedStore(tempRoot), join(tempRoot, "pnpm", "store", "v10"));
    assert.equal(safeEnvironment(tempRoot).NODE_AUTH_TOKEN, undefined);
  } finally {
    if (previousHome === undefined) delete process.env.PNPM_HOME;
    else process.env.PNPM_HOME = previousHome;
    if (previousToken === undefined) delete process.env.NODE_AUTH_TOKEN;
    else process.env.NODE_AUTH_TOKEN = previousToken;
    assertOwnedTempRoot(tempRoot);
    rmSync(tempRoot, { force: true, recursive: true });
  }
});

test("pack source copying excludes sentinel npm configuration", () => {
  const tempRoot = mkdtempSync(join(tmpdir(), "switchfrog-better-auth-"));
  const sourceRoot = join(tempRoot, "source");
  const destinationRoot = join(tempRoot, "destination");
  try {
    for (const path of packageBuildSourceFiles) {
      const sourcePath = join(sourceRoot, path);
      mkdirSync(dirname(sourcePath), { recursive: true });
      writeFileSync(sourcePath, path);
    }
    writeFileSync(join(sourceRoot, ".env"), "sentinel");
    writeFileSync(join(sourceRoot, ".npmrc"), "sentinel");

    copyRegularFiles(sourceRoot, destinationRoot, packageBuildSourceFiles);

    assert.equal(existsSync(join(destinationRoot, ".env")), false);
    assert.equal(existsSync(join(destinationRoot, ".npmrc")), false);
  } finally {
    assertOwnedTempRoot(tempRoot);
    rmSync(tempRoot, { force: true, recursive: true });
  }
});

test(
  "verifies the packed package through its Chromium lifecycle",
  { timeout: 240_000 },
  async (context) => {
    await verifyPackedPackage(context, verifierConfiguration);
  },
);

function createTestTarball(
  tempRoot: string,
  fixtureRoot: string,
  filename: string,
  members: readonly string[],
): string {
  const tarballPath = join(tempRoot, filename);
  runCommand(
    "tar",
    ["-czf", tarballPath, "-C", fixtureRoot, ...members],
    tempRoot,
  );
  return tarballPath;
}

function readConfiguration(
  environment: NodeJS.ProcessEnv,
): VerifierConfiguration {
  const mode = readVerificationMode(environment);
  const inputTarball = environment.SWITCHFROG_BETTER_AUTH_INPUT_TARBALL;
  const outputTarball = environment.SWITCHFROG_BETTER_AUTH_OUTPUT_TARBALL;
  if (inputTarball !== undefined && !isAbsolute(inputTarball)) {
    throw new TypeError("SWITCHFROG_BETTER_AUTH_INPUT_TARBALL must be absolute");
  }
  if (outputTarball !== undefined && !isAbsolute(outputTarball)) {
    throw new TypeError("SWITCHFROG_BETTER_AUTH_OUTPUT_TARBALL must be absolute");
  }
  if (
    inputTarball !== undefined &&
    outputTarball !== undefined &&
    resolve(inputTarball) === resolve(outputTarball)
  ) {
    throw new TypeError("input and output tarballs must differ");
  }

  return {
    ...(inputTarball === undefined ? {} : { inputTarball }),
    mode,
    ...(outputTarball === undefined ? {} : { outputTarball }),
    version:
      environment.SWITCHFROG_BETTER_AUTH_TEST_VERSION ??
      packageManifest.devDependencies["better-auth"]!,
  };
}

function readVerificationMode(
  environment: NodeJS.ProcessEnv,
): VerificationMode {
  if (environment.npm_lifecycle_event !== "smoke:canary") {
    return { kind: "hermetic" };
  }
  if (environment.SWITCHFROG_BETTER_AUTH_CANARY !== "production") {
    throw new TypeError("canary acknowledgment is required");
  }

  const origin = environment.SWITCHFROG_CANARY_ORIGIN;
  let parsedOrigin: URL;
  try {
    parsedOrigin = new URL(origin ?? "");
  } catch {
    throw new TypeError("canary origin is invalid");
  }
  if (
    origin !== parsedOrigin.origin ||
    parsedOrigin.protocol !== "https:"
  ) {
    throw new TypeError("canary origin is invalid");
  }
  if (parsedOrigin.hostname.replace(/\.+$/u, "") === "api.switchfrog.com") {
    throw new TypeError("canary origin is forbidden");
  }

  const publishableKey = environment.SWITCHFROG_PUBLISHABLE_KEY;
  if (!isCanaryKey(publishableKey, "sf_pk_")) {
    throw new TypeError("canary publishable key is invalid");
  }
  const siteSecretKey = environment.SWITCHFROG_SITE_SECRET_KEY;
  if (!isCanaryKey(siteSecretKey, "sf_sk_")) {
    throw new TypeError("canary Site secret key is invalid");
  }

  return {
    kind: "production",
    origin,
    publishableKey,
    siteSecretKey,
  };
}

function isCanaryKey(
  value: string | undefined,
  prefix: "sf_pk_" | "sf_sk_",
): value is string {
  if (
    value === undefined ||
    !new RegExp(`^${prefix}[A-Za-z0-9_-]+$`).test(value)
  ) {
    return false;
  }
  return ![
    "placeholder",
    "replace_me",
    "your_publishable_key",
    "your_site_secret_key",
  ].includes(value.slice(prefix.length).toLowerCase());
}

function createServerFetch(
  mode: VerificationMode,
  originalFetch: typeof fetch,
  calls: IdentityCall[],
): typeof fetch {
  return async (input, init) => {
    const url = new URL(
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url,
    );
    if (url.origin !== "https://api.switchfrog.com") {
      return originalFetch(input, init);
    }
    if (url.pathname !== "/v1/identify" || url.search !== "") {
      throw new Error("unexpected Switchfrog server request");
    }

    const body = JSON.parse(String(init?.body)) as Readonly<{
      accountId?: string;
      sessionToken: string;
      userId: string;
    }>;
    const headers = new Headers(init?.headers);
    const observation = {
      ...(body.accountId === undefined ? {} : { accountId: body.accountId }),
      authorizationMatches:
        headers.get("authorization") ===
        `Bearer ${mode.kind === "production" ? mode.siteSecretKey : "sf_sk_test"}`,
      contentTypeMatches: headers.get("content-type") === "application/json",
      sessionFingerprint: fingerprintToken(body.sessionToken),
      userId: body.userId,
    };
    if (mode.kind === "hermetic") {
      calls.push({ ...observation, accepted: true, status: 200 });
      return Response.json({ status: "accepted" });
    }

    const response = await originalFetch(input, init);
    let accepted = false;
    try {
      const result = (await response.clone().json()) as { status?: unknown };
      accepted = result.status === "accepted";
    } catch {
      accepted = false;
    }
    calls.push({
      ...observation,
      accepted,
      status: response.status,
    });
    return response;
  };
}

function fingerprintToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

const bridgedRequestMethods = new Map([
  ["/", "GET"],
  ["/client.js", "GET"],
  ["/config.json", "GET"],
  ["/api/auth/get-session", "GET"],
  ["/api/auth/sign-up/email", "POST"],
  ["/api/auth/sign-in/email", "POST"],
  ["/api/auth/sign-out", "POST"],
  ["/api/auth/organization/create", "POST"],
  ["/api/auth/organization/set-active", "POST"],
  ["/api/auth/switchfrog/identify", "POST"],
]);
const droppedBridgeHeaders = new Set([
  "connection",
  "content-length",
  "host",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

async function installCanaryBridge(
  browserContext: BrowserContext,
  requestContext: APIRequestContext,
  canaryOrigin: string,
  loopbackOrigin: string,
  shouldGate: (request: PlaywrightRequest) => boolean,
  gate: PendingGate,
  gatedStatuses: number[],
): Promise<void> {
  await browserContext.route(
    (url) => url.origin === canaryOrigin,
    async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      if (bridgedRequestMethods.get(url.pathname) !== request.method()) {
        await route.abort("blockedbyclient");
        return;
      }
      const gated =
        url.pathname === "/api/auth/switchfrog/identify" &&
        shouldGate(request);
      if (gated) await gate.promise;

      const headers: Record<string, string> = {};
      for (const header of await request.headersArray()) {
        if (!droppedBridgeHeaders.has(header.name.toLowerCase())) {
          headers[header.name] = header.value;
        }
      }
      const body = request.postDataBuffer();
      const response = await requestContext.fetch(
        new URL(`${url.pathname}${url.search}`, loopbackOrigin).href,
        {
          ...(body === null ? {} : { data: body }),
          headers,
          maxRedirects: 0,
          method: request.method(),
        },
      );
      if (gated) gatedStatuses.push(response.status());
      await route.fulfill({ response });
    },
  );
}

function assertOwnedTempRoot(root: string): void {
  const absoluteRoot = resolve(root);
  if (
    dirname(absoluteRoot) !== resolve(tmpdir()) ||
    !basename(absoluteRoot).startsWith("switchfrog-better-auth-")
  ) {
    throw new TypeError("refusing to remove an unowned temporary path");
  }
}

async function cleanup(
  errors: unknown[],
  operation: () => Promise<void> | void,
): Promise<void> {
  try {
    await operation();
  } catch (error) {
    errors.push(error);
  }
}

function finishVerification(
  mode: VerificationMode,
  primaryFailure: unknown,
  cleanupErrors: readonly unknown[],
  output?: Readonly<{ bytes: Buffer; path: string }>,
): void {
  try {
    if (primaryFailure !== undefined) throw primaryFailure;
    if (cleanupErrors.length > 0) {
      throw new AggregateError(cleanupErrors, "package verifier cleanup failed");
    }
    if (output !== undefined) {
      writeFileSync(output.path, output.bytes, { flag: "wx" });
    }
  } catch (error) {
    if (mode.kind === "production") throw new Error("production canary failed");
    throw error;
  }
}

async function verifyPackedPackage(
  context: TestContext,
  configuration: VerifierConfiguration,
): Promise<void> {
  const tempRoot = mkdtempSync(join(tmpdir(), "switchfrog-better-auth-"));
  const cleanupErrors: unknown[] = [];
  const resources: LifecycleResources = {};
  const originalFetch = globalThis.fetch;
  let primaryFailure: unknown;
  let verified: VerifiedConsumer | undefined;
  let verifiedPort: number | undefined;

  try {
    verified = prepareVerifiedConsumer(tempRoot, configuration);
    verifiedPort = await verifyChromiumLifecycle(
      context,
      verified,
      resources,
      configuration.mode,
      originalFetch,
    );
  } catch (error) {
    primaryFailure = error;
  } finally {
    await cleanup(cleanupErrors, () => resources.pendingGate?.release());
    await cleanup(cleanupErrors, () =>
      resources.context?.unrouteAll({ behavior: "wait" }),
    );
    await cleanup(cleanupErrors, () => resources.apiRequestContext?.dispose());
    await cleanup(cleanupErrors, () => resources.context?.close());
    await cleanup(cleanupErrors, () => resources.browser?.close());
    await cleanup(cleanupErrors, () => resources.example?.close());
    globalThis.fetch = originalFetch;
    await cleanup(cleanupErrors, () => {
      assertOwnedTempRoot(tempRoot);
      rmSync(tempRoot, { force: true, recursive: true });
    });
  }

  if (primaryFailure !== undefined) {
    for (const error of cleanupErrors) {
      context.diagnostic(
        configuration.mode.kind === "production"
          ? "production canary cleanup failed"
          : `cleanup error: ${String(error)}`,
      );
    }
  }
  finishVerification(
    configuration.mode,
    primaryFailure,
    cleanupErrors,
    configuration.outputTarball === undefined || verified === undefined
      ? undefined
      : { bytes: verified.tarballBytes, path: configuration.outputTarball },
  );
  assert.equal(existsSync(tempRoot), false);
  assert.ok(verified);
  assert.ok(verifiedPort);
  context.diagnostic(
    configuration.mode.kind === "production"
      ? "production canary cleanup passed"
      : `verified ephemeral port ${verifiedPort}; removed ${tempRoot}`,
  );
}

function prepareVerifiedConsumer(
  tempRoot: string,
  configuration: VerifierConfiguration,
): VerifiedConsumer {
  writeFileSync(
    join(tempRoot, "package.json"),
    `${JSON.stringify({ packageManager: packageManifest.packageManager })}\n`,
  );
  const defaultVersion = packageManifest.devDependencies["better-auth"]!;
  const sharedStore = findSharedStore(tempRoot);
  const tarballPath = configuration.inputTarball
    ? copyInputTarball(tempRoot, configuration.inputTarball)
    : packLocalPackage(tempRoot, sharedStore);
  const tarballBytes = readFileSync(tarballPath);
  const extractedPackageRoot = extractPackedPackage(tempRoot, tarballPath);
  const extractedManifest = JSON.parse(
    readFileSync(join(extractedPackageRoot, "package.json"), "utf8"),
  ) as { exports?: Record<string, unknown> };
  assert.deepEqual(Object.keys(extractedManifest.exports ?? {}).sort(), [
    ".",
    "./client",
  ]);

  runCommand(
    join(packageRoot, "node_modules", ".bin", "publint"),
    ["run", extractedPackageRoot, "--strict", "--pack", "false"],
    tempRoot,
  );

  const consumerRoot = join(tempRoot, "consumer");
  mkdirSync(consumerRoot);
  writeFileSync(
    join(consumerRoot, "package.json"),
    `${JSON.stringify(
      {
        private: true,
        type: "module",
        packageManager: packageManifest.packageManager,
      dependencies: {
        "@switchfrog/better-auth": `file:${tarballPath}`,
        "better-auth": configuration.version,
      },
      devDependencies: {
        "@types/node": packageManifest.devDependencies["@types/node"],
      },
      },
      null,
      2,
    )}\n`,
  );
  if (configuration.version === defaultVersion) {
    writeConsumerLockfile(consumerRoot, tarballPath, configuration.version);
  }
  const installArguments = [
    "install",
    "--store-dir",
    configuration.version === defaultVersion
      ? sharedStore
      : join(tempRoot, "release-store"),
    "--virtual-store-dir",
    join(consumerRoot, "node_modules", ".pnpm"),
  ];
  installArguments.push(
    configuration.version === defaultVersion
      ? "--frozen-lockfile"
      : "--no-frozen-lockfile",
  );
  if (configuration.version === defaultVersion) installArguments.push("--offline");
  runCommand(
    "pnpm",
    installArguments,
    consumerRoot,
    { CI: "true" },
  );

  copyRegularFiles(join(packageRoot, "example"), join(consumerRoot, "example"), exampleFiles);
  assertInstalledPackagePaths(consumerRoot);
  verifyConsumerTypes(consumerRoot);
  bundleBrowserEntry(consumerRoot);

  return {
    consumerRoot,
    tarballBytes,
  };
}

function extractPackedPackage(tempRoot: string, tarballPath: string): string {
  const archiveMembers = runCommand(
    "tar",
    ["-tzf", tarballPath],
    tempRoot,
  )
    .split(/\r?\n/)
    .filter(Boolean)
    .sort();
  assert.deepEqual(
    archiveMembers,
    expectedPackedArchiveMembers,
    "package archive inventory must be exact",
  );
  const extractedRoot = join(tempRoot, "extracted");
  mkdirSync(extractedRoot);
  runCommand(
    "tar",
    ["-xzf", tarballPath, "-C", extractedRoot],
    tempRoot,
  );
  const extractedPackageRoot = join(extractedRoot, "package");
  assert.deepEqual(packageFiles(extractedPackageRoot), expectedPackedFiles);
  return extractedPackageRoot;
}

async function verifyChromiumLifecycle(
  context: TestContext,
  verified: VerifiedConsumer,
  resources: LifecycleResources,
  mode: VerificationMode,
  originalFetch: typeof fetch,
): Promise<number> {
  const upstreamCalls: IdentityCall[] = [];
  globalThis.fetch = createServerFetch(mode, originalFetch, upstreamCalls);

  const examplePath = join(verified.consumerRoot, "example", "server.ts");
  assertPathWithin(verified.consumerRoot, examplePath);
  const exampleModule = await import(pathToFileURL(examplePath).href) as {
    startExampleServer?: unknown;
  };
  assert.equal(typeof exampleModule.startExampleServer, "function");
  resources.example = await (
    exampleModule.startExampleServer as (options: Readonly<{
      authOrigin?: string;
      betterAuthSecret: string;
      port: number;
      publishableKey: string;
      siteSecretKey: string;
    }>) => Promise<Readonly<{ close(): Promise<void>; origin: string }>>
  )({
    ...(mode.kind === "production" ? { authOrigin: mode.origin } : {}),
    betterAuthSecret: randomBytes(32).toString("base64url"),
    port: 0,
    publishableKey:
      mode.kind === "production" ? mode.publishableKey : "sf_pk_test",
    siteSecretKey:
      mode.kind === "production" ? mode.siteSecretKey : "sf_sk_test",
  });
  const loopbackOrigin = resources.example.origin;
  const pageOrigin = mode.kind === "production" ? mode.origin : loopbackOrigin;
  const port = Number(new URL(loopbackOrigin).port);
  assert.ok(Number.isInteger(port) && port > 0);

  const browser = await chromium.launch();
  resources.browser = browser;
  const browserContext = await browser.newContext({ serviceWorkers: "block" });
  resources.context = browserContext;
  const sdkStatuses: number[] = [];
  let gatedPage: Page | undefined;
  browserContext.on("response", (response) => {
    if (response.url() === "https://api.switchfrog.com/sdk/v1.js") {
      sdkStatuses.push(response.status());
    }
  });
  let usedGate = false;
  const gate = createPendingGate();
  resources.pendingGate = gate;
  const gatedStatuses: number[] = [];
  if (mode.kind === "hermetic") {
    await browserContext.route("https://api.switchfrog.com/**", (route) => {
      const request = route.request();
      const url = new URL(request.url());
      if (
        request.method() === "GET" &&
        url.pathname === "/sdk/v1.js" &&
        url.search === ""
      ) {
        return route.fulfill({
          body: hostedSdkStub,
          contentType: "application/javascript",
          status: 200,
        });
      }
      return route.abort("blockedbyclient");
    });
    await browserContext.route(
      `${loopbackOrigin}/api/auth/switchfrog/identify`,
      async (route) => {
        if (
          !usedGate &&
          gatedPage !== undefined &&
          route.request().frame().page() === gatedPage
        ) {
          usedGate = true;
          await gate.promise;
          const response = await route.fetch();
          gatedStatuses.push(response.status());
          await route.fulfill({ response });
          return;
        }
        await route.continue();
      },
    );
  } else {
    resources.apiRequestContext = await playwrightRequest.newContext();
    await installCanaryBridge(
      browserContext,
      resources.apiRequestContext,
      mode.origin,
      loopbackOrigin,
      (request) => {
        if (
          !usedGate &&
          gatedPage !== undefined &&
          request.frame().page() === gatedPage
        ) {
          usedGate = true;
          return true;
        }
        return false;
      },
      gate,
      gatedStatuses,
    );
  }

  const runId =
    mode.kind === "production" ? randomBytes(12).toString("hex") : "package";
  const email =
    mode.kind === "production"
      ? `switchfrog-canary-${runId}@example.invalid`
      : "test@example.com";
  const password =
    mode.kind === "production"
      ? randomBytes(24).toString("base64url")
      : "password123";
  const organizationAName =
    mode.kind === "production" ? `Canary A ${runId}` : "Organization A";
  const organizationASlug =
    mode.kind === "production" ? `canary-a-${runId}` : "organization-a";
  const organizationBName =
    mode.kind === "production" ? `Canary B ${runId}` : "Organization B";
  const organizationBSlug =
    mode.kind === "production" ? `canary-b-${runId}` : "organization-b";

  const pageA = await browserContext.newPage();
  const pageErrors: string[] = [];
  observePage(pageA, pageErrors, mode.kind === "production");
  await pageA.goto(pageOrigin);
  assert.equal(await pageA.title(), "Switchfrog Better Auth example");
  await expect(
    pageA.getByRole("button", { name: "Create account" }),
  ).toBeEnabled();
  await waitForExampleReady(pageA, pageErrors);
  if (mode.kind === "hermetic") {
    await waitForPageCall(pageA, "reset", 1);
    await waitForPageCall(pageA, "start", 1);
  }
  const anonymousFingerprint = await pageSessionFingerprint(pageA, mode);
  const resetCountBeforeLogin =
    mode.kind === "hermetic" ? await pageCallCount(pageA, "reset") : 0;

  await pageA.locator("#sign-up-name").fill("Package Tester");
  await pageA.locator("#sign-up-email").fill(email);
  await pageA.locator("#sign-up-password").fill(password);
  await pageA.getByRole("button", { name: "Create account" }).click();
  await waitForCondition(
    () => upstreamCalls.some((call) => call.accountId === undefined),
    "authenticated user association",
  );
  await expect(pageA.locator("#status")).toHaveJSProperty(
    "value",
    "Account created.",
  );
  assert.equal(
    (await pageSessionFingerprint(pageA, mode)) === anonymousFingerprint,
    true,
    "initial authentication must preserve the anonymous session",
  );
  if (mode.kind === "hermetic") {
    assert.equal(await pageCallCount(pageA, "reset"), resetCountBeforeLogin);
  }
  const userOnlyCall = upstreamCalls.find(
    (call) => call.accountId === undefined,
  );
  assert.ok(userOnlyCall);
  assert.equal(
    userOnlyCall.sessionFingerprint === anonymousFingerprint,
    true,
    "server association must use the anonymous session",
  );
  assert.equal(userOnlyCall.authorizationMatches, true);
  assert.equal(userOnlyCall.contentTypeMatches, true);
  assert.equal(userOnlyCall.accepted, true);

  const organizationA = await createOrganization(
    pageA,
    organizationAName,
    organizationASlug,
  );
  await pageA.locator("#active-organization").selectOption(organizationA);
  await pageA.getByRole("button", { name: "Set active organization" }).click();
  await waitForCondition(
    () => upstreamCalls.some((call) => call.accountId === organizationA),
    "organization A association",
  );
  await expect(pageA.locator("#status")).toHaveJSProperty(
    "value",
    "Active organization updated.",
  );
  const organizationAFingerprint = await pageSessionFingerprint(pageA, mode);
  assert.equal(
    organizationAFingerprint !== anonymousFingerprint,
    true,
    "organization change must create a successor session",
  );

  const organizationB = await createOrganization(
    pageA,
    organizationBName,
    organizationBSlug,
  );
  const organizationBIdentityDigest = createHash("sha256")
    .update(JSON.stringify([userOnlyCall.userId, organizationB]))
    .digest("hex");

  const pageB = await browserContext.newPage();
  let pageBOrganizationBAccepted = false;
  pageB.on("response", (response) => {
    const request = response.request();
    if (
      response.ok() &&
      new URL(request.url()).pathname === "/api/auth/switchfrog/identify"
    ) {
      const { expectedIdentityDigest: digest } = request.postDataJSON() as Record<
        string,
        unknown
      >;
      if (digest === organizationBIdentityDigest) {
        pageBOrganizationBAccepted = true;
      }
    }
  });
  observePage(
    pageB,
    pageErrors,
    mode.kind === "production",
    gatedStatuses,
    mode.kind === "production"
      ? new URL("/api/auth/switchfrog/identify", mode.origin).href
      : undefined,
  );
  gatedPage = pageB;
  await pageB.goto(pageOrigin);
  await waitForExampleReady(pageB, pageErrors);
  await waitForCondition(
    () => usedGate,
    "tab B organization A reassertion",
  );
  assert.equal(
    (await pageSessionFingerprint(pageA, mode)) === organizationAFingerprint,
    true,
    "tab A must retain the organization A session",
  );
  assert.equal(
    (await pageSessionFingerprint(pageB, mode)) === organizationAFingerprint,
    true,
    "tab B must share the organization A session",
  );

  const callsBeforeOrganizationB = upstreamCalls.length;
  await pageA.locator("#active-organization").selectOption(organizationB);
  await pageA.getByRole("button", { name: "Set active organization" }).click();
  await waitForCondition(
    () =>
      upstreamCalls
        .slice(callsBeforeOrganizationB)
        .some((call) => call.accountId === organizationB),
    "organization B association",
  );
  const organizationBFingerprint = await pageSessionFingerprint(pageA, mode);
  assert.equal(
    organizationBFingerprint !== organizationAFingerprint,
    true,
    "second organization change must create a successor session",
  );

  await waitForCondition(
    () => pageBOrganizationBAccepted,
    "tab B organization B association before stale gate release",
  );

  const callsBeforeGateRelease = upstreamCalls.length;
  gate.release();
  await waitForCondition(
    () => gatedStatuses.includes(412),
    "tab B stale identity rejection",
  );
  assert.equal(
    upstreamCalls
      .slice(callsBeforeGateRelease)
      .some((call) => call.accountId === organizationA),
    false,
  );
  await waitForCondition(
    async () =>
      (await pageSessionFingerprint(pageA, mode)) ===
        organizationBFingerprint &&
      (await pageSessionFingerprint(pageB, mode)) ===
        organizationBFingerprint,
    "two-tab Switchfrog token convergence",
  );

  const resetCountsBeforeSignOut =
    mode.kind === "hermetic"
      ? await Promise.all([
          pageCallCount(pageA, "reset"),
          pageCallCount(pageB, "reset"),
        ])
      : [0, 0];
  await pageA.getByRole("button", { name: "Sign out" }).click();
  await expect(pageA.locator("#status")).toHaveJSProperty(
    "value",
    "Signed out.",
  );
  await waitForCondition(
    async () =>
      mode.kind === "hermetic"
        ? (await pageCallCount(pageA, "reset")) >
            resetCountsBeforeSignOut[0]! ||
          (await pageCallCount(pageB, "reset")) > resetCountsBeforeSignOut[1]!
        : (await pageSessionFingerprint(pageA, mode)) !==
          organizationBFingerprint,
    "sign-out reset",
  );
  const anonymousSuccessorFingerprint = await pageSessionFingerprint(
    pageA,
    mode,
  );
  assert.equal(
    anonymousSuccessorFingerprint !== organizationBFingerprint,
    true,
    "sign-out must create an anonymous successor session",
  );
  if (mode.kind === "hermetic") {
    const emittedToken = await pageA.evaluate(() => {
      const pageWindow = window as unknown as Window & {
        __switchfrogEmit(payload: unknown): string;
      };

      return pageWindow.__switchfrogEmit({ type: "anonymous-successor" });
    });
    assert.equal(
      fingerprintToken(emittedToken) === anonymousSuccessorFingerprint,
      true,
    );
  }
  await pageA.reload();
  await waitForExampleReady(pageA, pageErrors);
  if (mode.kind === "hermetic") {
    await waitForPageCall(pageA, "start", 1);
    assert.equal(await pageCallCount(pageA, "reset"), 0);
  }
  assert.equal(
    (await pageSessionFingerprint(pageA, mode)) ===
      anonymousSuccessorFingerprint,
    true,
    "reload must preserve the anonymous successor session",
  );
  await pageA.locator("#sign-in-email").fill(email);
  await pageA.locator("#sign-in-password").fill(password);
  await pageA.getByRole("button", { name: "Sign in" }).click();
  await waitForCondition(
    () => upstreamCalls.filter((call) => call.accountId === undefined).length >= 2,
    "authenticated successor association",
  );
  await expect(pageA.locator("#status")).toHaveJSProperty(
    "value",
    "Signed in.",
  );
  assert.equal(
    (await pageSessionFingerprint(pageA, mode)) ===
      anonymousSuccessorFingerprint,
    true,
    "reauthentication must preserve the anonymous successor session",
  );
  const successorCall = upstreamCalls.filter(
    (call) => call.accountId === undefined,
  )[1]!;
  assert.equal(
    successorCall.sessionFingerprint === anonymousSuccessorFingerprint,
    true,
    "reauthentication must associate the anonymous successor session",
  );
  assert.equal(successorCall.accepted, true);
  assert.equal(pageErrors.length, 0, "browser and authentication errors are forbidden");

  if (mode.kind === "production") {
    assert.equal(
      sdkStatuses.some((status) => status >= 200 && status < 300),
      true,
      "hosted SDK request must succeed",
    );
    assert.equal(
      upstreamCalls.every(
        (call) =>
          call.accepted &&
          call.authorizationMatches &&
          call.contentTypeMatches,
      ),
      true,
      "all production identity associations must be accepted",
    );
    context.diagnostic(
      `mode production pass; run ${runId}; user ${userOnlyCall.userId}; organizations ${organizationA},${organizationB}; SDK status ${sdkStatuses[0]}; identity statuses ${upstreamCalls.map((call) => call.status).join(",")}; timestamp ${new Date().toISOString()}`,
    );
  } else {
    context.diagnostic(
      `Chromium sequence passed on ${loopbackOrigin}: 412 gate, ${upstreamCalls.length} accepted associations`,
    );
  }
  return port;
}

const hostedSdkStub = String.raw`(() => {
  const tokenKey = "switchfrog:test:session-token";
  const counterKey = "switchfrog:test:session-counter";
  window.__switchfrogCalls = [];

  const record = (type, details = {}) => {
    window.__switchfrogCalls.push({ type, ...details });
  };
  const currentToken = () => {
    let token = localStorage.getItem(tokenKey);
    if (token === null) {
      token = "sf_session_0";
      localStorage.setItem(counterKey, "0");
      localStorage.setItem(tokenKey, token);
    }
    return token;
  };

  window.Switchfrog = {
    init(publishableKey) {
      record("init", { publishableKey });
      return {
        async start() {
          record("start", { token: currentToken() });
        },
        async getSessionToken() {
          const token = currentToken();
          record("getSessionToken", { token });
          return token;
        },
        async reset() {
          const before = currentToken();
          const counter = Number(localStorage.getItem(counterKey) ?? "0") + 1;
          const after = "sf_session_" + counter;
          localStorage.setItem(counterKey, String(counter));
          localStorage.setItem(tokenKey, after);
          record("reset", { after, before });
        },
      };
    },
  };
  window.__switchfrogToken = currentToken;
  window.__switchfrogEmit = (payload) => {
    const token = currentToken();
    record("traffic", { payload, token });
    return token;
  };
})();`;

function createPendingGate(): PendingGate {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = () => resolve();
  });
  return { promise, release };
}

function observePage(
  page: Page,
  errors: string[],
  opaque = false,
  gatedStatuses: readonly number[] = [],
  expectedStaleUrl?: string,
): void {
  let pendingStaleUrl = expectedStaleUrl;
  page.on("console", (message) => {
    if (message.type() !== "error") return;
    if (
      opaque &&
      gatedStatuses.includes(412) &&
      message.location().url === pendingStaleUrl &&
      message.text() ===
        "Failed to load resource: the server responded with a status of 412 (Precondition Failed)"
    ) {
      pendingStaleUrl = undefined;
      return;
    }
    errors.push(opaque ? "browser console error" : message.text());
  });
  page.on("pageerror", (error) =>
    errors.push(opaque ? "browser page error" : error.message),
  );
}

async function waitForExampleReady(
  page: Page,
  pageErrors: readonly string[],
): Promise<void> {
  try {
    await expect(page.locator("#controls")).toBeEnabled({ timeout: 10_000 });
  } catch (error) {
    throw new Error(
      `example did not initialize: ${String(error)}; page errors: ${pageErrors.join(" | ")}`,
    );
  }
}

async function createOrganization(
  page: Page,
  name: string,
  slug: string,
): Promise<string> {
  await page.locator("#organization-name").fill(name);
  await page.locator("#organization-slug").fill(slug);
  await page.getByRole("button", { name: "Create organization" }).click();
  const option = page.locator("#active-organization option").filter({ hasText: name });
  await expect(option).toHaveCount(1);
  const id = await option.getAttribute("value");
  if (!id) throw new TypeError("organization option has no ID");
  return id;
}

async function pageCallCount(page: Page, type: string): Promise<number> {
  return page.evaluate(
    (callType) =>
      (
        (window as Window & {
          __switchfrogCalls?: ReadonlyArray<Readonly<{ type?: string }>>;
        }).__switchfrogCalls ?? []
      ).filter((call) => call.type === callType).length,
    type,
  );
}

async function waitForPageCall(
  page: Page,
  type: string,
  count: number,
): Promise<void> {
  await page.waitForFunction(
    ({ callCount, callType }) =>
      (
        (window as Window & {
          __switchfrogCalls?: ReadonlyArray<Readonly<{ type?: string }>>;
        }).__switchfrogCalls ?? []
      ).filter((call) => call.type === callType).length >= callCount,
    { callCount: count, callType: type },
  );
}

async function pageToken(page: Page): Promise<string> {
  return page.evaluate(() => {
    const token = (
      window as Window & { __switchfrogToken?: () => string }
    ).__switchfrogToken?.();
    if (typeof token !== "string") throw new TypeError("missing Switchfrog token");
    return token;
  });
}

async function pageSessionFingerprint(
  page: Page,
  mode: VerificationMode,
): Promise<string> {
  if (mode.kind === "hermetic") {
    return fingerprintToken(await pageToken(page));
  }
  return page.evaluate(async (publishableKey) => {
    const switchfrog = (
      window as Window & {
        Switchfrog?: {
          init(key: string): { getSessionToken(): Promise<string> };
        };
      }
    ).Switchfrog;
    if (!switchfrog) throw new TypeError("hosted Switchfrog SDK is unavailable");
    const token = await switchfrog.init(publishableKey).getSessionToken();
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(token),
    );
    return Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
  }, mode.publishableKey);
}

async function waitForCondition(
  predicate: () => boolean | Promise<boolean>,
  label: string,
  timeout = 10_000,
): Promise<void> {
  const deadline = Date.now() + timeout;
  while (!(await predicate())) {
    if (Date.now() >= deadline) throw new Error(`timed out waiting for ${label}`);
    await new Promise<void>((resolve) => setTimeout(resolve, 25));
  }
}

function writeConsumerLockfile(
  consumerRoot: string,
  tarballPath: string,
  version: string,
): void {
  const sourceLockfile = readFileSync(join(packageRoot, "pnpm-lock.yaml"), "utf8");
  const importersStart = sourceLockfile.indexOf("importers:\n");
  const packagesStart = sourceLockfile.indexOf("packages:\n");
  const snapshotsStart = sourceLockfile.indexOf("snapshots:\n");
  assert.notEqual(importersStart, -1);
  assert.notEqual(packagesStart, -1);
  assert.notEqual(snapshotsStart, -1);
  const sourceImporter = sourceLockfile.slice(importersStart, packagesStart);
  const escapedVersion = version.replaceAll(".", "\\.");
  const resolution = sourceImporter.match(
    new RegExp(
      `\\n      better-auth:\\n        specifier: ${escapedVersion}\\n        version: (.+)`,
    ),
  )?.[1];
  assert.ok(resolution, `standalone lockfile has no Better Auth ${version} resolution`);
  const nodeTypesVersion = sourceImporter.match(
    /\n      '@types\/node':\n        specifier: [^\n]+\n        version: (.+)/,
  )?.[1];
  assert.ok(nodeTypesVersion, "standalone lockfile has no @types/node resolution");
  const relativeTarball = relative(consumerRoot, tarballPath).split(sep).join("/");
  const fileResolution = `file:${relativeTarball}`;
  const peerResolution = `better-auth@${resolution}`;
  const integrity = `sha512-${createHash("sha512")
    .update(readFileSync(tarballPath))
    .digest("base64")}`;
  writeFileSync(
    join(consumerRoot, "pnpm-lock.yaml"),
    [
      sourceLockfile.slice(0, importersStart),
      "importers:\n\n",
      "  .:\n",
      "    dependencies:\n",
      "      better-auth:\n",
      `        specifier: ${version}\n`,
      `        version: ${resolution}\n`,
      `      '@switchfrog/better-auth':\n`,
      `        specifier: file:${tarballPath}\n`,
      `        version: ${fileResolution}(${peerResolution})\n\n`,
      "    devDependencies:\n",
      "      '@types/node':\n",
      `        specifier: ${packageManifest.devDependencies["@types/node"]}\n`,
      `        version: ${nodeTypesVersion}\n\n`,
      sourceLockfile.slice(packagesStart, snapshotsStart),
      `  '@switchfrog/better-auth@${fileResolution}':\n`,
      `    resolution: {integrity: ${integrity}, tarball: ${fileResolution}}\n`,
      `    version: ${packageManifest.version}\n`,
      `    engines: {node: '${packageManifest.engines.node}'}\n`,
      "    peerDependencies:\n",
      `      better-auth: '${packageManifest.peerDependencies["better-auth"]}'\n\n`,
      "snapshots:\n\n",
      `  '@switchfrog/better-auth@${fileResolution}(${peerResolution})':\n`,
      "    dependencies:\n",
      `      better-auth: ${resolution}\n`,
      `      zod: ${packageManifest.dependencies.zod}\n\n`,
      sourceLockfile.slice(snapshotsStart + "snapshots:\n".length),
    ].join(""),
  );
}

function findSharedStore(tempRoot: string): string {
  return runCommand("pnpm", ["store", "path", "--silent"], tempRoot, {
    PNPM_HOME: process.env.PNPM_HOME,
  }).trim();
}

function copyInputTarball(tempRoot: string, inputTarball: string): string {
  if (!statSync(inputTarball).isFile()) {
    throw new TypeError("input tarball must be a regular file");
  }
  const tarballPath = join(tempRoot, "input.tgz");
  copyFileSync(inputTarball, tarballPath, constants.COPYFILE_EXCL);
  return tarballPath;
}

function packLocalPackage(tempRoot: string, sharedStore: string): string {
  const sourceRoot = join(tempRoot, "source");
  copyRegularFiles(packageRoot, sourceRoot, packageBuildSourceFiles);
  runCommand(
    "pnpm",
    [
      "install",
      "--frozen-lockfile",
      "--offline",
      "--store-dir",
      sharedStore,
      "--virtual-store-dir",
      join(sourceRoot, "node_modules", ".pnpm"),
    ],
    sourceRoot,
    { CI: "true" },
  );
  const stdout = runCommand(
    "npm",
    ["pack", "--silent", "--json", "--pack-destination", tempRoot],
    sourceRoot,
    { npm_config_cache: join(tempRoot, "npm-cache") },
  );
  const results = parseNpmPackOutput(stdout);
  assert.equal(results.length, 1);
  const result = results[0]!;
  assert.deepEqual(
    result.files.map(({ path }) => path).sort(),
    expectedPackedFiles,
  );
  const tarballPath = resolve(tempRoot, result.filename);
  assert.equal(dirname(tarballPath), tempRoot);
  assert.equal(statSync(tarballPath).isFile(), true);
  return tarballPath;
}

function parseNpmPackOutput(output: string): NpmPackResult[] {
  const jsonStart = output.lastIndexOf("\n[");
  const json = output.slice(jsonStart < 0 ? 0 : jsonStart + 1).trim();
  return JSON.parse(json) as NpmPackResult[];
}

function packageFiles(root: string, directory = root): string[] {
  return readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        throw new TypeError(`packed package contains a symlink: ${relative(root, path)}`);
      }
      if (entry.isDirectory()) return packageFiles(root, path);
      if (!entry.isFile()) {
        throw new TypeError(`packed package contains a non-file: ${relative(root, path)}`);
      }
      return [relative(root, path)];
    })
    .sort();
}

function assertInstalledPackagePaths(consumerRoot: string): void {
  const distRoot = join(
    consumerRoot,
    "node_modules",
    "@switchfrog",
    "better-auth",
    "dist",
  );
  for (const filename of ["index.js", "client.js"]) {
    assertPathWithin(consumerRoot, join(distRoot, filename));
  }
}

function verifyConsumerTypes(consumerRoot: string): void {
  runCommand(
    join(packageRoot, "node_modules", ".bin", "tsc"),
    ["--project", "example/tsconfig.json"],
    consumerRoot,
  );
}

function bundleBrowserEntry(consumerRoot: string): void {
  runCommand(
    join(packageRoot, "node_modules", ".bin", "tsdown"),
    ["--config", "example/tsdown.config.mjs"],
    consumerRoot,
  );
  assert.equal(statSync(join(consumerRoot, "example", "dist", "client.js")).isFile(), true);
}

function assertPathWithin(root: string, path: string): void {
  const realRoot = realpathSync(root);
  const realPath = realpathSync(path);
  const pathFromRoot = relative(realRoot, realPath);
  assert.equal(
    pathFromRoot !== "" &&
      pathFromRoot !== ".." &&
      !pathFromRoot.startsWith(`..${sep}`) &&
      !isAbsolute(pathFromRoot),
    true,
    `${realPath} must be beneath ${realRoot}`,
  );
}

function copyRegularFiles(
  sourceRoot: string,
  destinationRoot: string,
  paths: readonly string[],
): void {
  for (const path of paths) {
    const sourcePath = join(sourceRoot, path);
    const information = lstatSync(sourcePath, { throwIfNoEntry: false });
    if (!information || information.isSymbolicLink() || !information.isFile()) {
      throw new TypeError(`expected a regular source file: ${path}`);
    }
    const destinationPath = join(destinationRoot, path);
    mkdirSync(dirname(destinationPath), { recursive: true });
    copyFileSync(sourcePath, destinationPath);
  }
}

function safeEnvironment(
  cwd: string,
  overrides: NodeJS.ProcessEnv = {},
): NodeJS.ProcessEnv {
  const inherited: NodeJS.ProcessEnv = {};
  for (const name of ["PATH", "Path", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR"]) {
    const value = process.env[name];
    if (value !== undefined) inherited[name] = value;
  }
  const nullDevice = process.platform === "win32" ? "NUL" : "/dev/null";
  return {
    ...inherited,
    npm_config_globalconfig: nullDevice,
    npm_config_registry: "https://registry.npmjs.org/",
    npm_config_userconfig: join(cwd, ".switchfrog-empty-npmrc"),
    pnpm_config_globalconfig: nullDevice,
    pnpm_config_userconfig: join(cwd, ".switchfrog-empty-pnpmrc"),
    ...overrides,
  };
}

function runCommand(
  command: string,
  arguments_: readonly string[],
  cwd: string,
  environment: NodeJS.ProcessEnv = {},
): string {
  const result = spawnSync(command, arguments_, {
    cwd,
    encoding: "utf8",
    env: safeEnvironment(cwd, environment),
    maxBuffer: 20 * 1_024 * 1_024,
  });
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(
      `${command} ${arguments_.join(" ")} exited ${String(result.status)}\n${output}`,
    );
  }
  return result.stdout ?? "";
}
