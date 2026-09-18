import { createRequire } from "node:module";

import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { switchfrogClient } from "../src/client";

type TestScript = {
  async: boolean;
  hasAttribute(name: string): boolean;
  onerror: null | (() => void);
  onload: null | (() => void);
  remove(): void;
  removed: boolean;
  src: string;
};

type PageState = {
  sdkPromise?: Promise<unknown>;
  synchronizersByPublishableKey: Map<string, {
    memoryState: null | string;
    queue: Promise<void>;
    revision: number;
  }>;
};

type SessionData = {
  session: { activeOrganizationId?: null | string };
  user: { id: string };
};

type SessionResult = {
  data: null | SessionData;
  error: null | { status: number };
  isPending: boolean;
  isRefetching: boolean;
};

type EndpointResult = {
  data: unknown;
  error: null | { code?: string; status: number };
};

type Awaitable<T> = Promise<T> | T;

type EndpointResponse =
  | Awaitable<EndpointResult>
  | ((signal?: AbortSignal) => Awaitable<EndpointResult>);

type TestStorage = {
  externalSet(key: string, value: null | string): void;
  storage: Storage;
  values: Map<string, string>;
};

const digestA = "c8af7fdd9744895e64a3588747bfa13394df2015ce1f747b97be1a481a3ba7d8";
const digestB = "cc2060a34b18ba96ad4f601ea2d0906923093a751bd5f390807004b4de3a28ba";
const digestOrgA = "00dabf99a02cda814ce69e92b6d9154b4139bcdf5a0ae0cda9a8d652f20c9bb2";
const digestOrgB = "95adc36f044a31902aea45595f63a661d3844f8ad756bf24b91c7e4fc527c214";
const storageKey = "switchfrog:better-auth:v1:sf_pk_test";

const pageStateKey = Symbol.for("switchfrog.better-auth.client.state");

function createStorage(calls: string[] = []): TestStorage {
  const values = new Map<string, string>();
  const storage = {
    clear() {
      values.clear();
    },
    getItem(key: string) {
      return values.get(key) ?? null;
    },
    key(index: number) {
      return [...values.keys()][index] ?? null;
    },
    get length() {
      return values.size;
    },
    removeItem(key: string) {
      calls.push("remove");
      values.delete(key);
    },
    setItem(key: string, value: string) {
      calls.push(`write:${value}`);
      values.set(key, value);
    },
  } satisfies Storage;

  return {
    externalSet(key, value) {
      if (value === null) values.delete(key);
      else values.set(key, value);
    },
    storage,
    values,
  };
}

function installDom(options: { localStorage?: Storage; localStorageError?: Error } = {}) {
  const scripts: TestScript[] = [];
  const storageListeners: Array<
    (event: { key: null | string; newValue: null | string }) => void
  > = [];
  const createScript = (): TestScript => {
    const script: TestScript = {
      async: false,
      hasAttribute: () => false,
      onerror: null,
      onload: null,
      remove() {
        script.removed = true;
      },
      removed: false,
      src: "",
    };
    return script;
  };
  const document = {
    createElement: vi.fn((tagName: string) => {
      if (tagName !== "script") throw new Error(`unexpected element: ${tagName}`);
      return createScript();
    }),
    head: {
      append: vi.fn((script: TestScript) => scripts.push(script)),
    },
  };
  const window = {
    addEventListener(
      type: string,
      listener: (event: {
        key: null | string;
        newValue: null | string;
      }) => void,
    ) {
      if (type === "storage") storageListeners.push(listener);
    },
  } as unknown as Window & Record<symbol, unknown> & {
    Switchfrog?: { init(publishableKey: string): unknown };
  };
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    get() {
      if (options.localStorageError) throw options.localStorageError;
      return options.localStorage ?? createStorage().storage;
    },
  });

  vi.stubGlobal("document", document);
  vi.stubGlobal("window", window);

  return {
    dispatchStorage(key: null | string, newValue: null | string = null) {
      for (const listener of storageListeners) listener({ key, newValue });
    },
    document,
    scripts,
    window,
  };
}

function sessionResult(data: null | SessionData): SessionResult {
  return { data, error: null, isPending: false, isRefetching: false };
}

const anonymous = () => sessionResult(null);
const authenticated = (userId: string, activeOrganizationId?: string): SessionResult =>
  sessionResult({
    session: activeOrganizationId === undefined ? {} : { activeOrganizationId },
    user: { id: userId },
  });
const pending = (): SessionResult => ({
  data: null,
  error: null,
  isPending: true,
  isRefetching: false,
});
const refetching = (result: SessionResult): SessionResult => ({
  ...result,
  isRefetching: true,
});

function createSessionAtom(initial: SessionResult) {
  let current = initial;
  const listeners = new Set<(result: SessionResult) => void>();
  return {
    get: () => current,
    emit(result: SessionResult) {
      current = result;
      for (const listener of listeners) listener(result);
    },
    subscribe(listener: (result: SessionResult) => void) {
      listeners.add(listener);
      listener(current);
      return () => listeners.delete(listener);
    },
  };
}

function createStore(initial: SessionResult = pending()) {
  const session = createSessionAtom(initial);
  const notify = vi.fn();
  return {
    session,
    store: { atoms: { session }, notify },
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((promiseResolve) => {
    resolve = promiseResolve;
  });
  return { promise, resolve };
}

function rejectOnAbort(signal?: AbortSignal): Promise<EndpointResult> {
  return new Promise((_resolve, reject) => {
    signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
  });
}

function getActions(
  publishableKey: string,
  options?: { basePath?: string; baseURL?: string },
  dependencies?: {
    $fetch?: ReturnType<typeof vi.fn>;
    $store?: ReturnType<typeof createStore>["store"];
  },
) {
  const plugin = switchfrogClient({ publishableKey });
  const $fetch = dependencies?.$fetch ?? vi.fn(async () => ({ data: null, error: null }));
  const $store = dependencies?.$store ?? createStore().store;
  return plugin.getActions?.($fetch as never, $store as never, options);
}

function getPageState(window: Window & Record<symbol, unknown>): PageState {
  return window[pageStateKey] as PageState;
}

async function settle() {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
}

async function drain(window: Window & Record<symbol, unknown>, publishableKey = "sf_pk_test") {
  const synchronizer = getPageState(window).synchronizersByPublishableKey.get(publishableKey);
  expect(synchronizer).toBeDefined();
  while (synchronizer) {
    const queue = synchronizer.queue;
    await queue;
    if (queue === synchronizer.queue) return;
  }
}

function installSynchronizer(options: {
  hostThrows?: boolean;
  initial: SessionResult;
  initError?: Error;
  localStorageError?: Error;
  notify?: () => void;
  priorState?: string;
  reset?: Promise<void>;
  responses?: EndpointResponse[];
  start?: Promise<void>;
  storage?: TestStorage;
  tokens?: Array<Awaitable<string>>;
  allowed?: boolean;
  waitForConsent?: boolean;
  fetch?: ReturnType<typeof vi.fn>;
}) {
  const calls: string[] = [];
  const storage = options.storage ?? createStorage(calls);
  if (options.priorState !== undefined) storage.externalSet(storageKey, options.priorState);
  const { dispatchStorage, window } = installDom({
    localStorage: storage.storage,
    localStorageError: options.localStorageError,
  });
  const tokens = [...(options.tokens ?? ["token-a"])];
  let allowed = options.allowed ?? true;
  const consentListeners = new Set<(allowed: boolean) => void>();
  const client = {
    onConsentChange: vi.fn((listener: (allowed: boolean) => void) => {
      consentListeners.add(listener);
      listener(allowed);
      return () => {
        consentListeners.delete(listener);
      };
    }),
    optIn: vi.fn(async () => {
      allowed = true;
      for (const listener of [...consentListeners]) listener(allowed);
    }),
    optOut: vi.fn(async () => {
      allowed = false;
      for (const listener of [...consentListeners]) listener(allowed);
    }),
    getSessionToken: vi.fn(async () => {
      const token = await (tokens.shift() ?? "token-a");
      calls.push(`token:${token}`);
      return token;
    }),
    reset: vi.fn(async () => {
      calls.push("reset");
      await options.reset;
    }),
    start: vi.fn(async () => {
      calls.push("start");
      await options.start;
    }),
  };
  window.Switchfrog = {
    init: vi.fn(() => {
      if (options.initError) throw options.initError;
      return client;
    }),
  };
  const { session, store } = createStore(options.initial);
  store.notify.mockImplementation(options.notify ?? (() => undefined));
  const responses = [...(options.responses ?? [{ data: { status: "accepted" }, error: null }])];
  const $fetch = vi.fn(
    async (
      _path: string,
      request: {
        body: { expectedIdentityDigest: string; sessionToken: string };
        signal?: AbortSignal;
        throw?: boolean;
      },
    ) => {
      calls.push(
        `identify:${request.body.expectedIdentityDigest}:${request.body.sessionToken}`,
      );
      const nextResponse = responses.shift() ?? {
        data: { status: "accepted" },
        error: null,
      };
      const response = await (typeof nextResponse === "function"
        ? nextResponse(request.signal)
        : nextResponse);
      if (options.hostThrows && request.throw !== false) {
        if (response.error) throw Object.assign(new Error("request failed"), response.error);
        return response.data;
      }
      return response;
    },
  );

  const plugin = switchfrogClient({
    publishableKey: "sf_pk_test",
    ...(options.waitForConsent === undefined
      ? {}
      : { waitForConsent: options.waitForConsent }),
  });
  plugin.getActions?.(
    (options.fetch ?? $fetch) as never,
    store as never,
    {},
  );

  return { $fetch, calls, client, dispatchStorage, session, storage, store, window };
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("switchfrogClient", () => {
  it.each(["", "   ", "sf_sk_test", "secret", "sf_pk_"])(
    "rejects an invalid publishable key synchronously: %j",
    (publishableKey) => {
      expect(() => switchfrogClient({ publishableKey })).toThrow(TypeError);
    },
  );

  it("performs no SSR browser, timer, network, or public-action work", () => {
    const fetch = vi.fn();
    const setTimeout = vi.spyOn(globalThis, "setTimeout");
    vi.stubGlobal("document", undefined);
    vi.stubGlobal("fetch", fetch);
    vi.stubGlobal("window", undefined);

    expect(getActions("sf_pk_test")).toEqual({});
    expect(fetch).not.toHaveBeenCalled();
    expect(setTimeout).not.toHaveBeenCalled();
  });

  it("isolates synchronous hosted SDK setup failures from Better Auth", async () => {
    const report = vi.spyOn(console, "error").mockImplementation(() => undefined);
    vi.stubGlobal("window", {});
    vi.stubGlobal("document", {
      createElement: () => {
        throw new TypeError("TrustedScriptURL required");
      },
    });

    expect(() => getActions("sf_pk_test")).not.toThrow();
    await settle();

    expect(report).toHaveBeenCalledWith(
      "Switchfrog Better Auth client failed to initialize",
      expect.objectContaining({ message: "TrustedScriptURL required" }),
    );
  });

  it("loads the hosted SDK once for duplicate construction and keeps one synchronizer", () => {
    const { document, scripts, window } = installDom();

    expect(getActions("sf_pk_test")).toEqual({});
    const state = getPageState(window);
    const firstPromise = state.sdkPromise;
    expect(getActions("sf_pk_test")).toEqual({});

    expect(firstPromise).toBeInstanceOf(Promise);
    expect(document.createElement).toHaveBeenCalledOnce();
    expect(scripts).toHaveLength(1);
    expect(state.sdkPromise).toBe(firstPromise);
    expect(state.synchronizersByPublishableKey).toHaveLength(1);
  });

  it("shares one hosted SDK load across publishable-key synchronizers", () => {
    const { document, scripts, window } = installDom();

    getActions("sf_pk_first");
    const state = getPageState(window);
    const firstPromise = state.sdkPromise;
    getActions("sf_pk_second");

    expect(document.createElement).toHaveBeenCalledOnce();
    expect(scripts).toHaveLength(1);
    expect(state.sdkPromise).toBe(firstPromise);
    expect(state.synchronizersByPublishableKey).toHaveLength(2);
  });

  it("keeps the first owner when a duplicate key claims a different auth scope", () => {
    const { document, scripts, window } = installDom();
    const report = vi.spyOn(console, "error").mockImplementation(() => undefined);

    expect(
      getActions("sf_pk_test", {
        basePath: "/api/auth",
        baseURL: "https://first.example",
      }),
    ).toEqual({});
    expect(
      getActions("sf_pk_test", {
        basePath: "/api/auth",
        baseURL: "https://second.example",
      }),
    ).toEqual({});

    expect(document.createElement).toHaveBeenCalledOnce();
    expect(scripts).toHaveLength(1);
    expect(getPageState(window).synchronizersByPublishableKey).toHaveLength(1);
    expect(report).toHaveBeenCalledWith(
      "Switchfrog Better Auth client already owns this publishable key",
    );
  });

  it("uses the direct hosted SDK script without auto-install attributes", () => {
    const { scripts } = installDom();

    getActions("sf_pk_test");

    const [script] = scripts;
    expect(script).toBeDefined();
    expect(script?.async).toBe(true);
    expect(script?.src).toBe("https://api.switchfrog.com/sdk/v1.js");
    expect(script?.hasAttribute("data-publishable-key")).toBe(false);
  });

  it("reuses an existing valid hosted SDK global", async () => {
    const { scripts, window } = installDom();
    const init = vi.fn(() => ({
      onConsentChange: (listener: (allowed: boolean) => void) => {
        listener(true);
        return () => undefined;
      },
      optIn: async () => undefined,
      optOut: async () => undefined,
      getSessionToken: async () => "sf_session",
      reset: async () => undefined,
      start: async () => undefined,
    }));
    window.Switchfrog = { init };

    getActions("sf_pk_test");
    await settle();

    expect(scripts).toHaveLength(0);
    expect(init).toHaveBeenCalledWith("sf_pk_test");
  });

  it("removes only its failed script when load completes without a valid global", async () => {
    const { scripts, window } = installDom();
    const report = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);

    getActions("sf_pk_test");
    scripts[0]?.onload?.();
    await drain(window);

    expect(scripts[0]?.removed).toBe(true);
    expect(report).toHaveBeenCalledWith(
      "Switchfrog Better Auth client failed to initialize",
      expect.any(Error),
    );
  });

  it("times out the hosted SDK after ten seconds and allows a successful retry", async () => {
    vi.useFakeTimers();
    const { scripts, window } = installDom();
    const report = vi.spyOn(console, "error").mockImplementation(() => undefined);

    getActions("sf_pk_test");
    await vi.advanceTimersByTimeAsync(10_000);
    await settle();

    expect(scripts[0]?.removed).toBe(true);
    expect(report).toHaveBeenCalledWith(
      "Switchfrog Better Auth client failed to initialize",
      expect.objectContaining({ message: "Hosted Switchfrog SDK load timed out" }),
    );

    const init = vi.fn(() => ({
      onConsentChange: (listener: (allowed: boolean) => void) => {
        listener(true);
        return () => undefined;
      },
      optIn: async () => undefined,
      optOut: async () => undefined,
      getSessionToken: async () => "sf_session",
      reset: async () => undefined,
      start: async () => undefined,
    }));
    getActions("sf_pk_retry");
    window.Switchfrog = { init };
    scripts[1]?.onload?.();
    await settle();

    expect(scripts).toHaveLength(2);
    expect(scripts[1]?.removed).toBe(false);
    expect(init).toHaveBeenCalledWith("sf_pk_retry");
  });

  it.each([
    {
      clearBeforeNext: false,
      initial: anonymous(),
      name: "missing to anonymous",
      next: undefined,
      priorState: undefined,
      tokens: ["token-a"],
      want: ["remove", "reset", "write:anonymous", "start"],
      wantFetches: 0,
    },
    {
      clearBeforeNext: false,
      initial: authenticated("user-a"),
      name: "missing to authenticated A",
      next: undefined,
      priorState: undefined,
      tokens: ["token-a"],
      want: [
        "remove",
        "reset",
        `write:unassociated:${digestA}`,
        "start",
        "token:token-a",
        `identify:${digestA}:token-a`,
        `write:accepted:${digestA}`,
      ],
      wantFetches: 1,
    },
    {
      clearBeforeNext: false,
      initial: authenticated("user-a"),
      name: "anonymous to authenticated A",
      next: undefined,
      priorState: "anonymous",
      tokens: ["token-a"],
      want: [
        `write:unassociated:${digestA}`,
        "start",
        "token:token-a",
        `identify:${digestA}:token-a`,
        `write:accepted:${digestA}`,
      ],
      wantFetches: 1,
    },
    {
      clearBeforeNext: false,
      initial: authenticated("user-a"),
      name: "accepted A to authenticated A with the same token",
      next: authenticated("user-a"),
      priorState: `accepted:${digestA}`,
      tokens: ["token-a", "token-a"],
      want: [
        "start",
        "token:token-a",
        `identify:${digestA}:token-a`,
        `write:accepted:${digestA}`,
        "token:token-a",
      ],
      wantFetches: 1,
    },
    {
      clearBeforeNext: true,
      initial: authenticated("user-a"),
      name: "accepted A to anonymous",
      next: anonymous(),
      priorState: `accepted:${digestA}`,
      tokens: ["token-a"],
      want: ["remove", "reset", "write:anonymous"],
      wantFetches: 1,
    },
    {
      clearBeforeNext: true,
      initial: authenticated("user-a", "org-a"),
      name: "accepted organization A to authenticated organization B",
      next: authenticated("user-a", "org-b"),
      priorState: `accepted:${digestOrgA}`,
      tokens: ["token-a", "token-b"],
      want: [
        "remove",
        "reset",
        `write:unassociated:${digestOrgB}`,
        "token:token-b",
        `identify:${digestOrgB}:token-b`,
        `write:accepted:${digestOrgB}`,
      ],
      wantFetches: 2,
    },
  ])(
    "orders the $name boundary transition",
    async ({ clearBeforeNext, initial, next, priorState, tokens, want, wantFetches }) => {
      const installed = installSynchronizer({ initial, priorState, tokens });
      await drain(installed.window);

      if (next) {
        if (clearBeforeNext) installed.calls.length = 0;
        installed.session.emit(next);
        await drain(installed.window);
      }

      expect(installed.calls).toEqual(want);
      expect(installed.$fetch).toHaveBeenCalledTimes(wantFetches);
    },
  );

  it("reasserts an accepted identity when its session token changes", async () => {
    const installed = installSynchronizer({
      initial: authenticated("user-a"),
      priorState: `accepted:${digestA}`,
      tokens: ["token-a", "token-b"],
    });
    await drain(installed.window);

    installed.session.emit(authenticated("user-a"));
    await drain(installed.window);

    expect(installed.$fetch).toHaveBeenCalledTimes(2);
    expect(installed.calls).toContain(`identify:${digestA}:token-b`);
  });

  it.each([
    { data: null, error: null, isPending: true, isRefetching: false },
    {
      data: null,
      error: { status: 503 },
      isPending: false,
      isRefetching: false,
    },
  ] satisfies SessionResult[])(
    "does no SDK lifecycle or association work for unresolved auth: %j",
    async (initial) => {
      const installed = installSynchronizer({ initial });

      await drain(installed.window);

      expect(installed.calls).toEqual([]);
      expect(installed.client.start).not.toHaveBeenCalled();
      expect(installed.client.reset).not.toHaveBeenCalled();
      expect(installed.$fetch).not.toHaveBeenCalled();
    },
  );

  it("fences an accepted A response after identity B arrives", async () => {
    const responseA = deferred<EndpointResult>();
    const installed = installSynchronizer({
      initial: authenticated("user-a"),
      priorState: "anonymous",
      responses: [responseA.promise, { data: { status: "accepted" }, error: null }],
      tokens: ["token-a", "token-b"],
    });
    await vi.waitFor(() => expect(installed.$fetch).toHaveBeenCalledOnce());

    installed.session.emit(authenticated("user-b"));
    responseA.resolve({ data: { status: "accepted" }, error: null });
    await drain(installed.window);

    expect(installed.calls).not.toContain(`write:accepted:${digestA}`);
    expect(installed.calls).toContain(`write:accepted:${digestB}`);
    expect(installed.$fetch).toHaveBeenCalledTimes(2);
    expect(installed.client.getSessionToken).toHaveBeenCalledTimes(2);
  });

  it("aborts a stale association so the next identity can synchronize", async () => {
    const installed = installSynchronizer({
      initial: authenticated("user-a"),
      priorState: "anonymous",
      responses: [
        rejectOnAbort,
        { data: { status: "accepted" }, error: null },
      ],
      tokens: ["token-a", "token-b"],
    });
    await vi.waitFor(() => expect(installed.$fetch).toHaveBeenCalledOnce());

    installed.session.emit(authenticated("user-b"));
    await vi.waitFor(() => expect(installed.$fetch).toHaveBeenCalledTimes(2));
    await drain(installed.window);

    expect(installed.client.reset).toHaveBeenCalledOnce();
    expect(installed.$fetch).toHaveBeenCalledTimes(2);
    expect(installed.storage.values.get(storageKey)).toBe(`accepted:${digestB}`);
  });

  it("refetches the session after a matching storage revision aborts stale work", async () => {
    let installed!: ReturnType<typeof installSynchronizer>;
    installed = installSynchronizer({
      initial: authenticated("user-a", "org-a"),
      notify: () => installed.session.emit(authenticated("user-a", "org-b")),
      priorState: `unassociated:${digestOrgA}`,
      responses: [
        rejectOnAbort,
        { data: { status: "accepted" }, error: null },
      ],
      tokens: ["token-a", "token-b"],
    });
    await vi.waitFor(() => expect(installed.$fetch).toHaveBeenCalledOnce());

    installed.storage.externalSet(storageKey, `accepted:${digestOrgB}`);
    installed.dispatchStorage(storageKey, `accepted:${digestOrgB}`);
    await vi.waitFor(() => expect(installed.$fetch).toHaveBeenCalledTimes(2));
    await drain(installed.window);

    expect(installed.store.notify).toHaveBeenCalledExactlyOnceWith("$sessionSignal");
    expect(installed.storage.values.get(storageKey)).toBe(`accepted:${digestOrgB}`);
  });

  it("uses a matching storage event to fence work before the endpoint call", async () => {
    const token = deferred<string>();
    const installed = installSynchronizer({
      initial: authenticated("user-a"),
      priorState: `accepted:${digestA}`,
      tokens: [token.promise],
    });
    await vi.waitFor(() =>
      expect(installed.client.getSessionToken).toHaveBeenCalledOnce(),
    );
    const synchronizer = getPageState(installed.window).synchronizersByPublishableKey.get(
      "sf_pk_test",
    );
    const revision = synchronizer?.revision;

    installed.dispatchStorage("unrelated");
    expect(synchronizer?.revision).toBe(revision);
    installed.dispatchStorage(storageKey);
    expect(synchronizer?.revision).toBe((revision ?? 0) + 1);
    token.resolve("token-a");
    await drain(installed.window);

    expect(installed.$fetch).not.toHaveBeenCalled();
    expect(installed.calls).not.toContain(`write:accepted:${digestA}`);
  });

  it("restarts work fenced by a peer accepting the same identity", async () => {
    let installed!: ReturnType<typeof installSynchronizer>;
    installed = installSynchronizer({
      initial: authenticated("user-a"),
      notify: () => installed.session.emit(authenticated("user-a")),
      priorState: `unassociated:${digestA}`,
      responses: [
        rejectOnAbort,
        { data: { status: "accepted" }, error: null },
      ],
      tokens: ["token-a", "token-b"],
    });
    await vi.waitFor(() => expect(installed.$fetch).toHaveBeenCalledOnce());

    installed.storage.externalSet(storageKey, `accepted:${digestA}`);
    installed.dispatchStorage(storageKey, `accepted:${digestA}`);
    await drain(installed.window);

    expect(installed.store.notify).toHaveBeenCalledExactlyOnceWith("$sessionSignal");
    expect(installed.$fetch).toHaveBeenCalledTimes(2);
  });

  it("bounds repeated peer 403 recovery across two tabs", async () => {
    const forbidden = { data: null, error: { status: 403 } } as const;
    let first!: ReturnType<typeof installSynchronizer>;
    let second!: ReturnType<typeof installSynchronizer>;
    first = installSynchronizer({
      initial: authenticated("user-a"),
      notify: () => first.session.emit(authenticated("user-a")),
      priorState: `accepted:${digestA}`,
      responses: Array(8).fill(forbidden),
    });
    second = installSynchronizer({
      initial: authenticated("user-a"),
      notify: () => second.session.emit(authenticated("user-a")),
      priorState: `accepted:${digestA}`,
      responses: Array(8).fill(forbidden),
    });
    await Promise.all([drain(first.window), drain(second.window)]);

    for (let round = 0; round < 3; round += 1) {
      first.dispatchStorage(storageKey, null);
      first.dispatchStorage(storageKey, `unassociated:${digestA}`);
      second.dispatchStorage(storageKey, null);
      second.dispatchStorage(storageKey, `unassociated:${digestA}`);
      await Promise.all([drain(first.window), drain(second.window)]);
    }

    expect(first.store.notify).not.toHaveBeenCalled();
    expect(second.store.notify).not.toHaveBeenCalled();
    expect(first.$fetch).toHaveBeenCalledOnce();
    expect(second.$fetch).toHaveBeenCalledOnce();
  });

  it("leaves missing durable state when reset is interrupted so the next page resets", async () => {
    const sharedStorage = createStorage();
    sharedStorage.externalSet(storageKey, `accepted:${digestA}`);
    const firstReset = deferred<void>();
    const firstPage = installSynchronizer({
      initial: authenticated("user-b"),
      reset: firstReset.promise,
      storage: sharedStorage,
    });
    await vi.waitFor(() => expect(firstPage.client.reset).toHaveBeenCalledOnce());
    expect(sharedStorage.values.has(storageKey)).toBe(false);

    const secondPage = installSynchronizer({
      initial: authenticated("user-b"),
      storage: sharedStorage,
      tokens: ["token-b"],
    });
    await drain(secondPage.window);

    expect(secondPage.client.reset).toHaveBeenCalledOnce();
    expect(sharedStorage.values.get(storageKey)).toBe(`accepted:${digestB}`);
    firstReset.resolve();
    await drain(firstPage.window);
  });

  it("notifies and converges after a 412 without stale mutation", async () => {
    const stale = deferred<EndpointResult>();
    let installed!: ReturnType<typeof installSynchronizer>;
    installed = installSynchronizer({
      initial: authenticated("user-a"),
      notify: () => installed.session.emit(authenticated("user-b")),
      priorState: `unassociated:${digestA}`,
      responses: [stale.promise, { data: { status: "accepted" }, error: null }],
      tokens: ["token-a", "token-b"],
    });
    await vi.waitFor(() => expect(installed.$fetch).toHaveBeenCalledOnce());

    stale.resolve({
      data: null,
      error: { code: "SWITCHFROG_IDENTITY_CHANGED", status: 412 },
    });
    await drain(installed.window);

    expect(installed.store.notify).toHaveBeenCalledExactlyOnceWith("$sessionSignal");
    expect(installed.client.reset).toHaveBeenCalledOnce();
    expect(installed.$fetch).toHaveBeenCalledTimes(2);
    expect(installed.calls).not.toContain(`write:accepted:${digestA}`);
    expect(installed.storage.values.get(storageKey)).toBe(`accepted:${digestB}`);
  });

  it("ignores stale identity A while Better Auth refetches before identity B arrives", async () => {
    const stale = deferred<EndpointResult>();
    let installed!: ReturnType<typeof installSynchronizer>;
    installed = installSynchronizer({
      initial: authenticated("user-a"),
      notify: () => installed.session.emit(refetching(authenticated("user-a"))),
      priorState: `unassociated:${digestA}`,
      responses: [stale.promise, { data: { status: "accepted" }, error: null }],
      tokens: ["token-a", "token-b"],
    });
    await vi.waitFor(() => expect(installed.$fetch).toHaveBeenCalledOnce());

    stale.resolve({
      data: null,
      error: { code: "SWITCHFROG_IDENTITY_CHANGED", status: 412 },
    });
    await drain(installed.window);

    expect(installed.$fetch).toHaveBeenCalledOnce();
    expect(installed.client.getSessionToken).toHaveBeenCalledOnce();
    expect(installed.storage.values.get(storageKey)).toBe(`unassociated:${digestA}`);

    installed.session.emit(authenticated("user-b"));
    await drain(installed.window);

    expect(installed.$fetch).toHaveBeenCalledTimes(2);
    expect(installed.client.getSessionToken).toHaveBeenCalledTimes(2);
    expect(installed.storage.values.get(storageKey)).toBe(`accepted:${digestB}`);
  });

  it("ignores stale 403 recovery after the tab advances to identity B", async () => {
    const forbidden = deferred<EndpointResult>();
    const installed = installSynchronizer({
      initial: authenticated("user-a"),
      priorState: `accepted:${digestA}`,
      responses: [forbidden.promise, { data: { status: "accepted" }, error: null }],
      tokens: ["token-a", "token-b"],
    });
    await vi.waitFor(() => expect(installed.$fetch).toHaveBeenCalledOnce());

    installed.session.emit(authenticated("user-b"));
    forbidden.resolve({ data: null, error: { status: 403 } });
    await drain(installed.window);

    expect(installed.client.reset).toHaveBeenCalledOnce();
    expect(installed.calls).not.toContain(`write:unassociated:${digestA}`);
    expect(installed.storage.values.get(storageKey)).toBe(`accepted:${digestB}`);
    expect(installed.$fetch).toHaveBeenCalledTimes(2);
  });

  it("uses page memory when localStorage is unavailable", async () => {
    const installed = installSynchronizer({
      initial: anonymous(),
      localStorageError: new DOMException("blocked", "SecurityError"),
      tokens: ["token-a"],
    });
    await drain(installed.window);
    installed.calls.length = 0;

    installed.session.emit(authenticated("user-a"));
    await drain(installed.window);

    expect(installed.client.reset).toHaveBeenCalledOnce();
    expect(installed.calls).toEqual([
      "token:token-a",
      `identify:${digestA}:token-a`,
    ]);
    expect(
      getPageState(installed.window).synchronizersByPublishableKey.get("sf_pk_test")
        ?.memoryState,
    ).toBe(`accepted:${digestA}`);
  });

  it.each([
    {
      initial: authenticated("user-a"),
      name: "changed user",
      next: authenticated("user-b"),
      resets: 2,
    },
    {
      initial: authenticated("user-a", "org-a"),
      name: "changed organization",
      next: authenticated("user-a", "org-b"),
      resets: 2,
    },
    {
      initial: authenticated("user-a", "org-a"),
      name: "same identity refresh",
      next: authenticated("user-a", "org-a"),
      resets: 1,
    },
  ])(
    "tracks a $name boundary in page memory when SubtleCrypto is unavailable",
    async ({ initial, next, resets }) => {
      vi.stubGlobal("crypto", {});
      const installed = installSynchronizer({ initial });
      await drain(installed.window);

      installed.session.emit(next);
      await drain(installed.window);

      expect(installed.client.reset).toHaveBeenCalledTimes(resets);
      expect(installed.client.start).toHaveBeenCalledOnce();
      expect(installed.$fetch).not.toHaveBeenCalled();
      expect(installed.storage.values.size).toBe(0);
    },
  );

  it("resets each new page without durable raw identity when SubtleCrypto is unavailable", async () => {
    vi.stubGlobal("crypto", {});
    const storage = createStorage();
    const firstPage = installSynchronizer({
      initial: authenticated("user-a"),
      storage,
    });
    await drain(firstPage.window);
    const secondPage = installSynchronizer({
      initial: authenticated("user-a"),
      storage,
    });
    await drain(secondPage.window);

    expect(firstPage.client.reset).toHaveBeenCalledOnce();
    expect(secondPage.client.reset).toHaveBeenCalledOnce();
    expect(firstPage.client.start).toHaveBeenCalledOnce();
    expect(secondPage.client.start).toHaveBeenCalledOnce();
    expect(firstPage.$fetch).not.toHaveBeenCalled();
    expect(secondPage.$fetch).not.toHaveBeenCalled();
    expect(storage.values.size).toBe(0);
  });

  it("isolates a hosted SDK load failure from Better Auth session results", async () => {
    const report = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const storage = createStorage();
    const { scripts, window } = installDom({ localStorage: storage.storage });
    const { store } = createStore(authenticated("user-a"));
    const $fetch = vi.fn();

    expect(() => getActions("sf_pk_test", undefined, { $fetch, $store: store })).not.toThrow();
    await settle();
    scripts[0]?.onerror?.();
    await drain(window);

    expect($fetch).not.toHaveBeenCalled();
    expect(report).toHaveBeenCalled();
  });

  it.each([
    {
      failure: "start",
      priorState: "anonymous",
      wantState: `unassociated:${digestA}`,
    },
    {
      failure: "reset",
      priorState: `accepted:${digestB}`,
      wantState: undefined,
    },
    {
      failure: "endpoint",
      priorState: "anonymous",
      wantState: `unassociated:${digestA}`,
    },
  ])(
    "isolates a $failure failure and leaves the safe boundary state",
    async ({ failure, priorState, wantState }) => {
      vi.spyOn(console, "error").mockImplementation(() => undefined);
      const rejection = Promise.reject(new Error(`${failure} failed`));
      void rejection.catch(() => undefined);
      const options =
        failure === "start"
          ? { start: rejection }
          : failure === "reset"
            ? { reset: rejection }
            : { responses: [rejection] };
      const installed = installSynchronizer({
        ...options,
        initial: authenticated("user-a"),
        priorState,
      });

      expect(() => installed.session.emit(authenticated("user-a"))).not.toThrow();
      await drain(installed.window);

      expect(installed.storage.values.get(storageKey)).toBe(wantState);
      if (failure === "reset") {
        expect(installed.$fetch).not.toHaveBeenCalled();
      }
    },
  );

  it("retries hosted client initialization on a later successful session result", async () => {
    const report = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const installed = installSynchronizer({
      initial: authenticated("user-a"),
      initError: new Error("init failed"),
      priorState: "anonymous",
    });
    await drain(installed.window);
    const testWindow = installed.window as typeof installed.window & {
      Switchfrog?: { init: ReturnType<typeof vi.fn> };
    };
    const init = testWindow.Switchfrog?.init;
    expect(init).toHaveBeenCalled();

    testWindow.Switchfrog = { init: vi.fn(() => installed.client) };
    installed.session.emit(authenticated("user-a"));
    await drain(installed.window);

    expect(installed.$fetch).toHaveBeenCalledOnce();
    expect(installed.storage.values.get(storageKey)).toBe(`accepted:${digestA}`);
    expect(report).toHaveBeenCalled();
  });

  it("keeps accepted state when same-identity reassertion fails", async () => {
    const installed = installSynchronizer({
      initial: authenticated("user-a"),
      priorState: `accepted:${digestA}`,
      responses: [{ data: null, error: { status: 502 } }],
    });

    await drain(installed.window);

    expect(installed.storage.values.get(storageKey)).toBe(`accepted:${digestA}`);
    expect(installed.client.reset).not.toHaveBeenCalled();
  });

  it("resets an uncertain association when later membership validation fails", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const lostResponse = Promise.reject(new TypeError("association response was lost"));
    void lostResponse.catch(() => undefined);
    const installed = installSynchronizer({
      initial: authenticated("user-a"),
      priorState: "anonymous",
      responses: [
        lostResponse,
        { data: null, error: { status: 403 } },
      ],
      tokens: ["token-a", "token-a"],
    });
    await drain(installed.window);

    expect(installed.storage.values.get(storageKey)).toBe(`unassociated:${digestA}`);
    expect(installed.client.reset).not.toHaveBeenCalled();

    installed.session.emit(authenticated("user-a"));
    await drain(installed.window);

    expect(installed.client.reset).toHaveBeenCalledOnce();
    expect(installed.storage.values.get(storageKey)).toBe(`unassociated:${digestA}`);
  });

  it("does not accept an unexpected success payload", async () => {
    const installed = installSynchronizer({
      initial: authenticated("user-a"),
      priorState: "anonymous",
      responses: [
        { data: { status: "unexpected" }, error: null },
        { data: { status: "accepted" }, error: null },
      ],
      tokens: ["token-a", "token-a"],
    });
    await drain(installed.window);

    expect(installed.storage.values.get(storageKey)).toBe(`unassociated:${digestA}`);

    installed.session.emit(authenticated("user-a"));
    await drain(installed.window);

    expect(installed.$fetch).toHaveBeenCalledTimes(2);
    expect(installed.storage.values.get(storageKey)).toBe(`accepted:${digestA}`);
  });

  it("forces envelope responses when the host fetch configuration throws", async () => {
    const installed = installSynchronizer({
      hostThrows: true,
      initial: authenticated("user-a"),
      priorState: "anonymous",
    });

    await drain(installed.window);

    expect(installed.storage.values.get(storageKey)).toBe(`accepted:${digestA}`);
    expect(installed.$fetch).toHaveBeenCalledWith(
      "/switchfrog/identify",
      expect.objectContaining({ throw: false }),
    );
  });

  it("handles 403 from accepted state once and waits for a later session result", async () => {
    const installed = installSynchronizer({
      initial: authenticated("user-a"),
      priorState: `accepted:${digestA}`,
      responses: [
        { data: null, error: { status: 403 } },
        { data: { status: "accepted" }, error: null },
      ],
      tokens: ["token-a", "token-a"],
    });
    await drain(installed.window);

    expect(installed.$fetch).toHaveBeenCalledOnce();
    expect(installed.client.reset).toHaveBeenCalledOnce();
    expect(installed.storage.values.get(storageKey)).toBe(`unassociated:${digestA}`);

    installed.session.emit(authenticated("user-a"));
    await drain(installed.window);

    expect(installed.$fetch).toHaveBeenCalledTimes(2);
    expect(installed.client.reset).toHaveBeenCalledOnce();
    expect(installed.storage.values.get(storageKey)).toBe(`accepted:${digestA}`);
  });

  it("handles 409 by resetting and retrying once with a new token", async () => {
    const installed = installSynchronizer({
      hostThrows: true,
      initial: authenticated("user-a"),
      priorState: `unassociated:${digestA}`,
      responses: [
        {
          data: null,
          error: {
            code: "SWITCHFROG_SESSION_REINIT_REQUIRED",
            status: 409,
          },
        },
        { data: { status: "accepted" }, error: null },
      ],
      tokens: ["old-token", "new-token"],
    });

    await drain(installed.window);

    expect(installed.calls).toEqual([
      "start",
      "token:old-token",
      `identify:${digestA}:old-token`,
      "remove",
      "reset",
      `write:unassociated:${digestA}`,
      "token:new-token",
      `identify:${digestA}:new-token`,
      `write:accepted:${digestA}`,
    ]);
    expect(installed.$fetch).toHaveBeenCalledTimes(2);
    expect(installed.client.reset).toHaveBeenCalledOnce();
  });

  it("does not perform stale 409 recovery after identity B arrives", async () => {
    const conflict = deferred<EndpointResult>();
    const installed = installSynchronizer({
      initial: authenticated("user-a"),
      priorState: `unassociated:${digestA}`,
      responses: [conflict.promise, { data: { status: "accepted" }, error: null }],
      tokens: ["token-a", "token-b"],
    });
    await vi.waitFor(() => expect(installed.$fetch).toHaveBeenCalledOnce());

    installed.session.emit(authenticated("user-b"));
    conflict.resolve({
      data: null,
      error: {
        code: "SWITCHFROG_SESSION_REINIT_REQUIRED",
        status: 409,
      },
    });
    await drain(installed.window);

    expect(installed.calls).not.toContain(`write:unassociated:${digestA}`);
    expect(installed.client.reset).toHaveBeenCalledOnce();
    expect(installed.$fetch).toHaveBeenCalledTimes(2);
    expect(installed.storage.values.get(storageKey)).toBe(`accepted:${digestB}`);
  });

  it("handles 412 by notifying once without reset", async () => {
    const installed = installSynchronizer({
      hostThrows: true,
      initial: authenticated("user-a"),
      priorState: `unassociated:${digestA}`,
      responses: [
        {
          data: null,
          error: { code: "SWITCHFROG_IDENTITY_CHANGED", status: 412 },
        },
      ],
    });

    await drain(installed.window);

    expect(installed.store.notify).toHaveBeenCalledExactlyOnceWith("$sessionSignal");
    expect(installed.client.reset).not.toHaveBeenCalled();
    expect(installed.storage.values.get(storageKey)).toBe(`unassociated:${digestA}`);
    expect(installed.$fetch).toHaveBeenCalledOnce();
  });
});

describe("Better Auth collection permission", () => {
  it("holds before digest storage, hashing, startup and auth snapshots", async () => {
    const storage = createStorage();
    const read = vi.spyOn(storage.storage, "getItem");
    const hash = vi.spyOn(crypto.subtle, "digest");
    const installed = installSynchronizer({
      initial: authenticated("user-a"),
      allowed: false,
      waitForConsent: true,
      storage,
    });
    await drain(installed.window);
    installed.session.emit(authenticated("user-b"));
    await drain(installed.window);
    expect(read).not.toHaveBeenCalled();
    expect(hash).not.toHaveBeenCalled();
    expect(installed.calls).toEqual([]);
    expect(installed.window.Switchfrog?.init).toHaveBeenCalledWith(
      "sf_pk_test",
      {
        waitForConsent: true,
      },
    );
  });

  it("validates old hosted capabilities before digest work", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const storage = createStorage();
    const read = vi.spyOn(storage.storage, "getItem");
    const hash = vi.spyOn(crypto.subtle, "digest");
    const { window } = installDom({ localStorage: storage.storage });
    const start = vi.fn();
    window.Switchfrog = {
      init: () => ({ start, reset: vi.fn(), getSessionToken: vi.fn() }),
    };
    getActions("sf_pk_test", undefined, {
      $store: createStore(authenticated("user-a")).store,
    });
    await drain(window);
    expect(read).not.toHaveBeenCalled();
    expect(hash).not.toHaveBeenCalled();
    expect(start).not.toHaveBeenCalled();
  });

  it.each(["user-a", "user-b", null])(
    "rereads current auth on grant: %s",
    async (currentUser) => {
      let installed!: ReturnType<typeof installSynchronizer>;
      installed = installSynchronizer({
        initial: authenticated("user-a"),
        notify: () =>
          installed.session.emit(
            currentUser === null ? anonymous() : authenticated(currentUser),
          ),
        tokens: ["token-a", "token-new"],
      });
      await drain(installed.window);
      await installed.client.optOut();
      expect(installed.storage.values.has(storageKey)).toBe(false);
      installed.session.emit(authenticated("discard-me"));
      await drain(installed.window);
      installed.calls.length = 0;
      await installed.client.optIn();
      await drain(installed.window);
      expect(installed.store.notify).toHaveBeenCalledExactlyOnceWith(
        "$sessionSignal",
      );
      expect(installed.storage.values.get(storageKey)).toBe(
        currentUser === null
          ? "anonymous"
          : `accepted:${currentUser === "user-a" ? digestA : digestB}`,
      );
      expect(installed.calls).not.toContain(`identify:${digestA}:token-a`);
      expect(installed.calls).toContain("start");
    },
  );

  it("discards an old token and queued auth snapshot on withdrawal", async () => {
    const token = deferred<string>();
    const installed = installSynchronizer({
      initial: authenticated("user-a"),
      priorState: `accepted:${digestA}`,
      tokens: [token.promise],
    });
    await vi.waitFor(() =>
      expect(installed.client.getSessionToken).toHaveBeenCalledOnce(),
    );
    installed.session.emit(authenticated("user-b"));
    await installed.client.optOut();
    expect(getPageState(installed.window).synchronizersByPublishableKey.get("sf_pk_test")).toMatchObject({
      pendingResult: undefined,
      currentDigest: undefined,
      lastAccepted: undefined,
      lastStoredIdentity: null,
      memoryState: null,
      unhashableIdentityKey: undefined,
      started: false,
    });
    token.resolve("token-old");
    await drain(installed.window);
    await settle();
    expect(installed.$fetch).not.toHaveBeenCalled();
    expect(installed.storage.values.has(storageKey)).toBe(false);
  });

  it.each([200, 412, 403, 409])(
    "discards a late %s response after withdrawal",
    async (status) => {
      const response = deferred<EndpointResult>();
      const installed = installSynchronizer({
        initial: authenticated("user-a"),
        responses: [response.promise],
      });
      await vi.waitFor(() => expect(installed.$fetch).toHaveBeenCalledOnce());
      const signal = installed.$fetch.mock.calls[0]?.[1].signal;
      await installed.client.optOut();
      response.resolve(
        status === 200
          ? { data: { status: "accepted" }, error: null }
          : {
              data: null,
              error: {
                status,
                code:
                  status === 412
                    ? "SWITCHFROG_IDENTITY_CHANGED"
                    : "SWITCHFROG_SESSION_REINIT_REQUIRED",
              },
            },
      );
      await settle();
      await drain(installed.window);
      expect(signal?.aborted).toBe(true);
      expect(installed.store.notify).not.toHaveBeenCalled();
      expect(installed.storage.values.has(storageKey)).toBe(false);
      expect(installed.$fetch).toHaveBeenCalledOnce();
    },
  );

  it.each(["request", "retry", "canonical request"])(
    "blocks actual Better Fetch dispatch after delayed %s hooks",
    async (phase) => {
      const require = createRequire(import.meta.url);
      const betterFetchPath = createRequire(
        require.resolve("better-auth/client"),
      ).resolve("@better-fetch/fetch");
      const { createFetch } = await import(betterFetchPath);
      const gate = deferred<void>();
      const entered = vi.fn();
      const network = vi.fn(async (_url: unknown, options: RequestInit) => {
        options.signal?.throwIfAborted();
        return Response.json({ error: "retry" }, { status: 503 });
      });
      const fetchOptions = {
        customFetchImpl: network,
        retry: { type: "linear", attempts: 1, delay: 0 },
        ...(phase !== "retry"
          ? {
              plugins: [
                {
                  id: "delay",
                  name: "delay",
                  hooks: {
                    onRequest: async () => {
                      entered();
                      await gate.promise;
                    },
                  },
                },
              ],
            }
          : {
              onRetry: async () => {
                entered();
                await gate.promise;
              },
            }),
      };
      const $fetch = vi.fn(
        createFetch({ baseURL: "https://auth.example", ...fetchOptions }),
      );
      const installed = installSynchronizer({
        initial: authenticated("user-a"),
        fetch: $fetch,
      });
      await vi.waitFor(() => expect(entered).toHaveBeenCalledOnce());
      if (phase === "canonical request") {
        // Model a missed storage event discovered by the SDK's next public snapshot.
        installed.client.onConsentChange.mockImplementationOnce((listener) => {
          void installed.client.optOut();
          listener(false);
          return () => undefined;
        });
      } else {
        await installed.client.optOut();
      }
      gate.resolve();
      await drain(installed.window);
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(network).toHaveBeenCalledTimes(phase === "retry" ? 1 : 0);
      expect(installed.storage.values.has(storageKey)).toBe(false);
    },
  );
});

describe("Better Auth permission races", () => {
  it("retains the digest cache format after an initial wait and fresh auth read", async () => {
    let installed!: ReturnType<typeof installSynchronizer>;
    installed = installSynchronizer({
      initial: authenticated("stale-user"),
      allowed: false,
      waitForConsent: true,
      priorState: `accepted:${digestA}`,
      notify: () => installed.session.emit(authenticated("user-a")),
      tokens: ["token-new"],
    });
    await drain(installed.window);
    await installed.client.optIn();
    await drain(installed.window);
    expect(installed.calls).toContain(`identify:${digestA}:token-new`);
    expect(installed.calls).toContain(`write:accepted:${digestA}`);
    expect(installed.client.reset).not.toHaveBeenCalled();
  });

  it("regrants without waiting for or replaying a revoked digest computation", async () => {
    const hash = deferred<ArrayBuffer>();
    const digest = vi
      .spyOn(crypto.subtle, "digest")
      .mockImplementationOnce(() => hash.promise);
    let installed!: ReturnType<typeof installSynchronizer>;
    installed = installSynchronizer({
      initial: authenticated("user-a"),
      notify: () => installed.session.emit(authenticated("user-b")),
    });
    await vi.waitFor(() => expect(digest).toHaveBeenCalledOnce());
    await installed.client.optOut();
    await installed.client.optIn();
    await drain(installed.window);
    expect(installed.storage.values.get(storageKey)).toBe(
      `accepted:${digestB}`,
    );
    hash.resolve(new Uint8Array(32).buffer);
    await settle();
    expect(installed.$fetch).toHaveBeenCalledOnce();
    expect(installed.storage.values.get(storageKey)).toBe(
      `accepted:${digestB}`,
    );
  });

  it("suppresses expected cancellation but still reports unrelated startup failures", async () => {
    const report = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);
    const cancelled = Promise.reject(
      new DOMException("superseded", "AbortError"),
    );
    void cancelled.catch(() => undefined);
    const installed = installSynchronizer({
      initial: anonymous(),
      start: cancelled,
    });
    await drain(installed.window);
    expect(report).not.toHaveBeenCalled();
    installed.client.start.mockRejectedValueOnce(new Error("unexpected"));
    installed.session.emit(anonymous());
    await drain(installed.window);
    expect(report).toHaveBeenCalledOnce();
  });

  it("rejects conflicting explicit repeated configuration while allowing omitted reuse", async () => {
    const installed = installSynchronizer({
      initial: pending(),
      allowed: false,
      waitForConsent: true,
    });
    await drain(installed.window);
    expect(() => getActions("sf_pk_test")).not.toThrow();
    expect(() =>
      switchfrogClient({
        publishableKey: "sf_pk_test",
        waitForConsent: true,
      }).getActions?.(vi.fn() as never, createStore().store as never, {}),
    ).not.toThrow();
    expect(() =>
      switchfrogClient({
        publishableKey: "sf_pk_test",
        waitForConsent: false,
      }).getActions?.(vi.fn() as never, createStore().store as never, {}),
    ).toThrow(TypeError);
    expect(() =>
      switchfrogClient({
        publishableKey: "sf_pk_test",
        waitForConsent: "true" as never,
      }),
    ).toThrow(TypeError);
  });
});

describe("Better Auth inherited SDK configuration", () => {
  it("validates explicit reuse against a held SDK originally reused with omitted options", async () => {
    const installed = installSynchronizer({ initial: pending(), allowed: false });
    await drain(installed.window);
    installed.window.Switchfrog = {
      init: (_key: string, options?: { waitForConsent?: boolean }) => {
        if (options?.waitForConsent === false) throw new TypeError("conflicting SDK configuration");
        return installed.client;
      },
    };
    const apply = (waitForConsent: boolean) => switchfrogClient({ publishableKey: "sf_pk_test", waitForConsent }).getActions?.(vi.fn() as never, createStore().store as never, {});
    expect(() => apply(false)).toThrow(TypeError);
    expect(() => apply(true)).not.toThrow();
  });
});


it("does not mark a withdrawn synchronizer started when old startup resolves", async () => {
  const start = deferred<void>();
  const installed = installSynchronizer({ initial: authenticated("user-a"), start: start.promise });
  await vi.waitFor(() => expect(installed.client.start).toHaveBeenCalledOnce());
  await installed.client.optOut();
  start.resolve();
  await settle();
  expect(getPageState(installed.window).synchronizersByPublishableKey.get("sf_pk_test")).toMatchObject({ started: false });
  expect(installed.client.getSessionToken).not.toHaveBeenCalled();
  expect(installed.storage.values.has(storageKey)).toBe(false);
});

it("keeps the adapter in memory after digest-storage failure and regrant", async () => {
  const storage = createStorage();
  const read = vi.spyOn(storage.storage, "getItem").mockImplementationOnce(() => { throw new DOMException("blocked", "SecurityError"); });
  const write = vi.spyOn(storage.storage, "setItem");
  let installed!: ReturnType<typeof installSynchronizer>;
  installed = installSynchronizer({ initial: authenticated("user-a"), storage, notify: () => installed.session.emit(authenticated("user-b")) });
  await drain(installed.window);
  await installed.client.optOut();
  await installed.client.optIn();
  await drain(installed.window);
  expect(read).toHaveBeenCalledOnce();
  expect(write).not.toHaveBeenCalled();
  expect(getPageState(installed.window).synchronizersByPublishableKey.get("sf_pk_test")).toMatchObject({ memoryState: `accepted:${digestB}` });
});

it.each([
  { phase: "request", allowed: false, dispatches: 0 },
  { phase: "request", allowed: true, dispatches: 1 },
  { phase: "retry", allowed: true, dispatches: 2 },
  { phase: "retry", allowed: false, dispatches: 1 },
])(
  "guards the host plugin's $phase boundary (allowed=$allowed)",
  async ({ phase, allowed, dispatches }) => {
    const require = createRequire(import.meta.url);
    const { createFetch } = await import(
      createRequire(require.resolve("better-auth/client")).resolve("@better-fetch/fetch")
    );
    const gate = deferred<void>();
    const entered = vi.fn();
    const fallback = vi.fn();
    const selectedTransport = vi.fn(async function (this: unknown, _url: unknown, request: RequestInit) {
      expect(this).toBeUndefined();
      request.signal?.throwIfAborted();
      return Response.json({ status: "accepted" }, { status: phase === "retry" ? 503 : 200 });
    });
    const fetchOptions = {
      customFetchImpl: fallback,
      retry: { type: "linear", attempts: 1, delay: 0 },
      plugins: [{
        id: "host-transport",
        name: "Host transport",
        init: (url: string, options: Record<string, unknown>) => {
          options.customFetchImpl = selectedTransport;
          return { url, options };
        },
        hooks: {
          onRequest: async (request: RequestInit) => {
            if (phase === "request") { entered(); await gate.promise; }
            return { ...request, signal: new AbortController().signal };
          },
          onRetry: async () => {
            if (phase === "retry") { entered(); await gate.promise; }
          },
        },
      }],
    };
    const $fetch = vi.fn(createFetch({ baseURL: "https://auth.example", ...fetchOptions }));
    const installed = installSynchronizer({ initial: authenticated("user-a"), fetch: $fetch });
    await vi.waitFor(() => expect(entered).toHaveBeenCalledOnce());
    if (!allowed) {
      installed.client.onConsentChange.mockImplementationOnce((listener) => {
        void installed.client.optOut();
        listener(false);
        return () => undefined;
      });
    }
    gate.resolve();
    await drain(installed.window);
    expect(selectedTransport).toHaveBeenCalledTimes(dispatches);
    expect(fallback).not.toHaveBeenCalled();
    const originalRequest = $fetch.mock.calls[0]?.[1] as { signal?: AbortSignal };
    for (const [, request] of selectedTransport.mock.calls) {
      expect(request.signal).toBe(originalRequest.signal);
    }
    if (allowed && phase === "request") expect(installed.storage.values.get(storageKey)).toBe(`accepted:${digestA}`);
  },
);


it("preserves configured Better Fetch schema transformations", async () => {
  const require = createRequire(import.meta.url);
  const { createFetch, createSchema } = await import(
    createRequire(require.resolve("better-auth/client")).resolve("@better-fetch/fetch")
  );
  const bodies: unknown[] = [];
  const transport = vi.fn(async (_url: unknown, request: RequestInit) => {
    bodies.push(JSON.parse(String(request.body)));
    return Response.json({ status: "accepted" });
  });
  const fetchOptions = {
    customFetchImpl: transport,
    schema: createSchema({
      "/switchfrog/identify": {
        input: z.object({ sessionToken: z.string(), expectedIdentityDigest: z.string() })
          .transform((body) => ({ ...body, schemaApplied: true })),
      },
    }),
  };
  const $fetch = vi.fn(createFetch({ baseURL: "https://auth.example", ...fetchOptions }));
  const installed = installSynchronizer({ initial: authenticated("user-a"), fetch: $fetch });
  await drain(installed.window);
  expect(bodies).toEqual([{ sessionToken: "token-a", expectedIdentityDigest: digestA, schemaApplied: true }]);
  expect(installed.storage.values.get(storageKey)).toBe(`accepted:${digestA}`);
});
