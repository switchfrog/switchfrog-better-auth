import type { BetterAuthClientPlugin } from "better-auth/client";

import { computeIdentityDigest } from "./identity-digest";

type HostedClient = Readonly<{
  start(): Promise<void>;
  getSessionToken(): Promise<string>;
  reset(): Promise<void>;
}>;

type SwitchfrogGlobal = Readonly<{
  init(publishableKey: string): HostedClient;
}>;

type ClientFetch = Parameters<
  NonNullable<BetterAuthClientPlugin["getActions"]>
>[0];

type ClientStore = Parameters<
  NonNullable<BetterAuthClientPlugin["getActions"]>
>[1];

type StoredIdentityState =
  | "anonymous"
  | `unassociated:${string}`
  | `accepted:${string}`;

type Synchronizer = {
  activeAssociation?: AbortController;
  authScope: string;
  clientPromise?: Promise<HostedClient>;
  currentDigest?: string;
  fetch: ClientFetch;
  lastAccepted?: Readonly<{ digest: string; sessionToken: string }>;
  memoryState: StoredIdentityState | null;
  pageState: PageState;
  publishableKey: string;
  queue: Promise<void>;
  revision: number;
  started: boolean;
  storage?: Storage;
  lastStoredIdentity: string | null;
  storageKey: string;
  store: ClientStore;
  unhashableIdentityKey?: string;
};

type PageState = {
  sdkPromise?: Promise<SwitchfrogGlobal>;
  synchronizersByPublishableKey: Map<string, Synchronizer>;
};

const pageStateKey = Symbol.for("switchfrog.better-auth.client.state");
const hostedSdkUrl = "https://api.switchfrog.com/sdk/v1.js";

function parseStoredIdentityState(value: string | null): StoredIdentityState | null {
  if (value === "anonymous") return value;
  return /^(unassociated|accepted):[0-9a-f]{64}$/.test(value ?? "")
    ? (value as StoredIdentityState)
    : null;
}

function identityFromStoredState(state: StoredIdentityState | null): string | null {
  if (state === null || state === "anonymous") return state;
  return state.slice(state.indexOf(":") + 1);
}

function readStoredState(synchronizer: Synchronizer): StoredIdentityState | null {
  if (!synchronizer.storage) return synchronizer.memoryState;
  try {
    return parseStoredIdentityState(
      synchronizer.storage.getItem(synchronizer.storageKey),
    );
  } catch {
    synchronizer.storage = undefined;
    synchronizer.memoryState = null;
    return null;
  }
}

function removeStoredState(synchronizer: Synchronizer): void {
  synchronizer.memoryState = null;
  if (!synchronizer.storage) return;
  try {
    synchronizer.storage.removeItem(synchronizer.storageKey);
  } catch {
    synchronizer.storage = undefined;
  }
}

function writeStoredState(
  synchronizer: Synchronizer,
  value: StoredIdentityState,
): void {
  synchronizer.memoryState = value;
  synchronizer.lastStoredIdentity = identityFromStoredState(value);
  if (!synchronizer.storage) return;
  try {
    synchronizer.storage.setItem(synchronizer.storageKey, value);
  } catch {
    synchronizer.storage = undefined;
  }
}

function installedGlobal(): SwitchfrogGlobal | null {
  const candidate = (window as Window & { Switchfrog?: SwitchfrogGlobal })
    .Switchfrog;
  return candidate && typeof candidate.init === "function" ? candidate : null;
}

async function loadHostedSdk(state: PageState): Promise<SwitchfrogGlobal> {
  const installed = installedGlobal();
  if (installed) return installed;
  if (state.sdkPromise) return state.sdkPromise;

  const script = document.createElement("script");
  script.async = true;
  script.src = hostedSdkUrl;

  const promise = new Promise<SwitchfrogGlobal>((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      script.onload = null;
      script.onerror = null;
      const loaded = installedGlobal();
      if (!error && loaded) resolve(loaded);
      else {
        script.remove();
        reject(error ?? new Error("Hosted Switchfrog SDK did not install its global"));
      }
    };
    const timeout = setTimeout(
      () => finish(new Error("Hosted Switchfrog SDK load timed out")),
      10_000,
    );
    script.onload = () => finish();
    script.onerror = () => finish(new Error("Hosted Switchfrog SDK failed to load"));
    try {
      document.head.append(script);
    } catch (error) {
      finish(error instanceof Error ? error : new Error(String(error)));
    }
  });

  state.sdkPromise = promise;
  void promise.catch(() => {
    if (state.sdkPromise === promise) state.sdkPromise = undefined;
  });
  return promise;
}

function getHostedClient(synchronizer: Synchronizer): Promise<HostedClient> {
  if (synchronizer.clientPromise) return synchronizer.clientPromise;

  const promise = loadHostedSdk(synchronizer.pageState).then((sdk) =>
    sdk.init(synchronizer.publishableKey),
  );
  synchronizer.clientPromise = promise;
  void promise.catch(() => {
    if (synchronizer.clientPromise === promise) {
      synchronizer.clientPromise = undefined;
    }
  });
  return promise;
}

type ResolvedIdentity =
  | Readonly<{ kind: "anonymous" }>
  | Readonly<{
      accountId: string | null;
      kind: "authenticated";
      userId: string;
    }>;

function resolveIdentity(result: unknown): ResolvedIdentity | null {
  if (typeof result !== "object" || result === null) return null;
  const candidate = result as {
    data?: unknown;
    error?: unknown;
    isPending?: unknown;
    isRefetching?: unknown;
  };
  if (
    candidate.isPending === true ||
    candidate.isRefetching === true ||
    candidate.error != null
  ) {
    return null;
  }
  if (candidate.data === null) return { kind: "anonymous" };
  if (typeof candidate.data !== "object" || candidate.data === null) return null;

  const data = candidate.data as { session?: unknown; user?: unknown };
  if (typeof data.user !== "object" || data.user === null) return null;
  const userId = (data.user as { id?: unknown }).id;
  if (typeof userId !== "string" || userId.trim().length === 0) return null;
  const activeOrganizationId =
    typeof data.session === "object" && data.session !== null
      ? (data.session as { activeOrganizationId?: unknown }).activeOrganizationId
      : null;
  const accountId =
    typeof activeOrganizationId === "string" &&
    activeOrganizationId.trim().length > 0
      ? activeOrganizationId
      : null;

  return {
    accountId,
    kind: "authenticated",
    userId,
  };
}

function isCurrent(
  synchronizer: Synchronizer,
  revision: number,
  digest?: string,
  storedState?: StoredIdentityState | null,
): boolean {
  if (
    synchronizer.revision !== revision ||
    (digest !== undefined && synchronizer.currentDigest !== digest)
  ) {
    return false;
  }
  return storedState === undefined || readStoredState(synchronizer) === storedState;
}

function advanceRevision(synchronizer: Synchronizer): number {
  synchronizer.activeAssociation?.abort();
  return ++synchronizer.revision;
}

async function startIfNeeded(
  synchronizer: Synchronizer,
  client: HostedClient,
): Promise<void> {
  if (synchronizer.started) return;
  await client.start();
  synchronizer.started = true;
}

async function associateIdentity(
  synchronizer: Synchronizer,
  client: HostedClient,
  digest: string,
  revision: number,
  expectedState: `accepted:${string}` | `unassociated:${string}`,
  allowReinitialization: boolean,
): Promise<void> {
  if (!isCurrent(synchronizer, revision, digest, expectedState)) return;
  const sessionToken = await client.getSessionToken();
  if (!isCurrent(synchronizer, revision, digest, expectedState)) return;
  if (
    synchronizer.lastAccepted?.digest === digest &&
    synchronizer.lastAccepted.sessionToken === sessionToken
  ) {
    return;
  }

  const controller = new AbortController();
  synchronizer.activeAssociation = controller;
  const response = await (async () => {
    try {
      return await synchronizer.fetch("/switchfrog/identify", {
        method: "POST",
        body: { sessionToken, expectedIdentityDigest: digest },
        signal: controller.signal,
        throw: false,
      });
    } catch (error) {
      if (controller.signal.aborted) return null;
      throw error;
    } finally {
      if (synchronizer.activeAssociation === controller) {
        synchronizer.activeAssociation = undefined;
      }
    }
  })();
  if (response === null) return;
  const { data, error } = response;
  if (
    error?.status === 412 &&
    "code" in error &&
    error.code === "SWITCHFROG_IDENTITY_CHANGED"
  ) {
    synchronizer.store.notify("$sessionSignal");
    return;
  }
  if (!isCurrent(synchronizer, revision, digest, expectedState)) return;

  if (
    error === null &&
    typeof data === "object" &&
    data !== null &&
    "status" in data &&
    data.status === "accepted"
  ) {
    writeStoredState(synchronizer, `accepted:${digest}`);
    synchronizer.lastAccepted = { digest, sessionToken };
    return;
  }
  if (error?.status === 403) {
    removeStoredState(synchronizer);
    synchronizer.lastAccepted = undefined;
    await client.reset();
    if (!isCurrent(synchronizer, revision, digest, null)) return;
    writeStoredState(synchronizer, `unassociated:${digest}`);
    return;
  }
  if (
    allowReinitialization &&
    error?.status === 409 &&
    "code" in error &&
    error.code === "SWITCHFROG_SESSION_REINIT_REQUIRED"
  ) {
    removeStoredState(synchronizer);
    synchronizer.lastAccepted = undefined;
    const retryRevision = ++synchronizer.revision;
    await client.reset();
    if (!isCurrent(synchronizer, retryRevision, digest, null)) return;
    const retryState = `unassociated:${digest}` as const;
    writeStoredState(synchronizer, retryState);
    await associateIdentity(
      synchronizer,
      client,
      digest,
      retryRevision,
      retryState,
      false,
    );
  }
}

async function syncUnhashableIdentity(
  synchronizer: Synchronizer,
  revision: number,
  clientPromise: Promise<HostedClient>,
  identityKey: string,
): Promise<void> {
  if (
    synchronizer.unhashableIdentityKey === identityKey &&
    readStoredState(synchronizer) === null
  ) {
    const client = await clientPromise;
    if (isCurrent(synchronizer, revision)) {
      await startIfNeeded(synchronizer, client);
    }
    return;
  }

  removeStoredState(synchronizer);
  synchronizer.lastAccepted = undefined;
  const client = await clientPromise;
  if (!isCurrent(synchronizer, revision, undefined, null)) return;
  await client.reset();
  if (!isCurrent(synchronizer, revision, undefined, null)) return;
  synchronizer.unhashableIdentityKey = identityKey;
  await startIfNeeded(synchronizer, client);
}

async function syncIdentity(
  synchronizer: Synchronizer,
  result: unknown,
  revision: number,
): Promise<void> {
  if (synchronizer.revision !== revision) return;
  const identity = resolveIdentity(result);
  if (!identity) return;
  const clientPromise = getHostedClient(synchronizer);

  if (identity.kind === "anonymous") {
    synchronizer.currentDigest = undefined;
    synchronizer.unhashableIdentityKey = undefined;
    const storedState = readStoredState(synchronizer);
    if (storedState !== "anonymous") {
      removeStoredState(synchronizer);
      synchronizer.lastAccepted = undefined;
      const client = await clientPromise;
      if (!isCurrent(synchronizer, revision, undefined, null)) return;
      await client.reset();
      if (!isCurrent(synchronizer, revision, undefined, null)) return;
      writeStoredState(synchronizer, "anonymous");
      await startIfNeeded(synchronizer, client);
      return;
    }
    const client = await clientPromise;
    if (!isCurrent(synchronizer, revision, undefined, "anonymous")) return;
    await startIfNeeded(synchronizer, client);
    return;
  }

  if (typeof globalThis.crypto?.subtle?.digest !== "function") {
    await syncUnhashableIdentity(
      synchronizer,
      revision,
      clientPromise,
      JSON.stringify([identity.userId, identity.accountId]),
    );
    return;
  }

  synchronizer.unhashableIdentityKey = undefined;
  const digest = await computeIdentityDigest(identity.userId, identity.accountId);
  if (synchronizer.revision !== revision) return;
  synchronizer.currentDigest = digest;
  const storedState = readStoredState(synchronizer);
  const acceptedState = `accepted:${digest}` as const;
  const unassociatedState = `unassociated:${digest}` as const;
  let associationState: typeof acceptedState | typeof unassociatedState;
  let client: HostedClient;

  if (storedState === "anonymous") {
    associationState = unassociatedState;
    writeStoredState(synchronizer, associationState);
    client = await clientPromise;
  } else if (storedState === acceptedState || storedState === unassociatedState) {
    associationState = storedState;
    client = await clientPromise;
  } else {
    removeStoredState(synchronizer);
    synchronizer.lastAccepted = undefined;
    client = await clientPromise;
    if (!isCurrent(synchronizer, revision, digest, null)) return;
    await client.reset();
    if (!isCurrent(synchronizer, revision, digest, null)) return;
    associationState = unassociatedState;
    writeStoredState(synchronizer, associationState);
  }

  if (!isCurrent(synchronizer, revision, digest, associationState)) return;
  await startIfNeeded(synchronizer, client);
  if (!isCurrent(synchronizer, revision, digest, associationState)) return;
  await associateIdentity(
    synchronizer,
    client,
    digest,
    revision,
    associationState,
    true,
  );
}

export function switchfrogClient(
  options: Readonly<{ publishableKey: string }>,
): BetterAuthClientPlugin {
  const publishableKey = options.publishableKey.trim();
  if (!publishableKey.startsWith("sf_pk_") || publishableKey.length === 6) {
    throw new TypeError("publishableKey must be a Switchfrog publishable key");
  }

  return {
    id: "switchfrog",
    getActions($fetch, $store, clientOptions) {
      if (typeof window === "undefined" || typeof document === "undefined") {
        return {};
      }

      const pageWindow = window as unknown as Window & Record<symbol, unknown>;
      const state = (pageWindow[pageStateKey] ??= {
        synchronizersByPublishableKey: new Map(),
      }) as PageState;
      const authScope = JSON.stringify([
        clientOptions?.baseURL ?? null,
        clientOptions?.basePath ?? null,
      ]);
      const existing = state.synchronizersByPublishableKey.get(publishableKey);
      if (existing) {
        if (existing.authScope !== authScope) {
          console.error("Switchfrog Better Auth client already owns this publishable key");
        }
        return {};
      }

      let storage: Storage | undefined;
      try {
        storage = window.localStorage;
      } catch {
        // Page memory is the safe fallback when durable storage is unavailable.
      }
      const synchronizer: Synchronizer = {
        authScope,
        fetch: $fetch,
        memoryState: null,
        pageState: state,
        publishableKey,
        queue: Promise.resolve(),
        revision: 0,
        started: false,
        storage,
        lastStoredIdentity: null,
        storageKey: `switchfrog:better-auth:v1:${publishableKey}`,
        store: $store,
      };
      synchronizer.lastStoredIdentity = identityFromStoredState(
        readStoredState(synchronizer),
      );
      state.synchronizersByPublishableKey.set(publishableKey, synchronizer);
      void getHostedClient(synchronizer).catch((error) =>
        console.error("Switchfrog Better Auth client failed to initialize", error),
      );
      $store.atoms.session.subscribe((result) => {
        synchronizer.currentDigest = undefined;
        const revision = advanceRevision(synchronizer);
        synchronizer.queue = synchronizer.queue
          .then(() => syncIdentity(synchronizer, result, revision))
          .catch(() => console.error("Switchfrog Better Auth identity synchronization failed"));
      });
      window.addEventListener?.("storage", (event) => {
        if (event.key !== synchronizer.storageKey) return;
        advanceRevision(synchronizer);
        const nextState = parseStoredIdentityState(event.newValue);
        const nextIdentity = identityFromStoredState(nextState);
        if (
          nextIdentity === null ||
          (nextIdentity === synchronizer.lastStoredIdentity &&
            !nextState?.startsWith("accepted:"))
        ) {
          return;
        }
        synchronizer.lastStoredIdentity = nextIdentity;
        synchronizer.store.notify("$sessionSignal");
      });
      return {};
    },
  } satisfies BetterAuthClientPlugin;
}
