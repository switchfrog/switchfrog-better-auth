import { organization } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { computeIdentityDigest } from "../src/identity-digest";
import { switchfrog } from "../src/index";

const baseURL = "http://localhost:3000/api/auth";
const upstreamFetch = vi.fn<typeof fetch>();

beforeEach(() => {
  upstreamFetch.mockReset();
  upstreamFetch.mockResolvedValue(Response.json({ status: "accepted" }));
  vi.stubGlobal("fetch", upstreamFetch);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

async function requestIdentify(
  instance: Readonly<{
    customFetchImpl: (
      url: string | URL | Request,
      init?: RequestInit,
    ) => Promise<Response>;
  }>,
  options: Readonly<{
    body: unknown;
    headers?: Headers;
    origin?: string;
  }>,
): Promise<Response> {
  const headers = new Headers(options.headers);
  headers.set("content-type", "application/json");
  headers.set("origin", options.origin ?? "http://localhost:3000");

  return instance.customFetchImpl(`${baseURL}/switchfrog/identify`, {
    method: "POST",
    headers,
    body: JSON.stringify(options.body),
  });
}

describe("computeIdentityDigest", () => {
  it("hashes the canonical JSON identity tuple", async () => {
    await expect(computeIdentityDigest("usr_123", null)).resolves.toBe(
      "837b4ea3e2fdcdf282b7f39a4662dde934e53beab404dab23756a8feb307daac",
    );
    await expect(computeIdentityDigest("usr_123", "acct_456")).resolves.not.toBe(
      await computeIdentityDigest("acct_456", "usr_123"),
    );
    await expect(computeIdentityDigest("usr_123", "")).resolves.not.toBe(
      await computeIdentityDigest("usr_123", null),
    );
  });
});

describe("switchfrog", () => {
  it.each(["", "   ", "sf_pk_test", "secret", "sf_sk_"])(
    "rejects an invalid Site secret key %#",
    (siteSecretKey) => {
      expect(() => switchfrog({ siteSecretKey })).toThrow(TypeError);
    },
  );

  it("accepts a Site secret key without serializing it into plugin metadata", () => {
    const plugin = switchfrog({ siteSecretKey: " sf_sk_test " });

    expect(plugin.id).toBe("switchfrog");
    expect(Object.keys(plugin.endpoints ?? {})).toEqual(["identifySession"]);
    expect(JSON.stringify(plugin)).not.toContain("sf_sk_test");
  });

  it("requires an authoritative Better Auth session", async () => {
    const instance = await getTestInstance({
      plugins: [switchfrog({ siteSecretKey: "sf_sk_test" })],
    });

    const response = await requestIdentify(instance, {
      body: {
        sessionToken: "sf_session",
        expectedIdentityDigest: "0".repeat(64),
      },
    });

    expect(response.status).toBe(401);
    expect(upstreamFetch).not.toHaveBeenCalled();
  });

  it.each([
    {},
    { sessionToken: " ", expectedIdentityDigest: "0".repeat(64) },
    {
      sessionToken: "sf_session",
      expectedIdentityDigest: "ABC".repeat(21) + "A",
    },
    {
      sessionToken: "sf_session",
      expectedIdentityDigest: "0".repeat(64),
      userId: "browser-controlled",
    },
  ])("rejects an invalid strict body", async (body) => {
    const instance = await getTestInstance({
      plugins: [switchfrog({ siteSecretKey: "sf_sk_test" })],
    });
    const signedIn = await instance.signInWithTestUser();

    const response = await requestIdentify(instance, {
      body,
      headers: signedIn.headers,
    });

    expect(response.status).toBe(400);
    expect(upstreamFetch).not.toHaveBeenCalled();
  });

  it("derives user and active organization identity and freshly confirms membership", async () => {
    const instance = await getTestInstance({
      plugins: [organization(), switchfrog({ siteSecretKey: "sf_sk_test" })],
    });
    const signedIn = await instance.signInWithTestUser();
    const createdOrganization = await instance.auth.api.createOrganization({
      headers: signedIn.headers,
      body: { name: "Test Organization", slug: "test-organization" },
    });
    await instance.auth.api.setActiveOrganization({
      headers: signedIn.headers,
      body: { organizationId: createdOrganization.id },
    });
    const expectedIdentityDigest = await computeIdentityDigest(
      signedIn.user.id,
      createdOrganization.id,
    );

    const response = await requestIdentify(instance, {
      body: { sessionToken: "sf_session", expectedIdentityDigest },
      headers: signedIn.headers,
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: "accepted" });
    expect(upstreamFetch).toHaveBeenCalledOnce();
    const [upstreamInput, upstreamInit] = upstreamFetch.mock.calls[0] ?? [];
    expect(upstreamInput).toBe("https://api.switchfrog.com/v1/identify");
    expect(upstreamInit?.method).toBe("POST");
    expect(JSON.parse(String(upstreamInit?.body))).toEqual({
      sessionToken: "sf_session",
      userId: signedIn.user.id,
      accountId: createdOrganization.id,
    });
    const upstreamHeaders = new Headers(upstreamInit?.headers);
    expect(upstreamHeaders.get("authorization")).toBe("Bearer sf_sk_test");
    expect(upstreamHeaders.get("content-type")).toBe("application/json");
    expect(upstreamHeaders.get("cookie")).toBeNull();

    await instance.db.delete({
      model: "member",
      where: [
        { field: "userId", value: signedIn.user.id },
        { field: "organizationId", value: createdOrganization.id },
      ],
    });
    const revokedResponse = await requestIdentify(instance, {
      body: { sessionToken: "sf_session", expectedIdentityDigest },
      headers: signedIn.headers,
    });

    expect(revokedResponse.status).toBe(403);
    expect(upstreamFetch).toHaveBeenCalledOnce();
  });

  it("fails closed when active organization membership cannot be read", async () => {
    const instance = await getTestInstance({
      plugins: [organization(), switchfrog({ siteSecretKey: "sf_sk_test" })],
    });
    const signedIn = await instance.signInWithTestUser();
    const createdOrganization = await instance.auth.api.createOrganization({
      headers: signedIn.headers,
      body: { name: "Test Organization", slug: "test-organization" },
    });
    await instance.auth.api.setActiveOrganization({
      headers: signedIn.headers,
      body: { organizationId: createdOrganization.id },
    });
    const adapter = (await instance.auth.$context).adapter;
    const findOne = adapter.findOne.bind(adapter);
    vi.spyOn(adapter, "findOne").mockImplementation(async (query) => {
      if (query.model === "member") throw new Error("membership unavailable");
      return findOne(query);
    });

    const response = await requestIdentify(instance, {
      body: {
        sessionToken: "sf_session",
        expectedIdentityDigest: await computeIdentityDigest(
          signedIn.user.id,
          createdOrganization.id,
        ),
      },
      headers: signedIn.headers,
    });

    expect(response.status).toBe(403);
    expect(upstreamFetch).not.toHaveBeenCalled();
  });

  it("omits account identity when the Organization plugin is absent", async () => {
    const instance = await getTestInstance({
      plugins: [switchfrog({ siteSecretKey: "sf_sk_test" })],
    });
    const signedIn = await instance.signInWithTestUser();
    const expectedIdentityDigest = await computeIdentityDigest(
      signedIn.user.id,
      null,
    );

    const response = await requestIdentify(instance, {
      body: { sessionToken: "sf_session", expectedIdentityDigest },
      headers: signedIn.headers,
    });

    expect(response.status).toBe(200);
    expect(upstreamFetch).toHaveBeenCalledOnce();
    expect(JSON.parse(String(upstreamFetch.mock.calls[0]?.[1]?.body))).toEqual({
      sessionToken: "sf_session",
      userId: signedIn.user.id,
    });
  });

  it("rejects a stale identity digest before calling Switchfrog", async () => {
    const instance = await getTestInstance({
      plugins: [switchfrog({ siteSecretKey: "sf_sk_test" })],
    });
    const signedIn = await instance.signInWithTestUser();

    const response = await requestIdentify(instance, {
      body: {
        sessionToken: "sf_session",
        expectedIdentityDigest: "0".repeat(64),
      },
      headers: signedIn.headers,
    });

    expect(response.status).toBe(412);
    expect(await response.json()).toMatchObject({
      code: "SWITCHFROG_IDENTITY_CHANGED",
    });
    expect(upstreamFetch).not.toHaveBeenCalled();
  });

  it("rejects an untrusted origin before calling Switchfrog", async () => {
    const instance = await getTestInstance({
      advanced: { disableOriginCheck: false },
      logger: { disabled: true },
      plugins: [switchfrog({ siteSecretKey: "sf_sk_test" })],
    });
    const signedIn = await instance.signInWithTestUser();
    const expectedIdentityDigest = await computeIdentityDigest(
      signedIn.user.id,
      null,
    );

    const response = await requestIdentify(instance, {
      body: { sessionToken: "sf_session", expectedIdentityDigest },
      headers: signedIn.headers,
      origin: "https://evil.example",
    });

    expect(response.status).toBe(403);
    expect(upstreamFetch).not.toHaveBeenCalled();
  });

  it.each([
    [
      "wrong accepted response",
      async () => Response.json({ status: "wrong" }),
      502,
      undefined,
    ],
    [
      "session reinitialization response",
      async () =>
        Response.json(
          { error: "session_reinit_required" },
          { status: 409 },
        ),
      409,
      { code: "SWITCHFROG_SESSION_REINIT_REQUIRED" },
    ],
    [
      "malformed accepted response",
      async () => new Response("not-json"),
      502,
      undefined,
    ],
    [
      "fetch failure",
      async () => {
        throw new TypeError("network failed");
      },
      502,
      undefined,
    ],
    [
      "other non-success response",
      async () =>
        Response.json(
          { error: "upstream-private-details" },
          { status: 418 },
        ),
      502,
      undefined,
    ],
  ])(
    "maps an upstream %s safely",
    async (_label, handler, expectedStatus, expectedBody) => {
      upstreamFetch.mockImplementation(handler);
      const timeout = vi.spyOn(AbortSignal, "timeout");
      const instance = await getTestInstance({
        plugins: [switchfrog({ siteSecretKey: "sf_sk_test" })],
      });
      const signedIn = await instance.signInWithTestUser();
      const expectedIdentityDigest = await computeIdentityDigest(
        signedIn.user.id,
        null,
      );

      const response = await requestIdentify(instance, {
        body: { sessionToken: "sf_session", expectedIdentityDigest },
        headers: signedIn.headers,
      });
      const responseText = await response.text();

      expect(response.status).toBe(expectedStatus);
      if (expectedBody) expect(JSON.parse(responseText)).toMatchObject(expectedBody);
      expect(responseText).not.toContain("upstream-private-details");
      expect(responseText).not.toContain("sf_sk_test");
      expect(upstreamFetch).toHaveBeenCalledOnce();
      const upstreamInit = upstreamFetch.mock.calls[0]?.[1];
      expect(upstreamInit?.redirect).toBe("error");
      expect(upstreamInit?.signal).toBeInstanceOf(AbortSignal);
      expect(timeout).toHaveBeenCalledOnce();
      expect(timeout).toHaveBeenCalledWith(5000);
    },
  );
});
