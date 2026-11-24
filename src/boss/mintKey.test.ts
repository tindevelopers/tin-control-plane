import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The action is exercised for real; only its edges are replaced: the admin check, the operator's token, and Next's navigation and
// cache calls (which must never be reached, because either could carry or keep the key).
const requireAdmin = vi.fn();
const operatorBearer = vi.fn();
const redirect = vi.fn();
const revalidatePath = vi.fn();
const revalidateTag = vi.fn();
vi.mock("@/src/auth/access", () => ({ requireAdmin: () => requireAdmin() }));
vi.mock("@/src/auth/token", () => ({ operatorBearer: () => operatorBearer() }));
vi.mock("next/navigation", () => ({ redirect: (...a: unknown[]) => redirect(...a) }));
vi.mock("next/cache", () => ({ revalidatePath: (...a: unknown[]) => revalidatePath(...a), revalidateTag: (...a: unknown[]) => revalidateTag(...a) }));

import { mintKey } from "@/app/(console)/boss/keys/actions";
import type { MintKeyState } from "@/app/(console)/boss/keys/actions";

const KEY = "kn_live_AbC123_-xyz";
const ID = "22222222-2222-4222-8222-222222222222";
const PAW = "urn:tin:pawpointers:production";
const idle: MintKeyState = { status: "idle" };

const form = (fields: Record<string, string | string[]>) => {
  const f = new FormData();
  for (const [k, v] of Object.entries(fields)) for (const one of Array.isArray(v) ? v : [v]) f.append(k, one);
  return f;
};
const good = () => form({ platform: "pawpointers", environment: "production", name: "pawpointers-production-2", scope: ["boss.reports.write", "boss.pins.read"] });
const answer = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const minted = () => answer(201, { id: ID, name: "pawpointers-production-2", identity: PAW, scopes: ["boss.reports.write", "boss.pins.read"], key: KEY });

const fetchMock = vi.fn<(url: URL, init: RequestInit) => Promise<Response>>();
let errorSpy: ReturnType<typeof vi.spyOn>;
let logSpy: ReturnType<typeof vi.spyOn>;
let warnSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  requireAdmin.mockReset().mockResolvedValue({ userId: "u1", email: "a@tin.info", role: "admin" });
  operatorBearer.mockReset().mockResolvedValue("jwt.token.here");
  for (const m of [redirect, revalidatePath, revalidateTag, fetchMock]) m.mockReset();
  fetchMock.mockImplementation(async () => minted());
  vi.stubEnv("BOSS_API_URL", "https://boss.example.com");
  vi.stubEnv("BOSS_CREDENTIALS_KEY", "console_creds_key");
  vi.stubGlobal("fetch", fetchMock);
  errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const logged = () => JSON.stringify([...errorSpy.mock.calls, ...logSpy.mock.calls, ...warnSpy.mock.calls]);

describe("mintKey (server action)", () => {
  it("requires an admin before it reads the form or calls BOSS", async () => {
    requireAdmin.mockRejectedValue(new Error("Admin access required."));
    await expect(mintKey(idle, good())).rejects.toThrow("Admin access required.");
    expect(operatorBearer).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("lets a person who is not signed in as an operator through to nothing", async () => {
    requireAdmin.mockRejectedValue(new Error("NEXT_REDIRECT"));
    await expect(mintKey(idle, good())).rejects.toThrow("NEXT_REDIRECT");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("mints for an admin and returns the key and its metadata in the result", async () => {
    const r = await mintKey(idle, good());
    expect(r).toEqual({ status: "minted", id: ID, name: "pawpointers-production-2", identity: PAW, scopes: ["boss.reports.write", "boss.pins.read"], key: KEY });
    expect(requireAdmin).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://boss.example.com/v1/credentials");
    expect(init.method).toBe("POST");
    const h = init.headers as Record<string, string>;
    expect(h["x-api-key"]).toBe("console_creds_key");
    expect(h.authorization).toBe("Bearer jwt.token.here");
    expect(JSON.parse(String(init.body))).toEqual({ platform: "pawpointers", environment: "production", scopes: ["boss.reports.write", "boss.pins.read"], name: "pawpointers-production-2" });
  });

  it("trims the typed fields and takes every ticked scope", async () => {
    await mintKey(idle, form({ platform: "  pawpointers ", environment: " staging", name: " key-1 ", scope: "boss.knowledge.releases.read" }));
    expect(JSON.parse(String(fetchMock.mock.calls[0]![1].body))).toEqual({ platform: "pawpointers", environment: "staging", scopes: ["boss.knowledge.releases.read"], name: "key-1" });
  });

  it("never logs, redirects or revalidates anything when it succeeds", async () => {
    const r = await mintKey(idle, good());
    expect(r.status).toBe("minted");
    expect(logged()).not.toContain(KEY);
    expect(logged()).not.toMatch(/kn_live|jwt\.token|console_creds_key/);
    expect(redirect).not.toHaveBeenCalled();
    expect(revalidatePath).not.toHaveBeenCalled();
    expect(revalidateTag).not.toHaveBeenCalled();
  });

  it("returns nothing but the key's own request: no cookie, no header, no URL to carry it", async () => {
    const r = await mintKey(idle, good());
    // The only place the key appears is the one result object the browser receives.
    expect(Object.keys(r).sort()).toEqual(["id", "identity", "key", "name", "scopes", "status"]);
    expect(JSON.stringify(fetchMock.mock.calls.map(([u, i]) => [String(u), i.headers, i.body]))).not.toContain(KEY);
  });

  it.each([
    ["no platform", { environment: "production", name: "k", scope: "boss.reports.write" }],
    ["tin", { platform: "tin", environment: "production", name: "k", scope: "boss.reports.write" }],
    ["no environment", { platform: "pawpointers", name: "k", scope: "boss.reports.write" }],
    ["an unknown environment", { platform: "pawpointers", environment: "live", name: "k", scope: "boss.reports.write" }],
    ["no name", { platform: "pawpointers", environment: "production", scope: "boss.reports.write" }],
    ["a name with a slash", { platform: "pawpointers", environment: "production", name: "a/b", scope: "boss.reports.write" }],
    ["no scope", { platform: "pawpointers", environment: "production", name: "k" }],
    ["an operator scope on a platform", { platform: "pawpointers", environment: "production", name: "k", scope: ["boss.reports.write", "boss.pins.write"] }],
    ["the reader scope on a platform", { platform: "pawpointers", environment: "production", name: "k", scope: "boss.reports.read" }],
    ["an operator scope on the console", { platform: "console", environment: "production", name: "k", scope: ["boss.reports.read", "boss.pins.write"] }],
    ["a platform scope on the console", { platform: "console", environment: "production", name: "k", scope: "boss.reports.write" }],
  ])("refuses %s without calling BOSS", async (_label, fields) => {
    const r = await mintKey(idle, form(fields));
    expect(r.status).toBe("error");
    expect(fetchMock).not.toHaveBeenCalled();
    expect(operatorBearer).not.toHaveBeenCalled();
  });

  it("mints the console's reports-read key", async () => {
    fetchMock.mockImplementation(async () => answer(201, { id: ID, name: "console-reports", identity: "urn:tin:console:production", scopes: ["boss.reports.read"], key: KEY }));
    const r = await mintKey(idle, form({ platform: "console", environment: "production", name: "console-reports", scope: "boss.reports.read" }));
    expect(r).toMatchObject({ status: "minted", identity: "urn:tin:console:production", scopes: ["boss.reports.read"] });
  });

  it("says there is no operator token and does not call BOSS", async () => {
    operatorBearer.mockResolvedValue(null);
    const r = await mintKey(idle, good());
    expect(r).toEqual({ status: "error", message: expect.stringMatching(/operator token/) });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("says minting is not configured when BOSS has no mint route", async () => {
    fetchMock.mockImplementation(async () => answer(404, { title: "Not Found" }));
    const r = await mintKey(idle, good());
    expect(r).toEqual({ status: "error", message: expect.stringMatching(/not configured on BOSS/) });
  });

  it("reports a failure with fixed text, logs only a fixed word and returns no key", async () => {
    fetchMock.mockImplementation(async () => answer(403, { detail: `nope ${KEY}`, title: "<script>" }));
    const r = await mintKey(idle, good());
    expect(r.status).toBe("error");
    const text = JSON.stringify(r);
    expect(text).not.toMatch(/kn_live|script|nope/);
    expect(errorSpy).toHaveBeenCalledWith("mint key failed", "forbidden");
    expect(logged()).not.toMatch(/kn_live|jwt\.token|console_creds_key/);
  });

  it("reports a 201 that does not match what was asked as a failure and shows no key", async () => {
    fetchMock.mockImplementation(async () => answer(201, { id: ID, name: "pawpointers-production-2", identity: "urn:tin:other:production", scopes: ["boss.reports.write", "boss.pins.read"], key: KEY }));
    const r = await mintKey(idle, good());
    expect(r).toEqual({ status: "error", message: expect.stringMatching(/may have been created/) });
    expect(JSON.stringify(r)).not.toContain(KEY);
    expect(logged()).not.toContain(KEY);
  });

  it("reports a network fault without any text from it", async () => {
    fetchMock.mockImplementation(async () => { throw new Error("connect ECONNREFUSED 10.0.0.1 kn_live_x"); });
    const r = await mintKey(idle, good());
    expect(r).toEqual({ status: "error", message: expect.stringMatching(/could not be reached/) });
    expect(JSON.stringify(r)).not.toMatch(/ECONNREFUSED|10\.0\.0\.1|kn_live/);
  });

  it("does not carry a previous key into the next result", async () => {
    const first = await mintKey(idle, good());
    fetchMock.mockImplementation(async () => answer(400, {}));
    const second = await mintKey(first, good());
    expect(second.status).toBe("error");
    expect(JSON.stringify(second)).not.toContain(KEY);
  });
});
