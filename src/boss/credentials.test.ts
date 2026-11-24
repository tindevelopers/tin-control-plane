import { describe, expect, it } from "vitest";
import { canRevoke, describeCredentialsFailure, describeMintFailure, describeRevokeFailure, listCredentials, mintableScopes, mintCredential, otherActive, parseCredential, revokeCredential, validateMint, validateRevoke } from "./credentials";
import type { BossCredential, MintFailure, MintInput } from "./credentials";

const env = { BOSS_API_URL: "https://boss.example.com", BOSS_CREDENTIALS_KEY: "console_creds_key" };
const OLD = "11111111-1111-4111-8111-111111111111";
const NEW = "22222222-2222-4222-8222-222222222222";
const PAW = "urn:tin:pawpointers:production";

const wire = (over: Record<string, unknown> = {}) => ({
  id: OLD,
  name: "pawpointers-production",
  identity: PAW,
  scopes: ["boss.reports.write"],
  status: "active",
  createdAt: "2026-10-27T22:29:39.567Z",
  lastUsedAt: "2026-10-27T22:29:44.072Z",
  revokedAt: null,
  ...over,
});
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const fetchWith = (handler: (url: URL, init: RequestInit) => Response | Promise<Response>) => {
  const calls: { url: URL; init: RequestInit }[] = [];
  const f = (async (u: URL | RequestInfo, init?: RequestInit) => {
    const url = u instanceof URL ? u : new URL(String(u));
    calls.push({ url, init: init! });
    return handler(url, init!);
  }) as typeof fetch;
  return { f, calls };
};
const cred = (over: Partial<BossCredential> = {}): BossCredential => ({
  id: OLD, name: "pawpointers-production", identity: PAW, scopes: ["boss.reports.write"], status: "active",
  createdAt: new Date("2026-10-27T22:29:39Z"), lastUsedAt: null, revokedAt: null, ...over,
});

describe("listCredentials", () => {
  it("sends the credentials key and the bearer, asks for one identity, and returns plain parsed data", async () => {
    const { f, calls } = fetchWith(() => json(200, { credentials: [wire()], truncated: false }));
    const r = await listCredentials("jwt.token.here", { platform: "pawpointers", environment: "production" }, { env, fetch: f });
    expect(r.status).toBe("ok");
    if (r.status !== "ok") return;
    expect(r.truncated).toBe(false);
    expect(r.credentials).toEqual([cred({ lastUsedAt: new Date("2026-10-27T22:29:44.072Z"), createdAt: new Date("2026-10-27T22:29:39.567Z") })]);
    expect(calls[0].url.pathname).toBe("/v1/credentials");
    expect(calls[0].url.searchParams.get("platform")).toBe("pawpointers");
    expect(calls[0].url.searchParams.get("environment")).toBe("production");
    expect(calls[0].url.searchParams.get("limit")).toBe("200");
    const h = calls[0].init.headers as Record<string, string>;
    expect(h["x-api-key"]).toBe("console_creds_key");
    expect(h.authorization).toBe("Bearer jwt.token.here");
    expect(calls[0].init.redirect).toBe("error");
    expect(calls[0].init.method).toBe("GET");
  });

  it("lists across identities when no filter is given", async () => {
    const { f, calls } = fetchWith(() => json(200, { credentials: [], truncated: false }));
    await listCredentials("t", {}, { env, fetch: f });
    expect(calls[0].url.searchParams.has("platform")).toBe(false);
  });

  it("says what is missing and refuses a bad filter before calling BOSS", async () => {
    const { f, calls } = fetchWith(() => json(200, { credentials: [], truncated: false }));
    expect(await listCredentials("t", {}, { env: {}, fetch: f })).toEqual({ status: "unconfigured", missing: ["BOSS_API_URL", "BOSS_CREDENTIALS_KEY"] });
    expect(await listCredentials(null, {}, { env, fetch: f })).toEqual({ status: "no-operator-token" });
    expect(await listCredentials("t", { platform: "pawpointers" }, { env, fetch: f })).toMatchObject({ status: "invalid" });
    expect(await listCredentials("t", { platform: "Paw Pointers", environment: "production" }, { env, fetch: f })).toMatchObject({ status: "invalid" });
    expect(await listCredentials("t", { platform: "pawpointers", environment: "live" }, { env, fetch: f })).toMatchObject({ status: "invalid" });
    expect(await listCredentials("t", {}, { env: { ...env, BOSS_API_URL: "http://boss.example.com" }, fetch: f })).toEqual({ status: "unavailable", reason: "misconfigured" });
    expect(calls).toHaveLength(0);
  });

  it("maps refusals and faults to fixed reasons and never passes BOSS's text through", async () => {
    const r = async (status: number, body?: unknown) => listCredentials("t", {}, { env, fetch: fetchWith(() => json(status, body ?? {})).f });
    expect(await r(401, { detail: "<script>" })).toEqual({ status: "unavailable", reason: "unauthorized" });
    expect(await r(403)).toEqual({ status: "unavailable", reason: "forbidden" });
    expect(await r(404)).toEqual({ status: "unavailable", reason: "forbidden" });
    expect(await r(500)).toEqual({ status: "unavailable", reason: "http_error" });
    expect(await r(503)).toEqual({ status: "unavailable", reason: "http_error" });
    const timeout = await listCredentials("t", {}, { env, fetch: (async () => { throw Object.assign(new Error("x"), { name: "TimeoutError" }); }) as typeof fetch });
    const network = await listCredentials("t", {}, { env, fetch: (async () => { throw new Error("secret-host"); }) as typeof fetch });
    expect(timeout).toEqual({ status: "unavailable", reason: "timeout" });
    expect(network).toEqual({ status: "unavailable", reason: "network" });
  });

  it.each([
    ["a body that is not JSON", () => new Response("<html>", { status: 200 })],
    ["no credentials array", () => json(200, { truncated: false })],
    ["no truncated flag", () => json(200, { credentials: [] })],
    ["a row with a bad id", () => json(200, { credentials: [wire({ id: "kn_live_abcdef" })], truncated: false })],
    ["a row with an unknown status", () => json(200, { credentials: [wire({ status: "deleted" })], truncated: false })],
    ["a row with an identity that is not a platform identity", () => json(200, { credentials: [wire({ identity: "javascript:alert(1)" })], truncated: false })],
    ["a row with a scope that has markup", () => json(200, { credentials: [wire({ scopes: ["<b>x</b>"] })], truncated: false })],
    ["a row with a malformed date", () => json(200, { credentials: [wire({ createdAt: "yesterday" })], truncated: false })],
    ["more than 200 rows", () => json(200, { credentials: Array.from({ length: 201 }, () => wire()), truncated: true })],
  ])("treats %s as malformed and shows nothing", async (_label, make) => {
    expect(await listCredentials("t", {}, { env, fetch: fetchWith(make).f })).toEqual({ status: "unavailable", reason: "malformed" });
  });

  it("refuses a response body that is too large", async () => {
    const big = () => new Response(" ".repeat(300 * 1024), { status: 200 });
    expect(await listCredentials("t", {}, { env, fetch: fetchWith(big).f })).toEqual({ status: "unavailable", reason: "too_large" });
  });
});

describe("parseCredential", () => {
  it("keeps only the known fields, so a stray digest or public id can never reach the page", () => {
    const parsed = parseCredential(wire({ digest: "abc", publicId: "kn_live_x", kid: "k1" }));
    expect(parsed).not.toBeNull();
    expect(Object.keys(parsed!).sort()).toEqual(["createdAt", "id", "identity", "lastUsedAt", "name", "revokedAt", "scopes", "status"]);
  });
  it("accepts a key with no identity and a revoked key with its date", () => {
    expect(parseCredential(wire({ identity: null }))?.identity).toBeNull();
    expect(parseCredential(wire({ status: "revoked", revokedAt: "2026-10-27T22:34:34.083Z" }))?.revokedAt).toEqual(new Date("2026-10-27T22:34:34.083Z"));
  });
});

describe("validateRevoke", () => {
  it("mirrors BOSS's shape", () => {
    expect(validateRevoke({ id: OLD, identity: PAW })).toBeNull();
    expect(validateRevoke({ id: "kn_live_abc", identity: PAW })).toMatch(/id/);
    expect(validateRevoke({ id: OLD, identity: "pawpointers" })).toMatch(/identity/);
    expect(validateRevoke({ id: OLD, identity: "urn:tin:pawpointers:live" })).toMatch(/identity/);
    expect(validateRevoke({ id: OLD, identity: PAW, reason: "a;drop" })).toMatch(/reason/);
  });
});

describe("revokeCredential", () => {
  const ok = () => json(200, { id: OLD, status: "revoked" });

  it("posts the identity to the key's own revoke route with both credentials and nothing else", async () => {
    const { f, calls } = fetchWith(ok);
    expect(await revokeCredential({ id: OLD, identity: PAW }, "jwt.token.here", { env, fetch: f })).toEqual({ status: "ok", id: OLD });
    expect(calls[0].url.toString()).toBe(`https://boss.example.com/v1/credentials/${OLD}/revoke`);
    expect(calls[0].init.method).toBe("POST");
    const h = calls[0].init.headers as Record<string, string>;
    expect(h["x-api-key"]).toBe("console_creds_key");
    expect(h.authorization).toBe("Bearer jwt.token.here");
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ identity: PAW });
    expect(calls[0].init.redirect).toBe("error");
  });

  it("sends allowLast only when asked, and the reason when given", async () => {
    const { f, calls } = fetchWith(ok);
    await revokeCredential({ id: OLD, identity: PAW, reason: "key lost", allowLast: true }, "t", { env, fetch: f });
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ identity: PAW, reason: "key lost", allowLast: true });
  });

  it("says what is missing and refuses a bad request before calling BOSS", async () => {
    const { f, calls } = fetchWith(ok);
    expect(await revokeCredential({ id: OLD, identity: PAW }, "t", { env: {}, fetch: f })).toEqual({ status: "unconfigured", missing: ["BOSS_API_URL", "BOSS_CREDENTIALS_KEY"] });
    expect(await revokeCredential({ id: OLD, identity: PAW }, null, { env, fetch: f })).toEqual({ status: "no-operator-token" });
    expect(await revokeCredential({ id: "../x", identity: PAW }, "t", { env, fetch: f })).toMatchObject({ status: "invalid" });
    expect(await revokeCredential({ id: OLD, identity: PAW }, "t", { env: { ...env, BOSS_API_URL: "http://boss.example.com" }, fetch: f })).toEqual({ status: "failed", reason: "misconfigured" });
    expect(calls).toHaveLength(0);
  });

  it("maps BOSS's answers to fixed reasons", async () => {
    const r = async (status: number, body?: unknown) => revokeCredential({ id: OLD, identity: PAW }, "t", { env, fetch: fetchWith(() => json(status, body ?? {})).f });
    expect(await r(401)).toEqual({ status: "failed", reason: "unauthorized" });
    expect(await r(403)).toEqual({ status: "failed", reason: "forbidden" });
    expect(await r(404)).toEqual({ status: "failed", reason: "not_found" });
    expect(await r(400)).toEqual({ status: "failed", reason: "rejected" });
    expect(await r(503)).toEqual({ status: "failed", reason: "http_error" });
    expect(await r(409, { detail: "The credential is not active." })).toEqual({ status: "failed", reason: "not_active" });
    expect(await r(409, { detail: "The credential is its identity's only active key; confirm to revoke it anyway." })).toEqual({ status: "failed", reason: "last_active" });
    expect(await r(409, { detail: "A credential cannot revoke itself." })).toEqual({ status: "failed", reason: "own_credential" });
    expect(await r(409, { detail: "something new" })).toEqual({ status: "failed", reason: "http_error" });
  });

  it("does not report success unless the body names the same key as revoked", async () => {
    const r = async (body: unknown) => revokeCredential({ id: OLD, identity: PAW }, "t", { env, fetch: fetchWith(() => json(200, body)).f });
    expect(await r({ id: NEW, status: "revoked" })).toEqual({ status: "failed", reason: "malformed" });
    expect(await r({ id: OLD, status: "active" })).toEqual({ status: "failed", reason: "malformed" });
    expect(await r({})).toEqual({ status: "failed", reason: "malformed" });
    expect(await revokeCredential({ id: OLD, identity: PAW }, "t", { env, fetch: fetchWith(() => new Response("nope", { status: 200 })).f })).toEqual({ status: "failed", reason: "malformed" });
  });

  it("treats a timeout and a network fault as such, with no text from the cause", async () => {
    const timeout = await revokeCredential({ id: OLD, identity: PAW }, "t", { env, fetch: (async () => { throw Object.assign(new Error("x"), { name: "AbortError" }); }) as typeof fetch });
    const network = await revokeCredential({ id: OLD, identity: PAW }, "t", { env, fetch: (async () => { throw new Error("password=hunter2"); }) as typeof fetch });
    expect(timeout).toEqual({ status: "failed", reason: "timeout" });
    expect(network).toEqual({ status: "failed", reason: "network" });
    expect(JSON.stringify(network)).not.toContain("hunter2");
  });
});

const KEY = "kn_live_AbC123_-xyz";
const mintInput = (over: Partial<MintInput> = {}): MintInput => ({ platform: "pawpointers", environment: "production", scopes: ["boss.reports.write", "boss.pins.read"], name: "pawpointers-production-2", ...over });
const minted = (over: Record<string, unknown> = {}) => ({ id: NEW, name: "pawpointers-production-2", identity: PAW, scopes: ["boss.reports.write", "boss.pins.read"], key: KEY, ...over });
const created = (body: unknown) => new Response(JSON.stringify(body), { status: 201, headers: { "content-type": "application/problem+json", "cache-control": "no-store" } });

describe("validateMint", () => {
  it("accepts a platform key with any non-empty subset of the three platform scopes", () => {
    expect(validateMint(mintInput())).toBeNull();
    expect(validateMint(mintInput({ scopes: ["boss.reports.write"] }))).toBeNull();
    expect(validateMint(mintInput({ scopes: ["boss.knowledge.releases.read", "boss.pins.read", "boss.reports.write"] }))).toBeNull();
  });
  it("accepts every environment BOSS knows and the boundaries of the name and platform patterns", () => {
    for (const environment of ["development", "preview", "staging", "production", "ci"]) expect(validateMint(mintInput({ environment }))).toBeNull();
    expect(validateMint(mintInput({ platform: "a", name: "a" }))).toBeNull();
    expect(validateMint(mintInput({ platform: "a" + "b".repeat(62) }))).toBeNull();
    expect(validateMint(mintInput({ name: "a" + "b".repeat(127) }))).toBeNull();
    expect(validateMint(mintInput({ name: "key.v2_prod-1" }))).toBeNull();
  });
  it("refuses a bad platform, including tin", () => {
    for (const platform of ["", "Paw", "paw pointers", "-paw", "paw_pointers", "paw.pointers", "a" + "b".repeat(63), "paw/../x", "paw\n"]) {
      expect(validateMint(mintInput({ platform }))).toMatch(/platform/);
    }
    expect(validateMint(mintInput({ platform: "tin" }))).toMatch(/tin/);
  });
  it("refuses an environment outside the five, and one that is not a string of them", () => {
    for (const environment of ["", "live", "Production", "prod", "production ", "production,ci"]) expect(validateMint(mintInput({ environment }))).toMatch(/environment/);
  });
  it("refuses a bad name", () => {
    for (const name of ["", "Key", "-key", ".key", "key name", "key/1", "key;drop", "<b>x</b>", "a" + "b".repeat(128), "key\n"]) expect(validateMint(mintInput({ name }))).toMatch(/name/);
  });
  it("refuses no scopes, duplicate scopes and scopes outside the platform set", () => {
    expect(validateMint(mintInput({ scopes: [] }))).toMatch(/scope/);
    expect(validateMint(mintInput({ scopes: ["boss.reports.write", "boss.reports.write"] }))).toMatch(/twice/);
    for (const scope of ["boss.reports.read", "boss.pins.write", "boss.releases.write", "boss.knowledge.write", "boss.session.issue", "boss.credentials.write", "boss.*", "*", ""]) {
      expect(validateMint(mintInput({ scopes: ["boss.reports.write", scope] }))).toMatch(/platform key/);
    }
  });
  it("lets the console have exactly boss.reports.read and nothing else", () => {
    expect(validateMint(mintInput({ platform: "console", scopes: ["boss.reports.read"] }))).toBeNull();
    expect(validateMint(mintInput({ platform: "console", scopes: [] }))).toMatch(/scope/);
    expect(validateMint(mintInput({ platform: "console", scopes: ["boss.reports.read", "boss.pins.write"] }))).toMatch(/exactly boss.reports.read/);
    expect(validateMint(mintInput({ platform: "console", scopes: ["boss.pins.write"] }))).toMatch(/exactly boss.reports.read/);
    expect(validateMint(mintInput({ platform: "console", scopes: ["boss.reports.write"] }))).toMatch(/exactly boss.reports.read/);
  });
  it("does not let an ordinary platform have the reports-read scope", () => {
    expect(validateMint(mintInput({ platform: "pawpointers", scopes: ["boss.reports.read"] }))).toMatch(/platform key/);
  });
  it("offers the console the one scope and every other platform the three", () => {
    expect(mintableScopes("console")).toEqual(["boss.reports.read"]);
    expect(mintableScopes(" console ")).toEqual(["boss.reports.read"]);
    expect(mintableScopes("pawpointers")).toEqual(["boss.reports.write", "boss.pins.read", "boss.knowledge.releases.read"]);
    expect(mintableScopes("")).toEqual(["boss.reports.write", "boss.pins.read", "boss.knowledge.releases.read"]);
  });
});

describe("mintCredential", () => {
  const ok = () => created(minted());
  const mint = (handler: () => Response | Promise<Response>, input = mintInput(), bearer: string | null = "t") => mintCredential(input, bearer, { env, fetch: fetchWith(handler).f });

  it("posts the request with both credentials and nothing else, and returns the key and its metadata", async () => {
    const { f, calls } = fetchWith(ok);
    const r = await mintCredential(mintInput(), "jwt.token.here", { env, fetch: f });
    expect(r).toEqual({ status: "ok", credential: { id: NEW, name: "pawpointers-production-2", identity: PAW, scopes: ["boss.reports.write", "boss.pins.read"], key: KEY } });
    expect(calls).toHaveLength(1);
    expect(calls[0].url.toString()).toBe("https://boss.example.com/v1/credentials");
    expect(calls[0].init.method).toBe("POST");
    const h = calls[0].init.headers as Record<string, string>;
    expect(h["x-api-key"]).toBe("console_creds_key");
    expect(h.authorization).toBe("Bearer jwt.token.here");
    expect(h["content-type"]).toBe("application/json");
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ platform: "pawpointers", environment: "production", scopes: ["boss.reports.write", "boss.pins.read"], name: "pawpointers-production-2" });
    expect(calls[0].init.redirect).toBe("error");
    expect(calls[0].init.cache).toBe("no-store");
  });

  it("accepts a test key, a different order of scopes, and the console's reports reader", async () => {
    const test = await mint(() => created(minted({ key: "kn_test_abc" })));
    expect(test).toMatchObject({ status: "ok", credential: { key: "kn_test_abc" } });
    const reordered = await mint(() => created(minted({ scopes: ["boss.pins.read", "boss.reports.write"] })));
    expect(reordered.status).toBe("ok");
    const consoleKey = await mint(() => created(minted({ identity: "urn:tin:console:production", scopes: ["boss.reports.read"] })), mintInput({ platform: "console", scopes: ["boss.reports.read"] }));
    expect(consoleKey).toMatchObject({ status: "ok", credential: { identity: "urn:tin:console:production", scopes: ["boss.reports.read"] } });
  });

  it("says what is missing and refuses a bad request before calling BOSS", async () => {
    const { f, calls } = fetchWith(ok);
    expect(await mintCredential(mintInput(), "t", { env: {}, fetch: f })).toEqual({ status: "unconfigured", missing: ["BOSS_API_URL", "BOSS_CREDENTIALS_KEY"] });
    expect(await mintCredential(mintInput(), "t", { env: { BOSS_API_URL: env.BOSS_API_URL }, fetch: f })).toEqual({ status: "unconfigured", missing: ["BOSS_CREDENTIALS_KEY"] });
    expect(await mintCredential(mintInput(), null, { env, fetch: f })).toEqual({ status: "no-operator-token" });
    expect(await mintCredential(mintInput({ platform: "tin" }), "t", { env, fetch: f })).toMatchObject({ status: "invalid" });
    expect(await mintCredential(mintInput({ scopes: ["boss.pins.write"] }), "t", { env, fetch: f })).toMatchObject({ status: "invalid" });
    expect(await mintCredential(mintInput(), "t", { env: { ...env, BOSS_API_URL: "http://boss.example.com" }, fetch: f })).toEqual({ status: "failed", reason: "misconfigured" });
    expect(await mintCredential(mintInput(), "t", { env: { ...env, BOSS_API_URL: "https://user:pw@boss.example.com" }, fetch: f })).toEqual({ status: "failed", reason: "misconfigured" });
    expect(calls).toHaveLength(0);
  });

  it("allows http for localhost only", async () => {
    const { f, calls } = fetchWith(ok);
    expect((await mintCredential(mintInput(), "t", { env: { ...env, BOSS_API_URL: "http://localhost:8080/" }, fetch: f })).status).toBe("ok");
    expect(calls[0].url.toString()).toBe("http://localhost:8080/v1/credentials");
  });

  it.each<[number, MintFailure]>([
    [400, "rejected"],
    [413, "rejected"],
    [401, "unauthorized"],
    [403, "forbidden"],
    [404, "not_configured"],
    [503, "unavailable"],
    [500, "http_error"],
    [409, "http_error"],
    [200, "http_error"],
    [202, "http_error"],
  ])("maps a %i from BOSS to %s, and passes none of its text through", async (status, reason) => {
    const r = await mint(() => new Response(JSON.stringify({ type: "about:blank", title: "<script>alert(1)</script>", detail: "kn_live_leaked_secret", status }), { status, headers: { "content-type": "application/problem+json" } }));
    expect(r).toEqual({ status: "failed", reason });
    expect(JSON.stringify(r)).not.toMatch(/script|leaked/);
  });

  it("does not treat a 200 carrying a good-looking body as a mint", async () => {
    expect(await mint(() => json(200, minted()))).toEqual({ status: "failed", reason: "http_error" });
  });

  it("treats a timeout and a network fault as such, with no text from the cause", async () => {
    const timeout = await mintCredential(mintInput(), "t", { env, fetch: (async () => { throw Object.assign(new Error("x"), { name: "TimeoutError" }); }) as typeof fetch });
    const aborted = await mintCredential(mintInput(), "t", { env, fetch: (async () => { throw Object.assign(new Error("x"), { name: "AbortError" }); }) as typeof fetch });
    const network = await mintCredential(mintInput(), "t", { env, fetch: (async () => { throw new Error("password=hunter2 kn_live_secret"); }) as typeof fetch });
    expect(timeout).toEqual({ status: "failed", reason: "timeout" });
    expect(aborted).toEqual({ status: "failed", reason: "timeout" });
    expect(network).toEqual({ status: "failed", reason: "network" });
    expect(JSON.stringify(network)).not.toMatch(/hunter2|kn_live/);
  });

  it.each([
    ["a body that is not JSON", () => new Response("<html>kn_live_abc</html>", { status: 201 })],
    ["an empty body", () => new Response("", { status: 201 })],
    ["a JSON array", () => created([minted()])],
    ["null", () => created(null)],
    ["a missing key", () => created((({ key: _k, ...rest }) => rest)(minted()))],
    ["a missing id", () => created((({ id: _i, ...rest }) => rest)(minted()))],
    ["an extra field", () => created(minted({ digest: "abc" }))],
    ["an id that is not a uuid", () => created(minted({ id: "kn_live_abcdef" }))],
    ["a name with markup", () => created(minted({ name: "<b>x</b>" }))],
    ["a name that is not a string", () => created(minted({ name: 7 }))],
    ["an identity for another platform", () => created(minted({ identity: "urn:tin:other:production" }))],
    ["an identity for another environment", () => created(minted({ identity: "urn:tin:pawpointers:staging" }))],
    ["a null identity", () => created(minted({ identity: null }))],
    ["fewer scopes than asked", () => created(minted({ scopes: ["boss.reports.write"] }))],
    ["more scopes than asked", () => created(minted({ scopes: ["boss.reports.write", "boss.pins.read", "boss.knowledge.releases.read"] }))],
    ["different scopes", () => created(minted({ scopes: ["boss.reports.write", "boss.pins.write"] }))],
    ["a scope repeated to match the count", () => created(minted({ scopes: ["boss.reports.write", "boss.reports.write"] }))],
    ["scopes that are not an array", () => created(minted({ scopes: "boss.reports.write boss.pins.read" }))],
    ["a key with the wrong prefix", () => created(minted({ key: "sk_live_abc" }))],
    ["a key with no body after the prefix", () => created(minted({ key: "kn_live_" }))],
    ["a key with a space or markup", () => created(minted({ key: "kn_live_abc def" }))],
    ["a key followed by a newline", () => created(minted({ key: "kn_live_abc\n" }))],
    ["a key that is not a string", () => created(minted({ key: 12345 }))],
  ])("treats %s as a failure and shows no key", async (_label, make) => {
    const r = await mint(make);
    expect(r).toEqual({ status: "failed", reason: "malformed" });
    expect(JSON.stringify(r)).not.toMatch(/kn_live|kn_test/);
  });

  it("refuses a body that is too large", async () => {
    expect(await mint(() => new Response(" ".repeat(300 * 1024), { status: 201 }))).toEqual({ status: "failed", reason: "malformed" });
  });

  it("treats a body that fails to read as a fault, not a success", async () => {
    const broken = () => ({ status: 201, text: async () => { throw new Error("socket closed kn_live_x"); } }) as unknown as Response;
    const r = await mint(broken);
    expect(r).toEqual({ status: "failed", reason: "network" });
    expect(JSON.stringify(r)).not.toContain("kn_live");
  });

  it("does not echo the request's own key or token in any failure", async () => {
    const results = [
      await mint(() => json(401, {})),
      await mint(() => json(500, {})),
      await mintCredential(mintInput(), "jwt.token.here", { env: { ...env, BOSS_API_URL: "ftp://x" }, fetch: fetchWith(ok).f }),
    ];
    expect(JSON.stringify(results)).not.toMatch(/console_creds_key|jwt\.token/);
  });
});

describe("describeMintFailure", () => {
  it("describes every failure with fixed text and no secrets", () => {
    const reasons: MintFailure[] = ["unauthorized", "forbidden", "not_configured", "rejected", "unavailable", "http_error", "malformed", "timeout", "network", "misconfigured"];
    const all = [
      describeMintFailure({ status: "unconfigured", missing: ["BOSS_API_URL", "BOSS_CREDENTIALS_KEY"] }),
      describeMintFailure({ status: "no-operator-token" }),
      describeMintFailure({ status: "invalid", reason: "choose at least one scope." }),
      ...reasons.map((reason) => describeMintFailure({ status: "failed", reason })),
    ];
    for (const text of all) expect(text.length).toBeGreaterThan(10);
    expect(new Set(all).size).toBe(all.length);
    expect(all.join(" ")).not.toMatch(/console_creds_key|jwt|kn_live|kn_test/);
  });
  it("says minting is not configured on BOSS for a 404", () => {
    expect(describeMintFailure({ status: "failed", reason: "not_configured" })).toMatch(/not configured on BOSS/);
  });
  it("warns that a key may exist when the outcome is unknown, and not when BOSS plainly refused", () => {
    for (const reason of ["timeout", "http_error", "malformed"] as const) expect(describeMintFailure({ status: "failed", reason })).toMatch(/may have been created/);
    for (const reason of ["rejected", "forbidden", "unauthorized", "not_configured", "unavailable"] as const) expect(describeMintFailure({ status: "failed", reason })).not.toMatch(/may have been created/);
  });
});

describe("page helpers", () => {
  it("counts the other active keys of the same identity only", () => {
    const a = cred();
    expect(otherActive([a], a)).toBe(0);
    expect(otherActive([a, cred({ id: NEW })], a)).toBe(1);
    expect(otherActive([a, cred({ id: NEW, status: "revoked" })], a)).toBe(0);
    expect(otherActive([a, cred({ id: NEW, status: "disabled" })], a)).toBe(0);
    expect(otherActive([a, cred({ id: NEW, identity: "urn:tin:console:production" })], a)).toBe(0);
  });
  it("lets a key be revoked until it is revoked", () => {
    expect(canRevoke(cred())).toBe(true);
    expect(canRevoke(cred({ status: "disabled" }))).toBe(true);
    expect(canRevoke(cred({ status: "revoked" }))).toBe(false);
  });
  it("describes every failure with fixed text and no secrets", () => {
    const all = [
      describeCredentialsFailure({ status: "unconfigured", missing: ["BOSS_CREDENTIALS_KEY"] }),
      describeCredentialsFailure({ status: "no-operator-token" }),
      describeCredentialsFailure({ status: "unavailable", reason: "forbidden" }),
      describeRevokeFailure({ status: "failed", reason: "last_active" }),
      describeRevokeFailure({ status: "failed", reason: "own_credential" }),
      describeRevokeFailure({ status: "invalid", reason: "the key id is not valid." }),
    ];
    for (const text of all) expect(text.length).toBeGreaterThan(10);
    expect(all.join(" ")).not.toMatch(/console_creds_key|jwt/);
  });
});
