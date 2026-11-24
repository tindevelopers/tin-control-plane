/**
 * Reader, minter and revoker for BOSS spoke credentials: `GET /v1/credentials`, `POST /v1/credentials` and
 * `POST /v1/credentials/:id/revoke` (tin-boss-api src/routes/credentials.ts), operator routes. This is the Keys page's only door to BOSS.
 *
 * - Server-side only. Two credentials, both from the server: the console's credentials key (`BOSS_CREDENTIALS_KEY`, scope
 *   `boss.credentials.write` and nothing else, a key of its own) as `x-api-key`, and the signed-in person's Neon Auth JWT as the
 *   bearer. BOSS also requires that person on its operator list. Neither is logged, returned or put into an error message.
 * - The list and revoke calls never carry a key, a digest or a public id: only metadata. The one exception is the 201 answer to a mint,
 *   which carries the new key exactly once; `mintCredential` hands it to its caller and nothing here stores, logs or echoes it.
 * - Fail closed. Anything unexpected is a fixed-string failure; nothing BOSS sends is interpolated into text. A revoke is only
 *   reported as done on a 200 whose body names the same credential and "revoked"; a mint only on a 201 whose body matches what was asked.
 * - Minting is limited to what BOSS's policy allows from here: a platform key (any non-empty subset of the three platform scopes)
 *   and the console's reports-read key. Console operator keys and the tin keys stay the owner's CLI (scripts/mint-spoke-credential.ts
 *   in tin-boss-api). `validateMint` mirrors that rule so a bad request never leaves the console; BOSS stays the authority.
 *
 * Environment:
 *   BOSS_API_URL          Base URL of the BOSS cell, https only (http only for localhost). Shared with the other BOSS readers.
 *   BOSS_CREDENTIALS_KEY  The console's spoke key with `boss.credentials.write` only. Server-only; never prefix with NEXT_PUBLIC_.
 */

import { ALLOWED } from "@/config/scopes";

export const CREDENTIAL_STATUS = ["active", "disabled", "revoked"] as const;
export type CredentialStatus = (typeof CREDENTIAL_STATUS)[number];

export type BossCredential = {
  id: string;
  name: string;
  /** `urn:tin:<platform>:<environment>`, or null for a key minted before identities existed. */
  identity: string | null;
  scopes: string[];
  status: CredentialStatus;
  createdAt: Date;
  lastUsedAt: Date | null;
  revokedAt: Date | null;
};

type Missing = ("BOSS_API_URL" | "BOSS_CREDENTIALS_KEY")[];
export type UnavailableReason = "misconfigured" | "timeout" | "network" | "unauthorized" | "forbidden" | "http_error" | "malformed" | "too_large";

export type CredentialsResult =
  | { status: "ok"; credentials: BossCredential[]; truncated: boolean }
  | { status: "unconfigured"; missing: Missing }
  | { status: "no-operator-token" }
  | { status: "invalid"; reason: string }
  | { status: "unavailable"; reason: UnavailableReason };

export type RevokeFailure = "unauthorized" | "forbidden" | "not_found" | "not_active" | "last_active" | "own_credential" | "rejected" | "http_error" | "malformed" | "timeout" | "network" | "misconfigured";

export type RevokeResult =
  | { status: "ok"; id: string }
  | { status: "unconfigured"; missing: Missing }
  | { status: "no-operator-token" }
  | { status: "invalid"; reason: string }
  | { status: "failed"; reason: RevokeFailure };

type Options = { env?: Record<string, string | undefined>; fetch?: typeof globalThis.fetch; timeoutMs?: number };

export type MintFailure = "unauthorized" | "forbidden" | "not_configured" | "rejected" | "unavailable" | "http_error" | "malformed" | "timeout" | "network" | "misconfigured";

// The patterns mirror what BOSS enforces (tin-boss-api src/platform-identity.ts, src/routes/credentials.ts).
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PLATFORM = /^[a-z0-9][a-z0-9-]{0,62}$/;
export const PLATFORM_ENVIRONMENTS = ["development", "preview", "staging", "production", "ci"] as const;
const IDENTITY = /^urn:tin:([a-z0-9][a-z0-9-]{0,62}):(development|preview|staging|production|ci)$/;
const NAME = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const SCOPE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const MAX_ROWS = 200;
const MAX_BODY_CHARS = 256 * 1024;
const REASON = /^[A-Za-z0-9 ._,:-]{1,100}$/;

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

export const isIdentity = (v: unknown): v is string => typeof v === "string" && IDENTITY.test(v);
export const isCredentialId = (v: unknown): v is string => typeof v === "string" && UUID.test(v);
export const isPlatformName = (v: unknown): v is string => typeof v === "string" && PLATFORM.test(v);
export const isPlatformEnvironment = (v: unknown): v is (typeof PLATFORM_ENVIRONMENTS)[number] => (PLATFORM_ENVIRONMENTS as readonly unknown[]).includes(v);

export function describeCredentialsFailure(r: Exclude<CredentialsResult, { status: "ok" }>): string {
  switch (r.status) {
    case "unconfigured":
      return `Keys are not configured: set ${r.missing.join(" and ")}.`;
    case "no-operator-token":
      return "Could not obtain your operator token from Neon Auth. Sign out and in again; if it persists, the auth base URL or the token endpoint is wrong.";
    case "invalid":
      return `Nothing was asked: ${r.reason}`;
    case "unavailable": {
      const why: Record<UnavailableReason, string> = {
        misconfigured: "BOSS_API_URL is not a valid https URL.",
        timeout: "BOSS did not answer in time.",
        network: "BOSS could not be reached.",
        unauthorized: "BOSS refused the Control Plane's key or your token.",
        forbidden: "BOSS refused: you are not on its operator list, or the Control Plane's key lacks boss.credentials.write, or BOSS has no credential admin login yet.",
        http_error: "BOSS answered with an error.",
        malformed: "BOSS returned an unexpected response.",
        too_large: "BOSS returned a response that is too large.",
      };
      return `Keys are unavailable: ${why[r.reason]}`;
    }
  }
}

export function describeRevokeFailure(r: Exclude<RevokeResult, { status: "ok" }>): string {
  switch (r.status) {
    case "unconfigured":
      return `Revoking is not configured: set ${r.missing.join(" and ")}.`;
    case "no-operator-token":
      return "Could not obtain your operator token from Neon Auth. Sign out and in again.";
    case "invalid":
      return `Nothing was revoked: ${r.reason}`;
    case "failed": {
      const why: Record<RevokeFailure, string> = {
        misconfigured: "BOSS_API_URL is not a valid https URL.",
        unauthorized: "BOSS refused the Control Plane's key or your token.",
        forbidden: "BOSS refused: you are not on its operator list, or the Control Plane's key lacks boss.credentials.write.",
        not_found: "BOSS has no such key for that identity. Reload the page.",
        not_active: "That key is no longer active. Reload the page.",
        last_active: "That is the only active key for this identity. Mint a replacement first, or confirm that you mean to cut the platform off.",
        own_credential: "That is the key this Control Plane uses to talk to BOSS. It cannot revoke itself.",
        rejected: "BOSS rejected the request's shape.",
        http_error: "BOSS answered with an error.",
        malformed: "BOSS returned an unexpected response.",
        timeout: "BOSS did not answer in time.",
        network: "BOSS could not be reached.",
      };
      return `Nothing was revoked: ${why[r.reason]}`;
    }
  }
}

function endpoint(base: string, path: string, search = ""): URL | null {
  let url: URL;
  try {
    url = new URL(base);
  } catch {
    return null;
  }
  const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) return null;
  if (url.username || url.password) return null;
  url.pathname = `${url.pathname.replace(/\/+$/, "")}${path}`;
  url.search = search;
  url.hash = "";
  return url;
}

function config(env: Record<string, string | undefined>): { base: string; key: string } | { missing: Missing } {
  const base = env.BOSS_API_URL?.trim();
  const key = env.BOSS_CREDENTIALS_KEY?.trim();
  const missing: Missing = [];
  if (!base) missing.push("BOSS_API_URL");
  if (!key) missing.push("BOSS_CREDENTIALS_KEY");
  return missing.length > 0 ? { missing } : { base: base!, key: key! };
}

const reasonOf = (e: unknown): "timeout" | "network" => {
  const name = isObject(e) ? (e as { name?: string }).name : undefined;
  return name === "TimeoutError" || name === "AbortError" ? "timeout" : "network";
};

function date(v: unknown): Date | null | undefined {
  if (v === null) return null;
  if (typeof v !== "string") return undefined;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? undefined : d;
}

/** Maps one wire row; null when any field is not exactly what BOSS promises. */
export function parseCredential(row: unknown): BossCredential | null {
  if (!isObject(row)) return null;
  const { id, name, identity, scopes, status } = row;
  if (!isCredentialId(id) || typeof name !== "string" || !NAME.test(name)) return null;
  if (identity !== null && !isIdentity(identity)) return null;
  if (!Array.isArray(scopes) || scopes.length > 20 || !scopes.every((s) => typeof s === "string" && SCOPE.test(s))) return null;
  if (!(CREDENTIAL_STATUS as readonly unknown[]).includes(status)) return null;
  const createdAt = date(row.createdAt);
  const lastUsedAt = date(row.lastUsedAt);
  const revokedAt = date(row.revokedAt);
  if (!createdAt || lastUsedAt === undefined || revokedAt === undefined) return null;
  return { id, name, identity: identity as string | null, scopes: scopes as string[], status: status as CredentialStatus, createdAt, lastUsedAt, revokedAt };
}

/** The keys of one identity (platform and environment together), or the newest across all identities. */
export async function listCredentials(bearer: string | null, filter: { platform?: string; environment?: string } = {}, opts: Options = {}): Promise<CredentialsResult> {
  const c = config(opts.env ?? process.env);
  if ("missing" in c) return { status: "unconfigured", missing: c.missing };
  if (!bearer) return { status: "no-operator-token" };
  const { platform, environment } = filter;
  if ((platform === undefined) !== (environment === undefined)) return { status: "invalid", reason: "give a platform and an environment together, or neither." };
  if (platform !== undefined && (!isPlatformName(platform) || !isPlatformEnvironment(environment))) return { status: "invalid", reason: "that platform or environment is not valid." };
  const query = new URLSearchParams({ limit: String(MAX_ROWS) });
  if (platform !== undefined && environment !== undefined) {
    query.set("platform", platform);
    query.set("environment", environment);
  }
  const url = endpoint(c.base, "/v1/credentials", query.toString());
  if (!url) return { status: "unavailable", reason: "misconfigured" };

  let res: Response;
  try {
    res = await (opts.fetch ?? fetch)(url, {
      method: "GET",
      headers: { "x-api-key": c.key, authorization: `Bearer ${bearer}`, accept: "application/json" },
      redirect: "error", // never forward credentials to a redirect target
      cache: "no-store",
      signal: AbortSignal.timeout(opts.timeoutMs ?? 5000),
    });
  } catch (e) {
    return { status: "unavailable", reason: reasonOf(e) };
  }
  if (res.status === 401) return { status: "unavailable", reason: "unauthorized" };
  if (res.status === 403 || res.status === 404) return { status: "unavailable", reason: "forbidden" };
  if (res.status !== 200) return { status: "unavailable", reason: "http_error" };
  let text: string;
  try {
    text = await res.text();
  } catch (e) {
    return { status: "unavailable", reason: reasonOf(e) };
  }
  if (text.length > MAX_BODY_CHARS) return { status: "unavailable", reason: "too_large" };
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return { status: "unavailable", reason: "malformed" };
  }
  if (!isObject(body) || !Array.isArray(body.credentials) || typeof body.truncated !== "boolean" || body.credentials.length > MAX_ROWS) {
    return { status: "unavailable", reason: "malformed" };
  }
  const credentials: BossCredential[] = [];
  for (const row of body.credentials) {
    const parsed = parseCredential(row);
    if (!parsed) return { status: "unavailable", reason: "malformed" };
    credentials.push(parsed);
  }
  return { status: "ok", credentials, truncated: body.truncated };
}

export type RevokeInput = { id: string; identity: string; reason?: string; allowLast?: boolean };

/** The same shape BOSS enforces, checked here so a bad request never leaves the console. */
export function validateRevoke(input: RevokeInput): string | null {
  if (!isCredentialId(input.id)) return "the key id is not valid.";
  if (!isIdentity(input.identity)) return "the identity is not valid.";
  if (input.reason !== undefined && !REASON.test(input.reason)) return "the reason has unexpected characters.";
  return null;
}

// BOSS's fixed 409 documents (tin-boss-api CREDENTIAL_PROBLEMS). Matched, never echoed: the text shown is this module's own.
const CONFLICTS: [RegExp, RevokeFailure][] = [
  [/not active/i, "not_active"],
  [/only active key/i, "last_active"],
  [/cannot revoke itself/i, "own_credential"],
];

export async function revokeCredential(input: RevokeInput, bearer: string | null, opts: Options = {}): Promise<RevokeResult> {
  const c = config(opts.env ?? process.env);
  if ("missing" in c) return { status: "unconfigured", missing: c.missing };
  const invalid = validateRevoke(input);
  if (invalid) return { status: "invalid", reason: invalid };
  if (!bearer) return { status: "no-operator-token" };
  const url = endpoint(c.base, `/v1/credentials/${input.id}/revoke`);
  if (!url) return { status: "failed", reason: "misconfigured" };

  let res: Response;
  try {
    res = await (opts.fetch ?? fetch)(url, {
      method: "POST",
      headers: { "x-api-key": c.key, authorization: `Bearer ${bearer}`, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ identity: input.identity, ...(input.reason === undefined ? {} : { reason: input.reason }), ...(input.allowLast ? { allowLast: true } : {}) }),
      redirect: "error",
      cache: "no-store",
      signal: AbortSignal.timeout(opts.timeoutMs ?? 5000),
    });
  } catch (e) {
    return { status: "failed", reason: reasonOf(e) };
  }
  if (res.status === 401) return { status: "failed", reason: "unauthorized" };
  if (res.status === 403) return { status: "failed", reason: "forbidden" };
  if (res.status === 404) return { status: "failed", reason: "not_found" };
  if (res.status === 400 || res.status === 413) return { status: "failed", reason: "rejected" };
  if (res.status === 409) {
    const body = (await res.json().catch(() => null)) as unknown;
    const detail = isObject(body) && typeof body.detail === "string" ? body.detail : "";
    const hit = CONFLICTS.find(([re]) => re.test(detail));
    return { status: "failed", reason: hit ? hit[1] : "http_error" };
  }
  if (res.status !== 200) return { status: "failed", reason: "http_error" };
  const body = (await res.json().catch(() => null)) as unknown;
  return isObject(body) && body.id === input.id && body.status === "revoked" ? { status: "ok", id: input.id } : { status: "failed", reason: "malformed" };
}

// ---- Minting -------------------------------------------------------------------------------------------------------------------
// BOSS's policy for what may be minted from the console ("Option A"): a platform key (any platform except `console` and `tin`) is a
// non-empty subset of the three platform scopes; the console's reports-read key is exactly `boss.reports.read`. Anything else
// (operator keys, the tin hub's key) is the owner's CLI and BOSS refuses it with 400. The lists come from config/scopes.ts.

/** Scopes a platform key may carry, and the single scope of the console's reports-read key. */
export const MINT_PLATFORM_SCOPES: readonly string[] = ALLOWED.platform.scopes;
export const MINT_CONSOLE_SCOPES: readonly string[] = ALLOWED["console-reader"].scopes;
/** The platform whose only mintable key is the reports reader, and the one platform whose keys are never minted here. */
export const CONSOLE_PLATFORM = "console";
export const TIN_PLATFORM = "tin";

/** The scopes the form may offer for a platform name as typed. */
export const mintableScopes = (platform: string): readonly string[] => (platform.trim() === CONSOLE_PLATFORM ? MINT_CONSOLE_SCOPES : MINT_PLATFORM_SCOPES);

export type MintInput = { platform: string; environment: string; scopes: string[]; name: string };

/** What a successful mint carries: the metadata the page already shows, plus the key itself, which exists nowhere else. */
export type MintedCredential = { id: string; name: string; identity: string; scopes: string[]; key: string };

export type MintResult =
  | { status: "ok"; credential: MintedCredential }
  | { status: "unconfigured"; missing: Missing }
  | { status: "no-operator-token" }
  | { status: "invalid"; reason: string }
  | { status: "failed"; reason: MintFailure };

const KEY = /^kn_(live|test)_[A-Za-z0-9_-]+$/;

/** The same rules BOSS enforces, checked here so a bad request never leaves the console. Null when the request is fine. */
export function validateMint(input: MintInput): string | null {
  const { platform, environment, scopes, name } = input;
  if (!isPlatformName(platform)) return "the platform must be lowercase letters, digits and hyphens, starting with a letter or digit.";
  if (platform === TIN_PLATFORM) return "keys for the tin platform are minted by the owner, not here.";
  if (!isPlatformEnvironment(environment)) return "choose an environment: development, preview, staging, production or ci.";
  if (typeof name !== "string" || !NAME.test(name)) return "the name must be lowercase letters, digits, dots, hyphens and underscores, starting with a letter or digit (up to 128 characters).";
  if (!Array.isArray(scopes) || scopes.length === 0 || !scopes.every((s) => typeof s === "string")) return "choose at least one scope.";
  if (new Set(scopes).size !== scopes.length) return "a scope was chosen twice.";
  if (platform === CONSOLE_PLATFORM) {
    if (scopes.length !== 1 || scopes[0] !== MINT_CONSOLE_SCOPES[0]) return "the Control Plane's key from here carries exactly boss.reports.read; operator keys are minted by the owner.";
    return null;
  }
  const outside = scopes.find((s) => !MINT_PLATFORM_SCOPES.includes(s));
  if (outside !== undefined) return "a platform key may carry only boss.reports.write, boss.pins.read and boss.knowledge.releases.read.";
  return null;
}

export function describeMintFailure(r: Exclude<MintResult, { status: "ok" }>): string {
  switch (r.status) {
    case "unconfigured":
      return `Minting is not configured: set ${r.missing.join(" and ")}.`;
    case "no-operator-token":
      return "Could not obtain your operator token from Neon Auth. Sign out and in again.";
    case "invalid":
      return `Nothing was minted: ${r.reason}`;
    case "failed": {
      const why: Record<MintFailure, string> = {
        misconfigured: "BOSS_API_URL is not a valid https URL.",
        unauthorized: "BOSS refused the Control Plane's key or your token.",
        forbidden: "BOSS refused: you are not on its operator list, or the Control Plane's key lacks boss.credentials.write.",
        not_configured: "minting is not configured on BOSS. The owner enables it there first.",
        rejected: "BOSS did not accept the platform, environment, name or scopes. Check them against the allowed set.",
        unavailable: "BOSS could not reach what it needs to mint a key. Try again shortly.",
        http_error: "BOSS answered with an error. A key may have been created: reload the list, and revoke any key you do not recognise.",
        malformed: "BOSS answered with something unexpected. A key may have been created and not shown: reload the list, and revoke any key you do not recognise.",
        timeout: "BOSS did not answer in time. A key may have been created: reload the list, and revoke any key you do not recognise.",
        network: "BOSS could not be reached.",
      };
      return `Nothing was minted: ${why[r.reason]}`;
    }
  }
}

const sameSet = (a: readonly string[], b: readonly string[]) => a.length === b.length && new Set(a).size === a.length && a.every((x) => b.includes(x));

/**
 * Parses BOSS's 201 body. Exactly the five promised fields, the identity and the scopes the console asked for, and a key of the
 * shape BOSS issues. Anything else is null: a key the console cannot vouch for is never shown.
 */
function parseMinted(body: unknown, asked: MintInput): MintedCredential | null {
  if (!isObject(body)) return null;
  const keys = Object.keys(body).sort();
  if (keys.join(",") !== "id,identity,key,name,scopes") return null;
  const { id, name, identity, scopes, key } = body;
  if (!isCredentialId(id) || typeof name !== "string" || !NAME.test(name)) return null;
  if (identity !== `urn:tin:${asked.platform}:${asked.environment}`) return null;
  if (!Array.isArray(scopes) || !scopes.every((s) => typeof s === "string") || !sameSet(scopes as string[], asked.scopes)) return null;
  if (typeof key !== "string" || !KEY.test(key)) return null;
  return { id, name, identity, scopes: scopes as string[], key };
}

/**
 * `POST /v1/credentials`. The result's `key` is shown to the person once and is not kept: callers must not log it, store it, put it in
 * a URL, cookie or redirect, or cache anything that contains it. Neither the key nor any other part of BOSS's body reaches an error.
 */
export async function mintCredential(input: MintInput, bearer: string | null, opts: Options = {}): Promise<MintResult> {
  const c = config(opts.env ?? process.env);
  if ("missing" in c) return { status: "unconfigured", missing: c.missing };
  const invalid = validateMint(input);
  if (invalid) return { status: "invalid", reason: invalid };
  if (!bearer) return { status: "no-operator-token" };
  const url = endpoint(c.base, "/v1/credentials");
  if (!url) return { status: "failed", reason: "misconfigured" };

  let res: Response;
  try {
    res = await (opts.fetch ?? fetch)(url, {
      method: "POST",
      headers: { "x-api-key": c.key, authorization: `Bearer ${bearer}`, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ platform: input.platform, environment: input.environment, scopes: input.scopes, name: input.name }),
      redirect: "error",
      cache: "no-store",
      signal: AbortSignal.timeout(opts.timeoutMs ?? 10_000), // longer than a read: a mint that times out may still have created the key
    });
  } catch (e) {
    return { status: "failed", reason: reasonOf(e) };
  }
  if (res.status === 401) return { status: "failed", reason: "unauthorized" };
  if (res.status === 403) return { status: "failed", reason: "forbidden" };
  if (res.status === 404) return { status: "failed", reason: "not_configured" };
  if (res.status === 400 || res.status === 413) return { status: "failed", reason: "rejected" };
  if (res.status === 503) return { status: "failed", reason: "unavailable" };
  if (res.status !== 201) return { status: "failed", reason: "http_error" };
  let text: string;
  try {
    text = await res.text();
  } catch (e) {
    return { status: "failed", reason: reasonOf(e) };
  }
  if (text.length > MAX_BODY_CHARS) return { status: "failed", reason: "malformed" };
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return { status: "failed", reason: "malformed" };
  }
  const credential = parseMinted(body, input);
  return credential ? { status: "ok", credential } : { status: "failed", reason: "malformed" };
}

/** Active keys of an identity other than `exclude`: the page warns, and the form asks for confirmation, when this is zero. */
export function otherActive(all: readonly BossCredential[], target: BossCredential): number {
  return all.filter((c) => c.id !== target.id && c.identity === target.identity && c.status === "active").length;
}

/** A key can be revoked while it is active or disabled; a revoked key is final. */
export const canRevoke = (c: BossCredential): boolean => c.status !== "revoked";

export const STATUS_COLOUR: Record<CredentialStatus, "green" | "amber" | "red"> = { active: "green", disabled: "amber", revoked: "red" };
