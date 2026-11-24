"use server";

import { redirect } from "next/navigation";
import { requireAdmin } from "@/src/auth/access";
import { operatorBearer } from "@/src/auth/token";
import { describeCredentialsFailure, describeMintFailure, describeRevokeFailure, isCredentialId, isIdentity, listCredentials, mintCredential, otherActive, revokeCredential, validateMint } from "@/src/boss/credentials";

/**
 * Revoke one BOSS key. The form carries only the key's id, its identity and what the person typed: the key's name and whether it is
 * the identity's last active key are re-read from BOSS here, so a stale or edited form cannot revoke anything the page did not show,
 * and cannot skip the confirmation. Revoking is final, so a person confirms it by typing the key's name.
 */
export async function revokeKey(f: FormData) {
  await requireAdmin();
  const id = String(f.get("id") ?? "");
  const identity = String(f.get("identity") ?? "");
  const typed = String(f.get("confirm") ?? "").trim();
  const confirmLast = f.get("confirmLast") === "on";
  const m = /^urn:tin:([a-z0-9-]+):([a-z]+)$/.exec(identity);
  const back = m ? `platform=${encodeURIComponent(m[1]!)}&environment=${encodeURIComponent(m[2]!)}` : "";
  let result: string;
  try {
    if (!isCredentialId(id) || !isIdentity(identity) || !m) throw new Error("That request is not valid. Reload the page.");
    const bearer = await operatorBearer();
    const listed = await listCredentials(bearer, { platform: m[1]!, environment: m[2]! });
    if (listed.status !== "ok") throw new Error(describeCredentialsFailure(listed));
    const target = listed.credentials.find((c) => c.id === id);
    if (!target) throw new Error("That key is no longer listed for this identity. Reload the page.");
    if (target.status === "revoked") throw new Error("That key is already revoked.");
    if (typed !== target.name) throw new Error("Nothing was revoked: type the key's name exactly to confirm.");
    const last = target.status === "active" && otherActive(listed.credentials, target) === 0;
    if (last && !confirmLast) throw new Error("Nothing was revoked: this is the only active key for this identity. Tick the box to confirm you mean to cut the platform off.");

    const r = await revokeCredential({ id, identity, reason: "revoked in the console", allowLast: last && confirmLast }, bearer);
    if (r.status !== "ok") throw new Error(describeRevokeFailure(r));
    result = `${back}&revoked=${encodeURIComponent(target.name)}`;
  } catch (e) {
    console.error("revoke key failed", e instanceof Error ? e.message : e);
    result = `${back}&error=${encodeURIComponent(e instanceof Error ? e.message : "Could not revoke the key.")}`;
  }
  redirect(`/boss/keys?${result}`);
}

/** What the mint form shows. `minted` carries the key: it exists only in this action's result and in the browser's memory. */
export type MintKeyState =
  | { status: "idle" }
  | { status: "error"; message: string }
  | { status: "minted"; id: string; name: string; identity: string; scopes: string[]; key: string };

/**
 * Mint one BOSS key (a platform key, or the console's reports-read key; BOSS refuses the rest) and return it to the page once.
 *
 * The key is returned in this action's result and nowhere else: not written to the database, a cookie, a log, a URL or a redirect
 * parameter, and nothing is revalidated or redirected, so no cached page or navigation entry can hold it. The person's browser keeps it
 * in memory until they leave the page. Failures are fixed strings; nothing BOSS sends is shown.
 */
export async function mintKey(_previous: MintKeyState, f: FormData): Promise<MintKeyState> {
  await requireAdmin();
  const input = {
    platform: String(f.get("platform") ?? "").trim(),
    environment: String(f.get("environment") ?? "").trim(),
    name: String(f.get("name") ?? "").trim(),
    scopes: f.getAll("scope").map(String),
  };
  const invalid = validateMint(input);
  if (invalid) return { status: "error", message: describeMintFailure({ status: "invalid", reason: invalid }) };

  const result = await mintCredential(input, await operatorBearer());
  if (result.status !== "ok") {
    console.error("mint key failed", result.status === "failed" ? result.reason : result.status); // fixed words only
    return { status: "error", message: describeMintFailure(result) };
  }
  return { status: "minted", ...result.credential };
}
