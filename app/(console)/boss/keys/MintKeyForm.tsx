"use client";

import { useActionState, useEffect, useState } from "react";
import { mintKey } from "./actions";
import type { MintKeyState } from "./actions";

type ScopeOption = { scope: string; purpose: string };
type Props = {
  environments: readonly string[];
  platformScopes: ScopeOption[];
  consoleScopes: ScopeOption[];
  /** The platform name that is offered the reports-read scope only. */
  consolePlatform: string;
};

const mono = "font-mono text-xs";
const field = "min-h-9 rounded-md border border-gray-300 bg-white px-3 py-1.5 text-sm text-gray-800 dark:border-gray-700 dark:bg-transparent dark:text-gray-100";
const primary = "inline-flex min-h-9 items-center rounded-md bg-brand-500 px-3.5 py-1.5 text-sm font-medium text-white hover:bg-brand-600 disabled:opacity-60";
const secondary = "inline-flex min-h-9 items-center rounded-md border border-gray-300 bg-white px-3.5 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50 dark:border-gray-700 dark:bg-transparent dark:text-gray-200 dark:hover:bg-white/5";

/**
 * "Mint a key". The new key comes back in the server action's result and lives only in this component's state: it is not put in the
 * URL, storage or a cookie, and it is hidden again when the person dismisses it, submits another request, leaves the page, or the
 * browser restores this page from its back/forward cache. Nothing on the page is revalidated, so the list below does not show the new
 * key until the page is loaded again.
 */
export default function MintKeyForm({ environments, platformScopes, consoleScopes, consolePlatform }: Props) {
  const [state, formAction, pending] = useActionState<MintKeyState, FormData>(mintKey, { status: "idle" });
  const [platform, setPlatform] = useState("");
  const [chosen, setChosen] = useState<string[]>([]);
  const [hidden, setHidden] = useState<MintKeyState | null>(null);
  const [copied, setCopied] = useState<"idle" | "done" | "failed">("idle");

  const isConsole = platform.trim() === consolePlatform;
  const options = isConsole ? consoleScopes : platformScopes;
  const checked = (scope: string) => (isConsole ? true : chosen.includes(scope));
  const toggle = (scope: string) => setChosen((prev) => (prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope]));

  // A page restored from the back/forward cache is a frozen copy of the old DOM: do not let it show a key again.
  useEffect(() => {
    const onShow = (e: PageTransitionEvent) => {
      if (e.persisted) setHidden(state);
    };
    window.addEventListener("pageshow", onShow);
    return () => window.removeEventListener("pageshow", onShow);
  }, [state]);

  const minted = state.status === "minted" && hidden !== state ? state : null;

  async function copy(key: string) {
    try {
      await navigator.clipboard.writeText(key);
      setCopied("done");
    } catch {
      setCopied("failed"); // the field is selectable; the person can copy it by hand
    }
  }

  return (
    <div className="space-y-4">
      <form action={formAction} onSubmit={() => { setHidden(state); setCopied("idle"); }} className="grid max-w-2xl gap-4" aria-label="Mint a key">
        <div className="flex flex-wrap items-start gap-4">
          <label className="text-sm text-gray-600 dark:text-gray-300">Platform
            <input name="platform" value={platform} onChange={(e) => setPlatform(e.target.value)} required placeholder="pawpointers" pattern="[a-z0-9][a-z0-9\-]{0,62}" autoComplete="off" spellCheck={false} className={`${field} mt-1 block`} />
          </label>
          <label className="text-sm text-gray-600 dark:text-gray-300">Environment
            <select name="environment" required defaultValue="" className={`${field} mt-1 block`}>
              <option value="" disabled>Choose…</option>
              {environments.map((e) => <option key={e} value={e}>{e}</option>)}
            </select>
          </label>
          <label className="text-sm text-gray-600 dark:text-gray-300">Key name
            <input name="name" required placeholder="pawpointers-production-2" pattern="[a-z0-9][a-z0-9._\-]{0,127}" autoComplete="off" spellCheck={false} className={`${field} mt-1 block`} />
          </label>
        </div>

        <fieldset className="text-sm text-gray-600 dark:text-gray-300">
          <legend className="mb-1">Scopes</legend>
          <div className="space-y-1.5">
            {options.map((o) => (
              <label key={o.scope} className="flex items-start gap-2">
                <input type="checkbox" name="scope" value={o.scope} checked={checked(o.scope)} onChange={() => { if (!isConsole) toggle(o.scope); }} className="mt-0.5" />
                <span><span className={mono}>{o.scope}</span> <span className="text-xs text-gray-500 dark:text-gray-400">{o.purpose}</span></span>
              </label>
            ))}
          </div>
          <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">
            {isConsole
              ? "The console's key from here is the reports reader: exactly boss.reports.read. Console operator keys and the tin hub's key are minted by the owner."
              : "A platform key carries any non-empty subset of these. Operator scopes are not offered here."}
          </p>
        </fieldset>

        <div>
          <button className={primary} disabled={pending}>{pending ? "Minting…" : "Mint key"}</button>
        </div>
      </form>

      {state.status === "error" && <p role="alert" className="rounded-lg border border-red-300 bg-red-50 px-4 py-3 text-sm text-red-800 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-200">{state.message}</p>}

      {minted && (
        <section role="status" aria-label="New key" className="max-w-2xl space-y-3 rounded-lg border border-amber-300 bg-amber-50 px-4 py-4 text-sm text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-100">
          <p className="font-medium">Minted <span className={mono}>{minted.name}</span> for <span className={mono}>{minted.identity}</span> ({minted.scopes.join(", ")}).</p>
          <p>Shown once. Put it in the platform&apos;s secret store now; BOSS keeps only a hash.</p>
          <div className="flex flex-wrap items-center gap-2">
            <input readOnly value={minted.key} aria-label="New key" autoComplete="off" spellCheck={false} onFocus={(e) => e.currentTarget.select()} className={`${field} ${mono} min-w-0 flex-1 basis-72`} />
            <button type="button" onClick={() => copy(minted.key)} className={secondary}>{copied === "done" ? "Copied" : "Copy"}</button>
          </div>
          {copied === "failed" && <p role="alert" className="text-xs">Could not copy automatically. Select the key above and copy it yourself.</p>}
          <button type="button" onClick={() => { setHidden(state); setCopied("idle"); }} className={secondary}>I have stored it: hide the key</button>
        </section>
      )}
    </div>
  );
}
