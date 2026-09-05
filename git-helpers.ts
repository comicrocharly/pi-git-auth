/**
 * Detection of file-persisting git credential helpers.
 *
 * The git gate keeps its token out of helpers by disabling them for the
 * instrumented process (see git-gate.ts). This module is the *advisory*
 * side: it detects whether the user's normal git configuration would have
 * persisted the injected token (e.g. `credential.helper = store` →
 * ~/.git-credentials) so the status view can note it. Passive only — no
 * prompt, no blocking, fail-silent (any error → `undefined`).
 */
import { execFile } from "node:child_process";

export interface CredHelperSink {
  /** The `credential.helper` value as configured (e.g. "store"). */
  helper: string;
  /** Where that helper persists credentials, for the status line. */
  target: string;
}

const TTL_MS = 60_000;
const TIMEOUT_MS = 3_000;

let cache: { at: number; sink: CredHelperSink | undefined } | undefined;
let inFlight: Promise<CredHelperSink | undefined> | undefined;

function sinkFor(value: string): CredHelperSink | undefined {
  const v = value.trim();
  const base = v.split("/").pop() ?? v;
  if (v === "store" || base === "credential-store" || v.endsWith("!store")) {
    return { helper: v, target: "~/.git-credentials (plaintext)" };
  }
  if (v === "netrc" || base === "credential-netrc" || v.endsWith("!netrc")) {
    return { helper: v, target: "~/.netrc" };
  }
  return undefined; // OS wallets (gnome-keyring, osxkeychain, …): fine, no note
}

/**
 * Detect a file-persisting credential helper in the user's normal git
 * config. Cached for 60 s, deduplicated in flight, and fail-silent:
 * missing git, timeout, or no such helper → `undefined`.
 */
export function detectCredHelperSink(): Promise<CredHelperSink | undefined> {
  const now = Date.now();
  if (cache && now - cache.at < TTL_MS) return Promise.resolve(cache.sink);
  if (inFlight) return inFlight;
  inFlight = new Promise<CredHelperSink | undefined>((resolve) => {
    let done = false;
    const finish = (sink: CredHelperSink | undefined) => {
      if (done) return;
      done = true;
      cache = { at: Date.now(), sink };
      inFlight = undefined;
      resolve(sink);
    };
    const timer = setTimeout(() => finish(undefined), TIMEOUT_MS);
    execFile(
      "git",
      ["config", "--get-all", "--show-origin", "credential.helper"],
      { timeout: TIMEOUT_MS },
      (err, stdout) => {
        clearTimeout(timer);
        if (err) return finish(undefined);
        // Lines: "<origin>\t<value>". Prefer the last (most specific) match.
        let sink: CredHelperSink | undefined;
        for (const line of stdout.split("\n")) {
          const idx = line.indexOf("\t");
          if (idx < 0) continue;
          const found = sinkFor(line.slice(idx + 1));
          if (found) sink = found;
        }
        finish(sink);
      },
    );
  });
  return inFlight;
}
