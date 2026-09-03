/**
 * OS keyring backend (freedesktop Secret Service API — the
 * org.freedesktop.secrets D-Bus standard, implemented by GNOME Keyring, KDE
 * KWallet via ksecretd, KeePassXC, …) for token storage.
 *
 * The python3 client is EMBEDDED below and (re)written to the state dir on
 * first use, so there is nothing to install and nothing to ship separately.
 * It talks JSON over stdin/stdout, which means the secret NEVER appears in
 * a process argument list — only in the parent process's memory.
 *
 * KWallet/ksecretd (KDE Plasma) notes:
 *   - ksecretd triggers a KWallet unlock dialog for every D-Bus operation
 *     on a LOCKED collection. To keep this from stacking prompts (and
 *     tripping kded's "Repeated attempts to access a wallet have
 *     occurred" warning):
 *       * "lookup" on a locked collection returns {"locked": true} and
 *         never touches the collection;
 *       * "upsert" does delete+create in ONE D-Bus roundtrip; when the
 *         collection is locked and a non-empty secret is being written it
 *         makes ONE explicit unlock attempt and then WAITS (`wait` seconds,
 *         default 20) for an interactive unlock (KWallet dialog / tray
 *         notification) to complete — ksecretd's Unlock call returns
 *         immediately, so a single recheck would always lose;
 *       * delete-only ("clear" / empty secret) never unlocks.
 * Non-interactive callers (bulk migration/repair at load) pass wait=0 and
 * get the old instant-fallback behavior.
 *
 * Two API generations are auto-detected at runtime by introspection:
 *   - modern 0.0.1 (gnome-keyring, kwallet --secretservice):
 *       Service.Store / SearchItems / item.GetSecret
 *   - legacy 0.0.0 (KDE ksecretd, default with KWallet 6):
 *       Collection.CreateItem / SearchItems / Service.GetSecrets
 *
 * Fallback: when python3/dbus/keyring are unavailable (headless, no D-Bus),
 * store.ts silently keeps the on-disk AES-encrypted file format.
 */
import { spawnSync } from "node:child_process";
import { writeFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const STATE_DIR = join(homedir(), ".pi", "agent", "pi-git-auth");
const PY_PATH = join(STATE_DIR, "wallet-tool.py");
const TIMEOUT_MS = 8000;
/** Default seconds to wait for an interactive wallet unlock on write. */
export const UNLOCK_WAIT_S = 20;
/** Upserts may block on an interactive unlock: give the wait room. */
const UPSERT_TIMEOUT_MS = (UNLOCK_WAIT_S + 15) * 1000;

/** Outcome of a keyring write: ok, keyring locked, or unreachable. */
export type WalletResult = "ok" | "locked" | "unreachable";

interface WalletRes {
  ok: boolean;
  secret?: string;
  api?: string;
  locked?: boolean;
  error?: string;
}

const PY = `#!/usr/bin/env python3
"""pi-git-auth keyring client (freedesktop Secret Service API).

Protocol: one JSON request on stdin, one JSON response line on stdout.
  {"cmd": "available"}
  {"cmd": "upsert", "attrs": {...}, "secret": "...", "wait": 20}
      # empty secret = delete only; wait = seconds to wait for an
      # interactive unlock while writing (0 = never wait)
  {"cmd": "lookup", "attrs": {...}}
  {"cmd": "clear",  "attrs": {...}}

Auto-detects the Secret Service API generation (modern 0.0.1 vs legacy
0.0.0/ksecretd) by introspecting the service.

KWallet/ksecretd (KDE) note: every D-Bus operation on a LOCKED collection
triggers a KWallet unlock dialog. So:
  - "lookup" on a locked collection returns {"locked": true} and never
    touches the collection;
  - "upsert" creates the new item (with its secret) FIRST and only then
    deletes the previously matched ones — kill-safe: an interrupted upsert
    never destroys the keyring copy; at most ONE explicit unlock attempt,
    and only when a non-empty secret is written; it then waits "wait"
    seconds for the interactive unlock to complete (ksecretd's Unlock
    returns immediately, so one recheck is not enough);
  - delete-only never unlocks.
This keeps the client from stacking unlock prompts, which is what makes
kded warn "Repeated attempts to access a wallet have occurred".
"""
import sys
import json
import re
import time

UNLOCK_WAIT_S = 20.0


def out(obj):
    sys.stdout.write(json.dumps(obj) + "\\n")
    sys.stdout.flush()


def to_bytes(v):
    return bytes(bytearray(v))


def main():
    line = sys.stdin.readline()
    req = json.loads(line) if line.strip() else {}
    cmd = req.get("cmd")
    secret = req.get("secret", "")

    try:
        import dbus
    except Exception:
        out({"ok": False, "error": "python3 dbus module not available"})
        return

    SVC = "org.freedesktop.secrets"
    try:
        bus = dbus.SessionBus()
    except Exception:
        out({"ok": False, "error": "no D-Bus session bus (headless?)"})
        return
    try:
        owner = bus.get_name_owner(SVC)
    except Exception:
        out({"ok": False, "error": "no keyring service on session bus"})
        return

    svc = bus.get_object(SVC, "/org/freedesktop/secrets")
    dbusi = dbus.Interface(svc, "org.freedesktop.Secret.Service")
    try:
        xml = dbus.Interface(
            bus.get_object(owner, "/org/freedesktop/secrets"),
            "org.freedesktop.DBus.Introspectable",
        ).Introspect()
    except Exception:
        xml = ""
    MODERN = 'name="Store"' in xml

    if cmd == "available":
        out({"ok": True, "api": "modern" if MODERN else "legacy"})
        return

    try:
        attrs = req["attrs"]
        label = "pi-git-auth %s %s" % (
            attrs.get("platform", "?"),
            attrs.get("login", "?"),
        )

        # open a plaintext session
        if MODERN:
            _o, session = dbusi.OpenSession("none", "")
        else:
            _o, session = dbusi.OpenSession("plain", "")
            coll = dbusi.ReadAlias("default")
            if str(coll) == "/":
                out({"ok": False, "error": "no default collection in keyring"})
                return

        def find_items():
            """Return (item paths in unlocked collections, locked flag).
            legacy ksecretd reports items in LOCKED collections separately;
            touching them would fire KWallet unlock dialogs, so callers
            get the flag instead."""
            if MODERN:
                res = dbusi.SearchItems(
                    dbus.UInt32(0),
                    dbus.Dictionary(
                        {k: v for k, v in attrs.items()}, "sv"
                    ),
                    dbus.ObjectPath("/"),
                )
                return [str(k) for k in res], False
            (u, locked) = dbusi.SearchItems(dbus.Dictionary(
                {k: v for k, v in attrs.items()}, "ss"
            ))
            return [str(k) for k in list(u)], bool(locked)

        def get_content(path):
            """Return the secret bytes for an item path, or None."""
            try:
                if MODERN:
                    _s, content = dbus.Interface(
                        bus.get_object(owner, path),
                        "org.freedesktop.Secret.Item",
                    ).GetSecret(session)
                    return to_bytes(content)
                secs = dbusi.GetSecrets(
                    [dbus.ObjectPath(path)], session
                )
                for st in secs.values():
                    c = to_bytes(st[2])
                    if c:
                        return c
            except Exception:
                pass
            # fallback: per-item GetSecret (both generations)
            try:
                _s, content = dbus.Interface(
                    bus.get_object(owner, path),
                    "org.freedesktop.Secret.Item",
                ).GetSecret(session)
                return to_bytes(content)
            except Exception:
                return None

        def item_delete(path):
            try:
                dbus.Interface(
                    bus.get_object(owner, path),
                    "org.freedesktop.Secret.Item",
                ).Delete()
            except Exception:
                pass

        if cmd in ("upsert", "store", "clear"):
            wait = max(0.0, float(req.get("wait", UNLOCK_WAIT_S)))
            paths, is_locked = find_items()
            writing = cmd != "clear" and bool(secret)
            if is_locked:
                if not writing:
                    # delete-only on a locked keyring: skip it rather than
                    # prompt (best-effort purge; the file is already clean).
                    out({"ok": False, "locked": True,
                         "error": "keyring is locked"})
                    return
                # writing while locked: exactly ONE unlock attempt, then
                # wait for the interactive unlock (KWallet dialog / tray
                # notification, GNOME prompt) to actually complete —
                # ksecretd's Unlock returns immediately, so a single
                # recheck would always report "locked".
                try:
                    dbusi.Unlock([coll])
                except Exception:
                    pass
                paths, is_locked = find_items()
                deadline = time.time() + wait
                while is_locked and time.time() < deadline:
                    time.sleep(1)
                    paths, is_locked = find_items()
                if is_locked:
                    out({"ok": False, "locked": True,
                         "error": "keyring is locked"})
                    return
            if cmd == "clear" or not secret:
                for path in paths:
                    item_delete(path)
                out({"ok": True})
                return
            # Kill-safe order: create the new item (with its secret) first,
            # then delete the previously matched items. Even if this process
            # is killed mid-upsert the keyring copy is never destroyed
            # (worst case: orphan items remain; the next upsert cleans them
            # up, and lookups take the first non-empty secret).
            new_path = ""
            if MODERN:
                item = "/org/freedesktop/secrets/0/item/" + re.sub(
                    r"[^A-Za-z0-9_]", "_", "%s_%s" % (
                        attrs.get("platform", "x"),
                        attrs.get("login", "x"),
                    )
                )
                item_props = dbus.Struct((
                    dbus.ObjectPath(item),
                    dbus.Dictionary({
                        "org.freedesktop.Secret.Item.Label": dbus.ByteArray(
                            label.encode("utf-8")
                        ),
                        "org.freedesktop.Secret.Item.Attributes":
                            dbus.Dictionary(
                                {k: v for k, v in attrs.items()}, "sv"
                            ),
                    }, "sv"),
                ))
                secret_props = dbus.Struct((
                    dbus.ObjectPath(item),
                    dbus.Dictionary({
                        "org.freedesktop.Secret.Secret.Value": dbus.ByteArray(
                            secret.encode("utf-8")
                        ),
                        "org.freedesktop.Secret.Secret.Content-Type":
                            "application/octet-stream",
                        "org.freedesktop.Secret.Secret.Parameters":
                            dbus.Dictionary({}, "sv"),
                    }, "sv"),
                ))
                dbusi.Store(
                    dbus.Dictionary({item: ""}, "sv"),
                    dbus.UInt32(0),
                    dbus.Dictionary(
                        {item: dbus.Struct((item_props, secret_props))},
                        "sv",
                    ),
                )
                new_path = item
            else:
                coll_obj = dbus.Interface(
                    bus.get_object(owner, str(coll)),
                    "org.freedesktop.Secret.Collection",
                )
                secret_arg = dbus.Struct((
                    session,
                    dbus.ByteArray(b""),
                    dbus.ByteArray(secret.encode("utf-8")),
                    "application/octet-stream",
                ))
                props = dbus.Dictionary({
                    "org.freedesktop.Secret.Item.Label": dbus.ByteArray(
                        label.encode("utf-8")
                    ),
                    "org.freedesktop.Secret.Item.Attributes":
                        dbus.Dictionary(
                            {k: v for k, v in attrs.items()}, "ss"
                        ),
                }, "sv")
                create_res = coll_obj.CreateItem(props, secret_arg, True)
                if create_res and len(create_res) > 1:
                    new_path = str(create_res[1])
            for path in paths:
                if path == new_path:
                    continue
                item_delete(path)
            out({"ok": True})
            return

        if cmd == "lookup":
            paths, is_locked = find_items()
            for path in paths:
                content = get_content(path)
                if content:
                    out({
                        "ok": True,
                        "secret": content.decode("utf-8", "replace"),
                    })
                    return
            if is_locked:
                # Item exists but its collection is locked (KWallet):
                # report it, don't touch the collection (no unlock prompt).
                out({"ok": False, "locked": True,
                     "error": "keyring is locked"})
                return
            out({"ok": False, "error": "item not found"})
            return

        out({"ok": False, "error": "unknown command"})
    except Exception as e:
        msg = str(e)
        if secret:
            msg = msg.replace(secret, "***")
        out({"ok": False, "error": msg or e.__class__.__name__})


main()
`;

/** Attribute set that identifies one account in the keyring. */
export function walletAttrs(platform: string, login: string): Record<string, string> {
  return { app: "pi-git-auth", platform, login: login.trim().toLowerCase() };
}

function writeScript(): boolean {
  try {
    mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
    writeFileSync(PY_PATH, PY, { mode: 0o600 });
    return true;
  } catch {
    return false;
  }
}

/** Run one keyring round-trip. Returns null when python3 itself is missing. */
function call(req: Record<string, unknown>, timeoutMs = TIMEOUT_MS): WalletRes | null {
  try {
    if (!writeScript()) return null;
    const r = spawnSync("python3", [PY_PATH], {
      input: JSON.stringify(req),
      encoding: "utf8",
      timeout: timeoutMs,
    });
    if (r.error) return { ok: false, error: r.error.message };
    const lines = (r.stdout ?? "").trim().split("\n").filter(Boolean);
    const last = lines[lines.length - 1];
    if (last) {
      try {
        return JSON.parse(last) as WalletRes;
      } catch {
        /* fall through to stderr-based error */
      }
    }
    return {
      ok: false,
      error:
        (r.stderr ?? "").trim().split("\n").slice(-1)[0] ||
        `keyring client exited with status ${r.status}`,
    };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

let availCache: boolean | null = null;

/** True when a keyring (Secret Service) is reachable. Result is cached. */
export function walletAvailable(): boolean {
  if (availCache !== null) return availCache;
  const r = call({ cmd: "available" }, 5000);
  availCache = !!(r && r.ok);
  return availCache;
}

let lastLookupLocked = false;

/**
 * Upsert a secret for the given attrs in ONE D-Bus roundtrip: the new item
 * is created (with its secret) first, then the previously matched items are
 * deleted — an interrupted upsert never destroys the keyring copy. An empty
 * secret deletes only (best-effort, never prompts).
 * `waitSec` is how long to wait for an interactive unlock when the
 * keyring is locked while writing (default UNLOCK_WAIT_S for interactive
 * callers such as login; pass 0 for non-interactive paths so they fall
 * back to the file instantly). "locked" = the keyring exists but is
 * locked (KWallet): the token must be kept in the file fallback;
 * "unreachable" = no keyring/D-Bus at all.
 */
export function walletUpsert(attrs: Record<string, string>, secret: string, waitSec = UNLOCK_WAIT_S): WalletResult {
  const r = call({ cmd: "upsert", attrs, secret, wait: waitSec }, Math.max(UPSERT_TIMEOUT_MS, (waitSec + 15) * 1000));
  if (!r) return "unreachable";
  if (r.ok) return "ok";
  if (r.locked) return "locked";
  return "unreachable";
}

/**
 * Read a secret; null when not found, the keyring is locked, or the
 * keyring is unreachable. See walletWasLocked() to distinguish a locked
 * keyring from a missing item.
 */
export function walletLookup(attrs: Record<string, string>): string | null {
  const r = call({ cmd: "lookup", attrs });
  lastLookupLocked = !!(r && r.locked);
  return r && r.ok ? (r.secret ?? null) : null;
}

/** True when the last lookup failed because the keyring is locked. */
export function walletWasLocked(): boolean {
  return lastLookupLocked;
}
