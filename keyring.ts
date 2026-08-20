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
 * Two API generations are auto-detected at runtime by introspection:
 *   - modern 0.0.1 (gnome-keyring, kwallet --secretservice):
 *       Service.Store / SearchItems / item.GetSecret
 *   - legacy 0.0.0 (KDE ksecretd, default with KWallet 6):
 *       Collection.CreateItem / Service.SearchItems / Service.GetSecrets
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

interface WalletRes {
  ok: boolean;
  secret?: string;
  api?: string;
  error?: string;
}

const PY = `#!/usr/bin/env python3
"""pi-git-auth keyring client (freedesktop Secret Service API).

Protocol: one JSON request on stdin, one JSON response line on stdout.
  {"cmd": "available"}
  {"cmd": "store",  "attrs": {...}, "secret": "..."}
  {"cmd": "lookup", "attrs": {...}}
  {"cmd": "clear",  "attrs": {...}}

Auto-detects the Secret Service API generation (modern 0.0.1 vs legacy
0.0.0/ksecretd) by introspecting the service.
"""
import sys
import json
import re


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
            try:
                dbusi.Unlock([coll])
            except Exception:
                pass

        def find_items():
            if MODERN:
                res = dbusi.SearchItems(
                    dbus.UInt32(0),
                    dbus.Dictionary(
                        {k: v for k, v in attrs.items()}, "sv"
                    ),
                    dbus.ObjectPath("/"),
                )
                return [str(k) for k in res]
            (u, _l) = dbusi.SearchItems(dbus.Dictionary(
                {k: v for k, v in attrs.items()}, "ss"
            ))
            return [str(k) for k in list(u) + list(_l)]

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

        if cmd == "store":
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
            else:
                coll_obj = dbus.Interface(
                    bus.get_object(owner, str(dbusi.ReadAlias("default"))),
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
                coll_obj.CreateItem(props, secret_arg, True)
            out({"ok": True})
            return

        if cmd == "lookup":
            for path in find_items():
                content = get_content(path)
                if content:
                    out({
                        "ok": True,
                        "secret": content.decode("utf-8", "replace"),
                    })
                    return
            out({"ok": False, "error": "item not found"})
            return

        if cmd == "clear":
            for path in find_items():
                item_delete(path)
            out({"ok": True})
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

/** Store (upsert) a secret. */
export function walletStore(attrs: Record<string, string>, secret: string): boolean {
  const r = call({ cmd: "store", attrs, secret });
  return !!(r && r.ok);
}

/** Read a secret; null when not found or the keyring is unreachable. */
export function walletLookup(attrs: Record<string, string>): string | null {
  const r = call({ cmd: "lookup", attrs });
  return r && r.ok ? (r.secret ?? null) : null;
}

/** Remove every item matching attrs. No-op when none exist. */
export function walletClear(attrs: Record<string, string>): boolean {
  const r = call({ cmd: "clear", attrs });
  return !!(r && r.ok);
}
