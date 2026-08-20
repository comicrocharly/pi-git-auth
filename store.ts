import { readFileSync, writeFileSync, mkdirSync, rmSync, renameSync, chmodSync, copyFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import type { Platform } from "./forge";
import { STATE_DIR, walletAvailable, walletStore, walletLookup, walletClear, walletAttrs } from "./keyring";

/**
 * Credential persistence for pi-git-auth (multi-account, multi-service).
 *
 * Tokens are NEVER stored plaintext on disk. Two backends:
 *
 *   wallet (preferred, auto-detected): the token lives in the OS keyring
 *       (Secret Service: KWallet / GNOME Keyring / …). The file holds only
 *       a `wallet:v1:<accountKey>` marker. No key file, no disk ciphertext.
 *
 *   file (fallback, e.g. headless without D-Bus): credentials.json (0600)
 *       holds each token as an `enc:v1:<base64>` AES-256-GCM envelope; the
 *       key lives in a separate 0600 file (key) generated on first use.
 *
 * Migration is transparent: legacy plaintext or `enc:v1:` tokens are moved
 * into the keyring on first load (a `.bak` copy of the file is kept).
 *
 * Env override: PI_GIT_AUTH_STORE = auto (default) | wallet | file
 *
 * In memory (and everywhere loadStore() is used) tokens are plaintext.
 *
 * Accounts are keyed by `<platform>:<login>` so the same login can exist
 * on GitHub and GitLab. One account is "active": it is used for git auth
 * and by the /auth actions and LLM tool, and every action dispatches to
 * the REST API of that account's platform.
 *
 * File migrations (all transparent on load):
 *   v0: { auth: AccountRecord }                 → github account
 *   v1: { accounts: { <login>: … }, activeLogin } → github keys
 *   v2: { accounts: { "<platform>:<login>": … }, activeLogin }
 *   v3: accessToken is a `wallet:v1:` marker (keyring) or `enc:v1:` (file)
 */

const CREDENTIALS_FILE = join(STATE_DIR, "credentials.json");
const KEY_FILE = join(STATE_DIR, "key");

export interface AccountRecord {
  /** How the token was obtained. */
  type: "pat";
  /** Which service the account belongs to. */
  platform: Platform;
  /**
   * On disk: a `wallet:v1:<accountKey>` marker (keyring backend) or an
   * `enc:v1:<base64>` AES-256-GCM envelope (file backend).
   * In memory (loadStore result): the plaintext token.
   */
  accessToken: string;
  /** Resolved login (original casing). */
  user?: string;
  /** Scopes reported by the service, best-effort. */
  scopes?: string;
  savedAt: string;
}

export interface StoreData {
  /** Accounts keyed by accountKey(platform, login). */
  accounts: Record<string, AccountRecord>;
  /** Key of the active account. */
  activeLogin?: string;
}

let cache: StoreData | null = null;
let keyCache: Buffer | null = null;

const ENC_PREFIX = "enc:v1:";
const WALLET_PREFIX = "wallet:v1:";

function isEncrypted(s: string): boolean {
  return s.startsWith(ENC_PREFIX);
}

/** Canonical account key: `platform:login` (login trimmed, lowercased). */
export function accountKey(platform: Platform, login: string): string {
  return `${platform}:${login.trim().toLowerCase()}`;
}

/** The active account record, or undefined when none is active. */
export function activeAccount(data: StoreData): AccountRecord | undefined {
  return data.activeLogin ? data.accounts[data.activeLogin] : undefined;
}

// ---------------------------------------------------------------------------
// Backend selection
// ---------------------------------------------------------------------------

/** Resolved storage backend. PI_GIT_AUTH_STORE forces one; "auto" probes
 *  the keyring once per process. */
function storeMode(): "wallet" | "file" {
  const env = (process.env.PI_GIT_AUTH_STORE ?? "auto").toLowerCase();
  if (env === "file") return "file";
  if (env === "wallet") return "wallet";
  return walletAvailable() ? "wallet" : "file";
}

/** Human-readable backend name for status output. */
export function storeBackend(): "keyring" | "file" {
  return storeMode() === "wallet" ? "keyring" : "file";
}

/** Keyring attrs for an account record. */
function recAttrs(rec: Pick<AccountRecord, "platform" | "user">, key: string): Record<string, string> {
  const login = rec.user ?? key.slice(key.indexOf(":") + 1);
  return walletAttrs(rec.platform, login);
}

// ---------------------------------------------------------------------------
// Key management (file backend only)
// ---------------------------------------------------------------------------

function getKey(): Buffer {
  if (keyCache) return keyCache;
  try {
    const b = Buffer.from(readFileSync(KEY_FILE, "utf8").trim(), "base64");
    if (b.length === 32) {
      keyCache = b;
      return keyCache;
    }
  } catch {
    /* no key yet */
  }
  const k = randomBytes(32);
  keyCache = k;
  mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
  const tmp = KEY_FILE + ".tmp";
  writeFileSync(tmp, k.toString("base64"), { mode: 0o600 });
  renameSync(tmp, KEY_FILE);
  chmodSync(KEY_FILE, 0o600);
  return k;
}

// ---------------------------------------------------------------------------
// Crypto (AES-256-GCM, file backend)
// ---------------------------------------------------------------------------

function encryptToken(plain: string): string {
  const key = getKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes
  return ENC_PREFIX + Buffer.concat([iv, tag, ct]).toString("base64");
}

function decryptToken(enc: string): string {
  const key = getKey();
  const raw = Buffer.from(enc.slice(ENC_PREFIX.length), "base64");
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const ct = raw.subarray(28);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const out = Buffer.concat([decipher.update(ct), decipher.final()]);
  return out.toString("utf8");
}

// ---------------------------------------------------------------------------
// Store API
// ---------------------------------------------------------------------------

function persist(data: StoreData): void {
  // The in-memory copy holds plaintext; for each account the token is
  // stored in the backend and the file keeps only a marker/envelope.
  const mode = storeMode();
  const accounts: Record<string, AccountRecord> = {};
  for (const [k, a] of Object.entries(data.accounts)) {
    let stored: string;
    if (mode === "wallet") {
      // Clear-then-store keeps the keyring free of duplicate items.
      const attrs = recAttrs(a, k);
      walletClear(attrs);
      stored = walletStore(attrs, a.accessToken) ? WALLET_PREFIX + k : encryptToken(a.accessToken);
    } else {
      stored = encryptToken(a.accessToken);
    }
    accounts[k] = { ...a, accessToken: stored };
  }
  const out: StoreData = {
    accounts,
    ...(data.activeLogin ? { activeLogin: data.activeLogin } : {}),
  };
  mkdirSync(dirname(CREDENTIALS_FILE), { recursive: true, mode: 0o700 });
  const tmp = CREDENTIALS_FILE + ".tmp";
  writeFileSync(tmp, JSON.stringify(out, null, 2) + "\n", { mode: 0o600 });
  renameSync(tmp, CREDENTIALS_FILE);
  chmodSync(CREDENTIALS_FILE, 0o600);
}

export function loadStore(): StoreData {
  if (cache) return cache;
  let raw: any = {};
  let hadFile = false;
  try {
    raw = JSON.parse(readFileSync(CREDENTIALS_FILE, "utf8"));
    hadFile = true;
  } catch {
    raw = {};
  }
  const data: StoreData = { accounts: {} };
  let migrated = false;

  const absorb = (rec: any, key: string) => {
    if (!rec?.accessToken) return;
    if (rec.accessToken.startsWith(WALLET_PREFIX)) {
      const got = walletLookup(recAttrs(rec, key));
      if (got === null) {
        rec.accessToken = ""; // keyring unreachable/cleared: don't crash, don't leak
      } else {
        rec.accessToken = got;
      }
    } else if (isEncrypted(rec.accessToken)) {
      try {
        rec.accessToken = decryptToken(rec.accessToken);
      } catch {
        // Key rotated/corrupt: don't crash, and don't expose a broken token.
        rec.accessToken = "";
      }
      migrated = true; // legacy file format — re-stored per current backend
    } else {
      migrated = true; // legacy plaintext
    }
    if (!rec.platform) {
      rec.platform = "github"; // pre-v2 records were GitHub-only
      migrated = true;
    }
    data.accounts[key] = rec as AccountRecord;
  };

  if (raw.accounts && typeof raw.accounts === "object") {
    for (const [k, a] of Object.entries<any>(raw.accounts)) {
      // v1 keys have no platform prefix; v2 keys are `platform:login`.
      absorb(a, k.includes(":") ? k : accountKey("github", k));
    }
    if (raw.activeLogin) {
      const migratedKey = raw.activeLogin.includes(":") ? raw.activeLogin : accountKey("github", raw.activeLogin);
      if (data.accounts[migratedKey]) data.activeLogin = migratedKey;
    }
  } else if (raw.auth?.accessToken) {
    // v0: { auth: AccountRecord }
    const key = accountKey("github", raw.auth.user ?? "account");
    absorb(raw.auth, key);
    data.activeLogin = key;
  }

  cache = data;
  if (migrated) {
    try {
      // Keep a rollback copy of the pre-migration file (still 0600, no
      // new secrets — it only contains ciphertexts/markers).
      if (hadFile && existsSync(CREDENTIALS_FILE)) copyFileSync(CREDENTIALS_FILE, CREDENTIALS_FILE + ".bak");
      persist(cache);
    } catch {
      /* best-effort migration */
    }
  }
  return cache;
}

export function saveStore(data: StoreData): void {
  cache = data;
  persist(data);
}

/** Remove one account's keyring item (idempotent, best-effort). */
export function purgeAccountStorage(key: string, rec?: AccountRecord | null): void {
  try {
    if (rec) walletClear(recAttrs(rec, key));
  } catch {
    /* best-effort */
  }
}

export function clearStore(): void {
  // Purge keyring items for every known account before wiping the file.
  try {
    if (cache) {
      for (const [k, rec] of Object.entries(cache.accounts)) {
        walletClear(recAttrs(rec, k));
      }
    }
  } catch {
    /* best-effort */
  }
  cache = { accounts: {} };
  try {
    rmSync(CREDENTIALS_FILE);
  } catch {
    /* ignore */
  }
}

/** Masked token for display: ghp_…Qw9 */
export function maskToken(token: string | undefined): string {
  if (!token) return "(none)";
  if (token.length <= 8) return "****";
  return `${token.slice(0, 4)}…${token.slice(-4)}`;
}
