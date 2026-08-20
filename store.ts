import { readFileSync, writeFileSync, mkdirSync, rmSync, renameSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import type { Platform } from "./forge";

/**
 * Credential persistence for pi-git-auth (multi-account, multi-service).
 *
 * Tokens are ENCRYPTED AT REST:
 *   - credentials.json (0600) holds each token as an AES-256-GCM envelope,
 *     never as plaintext.
 *   - The key lives in a separate 0600 file (key) generated on first use.
 *
 * In memory (and everywhere loadStore() is used) tokens are plaintext.
 *
 * Accounts are keyed by `<platform>:<login>` so the same login can exist
 * on GitHub and GitLab. One account is "active": it is used for git auth
 * and by the /auth actions and LLM tool, and every action dispatches to
 * the REST API of that account's platform.
 *
 * Migrations (all transparent on load):
 *   v0: { auth: AccountRecord }                 → github account
 *   v1: { accounts: { <login>: … }, activeLogin } → github keys
 *   v2: { accounts: { "<platform>:<login>": … }, activeLogin }
 */

const STATE_DIR = join(homedir(), ".pi", "agent", "pi-git-auth");
const CREDENTIALS_FILE = join(STATE_DIR, "credentials.json");
const KEY_FILE = join(STATE_DIR, "key");

export interface AccountRecord {
  /** How the token was obtained. */
  type: "pat";
  /** Which service the account belongs to. */
  platform: Platform;
  /**
   * On disk: an `enc:v1:<base64>` AES-256-GCM envelope.
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
// Key management
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
  return keyCache;
}

// ---------------------------------------------------------------------------
// Crypto (AES-256-GCM)
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
  // Encrypt for disk; keep the in-memory copy plaintext.
  const accounts: Record<string, AccountRecord> = {};
  for (const [k, a] of Object.entries(data.accounts)) {
    accounts[k] = { ...a, accessToken: encryptToken(a.accessToken) };
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
  try {
    raw = JSON.parse(readFileSync(CREDENTIALS_FILE, "utf8"));
  } catch {
    raw = {};
  }
  const data: StoreData = { accounts: {} };
  let migrated = false;

  const absorb = (rec: any, key: string) => {
    if (!rec?.accessToken) return;
    if (isEncrypted(rec.accessToken)) {
      try {
        rec.accessToken = decryptToken(rec.accessToken);
      } catch {
        // Key rotated/corrupt: don't crash, and don't expose a broken token.
        rec.accessToken = "";
      }
    } else {
      migrated = true; // legacy plaintext — re-encrypted on next persist
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
      persist(cache); // rewrite as ciphertext / v2 shape
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

export function clearStore(): void {
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
