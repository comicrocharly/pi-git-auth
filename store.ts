import { readFileSync, writeFileSync, mkdirSync, rmSync, renameSync, chmodSync, copyFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import type { Platform } from "./forge";
import { STATE_DIR, walletAvailable, walletUpsert, walletLookup, walletAttrs, UNLOCK_WAIT_S } from "./keyring";

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
 * This is also the self-heal: a token kept in the file after a locked
 * wallet goes back to the keyring on the next load while it is reachable
 * (load-time writes use wait=0, so a still-locked wallet never delays
 * startup).
 *
 * If the keyring is locked on load, the token for `wallet:v1:` accounts
 * is "" for this process but is retried (throttled, prompt-safe) via
 * retryKeyringLoad() on the next status/git-gate hit, so it recovers
 * automatically once the wallet unlocks.
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
/** Stored strings (markers/envelopes) from the last file read/write. */
let diskData: StoreData | null = null;
/** Plaintext tokens as last persisted, per account key ("" = unreadable). */
let storedPlaintext: Record<string, string> = {};
/** A `wallet:v1:` token could not be read on load (keyring locked/absent). */
let keyringUnavailableAtLoad = false;
/** Accounts with a `wallet:v1:` marker that failed to read on load. */
let loadFailedKeys: string[] = [];
let lastRetryAt = 0;
const RETRY_THROTTLE_MS = 10_000;

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

/**
 * Persist the in-memory (plaintext) state. Only accounts whose token
 * changed since the last persist are (re)written to the backend; the
 * others keep their on-disk marker/envelope untouched. This matters on
 * KDE/ksecretd: a keyring write is the only operation that may trigger
 * the KWallet unlock dialog, so e.g. `/auth switch` performs zero
 * keyring writes (no prompts, no "repeated wallet access" warnings).
 * When the keyring is locked/unreachable the token is kept in the
 * encrypted file instead of leaving a dead `wallet:v1:` marker behind.
 *
 * `waitSec` = how long a keyring write may wait for an interactive
 * wallet unlock. Interactive callers (login) pass UNLOCK_WAIT_S so the
 * user can answer the KWallet prompt; load-time migration/repair passes
 * 0 so a locked wallet never delays startup.
 */
function persist(data: StoreData, forceStore = false, waitSec = 0): void {
  const mode = storeMode();
  const accounts: Record<string, AccountRecord> = {};
  const nowPlaintext: Record<string, string> = {};
  for (const [k, a] of Object.entries(data.accounts)) {
    const changed = forceStore || storedPlaintext[k] !== a.accessToken;
    const diskStored = diskData?.accounts[k]?.accessToken;
    let stored: string;
    if (changed && a.accessToken) {
      // Single keyring roundtrip (delete matching items + create).
      const r = mode === "wallet" ? walletUpsert(recAttrs(a, k), a.accessToken, waitSec) : null;
      stored = r === "ok" ? WALLET_PREFIX + k : encryptToken(a.accessToken);
    } else if (diskStored) {
      stored = diskStored; // unchanged: keep the existing marker/envelope
    } else {
      stored = a.accessToken ? encryptToken(a.accessToken) : "";
    }
    accounts[k] = { ...a, accessToken: stored };
    nowPlaintext[k] = a.accessToken;
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
  diskData = out;
  storedPlaintext = nowPlaintext;
  cache = data;
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
  // Deep snapshot BEFORE absorb() mutates records in place — diskData must
  // keep the on-disk stored strings (markers/envelopes), never the
  // plaintext tokens that absorb decrypts into the same objects.
  diskData = raw.accounts && typeof raw.accounts === "object" ? JSON.parse(JSON.stringify(raw)) : null;
  keyringUnavailableAtLoad = false;
  loadFailedKeys = [];
  const data: StoreData = { accounts: {} };
  let migrated = false;

  const absorb = (rec: any, key: string) => {
    if (!rec?.accessToken) return;
    if (rec.accessToken.startsWith(WALLET_PREFIX)) {
      const got = walletLookup(recAttrs(rec, key));
      if (got === null) {
        // keyring locked/cleared: keep the marker on disk, run this
        // process without the token, and flag it for the status output
        // and for retryKeyringLoad().
        rec.accessToken = "";
        keyringUnavailableAtLoad = true;
        loadFailedKeys.push(key);
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
    storedPlaintext[key] = (rec as AccountRecord).accessToken;
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
      persist(cache, true); // force re-store under the current backend
    } catch {
      /* best-effort migration */
    }
  }
  return cache;
}

/**
 * Persist after an interactive change (login): keyring writes may wait
 * up to UNLOCK_WAIT_S for the user to answer the wallet unlock prompt.
 */
export function saveStore(data: StoreData): void {
  persist(data, false, UNLOCK_WAIT_S);
}

/**
 * Lazy recovery for tokens that could not be read on load (keyring
 * locked): retry the lookup, throttled. Prompt-safe — a lookup never
 * touches a locked collection, so this cannot stack unlock prompts.
 * No-op once nothing is pending. Call it from hot paths (git gate,
 * /auth status) so the token recovers as soon as the wallet unlocks.
 */
export function retryKeyringLoad(): void {
  if (loadFailedKeys.length === 0) return;
  const now = Date.now();
  if (now - lastRetryAt < RETRY_THROTTLE_MS) return;
  lastRetryAt = now;
  const data = cache;
  if (!data) return;
  for (const k of [...loadFailedKeys]) {
    const rec = data.accounts[k];
    if (!rec || rec.accessToken) {
      loadFailedKeys = loadFailedKeys.filter((x) => x !== k);
      continue;
    }
    const got = walletLookup(recAttrs(rec, k));
    if (got !== null) {
      rec.accessToken = got;
      storedPlaintext[k] = got;
      loadFailedKeys = loadFailedKeys.filter((x) => x !== k);
    }
  }
  if (loadFailedKeys.length === 0) keyringUnavailableAtLoad = false;
}

/** Where the active account's token actually lives on disk right now. */
export function activeTokenStorage(): "keyring" | "file" {
  const key = cache?.activeLogin;
  const stored = key ? diskData?.accounts[key]?.accessToken : undefined;
  return stored?.startsWith(WALLET_PREFIX) ? "keyring" : "file";
}

/** True when a `wallet:v1:` token could not be read on load (keyring
 *  locked or unreachable) — the in-memory token for that account is "". */
export function keyringUnavailableAtLoadFlag(): boolean {
  return keyringUnavailableAtLoad;
}

/** Remove one account's keyring item (idempotent, best-effort). */
export function purgeAccountStorage(key: string, rec?: AccountRecord | null): void {
  try {
    // Empty secret = delete-only: best-effort, never triggers a prompt.
    if (rec) walletUpsert(recAttrs(rec, key), "");
  } catch {
    /* best-effort */
  }
}

export function clearStore(): void {
  // Purge keyring items for every known account before wiping the file.
  try {
    if (cache) {
      for (const [k, rec] of Object.entries(cache.accounts)) {
        walletUpsert(recAttrs(rec, k), "");
      }
    }
  } catch {
    /* best-effort */
  }
  cache = { accounts: {} };
  diskData = null;
  storedPlaintext = {};
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
