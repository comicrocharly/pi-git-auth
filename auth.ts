import { spawn } from "node:child_process";
import { loadStore, saveStore, maskToken, activeAccount, accountKey, purgeAccountStorage, storeBackend, type StoreData } from "./store";
import { SERVICES, type Platform, type Service } from "./forge";

/** The subset of ctx.ui the auth flows need. */
export interface UiLike {
  input(title: string, placeholder?: string): Promise<string | undefined>;
  notify(message: string, type?: "info" | "warning" | "error"): void;
}

function fail(ui: UiLike, e: unknown): void {
  ui.notify(`Login failed: ${e instanceof Error ? e.message : String(e)}`, "error");
}

function openBrowser(url: string): void {
  const cmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "explorer" : "xdg-open";
  try {
    const p = spawn(cmd, [url], { stdio: "ignore", detached: true });
    p.on("error", () => {});
    p.unref();
  } catch {
    /* headless: the URL is shown in the notify message anyway */
  }
}

/** Display name for an account key: the login part, without platform. */
export function accountName(data: StoreData, key: string): string {
  return data.accounts[key]?.user ?? key.slice(key.indexOf(":") + 1);
}

/**
 * Login for a specific service (GitHub or GitLab). The account is keyed
 * by platform+login: logging in again with the same pair replaces its
 * token; either way the account becomes the active one.
 */
export async function loginWithPastedToken(ui: UiLike, service: Service): Promise<void> {
  openBrowser(service.tokenUrl);
  ui.notify(`Create a ${service.label} token here: ${service.tokenUrl}  (scopes: ${service.scopesHint})`, "info");
  const raw = (await ui.input(`Paste ${service.label} token (page opened in browser)`, service.tokenPlaceholder))?.trim();
  if (!raw) {
    ui.notify("Login cancelled", "info");
    return;
  }
  ui.notify("Verifying token…", "info");
  let user;
  try {
    user = await service.verify(raw);
  } catch (e) {
    fail(ui, e);
    return;
  }
  const data = loadStore();
  const key = accountKey(service.id, user.login);
  const isExisting = !!data.accounts[key];
  data.accounts[key] = {
    type: "pat",
    platform: service.id,
    accessToken: raw,
    user: user.login,
    scopes: user.scopes,
    savedAt: new Date().toISOString(),
  };
  data.activeLogin = key;
  saveStore(data);
  ui.notify(
    isExisting
      ? `Token updated for @${user.login} (${service.id}) — now active`
      : `Logged in as @${user.login} (${service.id}) — now active`,
    "info",
  );
}

/**
 * Remove one stored account. If it was active, another remaining account
 * becomes active (or none when it was the last).
 */
export function removeAccount(key: string): void {
  const data = loadStore();
  const rec = data.accounts[key];
  delete data.accounts[key];
  purgeAccountStorage(key, rec); // drop the keyring item, if any
  if (data.activeLogin === key) {
    const rest = Object.keys(data.accounts);
    data.activeLogin = rest.length > 0 ? rest[0] : undefined;
  }
  saveStore(data);
}

/** Make an account the active one. Returns false for unknown keys. */
export function setActiveAccount(key: string): boolean {
  const data = loadStore();
  if (!data.accounts[key]) return false;
  if (data.activeLogin === key) return true;
  data.activeLogin = key;
  saveStore(data);
  return true;
}

/**
 * Resolve an account query ("login" or "platform:login") to stored keys.
 * [] = unknown; >1 = ambiguous (same login on several platforms).
 */
export function findAccounts(query: string): string[] {
  const q = query.trim().toLowerCase();
  const keys = Object.keys(loadStore().accounts);
  if (q.includes(":")) {
    const key = accountKey(q.slice(0, q.indexOf(":")) as Platform, q.slice(q.indexOf(":") + 1));
    return keys.includes(key) ? [key] : [];
  }
  return keys.filter((k) => k.endsWith(`:${q}`));
}

/** Service (REST API) of the active account, or undefined. */
export function activeService(data: StoreData): Service | undefined {
  const acc = activeAccount(data);
  return acc ? SERVICES[acc.platform] : undefined;
}

/** Human-readable status block: all accounts, details for the active one. */
export function statusDetail(data: StoreData): string {
  const keys = Object.keys(data.accounts);
  if (keys.length === 0) return "No git accounts. Run /auth login.";
  const lines = ["Git accounts:"];
  for (const k of keys) {
    const a = data.accounts[k];
    const star = data.activeLogin === k ? "*" : " ";
    lines.push(
      `  ${star} @${a?.user ?? k.slice(k.indexOf(":") + 1)}  (${a?.platform ?? "github"})${
        data.activeLogin === k ? "  (active)" : ""
      }`,
    );
  }
  const activeKey = data.activeLogin;
  if (activeKey) lines.push("");
  lines.push(`Store: ${storeBackend() === "keyring" ? "OS keyring (Secret Service)" : "encrypted file"}`);
  if (activeKey) lines.push("");
  const active = activeKey ? data.accounts[activeKey] : undefined;
  if (active && activeKey) {
    lines.push("");
    lines.push(`Active: @${active.user ?? activeKey.slice(activeKey.indexOf(":") + 1)}  (${active.platform})`);
    lines.push(`Token: ${maskToken(active.accessToken)}`);
    if (active.scopes) lines.push(`Scopes: ${active.scopes}`);
    lines.push(`Saved: ${active.savedAt}`);
  }
  return lines.join("\n");
}
