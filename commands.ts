import type { ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { loadStore, activeAccount, type StoreData } from "./store";
import { SERVICES, type Service, type TreeEntry } from "./forge";
import { buildDetailsText, RepoDetailsPanel } from "./details";
import { activeService, accountName, loginWithPastedToken, removeAccount, setActiveAccount, statusDetail } from "./auth";

type Ctx = ExtensionCommandContext;

async function showStatus(ctx: Ctx): Promise<void> {
  const data = loadStore();
  if (Object.keys(data.accounts).length === 0) {
    ctx.ui.notify("git auth: not connected — run /auth login", "info");
  } else {
    ctx.ui.notify(statusDetail(data), "info");
  }
}

async function doLogin(ctx: Ctx): Promise<void> {
  const pick = await ctx.ui.select("git auth — which service?", [SERVICES.github.label, SERVICES.gitlab.label]);
  const service: Service = pick === SERVICES.gitlab.label ? SERVICES.gitlab : SERVICES.github;
  await loginWithPastedToken(ctx.ui, service);
}

function accountLabels(data: StoreData): string[] {
  return Object.keys(data.accounts).map(
    (k) =>
      `@${data.accounts[k]?.user ?? k.slice(k.indexOf(":") + 1)}  (${data.accounts[k]?.platform ?? "github"})${
        data.activeLogin === k ? "  (current)" : ""
      }`,
  );
}

async function doSwitch(ctx: Ctx): Promise<void> {
  const data = loadStore();
  if (Object.keys(data.accounts).length === 0) {
    ctx.ui.notify("No git accounts — run /auth login", "info");
    return;
  }
  const keys = Object.keys(data.accounts);
  const labels = accountLabels(data);
  const picked = await ctx.ui.select("git auth — set active account", labels);
  const idx = labels.indexOf(picked ?? "");
  if (idx < 0) return;
  const key = keys[idx];
  if (setActiveAccount(key)) {
    ctx.ui.notify(
      `Active account: @${accountName(data, key)} (${data.accounts[key]?.platform ?? "github"})`,
      "info",
    );
  }
}

async function doLogout(ctx: Ctx): Promise<void> {
  const data = loadStore();
  if (Object.keys(data.accounts).length === 0) {
    ctx.ui.notify("No git accounts logged in", "info");
    return;
  }
  const keys = Object.keys(data.accounts);
  const labels = accountLabels(data);
  const picked = await ctx.ui.select("git auth — pick an account to remove", labels);
  const idx = labels.indexOf(picked ?? "");
  if (idx < 0) return;
  const key = keys[idx];
  const ok = await ctx.ui.confirm("git auth logout", `Remove @${accountName(data, key)} (${data.accounts[key]?.platform})?`);
  if (!ok) return;
  removeAccount(key);
  ctx.ui.notify(`Removed @${accountName(data, key)}`, "info");
}

/** Active account + its service, or a "not connected" notice. */
function requireActive(ctx: Ctx): { token: string; service: Service } | undefined {
  const data = loadStore();
  const acc = activeAccount(data);
  const service = activeService(data);
  if (!acc?.accessToken || !service) {
    ctx.ui.notify("git auth: not connected — run /auth login", "warning");
    return undefined;
  }
  return { token: acc.accessToken, service };
}

async function doRepos(ctx: Ctx, restArg: string): Promise<void> {
  const active = requireActive(ctx);
  if (!active) return;
  const org = restArg || undefined;
  try {
    const repos = await active.service.listRepos(active.token, org);
    if (repos.length === 0) {
      ctx.ui.notify(org ? `No repos in org ${org}` : "No repositories found", "info");
      return;
    }
    const labels = repos.map((r) => `${r.fullName} [${r.private ? "private" : "public"}]`);
    const picked = await ctx.ui.select(
      `Repositories${org ? ` (${org})` : " (owned)"} — pick one:`,
      labels,
    );
    const idx = labels.indexOf(picked ?? "");
    if (idx >= 0) {
      await showRepoDetails(ctx, active.service, active.token, repos[idx].fullName);
    }
  } catch (e) {
    ctx.ui.notify(`${active.service.label} error: ${e instanceof Error ? e.message : String(e)}`, "error");
  }
}

/** Fetch repo metadata, latest commits and tree, then show a scrollable details overlay. */
async function showRepoDetails(ctx: Ctx, service: Service, token: string, fullName: string): Promise<void> {
  try {
    const [repo, commits] = await Promise.all([service.meta(token, fullName), service.commits(token, fullName, 5)]);
    let tree: TreeEntry[] = [];
    if (commits.length > 0) {
      try {
        tree = await service.tree(token, fullName, repo.defaultBranch);
      } catch {
        tree = []; // non-fatal: details still shown without the tree
      }
    }
    const { title, lines } = buildDetailsText(repo, commits, tree);
    await ctx.ui.custom<void>(
      (tui, theme, _keybindings, done) =>
        new RepoDetailsPanel(
          title,
          lines,
          theme,
          () => tui.terminal.rows,
          () => done(undefined),
          () => tui.requestRender(),
        ),
      {
        overlay: true,
        overlayOptions: { width: "65%", minWidth: 64, maxHeight: "80%", margin: 1 },
      },
    );
  } catch (e) {
    ctx.ui.notify(`${service.label} error: ${e instanceof Error ? e.message : String(e)}`, "error");
  }
}

async function doCreate(ctx: Ctx, restArg: string): Promise<void> {
  const active = requireActive(ctx);
  if (!active) return;
  let fullName = restArg.trim();
  if (!fullName) {
    fullName = (await ctx.ui.input("New repository name", "name or owner/name"))?.trim() ?? "";
  }
  if (!fullName) return;
  const sep = fullName.indexOf("/");
  const org = sep > 0 ? fullName.slice(0, sep) : undefined;
  const name = sep > 0 ? fullName.slice(sep + 1) : fullName;
  if (!name) return;

  const visibility = (await ctx.ui.select(`Create ${org ? `${org}/` : ""}${name}`, ["private", "public"])) ?? "private";
  const description = await ctx.ui.input("Description (optional, Enter to skip)", "");

  try {
    const repo = await active.service.createRepo(active.token, name, {
      org,
      private: visibility === "private",
      description: description?.trim() || undefined,
    });
    ctx.ui.notify(`Created ${repo.fullName} → ${repo.htmlUrl}`, "info");
  } catch (e) {
    ctx.ui.notify(`${active.service.label} error: ${e instanceof Error ? e.message : String(e)}`, "error");
  }
}

const MENU: { label: string; key: string }[] = [
  { label: "status", key: "status" },
  { label: "login", key: "login" },
  { label: "logout", key: "logout" },
  { label: "switch account", key: "switch" },
  { label: "repos [org]", key: "repos" },
  { label: "create [org/]name", key: "create" },
];

/**
 * /auth [status|login|logout|switch|repos [org]|create [org/]name]
 *
 * Without arguments (or with an unknown one) an interactive TUI menu is
 * shown; each option runs the matching action, which prompts for any
 * missing arguments itself. `login` offers GitHub and GitLab; every other
 * action uses the service of the active account.
 */
export async function handleAuthCommand(args: string, ctx: Ctx): Promise<void> {
  const actions: Record<string, () => Promise<void>> = {
    status: () => showStatus(ctx),
    login: () => doLogin(ctx),
    logout: () => doLogout(ctx),
    switch: () => doSwitch(ctx),
    repos: () => doRepos(ctx, restArg),
    create: () => doCreate(ctx, restArg),
  };

  const [sub, ...rest] = (args ?? "").trim().split(/\s+/);
  const arg = (sub ?? "").toLowerCase();
  const restArg = rest.join(" ");

  let chosen = arg && actions[arg] ? arg : undefined;
  if (!chosen) {
    const pick = await ctx.ui.select("git auth — pick an action", MENU.map((m) => m.label));
    chosen = MENU.find((m) => m.label === pick)?.key;
  }

  if (chosen) {
    await actions[chosen]();
  }
}
