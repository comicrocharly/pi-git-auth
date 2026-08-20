import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { loadStore, activeAccount } from "./store";
import { SERVICES } from "./forge";
import { findAccounts, setActiveAccount, statusDetail } from "./auth";
import { instrumentGit } from "./git-gate";
import { redactSecrets } from "./redact";
import { handleAuthCommand } from "./commands";

export default function (pi: ExtensionAPI) {
  // ------------------------------------------------------------------
  // Deterministic git auth: instrument bash tool calls that run git,
  // using the token of the ACTIVE account for its host.
  // ------------------------------------------------------------------
  pi.on("tool_call", async (event, ctx) => {
    if (!isToolCallEventType("bash", event)) return;
    const acc = activeAccount(loadStore());
    if (!acc?.accessToken) return;
    const host = SERVICES[acc.platform].host;
    event.input.command = instrumentGit(event.input.command, host, acc.accessToken);
  });

  // ------------------------------------------------------------------
  // Secret redaction: never let token-shaped strings reach the
  // transcript. The gate keeps the token out of argv and off disk,
  // but any bash output (env dump, config echo) would otherwise land
  // in the session file and the conversation.
  // ------------------------------------------------------------------
  pi.on("tool_result", (event) => {
    let changed = false;
    const content = event.content.map((block) => {
      if (block.type !== "text") return block;
      const text = redactSecrets(block.text);
      if (text === block.text) return block;
      changed = true;
      return { ...block, text };
    });
    if (!changed) return;
    return { content };
  });

  // ------------------------------------------------------------------
  // /auth command
  // ------------------------------------------------------------------
  pi.registerCommand("auth", {
    description: "Git auth (GitHub/GitLab): status, login, logout, switch account, repos, create repos",
    handler: (args, ctx) => handleAuthCommand(args, ctx),
  });

  // ------------------------------------------------------------------
  // Tool for the LLM
  // ------------------------------------------------------------------
  pi.registerTool({
    name: "auth",
    label: "git auth",
    description:
        "Manage git forges (GitHub & GitLab): multiple accounts (status, switch), list/create repositories. " +
        "Every action uses the service of the active account — switch accounts to work as a different user. " +
        "Requires the user to have run `/auth login`. For clone/push just run `git` via bash — the harness " +
        "authenticates the active account's host automatically (the git gate).",
    promptSnippet: "Git forges (GitHub/GitLab): accounts (status/switch), list/create repos (git auth managed by harness)",
    parameters: Type.Object({
      action: Type.Union([
        Type.Literal("status"),
        Type.Literal("switch"),
        Type.Literal("list"),
        Type.Literal("create"),
      ]),
      repo: Type.Optional(Type.String({ description: 'Repository as "owner/name"; bare name for create' })),
      org: Type.Optional(Type.String({ description: "Org/owner for list, create (default: logged-in user)" })),
      private: Type.Optional(Type.Boolean({ description: "Visibility for create (default: private)" })),
      description: Type.Optional(Type.String({ description: "Description for create" })),
      account: Type.Optional(Type.String({ description: "Login for switch (\"platform:login\" to disambiguate)" })),
    }),
    async execute(_toolCallId, params, signal) {
      const text = (t: string) => ({ content: [{ type: "text" as const, text: t }], details: {} });
      const notConnected = "Not connected. Ask the user to run /auth login, then retry.";

      const active = () => {
        const data = loadStore();
        const acc = activeAccount(data);
        const service = acc ? SERVICES[acc.platform] : undefined;
        return acc?.accessToken && service ? { data, acc, service } : undefined;
      };

      switch (params.action) {
        case "status": {
          const data = loadStore();
          if (Object.keys(data.accounts).length === 0) return { ...text(notConnected), isError: true };
          return text(statusDetail(data));
        }

        case "switch": {
          if (!params.account) return { ...text("Missing account (login) for switch."), isError: true };
          const matches = findAccounts(params.account);
          if (matches.length === 0) return { ...text(`Unknown account "${params.account}".`), isError: true };
          if (matches.length > 1)
            return { ...text(`Ambiguous login — use "platform:login" (e.g. github:${params.account}).`), isError: true };
          if (setActiveAccount(matches[0])) {
            const data = loadStore();
            const acc = data.accounts[matches[0]];
            return text(`Active account: @${acc?.user ?? matches[0]} (${acc?.platform ?? "github"})`);
          }
          return { ...text(`Switch failed for "${params.account}".`), isError: true };
        }

        case "list": {
          const a = active();
          if (!a) return { ...text(notConnected), isError: true };
          const repos = await a.service.listRepos(a.acc.accessToken, params.org);
          return text(
            repos.length
              ? repos.map((r) => `${r.fullName} [${r.private ? "private" : "public"}] ${r.description ?? ""}`).join("\n")
              : "No repositories found.",
          );
        }

        case "create": {
          const a = active();
          if (!a) return { ...text(notConnected), isError: true };
          if (!params.repo) return { ...text("Missing repo name for create."), isError: true };
          const sep = params.repo.indexOf("/");
          const org = params.repo.includes("/") ? params.repo.slice(0, sep) : params.org;
          const name = params.repo.includes("/") ? params.repo.slice(sep + 1) : params.repo;
          const repo = await a.service.createRepo(a.acc.accessToken, name, {
            org,
            private: params.private ?? true,
            description: params.description,
          });
          return text(`Created ${repo.fullName} (${repo.private ? "private" : "public"}) → ${repo.htmlUrl}`);
        }

        default:
          return { ...text(`Unknown action.`), isError: true };
      }
    },
  });
}
