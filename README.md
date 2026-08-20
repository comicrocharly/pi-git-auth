# pi-git-auth

A pi (coding-agent) extension that gives the agent **deterministic git
authentication** for **GitHub and GitLab**: login tokens are stored, the
active account is selected in the TUI, and every `git` command the agent
runs is transparently authenticated with that account's token for its
host. It also manages accounts and repositories through each service's
REST API.

No npm dependencies — only pi's bundled packages and Node built-ins.

## Layout

```
index.ts     extension entry: git-gate hook, /auth command, `auth` LLM tool
auth.ts      login/logout/switch flows (per service), status text
commands.ts  /auth subcommands + interactive TUI menu
store.ts     multi-account credential persistence (encrypted at rest)
forge.ts     service abstraction: normalized types + GitHub/GitLab registry
github.ts    GitHub REST client
gitlab.ts    GitLab REST client
details.ts   read-only repo details overlay (tree + commits + metadata)
git-gate.ts  command rewriting that injects the token for a host
```

## Usage

### /auth
With no argument an interactive TUI menu is shown (status / login /
logout / switch account / repos / create); each action prompts for
anything missing.

Multiple accounts are supported, across GitHub **and** GitLab. One
account is **active** at a time. Every action — git auth, repos, create,
the LLM tool — uses **the REST API of the active account's service**, so
switching accounts also switches the backend.

### /auth status
List all stored accounts (service + active marker), plus the active
account's details (masked token, scopes).

### /auth login
Pick a service (GitHub or GitLab), then paste a token straight into the
TUI — the token-creation page is opened in the browser.

- GitHub: `ghp_…` PAT, `github_pat_…` fine-grained, or classic
  `gho_…`/`ghs_…` (scopes: `repo`, `user:email`).
- GitLab: personal access token `glpat-…` (scope: `api`).

Verified against the service (`GET /user` / `GET /api/v4/user`) before
storing. Accounts are keyed by service+login: logging in again with the
same pair replaces its token. The logged-in account becomes the active
one.

### /auth logout
Picks an account to remove. If it was the active one, another remaining
account becomes active (or none, if it was the last).

### /auth switch
Picks a stored account and makes it the active one.

### /auth repos [org]
Lists your repos (or an org's/group's) **on the active account's service**.
Picking one opens a details overlay: description, branch/size/stars/forks/
last-push, a two-level file tree, and the five latest commits. Close with
esc/enter/q.

### /auth create [org/]name
Creates a repo on the active account's service (prompts for visibility
and description).

### LLM tool: `auth`
The model can call `auth` with actions `status | switch | list | create`
(plus an `account` parameter for `switch`; `"platform:login"`
disambiguates a login that exists on both services). These are REST API
operations run against the active account's service — the git gate can't
do them. For clone/push the model just runs `git` via bash: the harness
authenticates the active account's host automatically (the git gate), so
no tool action is needed for git.

Repository deletion is intentionally not exposed (safety).

## Deterministic git auth

A `tool_call` hook watches every `bash` tool invocation. If an active
account is stored and the command runs `git`, it rewrites the command to
use that account's token for the account's host (`github.com` or
`gitlab.com`):

```
export GIT_TERMINAL_PROMPT=0 \
  GIT_CONFIG_COUNT=1 \
  GIT_CONFIG_KEY_0="url.https://x-access-token:<token>@<host>/.insteadOf" \
  GIT_CONFIG_VALUE_0="https://<host>/" && <command>
```

Forging hosts' git-over-HTTPS endpoints ignore `Authorization` headers
and only accept URL-embedded credentials, hence the `insteadOf` rewrite.
Only the active host is touched; other remotes are untouched.

## Storage & performance

- Credentials: `~/.pi/agent/pi-git-auth/credentials.json` (0600), each
  token AES-256-GCM encrypted at rest; the key lives in a separate 0600
  `key` file. Tokens are plaintext only in memory.
- Performance: the git gate adds one regex pass per `git` command
  (same as any string rewrite) and no network calls; login adds one TUI
  prompt. Both services' details views use a single bounded set of REST
  calls (repo meta + 5 commits + 1 recursive tree).

## Limits

- GitHub: `github.com` only (no GitHub Enterprise).
- GitLab: `gitlab.com` only (no self-hosted instances).
- GitLab does not expose project size or per-file sizes via this API;
  the details overlay simply omits them.
- GitLab project list for an org tries the group first, then a user.
