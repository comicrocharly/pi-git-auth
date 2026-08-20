# pi-git-auth

A [pi](https://github.com/badlogic/pi-mono) (coding-agent) extension that 
gives the agent **git forges authentication** for **GitHub and GitLab**: login tokens are stored in the
OS keyring, the active account is selected in the TUI, and every `git`
command the agent runs is transparently authenticated with that account's
token for its host. It also manages accounts and repositories through each
service's REST API.

No npm dependencies — only pi's bundled packages and Node built-ins.

## Install

As a pi package:

```
pi install npm:pi-git-auth
```

Or from git:

```
pi install git:github.com/comicrocharly/pi-git-auth
```

Or manually: copy the `.ts` files into
`~/.pi/agent/extensions/pi-git-auth/`. No build step — pi loads the
TypeScript directly.

## How it works

- **Login** stores a token per (service, login) pair.
- One account is **active** at a time. Every action — git auth, repos,
  create, the LLM tool — uses **the REST API of the active account's
  service**, so switching accounts also switches the backend.
- A `tool_call` hook watches every `bash` invocation. When an active
  account exists and the command runs `git`, the command is rewritten to
  authenticate that account's host (see [git auth](#git-auth)).

## Layout

```
index.ts     extension entry: git-gate hook, /auth command, `auth` LLM tool
auth.ts      login/logout/switch flows (per service), status text
commands.ts  /auth subcommands + interactive TUI menu
store.ts     multi-account credential persistence (keyring or file)
keyring.ts   OS keyring backend (freedesktop Secret Service) + python D-Bus client
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
account is **active** at a time.

### /auth status
List all stored accounts (service + active marker), the active storage
backend, plus the active account's details (masked token, scopes).

### /auth login
Pick a service (GitHub or GitLab), then paste a token straight into the
TUI — the token-creation page is opened in the browser.

- GitHub: classic PAT `ghp_…` (scopes: `repo`, `user:email`) or a
  fine-grained `github_pat_…` token.
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

## git auth

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

## Token storage

Tokens are **never stored plaintext on disk**. Two backends are
available; the extension picks one at load time.

### OS keyring (preferred)
The token lives in the session keyring, addressed by the
[freedesktop Secret Service API](https://specifications.freedesktop.org/secret-service/)
(`org.freedesktop.secrets` over D-Bus). This covers KWallet (via
`ksecretd`), GNOME Keyring, KeePassXC, and any other Secret Service
provider.

- The embedded python3 client (a small script that `keyring.ts` keeps
  in sync in the state dir) opens a D-Bus session and talks
  **JSON over stdin/stdout**. The token therefore never appears in a
  process argument list — only in the parent's memory.
- The client **auto-detects the Secret Service API generation** by
  introspecting the service: modern 0.0.1
  (`Store`/`GetSecret`) for gnome-keyring / `kwallet --secretservice`,
  or legacy 0.0.0 (`Collection.CreateItem`/`GetSecrets`) for KDE
  `ksecretd`. Both are implemented.
- `credentials.json` keeps only a `wallet:v1:<accountKey>` marker per
  account; the token itself is in the keyring.

### Encrypted file (fallback)
When python3 / D-Bus / a keyring are unavailable (headless server, no
session bus), the extension transparently falls back to an on-disk
AES-256-GCM envelope:

- `~/.pi/agent/pi-git-auth/credentials.json` (0600) holds each token as
  an `enc:v1:<base64>` envelope.
- The key lives in a separate 0600 `key` file (0700 dir).

### Migration
Moving from the old plaintext/`enc:v1:` layout to the keyring is
transparent. On first load, any legacy token is read, written to the
keyring, and the file is rewritten with `wallet:v1:` markers. A `.bak`
copy of the pre-migration file is kept (ciphertext/markers only, no
plaintext).

### Override
`PI_GIT_AUTH_STORE` forces the backend: `auto` (default — keyring when
reachable, else file), `wallet`, or `file`.

## Performance

- The git gate adds one regex pass per `git` command (same as any string
  rewrite) and no network calls; login adds one TUI prompt.
- The keyring round-trip is one D-Bus exchange per account, only at load
  and write time.
- GitHub's details view uses a single bounded set of REST calls
  (repo meta + 5 commits + 1 recursive tree). GitLab's tree is top-level
  only (its API does not recurse), bounded to 100 entries.

## Limits

- GitHub: `github.com` only (no GitHub Enterprise).
- GitLab: `gitlab.com` only (no self-hosted instances).
- GitLab does not expose project size or per-file sizes via this API;
  the details overlay simply omits them.
- GitLab's repository tree is top-level only (the API ignores `recursive`),
  so nested directories are not listed in the details overlay.
- GitLab project list for an org tries the group first, then a user.
- Keyring storage requires a D-Bus session bus and a Secret Service
  provider; otherwise the encrypted-file fallback is used.

## About pi

This extension is built for [pi](https://github.com/badlogic/pi-mono),
the minimal, coding-agent-first terminal agent by Mario Zechner.
See the pi repo for docs on the extension and package system this
extension plugs into.
