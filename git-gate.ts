/**
 * Deterministic forge auth for git commands (GitHub / GitLab).
 *
 * When pi's bash tool is about to run a git command and a token is
 * stored for a host, we rewrite the command so git uses the stored token
 * for that host, regardless of git's own credential configuration:
 *
 *   export GIT_TERMINAL_PROMPT=0 \
 *     GIT_CONFIG_COUNT=1 \
 *     GIT_CONFIG_KEY_0="url.https://x-access-token:<token>@<host>/.insteadOf" \
 *     GIT_CONFIG_VALUE_0="https://<host>/" && <command>
 *
 * Forging hosts' git-over-HTTPS endpoints ignore Authorization headers
 * and only accept URL-embedded (Basic) credentials, hence the insteadOf
 * rewrite.
 *
 * Guarantees:
 *  - Scoped to the given host's URLs; other remotes are untouched.
 *  - GIT_TERMINAL_PROMPT=0: a failed auth surfaces as a clean error
 *    instead of an interactive prompt hanging the TUI.
 *  - Deterministic: no credential-helper races, same behavior every run.
 *  - SSH-style URLs for the host are rewritten to HTTPS so the token applies.
 */

export function looksLikeGit(command: string): boolean {
  // git at the start of a simple command, or after a shell separator, with
  // any number of leading VAR=value assignments allowed before it.
  return /(^|[\n;&|]\s*)(?:[A-Za-z_][A-Za-z_0-9]*=\S*\s+)*git(\s|$)/.test(command);
}

export function instrumentGit(command: string, host: string, token: string): string {
  if (!looksLikeGit(command)) return command;
  if (command.includes("GIT_CONFIG_COUNT=")) return command; // already instrumented

  const rewritten = command
    .replace(new RegExp(`ssh://git@${host}/`, "g"), `https://${host}/`)
    .replace(new RegExp(`git@${host}:`, "g"), `https://${host}/`);
  const prefix =
    `export GIT_TERMINAL_PROMPT=0 ` +
    `GIT_CONFIG_COUNT=1 ` +
    `GIT_CONFIG_KEY_0="url.https://x-access-token:${token}@${host}/.insteadOf" ` +
    `GIT_CONFIG_VALUE_0="https://${host}/" && `;
  return prefix + rewritten;
}
