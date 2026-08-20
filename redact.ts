/**
 * Secret redaction for tool results.
 *
 * The git gate keeps the active token out of argv and off disk, but a
 * bash command (an `env` dump, a `git config` echo, a `printenv`) can
 * still print it into the tool output, which then lands in the session
 * transcript. This module masks token-shaped strings in tool results
 * before they are stored, so an accidental echo can never put the live
 * token into the conversation — and there is nothing to rotate because
 * of it.
 *
 * Patterns (masked to a short fingerprint, e.g. `ghp_…7SAQ`):
 *  - GitHub classic PATs:      gh[pousr]_ + 20+ base62
 *  - GitHub fine-grained PATs: github_pat_ + 30+
 *  - GitLab PATs:              glpat- + 16+
 *  - URL-embedded credentials: user:secret@ — the secret part only
 *
 * Masking is idempotent: a masked string never matches the patterns
 * again, so repeated passes are a no-op.
 */

function maskTail(match: string, head: number): string {
  return match.length <= head + 4 ? "***" : `${match.slice(0, head)}…${match.slice(-4)}`;
}

export function redactSecrets(text: string): string {
  return text
    .replace(/\bgh[pousr]_[A-Za-z0-9]{20,}/g, (m) => maskTail(m, 4))
    .replace(/\bgithub_pat_[A-Za-z0-9_]{30,}/g, (m) => maskTail(m, 10))
    .replace(/\bglpat-[A-Za-z0-9_-]{16,}/g, (m) => maskTail(m, 6))
    .replace(/(\/\/[^/\s:@]+:)([^@\s]{4,})(@)/g, "$1***$3");
}
