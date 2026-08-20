/**
 * Read-only "repo details" overlay: metadata + 2-level tree + latest commits.
 *
 * `buildDetailsText` is pure (easy to test); `RepoDetailsPanel` is thin TUI
 * glue that renders it in a scrollable, dismissible overlay.
 */

import type { Theme } from "@earendil-works/pi-coding-agent";
import { matchesKey, truncateToWidth, visibleWidth, type Focusable } from "@earendil-works/pi-tui";
import type { CommitInfo, RepoMeta, TreeEntry } from "./forge";

const MAX_TOP_ENTRIES = 10;
const MAX_CHILD_ENTRIES = 8;
const MAX_COMMITS = 5;
const MAX_SUBJECT = 56;
/** Chrome rows of the panel: top border, title, hint row, bottom border (+1 slack). */
const PANEL_CHROME = 5;

function relTime(iso: string): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "";
  const s = Math.floor((Date.now() - then) / 1000);
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d ago`;
  const mo = Math.floor(d / 30);
  if (mo < 12) return `${mo}mo ago`;
  return `${Math.floor(mo / 12)}y ago`;
}

function fmtSize(kb: number): string {
  if (!Number.isFinite(kb) || kb <= 0) return "";
  if (kb >= 1024) return `${(kb / 1024).toFixed(1)} MB`;
  return `${Math.round(kb)} KB`;
}

function sortEntries(list: TreeEntry[]): TreeEntry[] {
  return [...list].sort((a, b) => {
    const ad = a.type === "tree" ? 0 : 1;
    const bd = b.type === "tree" ? 0 : 1;
    if (ad !== bd) return ad - bd;
    return a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
  });
}

/**
 * Flat recursive tree entries → compact 2-level listing (dirs first,
 * capped per level, with "… +N more" markers).
 */
export function renderTree(entries: TreeEntry[]): string[] {
  if (entries.length === 0) return [];
  const tops: TreeEntry[] = [];
  const children = new Map<string, TreeEntry[]>();
  for (const e of entries) {
    if (!e.path.includes("/")) {
      tops.push(e);
      continue;
    }
    const topDir = `${e.path.split("/")[0]!}/`;
    const rest = e.path.slice(topDir.length);
    if (rest.includes("/")) continue; // depth > 2: not shown
    let list = children.get(topDir);
    if (!list) {
      list = [];
      children.set(topDir, list);
    }
    list.push(e);
  }
  const out: string[] = [];
  const shown = sortEntries(tops).slice(0, MAX_TOP_ENTRIES);
  for (const t of shown) {
    out.push(`  ${t.path}${t.type === "tree" ? "/" : ""}`);
    if (t.type === "tree") {
      const kids = sortEntries(children.get(`${t.path}/`) ?? []);
      for (const k of kids.slice(0, MAX_CHILD_ENTRIES)) {
        out.push(`    ${k.path.slice(t.path.length + 1)}${k.type === "tree" ? "/" : ""}`);
      }
      if (kids.length > MAX_CHILD_ENTRIES) out.push(`    … +${kids.length - MAX_CHILD_ENTRIES} more`);
    }
  }
  if (tops.length > MAX_TOP_ENTRIES) out.push(`  … +${tops.length - MAX_TOP_ENTRIES} more`);
  return out;
}

/** Compose the details view content (plain text lines, no ANSI). */
export function buildDetailsText(
  repo: RepoMeta,
  commits: CommitInfo[],
  tree: TreeEntry[],
): { title: string; lines: string[] } {
  const meta = [
    `branch: ${repo.defaultBranch}`,
    fmtSize(repo.sizeKb ?? 0),
    `★ ${repo.stars}`,
    `${repo.forks} fork${repo.forks === 1 ? "" : "s"}`,
    repo.lastPush ? `pushed ${relTime(repo.lastPush)}` : "",
  ].filter(Boolean);

  const lines: string[] = [];
  if (repo.description) {
    lines.push(repo.description);
    lines.push("");
  }
  lines.push(meta.join(" · "));
  lines.push(repo.htmlUrl);
  lines.push("");
  lines.push("Tree");
  if (tree.length === 0) {
    lines.push(`  ${commits.length > 0 ? "(could not load)" : "(empty repository)"}`);
  } else {
    lines.push(...renderTree(tree));
  }
  lines.push("");
  if (commits.length === 0) {
    lines.push("Commits — none");
  } else {
    lines.push(`Commits (${commits.length})`);
    for (const c of commits.slice(0, MAX_COMMITS)) {
      const subject =
        c.subject.length > MAX_SUBJECT ? `${c.subject.slice(0, MAX_SUBJECT - 1)}…` : c.subject;
      const when = c.date ? `  (${relTime(c.date)})` : "";
      lines.push(`  ${c.sha.slice(0, 7)}  ${subject}${when}`);
    }
  }
  return { title: `${repo.fullName} [${repo.private ? "private" : "public"}]`, lines };
}

/**
 * Border-drawn overlay panel. Scroll with up/down/j/k/pgup/pgdn/home/end;
 * dismiss with esc/enter/q/ctrl+c.
 */
export class RepoDetailsPanel implements Focusable {
  focused = false;

  private scrollTop = 0;
  private dismissed = false;

  constructor(
    private readonly title: string,
    private readonly lines: string[],
    private readonly theme: Theme,
    private readonly getRows: () => number,
    private readonly done: () => void,
    private readonly requestRender: () => void,
  ) {}

  handleInput(data: string): void {
    if (
      matchesKey(data, "escape") ||
      matchesKey(data, "return") ||
      matchesKey(data, "enter") ||
      matchesKey(data, "q") ||
      matchesKey(data, "ctrl+c")
    ) {
      this.dismiss();
      return;
    }
    const page = Math.max(2, Math.floor(this.visibleRows() / 2));
    if (matchesKey(data, "up") || matchesKey(data, "k")) {
      this.move(-1);
    } else if (matchesKey(data, "down") || matchesKey(data, "j")) {
      this.move(1);
    } else if (matchesKey(data, "pageUp")) {
      this.move(-page);
    } else if (matchesKey(data, "pageDown")) {
      this.move(page);
    } else if (matchesKey(data, "home")) {
      this.scrollTop = 0;
      this.requestRender();
    } else if (matchesKey(data, "end")) {
      this.scrollTop = Number.MAX_SAFE_INTEGER;
      this.requestRender();
    }
  }

  invalidate(): void {
    // Stateless render — nothing to clear.
  }

  render(width: number): string[] {
    const innerW = Math.max(10, width - 2);
    const maxScroll = Math.max(0, this.lines.length - this.visibleRows());
    this.scrollTop = Math.min(Math.max(0, this.scrollTop), maxScroll);
    const view = this.lines.slice(this.scrollTop, this.scrollTop + this.visibleRows());

    const B = (s: string) => this.theme.fg("border", s);
    const row = (content: string) => {
      const t = truncateToWidth(content, innerW - 2);
      return B("│") + " " + t + " ".repeat(Math.max(0, innerW - 2 - visibleWidth(t))) + " " + B("│");
    };

    const out: string[] = [];
    out.push(B("╭") + B("─".repeat(innerW)) + B("╮"));
    out.push(row(this.theme.fg("accent", this.theme.bold(this.title))));
    for (const line of view) out.push(row(line));
    out.push(row(this.theme.fg("dim", "esc close")));
    out.push(B("╰") + B("─".repeat(innerW)) + B("╯"));
    return out;
  }

  private visibleRows(): number {
    return Math.max(4, Math.floor(this.getRows() * 0.8) - PANEL_CHROME);
  }

  private move(delta: number): void {
    this.scrollTop += delta;
    this.requestRender();
  }

  private dismiss(): void {
    if (this.dismissed) return;
    this.dismissed = true;
    this.done();
  }
}
