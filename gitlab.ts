/**
 * Minimal GitLab REST client (gitlab.com, no dependencies).
 * Mirrors github.ts: verify, list, create, meta, commits, tree —
 * all returning the normalized types from forge.ts.
 */

import type { CommitInfo, ForgeRepo, RepoMeta, TreeEntry } from "./forge";

const API_BASE = "https://gitlab.com/api/v4";

interface ApiResult {
  status: number;
  data: any;
}

async function glFetch(path: string, token: string, init: RequestInit = {}): Promise<ApiResult> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      accept: "application/json",
      authorization: `Bearer ${token}`,
      ...(init.body ? { "content-type": "application/json" } : {}),
    },
  });
  let data: any = null;
  if (res.status !== 204) {
    try {
      data = await res.json();
    } catch {
      data = null;
    }
  }
  return { status: res.status, data };
}

function errMsg(status: number, data: any): string {
  return typeof data?.message === "string"
    ? data.message
    : Array.isArray(data?.errors)
      ? data.errors.join(", ")
      : data?.error
        ? String(data.error)
        : "";
}

function checkAuth(status: number): void {
  if (status === 401) throw new Error("Token invalid or revoked (HTTP 401)");
  if (status === 403) throw new Error("Token lacks permissions (HTTP 403)");
}

/** Verify a token by resolving the current user. */
export async function getUser(token: string): Promise<{ login: string; name?: string }> {
  const { status, data } = await glFetch("/user", token);
  checkAuth(status);
  if (status >= 400 || !data?.username) throw new Error(`Unexpected response (HTTP ${status})`);
  return { login: data.username, name: data.name };
}

/**
 * Projects, normalized. With `org`: the group's projects; if the name is
 * not a group, falls back to a user's projects.
 */
export async function listRepos(token: string, opts: { org?: string; perPage?: number }): Promise<ForgeRepo[]> {
  const perPage = opts.perPage ?? 100;
  if (opts.org) {
    // Prefer group; fall back to a user's projects.
    const g = await glFetch(`/groups/${encodeURIComponent(opts.org)}/projects?include_subgroups=true&per_page=${perPage}`, token);
    if (g.status < 400 && Array.isArray(g.data)) return g.data.map(mapProject);
    const u = await glFetch(`/users/${encodeURIComponent(opts.org)}/projects?per_page=${perPage}`, token);
    checkAuth(u.status);
    if (u.status >= 400 || !Array.isArray(u.data)) {
      throw new Error(`List projects failed (HTTP ${u.status}): ${errMsg(u.status, u.data)}`);
    }
    return u.data.map(mapProject);
  }
  const { status, data } = await glFetch(`/projects?owned=true&per_page=${perPage}`, token);
  checkAuth(status);
  if (status >= 400 || !Array.isArray(data)) throw new Error(`List projects failed (HTTP ${status}): ${errMsg(status, data)}`);
  return data.map(mapProject);
}

function mapProject(p: any): ForgeRepo {
  return {
    fullName: p.path_with_namespace,
    private: p.visibility === "private",
    description: p.description ?? undefined,
    htmlUrl: p.web_url,
  };
}

/** Full project metadata for the details view. */
export async function getRepo(token: string, fullName: string): Promise<RepoMeta> {
  const { status, data } = await glFetch(`/projects/${encodeURIComponent(fullName)}`, token);
  checkAuth(status);
  if (status === 404) throw new Error(`Project ${fullName} not found (HTTP 404)`);
  if (status >= 400 || !data) throw new Error(`Get project failed (HTTP ${status}): ${errMsg(status, data)}`);
  return {
    fullName: data.path_with_namespace,
    private: data.visibility === "private",
    description: data.description ?? undefined,
    defaultBranch: data.default_branch ?? "main",
    // GitLab's API does not expose project size.
    stars: data.star_count ?? 0,
    forks: data.forks_count ?? 0,
    lastPush: data.last_activity_at || undefined,
    htmlUrl: data.web_url,
  };
}

/** Latest commits, newest first (default branch). */
export async function listCommits(token: string, fullName: string, perPage = 5): Promise<CommitInfo[]> {
  const { status, data } = await glFetch(
    `/projects/${encodeURIComponent(fullName)}/repository/commits?per_page=${perPage}`,
    token,
  );
  checkAuth(status);
  if (status === 404) throw new Error(`Project ${fullName} not found (HTTP 404)`);
  if (status >= 400 || !Array.isArray(data)) throw new Error(`List commits failed (HTTP ${status}): ${errMsg(status, data)}`);
  return data.map((c: any) => ({
    sha: String(c.short_id ?? c.id ?? ""),
    subject: String(c.title ?? "").split("\n")[0],
    date: c.committed_date ?? c.created_at ?? "",
  }));
}

/** Flat recursive tree (default branch, or `ref`). Returns [] on 404. */
export async function getTree(token: string, fullName: string, ref?: string): Promise<TreeEntry[]> {
  const q = `recursive=1&per_page=100${ref ? `&ref=${encodeURIComponent(ref)}` : ""}`;
  const { status, data } = await glFetch(`/projects/${encodeURIComponent(fullName)}/repository/tree?${q}`, token);
  if (status === 404) return [];
  if (status >= 400 || !Array.isArray(data)) throw new Error(`Get tree failed (HTTP ${status}): ${errMsg(status, data)}`);
  return data.map((t: any) => ({
    path: String(t.path),
    type: t.type === "tree" ? ("tree" as const) : ("blob" as const),
  }));
}

/**
 * Create a project. Without `org` it is created in the user's namespace.
 */
export async function createRepo(
  token: string,
  name: string,
  opts: { org?: string; private?: boolean; description?: string },
): Promise<ForgeRepo> {
  const body = JSON.stringify({
    name,
    description: opts.description ?? null,
    visibility: opts.private ? "private" : "public",
    ...(opts.org ? { namespace_path: opts.org } : {}),
  });
  const { status, data } = await glFetch("/projects", token, { method: "POST", body });
  if (status >= 400 || !data?.web_url) {
    throw new Error(`Create project failed (HTTP ${status}): ${errMsg(status, data) || (opts.org ? `unknown namespace ${opts.org}` : "")}`);
  }
  return mapProject(data);
}
