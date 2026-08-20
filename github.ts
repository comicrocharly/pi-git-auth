/**
 * Minimal GitHub API client (REST, no dependencies).
 * Covers exactly what pi-git-auth needs: token verification, repo CRUD.
 */

const API_BASE = "https://api.github.com";

export interface RepoInfo {
  full_name: string;
  private: boolean;
  description?: string | null;
  html_url: string;
}

export interface UserInfo {
  login: string;
  /** Best-effort scopes (classic OAuth/PAT tokens only). */
  scopes?: string;
}

interface ApiResult {
  status: number;
  data: any;
  headers: Headers;
}

async function apiFetch(path: string, token: string, init: RequestInit = {}, signal?: AbortSignal): Promise<ApiResult> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    signal,
    headers: {
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      authorization: `bearer ${token}`,
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
  return { status: res.status, data, headers: res.headers };
}

/** Verify a token by resolving the login user. Throws on 401/403. */
export async function getUser(token: string, signal?: AbortSignal): Promise<UserInfo> {
  const { status, data, headers } = await apiFetch("/user", token, {}, signal);
  if (status === 401) throw new Error("Token invalid or revoked (HTTP 401)");
  if (status === 403) throw new Error(`Token lacks permissions (HTTP 403)${data?.message ? `: ${data.message}` : ""}`);
  if (status === 404 || !data) throw new Error(`Unexpected response (HTTP ${status})`);
  return {
    login: data.login,
    scopes: headers.get("x-oauth-scopes") ?? undefined,
  };
}

export async function listRepos(
  token: string,
  opts: { org?: string; perPage?: number; signal?: AbortSignal },
): Promise<RepoInfo[]> {
  const perPage = opts.perPage ?? 100;
  const path = opts.org
    ? `/orgs/${encodeURIComponent(opts.org)}/repos?per_page=${perPage}&type=owner`
    : `/user/repos?affiliation=owner&per_page=${perPage}`;
  const { status, data } = await apiFetch(path, token, {}, opts.signal);
  if (status === 401) throw new Error("Token invalid (HTTP 401)");
  if (status === 403) throw new Error("Insufficient scopes to list repos (needs `repo`)");
  if (status >= 400 || !Array.isArray(data)) throw new Error(`List repos failed (HTTP ${status})`);
  return data.map((r: any) => ({
    full_name: r.full_name,
    private: !!r.private,
    description: r.description ?? undefined,
    html_url: r.html_url,
  }));
}

export interface RepoDetail {
  full_name: string;
  private: boolean;
  description?: string;
  default_branch: string;
  /** Size in KB (GitHub's `size` field). */
  size: number;
  stargazers_count: number;
  forks_count: number;
  pushed_at: string;
  html_url: string;
}

export interface CommitInfo {
  sha: string;
  /** First line of the commit message. */
  message: string;
  author: string;
  /** ISO date. */
  date: string;
}

export interface TreeEntry {
  path: string;
  type: "blob" | "tree";
}

/** Full repo metadata for the details view. */
export async function getRepo(token: string, fullName: string, signal?: AbortSignal): Promise<RepoDetail> {
  const { status, data } = await apiFetch(`/repos/${fullName}`, token, {}, signal);
  if (status === 401) throw new Error("Token invalid (HTTP 401)");
  if (status === 404) throw new Error(`Repository ${fullName} not found (HTTP 404)`);
  if (status >= 400 || !data) throw new Error(`Get repo failed (HTTP ${status})`);
  return {
    full_name: data.full_name,
    private: !!data.private,
    description: data.description ?? undefined,
    default_branch: data.default_branch,
    size: data.size ?? 0,
    stargazers_count: data.stargazers_count ?? 0,
    forks_count: data.forks_count ?? 0,
    pushed_at: data.pushed_at ?? "",
    html_url: data.html_url,
  };
}

/** Latest commits, newest first. */
export async function listCommits(
  token: string,
  fullName: string,
  perPage = 5,
  signal?: AbortSignal,
): Promise<CommitInfo[]> {
  const { status, data } = await apiFetch(`/repos/${fullName}/commits?per_page=${perPage}`, token, {}, signal);
  if (status === 401) throw new Error("Token invalid (HTTP 401)");
  if (status === 404) throw new Error(`Repository ${fullName} not found (HTTP 404)`);
  if (status >= 400 || !Array.isArray(data)) throw new Error(`List commits failed (HTTP ${status})`);
  return data.map((c: any) => ({
    sha: c.sha,
    message: String(c.commit?.message ?? "").split("\n")[0],
    author: c.author?.login ?? c.commit?.author?.name ?? "unknown",
    date: c.commit?.author?.date ?? c.commit?.committer?.date ?? "",
  }));
}

/** Flat recursive tree (all paths). Returns [] on 404/409 (missing ref). */
export async function getTree(
  token: string,
  fullName: string,
  ref: string,
  signal?: AbortSignal,
): Promise<TreeEntry[]> {
  const { status, data } = await apiFetch(
    `/repos/${fullName}/git/trees/${encodeURIComponent(ref)}?recursive=1`,
    token,
    {},
    signal,
  );
  if (status === 404 || status === 409) return [];
  if (status >= 400 || !data) throw new Error(`Get tree failed (HTTP ${status})`);
  return (data.tree ?? []).map((t: any) => ({
    path: String(t.path),
    type: t.type === "tree" ? "tree" as const : ("blob" as const),
  }));
}

export async function createRepo(
  token: string,
  opts: { name: string; org?: string; private?: boolean; description?: string; signal?: AbortSignal },
): Promise<RepoInfo> {
  const path = opts.org ? `/orgs/${encodeURIComponent(opts.org)}/repos` : "/user/repos";
  const body = JSON.stringify({
    name: opts.name,
    description: opts.description ?? null,
    private: !!opts.private,
    has_issues: true,
  });
  const { status, data } = await apiFetch(path, token, { method: "POST", body }, opts.signal);
  if (status === 409) throw new Error(`Repository ${opts.name} already exists`);
  if (status >= 400) throw new Error(`Create repo failed (HTTP ${status}): ${data?.message ?? ""}`);
  return {
    full_name: data.full_name,
    private: !!data.private,
    description: data.description,
    html_url: data.html_url,
  };
}


