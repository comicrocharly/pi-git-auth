/**
 * Service (forge) abstraction: GitHub and GitLab behind one interface.
 *
 * Everything the extension does (verify, list, create, details) goes
 * through the Service of the ACTIVE account, so the rest of the code is
 * service-agnostic. Normalized types keep details.ts / commands.ts
 * independent of the two REST APIs.
 */

import {
  getUser as ghGetUser,
  listRepos as ghListRepos,
  createRepo as ghCreateRepo,
  getRepo as ghGetRepo,
  listCommits as ghListCommits,
  getTree as ghGetTree,
} from "./github";
import {
  getUser as glGetUser,
  listRepos as glListRepos,
  createRepo as glCreateRepo,
  getRepo as glGetRepo,
  listCommits as glListCommits,
  getTree as glGetTree,
} from "./gitlab";

export type Platform = "github" | "gitlab";

/** Repo reference as "owner/name" (gitlab: path_with_namespace, may nest). */
export interface ForgeRepo {
  fullName: string;
  private: boolean;
  description?: string;
  htmlUrl: string;
}

/** Normalized repo metadata for the details overlay. */
export interface RepoMeta {
  fullName: string;
  private: boolean;
  description?: string;
  defaultBranch: string;
  /** KB when the service reports it (GitHub); omitted otherwise. */
  sizeKb?: number;
  stars: number;
  forks: number;
  /** ISO date when the service reports it. */
  lastPush?: string;
  htmlUrl: string;
}

export interface CommitInfo {
  /** Full or short sha, as reported. */
  sha: string;
  /** First line of the commit message. */
  subject: string;
  /** ISO date. */
  date: string;
}

export interface TreeEntry {
  path: string;
  type: "blob" | "tree";
}

export interface Service {
  id: Platform;
  label: string;
  /** Git host, e.g. github.com / gitlab.com (used by the git gate). */
  host: string;
  tokenUrl: string;
  tokenPlaceholder: string;
  scopesHint: string;
  verify(token: string): Promise<{ login: string; scopes?: string }>;
  listRepos(token: string, org?: string): Promise<ForgeRepo[]>;
  createRepo(
    token: string,
    name: string,
    opts: { org?: string; private?: boolean; description?: string },
  ): Promise<ForgeRepo>;
  meta(token: string, fullName: string): Promise<RepoMeta>;
  commits(token: string, fullName: string, n: number): Promise<CommitInfo[]>;
  /** Flat recursive tree (depth limited by the service). Returns [] without a ref. */
  tree(token: string, fullName: string, ref?: string): Promise<TreeEntry[]>;
}

const ghService: Service = {
  id: "github",
  label: "GitHub",
  host: "github.com",
  tokenUrl: "https://github.com/settings/tokens/new",
  tokenPlaceholder: "ghp_… / github_pat_… / gho_…",
  scopesHint: "repo, user:email",
  verify: (token) => ghGetUser(token),
  listRepos: (token, org) => ghListRepos(token, { org }).then((rs) =>
    rs.map((r) => ({
      fullName: r.full_name,
      private: !!r.private,
      description: r.description ?? undefined,
      htmlUrl: r.html_url,
    })),
  ),
  createRepo: (token, name, opts) =>
    ghCreateRepo(token, { name, org: opts.org, private: opts.private, description: opts.description }).then((r) => ({
      fullName: r.full_name,
      private: !!r.private,
      description: r.description ?? undefined,
      htmlUrl: r.html_url,
    })),
  meta: (token, fullName) =>
    ghGetRepo(token, fullName).then((r) => ({
      fullName: r.full_name,
      private: !!r.private,
      description: r.description,
      defaultBranch: r.default_branch,
      sizeKb: r.size,
      stars: r.stargazers_count,
      forks: r.forks_count,
      lastPush: r.pushed_at || undefined,
      htmlUrl: r.html_url,
    })),
  commits: (token, fullName, n) =>
    ghListCommits(token, fullName, n).then((cs) =>
      cs.map((c) => ({ sha: c.sha, subject: c.message, date: c.date })),
    ),
  tree: (token, fullName, ref) => (ref ? ghGetTree(token, fullName, ref) : Promise.resolve([])),
};

const glService: Service = {
  id: "gitlab",
  label: "GitLab",
  host: "gitlab.com",
  tokenUrl: "https://gitlab.com/-/user_settings/personal_access_tokens",
  tokenPlaceholder: "glpat-…",
  scopesHint: "api",
  verify: (token) => glGetUser(token),
  listRepos: (token, org) => glListRepos(token, { org }),
  createRepo: (token, name, opts) => glCreateRepo(token, name, opts),
  meta: (token, fullName) => glGetRepo(token, fullName),
  commits: (token, fullName, n) => glListCommits(token, fullName, n),
  tree: (token, fullName, ref) => (ref ? glGetTree(token, fullName, ref) : Promise.resolve([])),
};

export const SERVICES: Record<Platform, Service> = { github: ghService, gitlab: glService };
