// SPDX-License-Identifier: MIT

import { spawnSync } from "node:child_process";
import { lstat, mkdir, readFile, readlink, realpath, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const manifestUrl = "https://github.com/xuelongling/manifests.git";
const projectUrls = new Map([
  [".agents", "https://github.com/xuelongling/.agents.git"],
  ["tsfg", "https://github.com/xuelongling/tsfg.git"],
]);
const selectedManifest = "bootstrap/r00.xml";

function fail(category: string, message: string): Error {
  return new Error(`${category}: ${message}`);
}

function git(root: string, arguments_: readonly string[]): string {
  const result = spawnSync("git", ["-C", root, ...arguments_], {
    encoding: "utf8",
    env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1" },
  });
  if (result.status !== 0) {
    throw fail("activation-materialization", result.stderr.trim() || "git command failed");
  }
  return result.stdout.trim();
}

function gitBytes(root: string, arguments_: readonly string[]): Buffer {
  const result = spawnSync("git", ["-C", root, ...arguments_], {
    encoding: "buffer",
    env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1" },
  });
  if (result.status !== 0) {
    throw fail("activation-materialization", result.stderr.toString("utf8").trim() || "git command failed");
  }
  return result.stdout;
}

function parseWorkspace(arguments_: readonly string[]): string {
  if (arguments_.length !== 2 || arguments_[0] !== "--workspace" || arguments_[1] === "") {
    throw fail("activation-materialization", "usage: materialize-agent-workspace --workspace <path>");
  }
  return path.resolve(arguments_[1]);
}

async function requireOrdinaryDirectory(workspace: string, relativePath: string): Promise<string> {
  const directory = path.join(workspace, ...relativePath.split("/"));
  const metadata = await lstat(directory).catch(() => undefined);
  if (!metadata?.isDirectory() || metadata.isSymbolicLink() || (await realpath(directory)) !== directory) {
    throw fail("activation-materialization", `${relativePath} must be an ordinary workspace directory`);
  }
  return directory;
}

async function requireSafeActivationParent(workspace: string, relativePath: string): Promise<void> {
  const directory = path.join(workspace, ...relativePath.split("/"));
  const metadata = await lstat(directory).catch(() => undefined);
  if (
    metadata &&
    (!metadata.isDirectory() || metadata.isSymbolicLink() || (await realpath(directory)) !== directory)
  ) {
    throw fail("activation-link-parent", `${relativePath} redirects the Agent Activation Surface`);
  }
}

function replaceProjectRevision(xml: string, projectName: string, revision: string): string {
  const escapedName = projectName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const projectPattern = new RegExp(`<project\\b([^>]*\\bname="${escapedName}"[^>]*)>`);
  let replacements = 0;
  const updated = xml.replace(projectPattern, (tag) => {
    const next = tag.replace(/revision="[^"]+"/, `revision="${revision}"`);
    if (next !== tag) {
      replacements += 1;
    }
    return next;
  });
  if (replacements !== 1) {
    throw fail("activation-materialization", `cannot pin ${projectName} in ${selectedManifest}`);
  }
  return updated;
}

async function createRequiredLink(workspace: string, destination: string, target: string): Promise<void> {
  const destinationPath = path.join(workspace, ...destination.split("/"));
  if (await lstat(destinationPath).catch(() => undefined)) {
    throw fail("activation-link-conflict", `${destination} already exists; copy fallback is forbidden`);
  }
  await mkdir(path.dirname(destinationPath), { recursive: true });
  try {
    await symlink(target, destinationPath, "file");
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw fail("activation-link-capability", `cannot create ${destination}: ${detail}`);
  }
}

async function verifyRequiredLink(workspace: string, destination: string, source: string): Promise<void> {
  const destinationPath = path.join(workspace, ...destination.split("/"));
  const sourcePath = path.join(workspace, ...source.split("/"));
  const metadata = await lstat(destinationPath).catch(() => undefined);
  if (!metadata?.isSymbolicLink()) {
    throw fail("activation-link-type", `${destination} is not a symbolic link`);
  }
  const target = await readlink(destinationPath);
  const resolvedTarget = path.resolve(path.dirname(destinationPath), target);
  const workspacePrefix = `${workspace}${path.sep}`;
  if (!resolvedTarget.startsWith(workspacePrefix) || resolvedTarget !== sourcePath) {
    throw fail("activation-link-target", `${destination} does not target ${source}`);
  }
  if ((await realpath(destinationPath)) !== (await realpath(sourcePath))) {
    throw fail("activation-link-target", `${destination} resolves outside its managed source`);
  }
}

async function requireCommittedActivationSources(agentsRoot: string, revision: string): Promise<void> {
  for (const relativePath of ["AGENTS.md", "codex/config.toml", "codex/hooks.json"]) {
    const sourcePath = path.join(agentsRoot, ...relativePath.split("/"));
    const metadata = await lstat(sourcePath).catch(() => undefined);
    if (!metadata?.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
      throw fail("activation-source-type", `${relativePath} must be an ordinary candidate file`);
    }
    const [actual, committed] = await Promise.all([
      readFile(sourcePath),
      Promise.resolve(gitBytes(agentsRoot, ["show", `${revision}:${relativePath}`])),
    ]);
    if (!actual.equals(committed)) {
      throw fail("activation-content", `${relativePath} does not match candidate commit ${revision}`);
    }
  }
}

async function main(): Promise<void> {
  const workspace = parseWorkspace(process.argv.slice(2));
  const agentsRoot = await requireOrdinaryDirectory(workspace, ".agents");
  const productRoot = await requireOrdinaryDirectory(workspace, "tsfg");
  const manifestsRoot = await requireOrdinaryDirectory(workspace, ".repo/manifests");
  await requireSafeActivationParent(workspace, ".codex");
  const heads = new Map([
    [".agents.git", git(agentsRoot, ["rev-parse", "HEAD"])],
    ["tsfg.git", git(productRoot, ["rev-parse", "HEAD"])],
  ]);
  for (const [projectName, revision] of heads) {
    if (!/^[0-9a-f]{40}$/.test(revision)) {
      throw fail("activation-materialization", `${projectName} does not have a complete commit identity`);
    }
  }
  await requireCommittedActivationSources(agentsRoot, heads.get(".agents.git")!);

  for (const [projectPath, url] of projectUrls) {
    const root = projectPath === ".agents" ? agentsRoot : productRoot;
    git(root, ["config", "remote.github-xuelongling.url", url]);
    git(root, ["config", "core.fsmonitor", "false"]);
  }

  const manifestPath = path.join(manifestsRoot, ...selectedManifest.split("/"));
  let manifest = await readFile(manifestPath, "utf8");
  for (const [projectName, revision] of heads) {
    manifest = replaceProjectRevision(manifest, projectName, revision);
  }
  await writeFile(manifestPath, manifest, "utf8");
  git(manifestsRoot, ["config", "user.name", "tsfg agent CI"]);
  git(manifestsRoot, ["config", "user.email", "agent-ci@tsfg.invalid"]);
  git(manifestsRoot, ["config", "commit.gpgsign", "false"]);
  git(manifestsRoot, ["config", "core.fsmonitor", "false"]);
  git(manifestsRoot, ["config", "remote.origin.url", manifestUrl]);
  git(manifestsRoot, ["add", "--", selectedManifest]);
  git(manifestsRoot, ["commit", "--quiet", "-m", "ci: pin candidate agent workspace"]);
  const manifestRevision = git(manifestsRoot, ["rev-parse", "HEAD"]);

  const manifestGit = path.join(workspace, ".repo", "manifests.git");
  if (await lstat(manifestGit).catch(() => undefined)) {
    throw fail("activation-materialization", ".repo/manifests.git already exists");
  }
  await mkdir(manifestGit, { recursive: true });
  git(manifestGit, ["init", "--bare", "--quiet"]);
  git(manifestGit, ["config", "remote.origin.url", manifestUrl]);
  git(manifestGit, ["config", "branch.default.merge", manifestRevision]);
  await writeFile(path.join(workspace, ".repo", "project.list"), ".agents\ntsfg\n", "utf8");

  await createRequiredLink(workspace, ".repo/manifest.xml", "manifests/bootstrap/r00.xml");
  await createRequiredLink(workspace, "AGENTS.md", ".agents/AGENTS.md");
  await createRequiredLink(workspace, ".codex/config.toml", "../.agents/codex/config.toml");
  await createRequiredLink(workspace, ".codex/hooks.json", "../.agents/codex/hooks.json");
  await verifyRequiredLink(workspace, "AGENTS.md", ".agents/AGENTS.md");
  await verifyRequiredLink(workspace, ".codex/config.toml", ".agents/codex/config.toml");
  await verifyRequiredLink(workspace, ".codex/hooks.json", ".agents/codex/hooks.json");

  console.log(JSON.stringify({ manifestRevision, manifestUrl, selectedManifest }));
}

try {
  await main();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
