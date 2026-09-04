// SPDX-License-Identifier: MIT

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

export type RepositoryCheck = "format" | "license-policy" | "secret-scan" | "source-integrity";

export type Finding = {
  readonly category: string;
  readonly relativePath: string;
};

type RepositoryEntries = {
  readonly files: readonly string[];
  readonly symlinks: readonly string[];
};

type ProvenanceInput = {
  readonly path: string;
  readonly digest: string;
};

type ArtifactProvenance = {
  readonly schema_version: string;
  readonly artifacts: ReadonlyArray<{
    readonly path: string;
    readonly digest: string;
    readonly sources: readonly ProvenanceInput[];
    readonly locks: readonly ProvenanceInput[];
  }>;
};

type AgentAssetInventory = {
  readonly schema_version: string;
  readonly instructions: readonly string[];
  readonly contexts: readonly string[];
  readonly skills: ReadonlyArray<{ readonly id: string; readonly source: string }>;
  readonly configuration_templates: readonly string[];
  readonly hooks: readonly string[];
  readonly support_documents: readonly string[];
  readonly tests: readonly string[];
  readonly tooling: readonly string[];
  readonly mcp_registry: string;
  readonly plugin_registry: string;
};

const execFileAsync = promisify(execFile);
const ignoredWalkDirectories = new Set([".git", "node_modules"]);
const generatedDirectoryNames = new Set(["build", "dist", "generated", "out"]);
const binaryExtensions = new Set([".gif", ".ico", ".jpeg", ".jpg", ".png", ".webp", ".woff", ".woff2", ".zip"]);
const authoritativeLockNames = new Set([
  "Cargo.lock",
  "bun.lock",
  "bun.lockb",
  "go.sum",
  "package-lock.json",
  "pnpm-lock.yaml",
  "poetry.lock",
  "uv.lock",
  "yarn.lock",
]);
const spdxExtensions = new Set([".bat", ".cmd", ".md", ".ps1", ".sh", ".toml", ".ts", ".yaml", ".yml"]);
const canonicalLicenseDigest = "6a71f67e525cf187d71520769172bc902fac20aa6e74c7f2e8268a8cb44da669";

function relativePortable(root: string, absolutePath: string): string {
  return path.relative(root, absolutePath).replaceAll(path.sep, "/");
}

function isInside(parent: string, candidate: string): boolean {
  const relative = path.relative(parent, candidate);
  return relative !== "" && relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

async function walkEntries(root: string, directory = root): Promise<RepositoryEntries> {
  const files: string[] = [];
  const symlinks: string[] = [];
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    if (entry.isDirectory() && ignoredWalkDirectories.has(entry.name)) {
      continue;
    }
    const absolutePath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      const nested = await walkEntries(root, absolutePath);
      files.push(...nested.files);
      symlinks.push(...nested.symlinks);
    } else if (entry.isSymbolicLink()) {
      symlinks.push(absolutePath);
    } else if (entry.isFile()) {
      files.push(absolutePath);
    }
  }
  return { files, symlinks };
}

async function gitEntries(root: string): Promise<RepositoryEntries | undefined> {
  try {
    const [{ stdout: names }, { stdout: stages }] = await Promise.all([
      execFileAsync("git", ["-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard"], {
        encoding: "utf8",
        maxBuffer: 16 * 1024 * 1024,
      }),
      execFileAsync("git", ["-C", root, "ls-files", "--stage", "-z"], {
        encoding: "utf8",
        maxBuffer: 16 * 1024 * 1024,
      }),
    ]);
    const trackedSymlinks = new Set(
      stages
        .split("\0")
        .filter((entry) => entry.startsWith("120000 "))
        .map((entry) => entry.slice(entry.indexOf("\t") + 1)),
    );
    const files: string[] = [];
    const symlinks: string[] = [];
    for (const relativePath of names.split("\0").filter(Boolean).sort()) {
      const absolutePath = path.join(root, relativePath);
      if (trackedSymlinks.has(relativePath)) {
        symlinks.push(absolutePath);
        continue;
      }
      try {
        const metadata = await lstat(absolutePath);
        if (metadata.isSymbolicLink()) {
          symlinks.push(absolutePath);
        } else if (metadata.isFile()) {
          files.push(absolutePath);
        }
      } catch {
        // A deleted worktree entry has no repository content to inspect here.
      }
    }
    return { files, symlinks };
  } catch {
    return undefined;
  }
}

async function repositoryEntries(root: string): Promise<RepositoryEntries> {
  return (await gitEntries(root)) ?? walkEntries(root);
}

function credentialPattern(): RegExp {
  const names = [
    ["client", "secret"],
    ["access", "token"],
    ["refresh", "token"],
    ["id", "token"],
    ["api", "key"],
    ["token"],
  ].map((parts) => parts.join("[_ -]?"));
  return new RegExp(
    `(?:^|[^A-Za-z0-9_])["']?(?:${names.join("|")}|authorization)["']?\\s*[:=]\\s*["']?(?!<|\\$\\{|%)[^\\s"']{8,}`,
    "i",
  );
}

function secretContentCategory(content: string): string | undefined {
  const knownToken = /sk-[A-Za-z0-9_-]{16,}|gh[oprsu]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/;
  const privateKey = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/;
  const windowsAbsolute = new RegExp(
    String.raw`(?:^|[^A-Za-z0-9_])(?:[A-Za-z]:[\\/]|\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9$._-]+\\)`,
    "im",
  );
  const posixHome = new RegExp(String.raw`/(?:home|Users)/[^/\s"']+`);
  if (knownToken.test(content) || privateKey.test(content) || credentialPattern().test(content)) {
    return "credential value";
  }
  if (windowsAbsolute.test(content) || posixHome.test(content)) {
    return "personal absolute path";
  }
  return undefined;
}

function isAuthenticationStateName(basename: string): boolean {
  return /^(?:auth|credentials|oauth(?:[-_.]?(?:session|tokens?))?|session|tokens?)(?:[-_.].*)?\.(?:db|json|jsonl|sqlite|sqlite3)$/.test(
    basename,
  );
}

async function scanSecrets(root: string, entries: RepositoryEntries): Promise<Finding[]> {
  const findings = entries.symlinks.map((absolutePath) => ({
    category: "symlink cannot be inspected without leaving repository ownership",
    relativePath: relativePortable(root, absolutePath),
  }));
  for (const absolutePath of entries.files) {
    const relativePath = relativePortable(root, absolutePath);
    if (!(await pathIsOwnedFile(root, absolutePath, entries))) {
      findings.push({ category: "file path crosses a symlink", relativePath });
      continue;
    }
    if (isAuthenticationStateName(path.basename(absolutePath).toLowerCase())) {
      findings.push({ category: "authentication state", relativePath });
      continue;
    }
    let content: string;
    try {
      content = await readFile(absolutePath, "utf8");
    } catch {
      findings.push({ category: "unreadable repository file", relativePath });
      continue;
    }
    const category = secretContentCategory(content);
    if (category !== undefined) {
      findings.push({ category, relativePath });
    }
  }
  return findings;
}

function touchesKnownSymlink(root: string, filePath: string, entries: RepositoryEntries): boolean {
  const relativePath = relativePortable(root, filePath);
  return entries.symlinks.some((symlinkPath) => {
    const relativeSymlink = relativePortable(root, symlinkPath);
    return relativePath === relativeSymlink || relativePath.startsWith(`${relativeSymlink}/`);
  });
}

async function pathIsOwnedFile(root: string, filePath: string, entries: RepositoryEntries): Promise<boolean> {
  if (!isInside(root, filePath) || touchesKnownSymlink(root, filePath, entries)) {
    return false;
  }
  try {
    const relativeParts = path.relative(root, filePath).split(path.sep);
    let currentPath = root;
    for (const [index, part] of relativeParts.entries()) {
      currentPath = path.join(currentPath, part);
      const metadata = await lstat(currentPath);
      if (metadata.isSymbolicLink()) {
        return false;
      }
      const isLast = index === relativeParts.length - 1;
      if ((isLast && !metadata.isFile()) || (!isLast && !metadata.isDirectory())) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

async function sha256File(filePath: string): Promise<string> {
  return `sha256:${createHash("sha256").update(await readFile(filePath)).digest("hex")}`;
}

function generatedProject(relativePath: string): string | undefined {
  const segments = relativePath.split("/");
  const generatedIndex = segments.findIndex((segment) => generatedDirectoryNames.has(segment));
  if (generatedIndex < 0 || generatedIndex === segments.length - 1) {
    return undefined;
  }
  return segments.slice(0, generatedIndex).join("/");
}

function generatedOutputCategory(project: string): string {
  return project.startsWith("mcp/") ? "generated MCP output is not declared" : "generated agent output is not declared";
}

function validProvenanceInput(value: unknown): value is ProvenanceInput {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const input = value as Record<string, unknown>;
  return typeof input.path === "string" && typeof input.digest === "string";
}

async function verifyDigest(
  root: string,
  entries: RepositoryEntries,
  expected: string,
  absolutePath: string,
  relativePath: string,
  missingCategory: string,
): Promise<Finding[]> {
  if (!(await pathIsOwnedFile(root, absolutePath, entries))) {
    return [{ category: missingCategory, relativePath }];
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(expected) || (await sha256File(absolutePath)) !== expected) {
    return [{ category: "digest mismatch", relativePath }];
  }
  return [];
}

async function checkArtifactProject(
  root: string,
  project: string,
  generatedFiles: readonly string[],
  entries: RepositoryEntries,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const projectRoot = path.resolve(root, project);
  const provenancePath = path.join(projectRoot, "artifact-provenance.json");
  const provenanceRelativePath = relativePortable(root, provenancePath);
  if (!(await pathIsOwnedFile(root, provenancePath, entries))) {
    return generatedFiles.map((relativePath) => ({ category: generatedOutputCategory(project), relativePath }));
  }

  let provenance: ArtifactProvenance;
  try {
    provenance = JSON.parse(await readFile(provenancePath, "utf8")) as ArtifactProvenance;
  } catch {
    return [{ category: "invalid artifact provenance", relativePath: provenanceRelativePath }];
  }
  if (provenance.schema_version !== "1" || !Array.isArray(provenance.artifacts)) {
    return [{ category: "invalid artifact provenance", relativePath: provenanceRelativePath }];
  }

  const declaredOutputs = new Set<string>();
  for (const artifact of provenance.artifacts) {
    if (
      typeof artifact?.path !== "string" ||
      typeof artifact.digest !== "string" ||
      !Array.isArray(artifact.sources) ||
      artifact.sources.length === 0 ||
      !artifact.sources.every(validProvenanceInput) ||
      !Array.isArray(artifact.locks) ||
      artifact.locks.length === 0 ||
      !artifact.locks.every(validProvenanceInput)
    ) {
      findings.push({ category: "invalid artifact provenance", relativePath: provenanceRelativePath });
      continue;
    }

    const outputPath = path.resolve(projectRoot, artifact.path);
    const outputRelativePath = relativePortable(root, outputPath);
    if (!isInside(projectRoot, outputPath) || generatedProject(outputRelativePath) !== project) {
      findings.push({ category: "artifact provenance path escapes generated project", relativePath: artifact.path });
      continue;
    }
    if (declaredOutputs.has(outputRelativePath)) {
      findings.push({ category: "duplicate generated artifact declaration", relativePath: outputRelativePath });
    }
    declaredOutputs.add(outputRelativePath);
    findings.push(
      ...(await verifyDigest(root, entries, artifact.digest, outputPath, outputRelativePath, "missing generated artifact")),
    );

    const sourceRoot = path.join(projectRoot, "src");
    for (const source of artifact.sources) {
      const sourcePath = path.resolve(projectRoot, source.path);
      const sourceRelativePath = relativePortable(root, sourcePath);
      if (!isInside(sourceRoot, sourcePath)) {
        findings.push({ category: "invalid maintainable source path", relativePath: source.path });
      } else {
        findings.push(...(await verifyDigest(root, entries, source.digest, sourcePath, sourceRelativePath, "missing source")));
      }
    }

    for (const lock of artifact.locks) {
      const lockPath = path.resolve(projectRoot, lock.path);
      const lockRelativePath = relativePortable(root, lockPath);
      if (!isInside(projectRoot, lockPath) || !authoritativeLockNames.has(path.basename(lockPath))) {
        findings.push({ category: "invalid authoritative lock", relativePath: lock.path });
      } else {
        findings.push(...(await verifyDigest(root, entries, lock.digest, lockPath, lockRelativePath, "missing lock")));
      }
    }
  }

  for (const relativePath of generatedFiles) {
    if (!declaredOutputs.has(relativePath)) {
      findings.push({ category: generatedOutputCategory(project), relativePath });
    }
  }
  return findings;
}

async function readJsonObject(
  root: string,
  filePath: string,
  entries: RepositoryEntries,
): Promise<Record<string, unknown> | undefined> {
  try {
    if (!(await pathIsOwnedFile(root, filePath, entries))) {
      return undefined;
    }
    const value: unknown = JSON.parse(await readFile(filePath, "utf8"));
    return typeof value === "object" && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

function stringArray(value: unknown): readonly string[] | undefined {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string") ? value : undefined;
}

async function checkAgentAssetInventory(root: string, entries: RepositoryEntries): Promise<Finding[]> {
  const inventoryPath = path.join(root, "agent-assets.json");
  if (!(await pathIsOwnedFile(root, inventoryPath, entries))) {
    return [{ category: "missing agent asset inventory", relativePath: "agent-assets.json" }];
  }
  const parsed = await readJsonObject(root, inventoryPath, entries);
  if (parsed === undefined || parsed.schema_version !== "1") {
    return [{ category: "invalid agent asset inventory", relativePath: "agent-assets.json" }];
  }
  const inventory = parsed as AgentAssetInventory;
  const findings: Finding[] = [];
  const declaredAssets = new Set<string>();
  const pathGroups = [
    stringArray(inventory.instructions),
    stringArray(inventory.contexts),
    stringArray(inventory.configuration_templates),
    stringArray(inventory.hooks),
    stringArray(inventory.support_documents),
    stringArray(inventory.tests),
    stringArray(inventory.tooling),
    typeof inventory.mcp_registry === "string" && typeof inventory.plugin_registry === "string"
      ? [inventory.mcp_registry, inventory.plugin_registry]
      : undefined,
  ];
  for (const group of pathGroups) {
    if (group === undefined) {
      findings.push({ category: "invalid agent asset inventory", relativePath: "agent-assets.json" });
      continue;
    }
    for (const declaredPath of group) {
      declaredAssets.add(declaredPath.replaceAll("\\", "/"));
      const absolutePath = path.resolve(root, declaredPath);
      if (!isInside(root, absolutePath)) {
        findings.push({ category: "inventoried asset escapes repository", relativePath: declaredPath });
      } else if (!(await pathIsOwnedFile(root, absolutePath, entries))) {
        findings.push({ category: "missing inventoried asset", relativePath: declaredPath });
      }
    }
  }

  if (!Array.isArray(inventory.skills)) {
    findings.push({ category: "invalid agent asset inventory", relativePath: "agent-assets.json" });
  } else {
    for (const skill of inventory.skills) {
      if (typeof skill?.id !== "string" || typeof skill.source !== "string") {
        findings.push({ category: "invalid skill inventory entry", relativePath: "agent-assets.json" });
        continue;
      }
      declaredAssets.add(skill.source.replaceAll("\\", "/"));
      const sourcePath = path.resolve(root, skill.source);
      if (!isInside(root, sourcePath) || !(await pathIsOwnedFile(root, sourcePath, entries))) {
        findings.push({ category: "missing inventoried asset", relativePath: skill.source });
        continue;
      }
      const content = await readFile(sourcePath, "utf8");
      if (!content.startsWith("---\n") || !content.includes(`\nname: ${skill.id}\n`) || !/\ndescription: .+\n/.test(content)) {
        findings.push({ category: "invalid skill frontmatter", relativePath: skill.source });
      }
    }
  }

  for (const hooksPath of stringArray(inventory.hooks) ?? []) {
    const hooks = await readJsonObject(root, path.resolve(root, hooksPath), entries);
    if (hooks === undefined || typeof hooks.hooks !== "object" || hooks.hooks === null || Array.isArray(hooks.hooks)) {
      findings.push({ category: "invalid hooks configuration", relativePath: hooksPath });
    }
  }
  if (typeof inventory.mcp_registry === "string") {
    const registry = await readJsonObject(root, path.resolve(root, inventory.mcp_registry), entries);
    if (registry === undefined || registry.schema_version !== "1" || !Array.isArray(registry.servers)) {
      findings.push({ category: "invalid MCP registry", relativePath: inventory.mcp_registry });
    }
  }
  if (typeof inventory.plugin_registry === "string") {
    const registry = await readJsonObject(root, path.resolve(root, inventory.plugin_registry), entries);
    if (registry === undefined || registry.schema_version !== "1" || !Array.isArray(registry.plugins)) {
      findings.push({ category: "invalid plugin registry", relativePath: inventory.plugin_registry });
    }
  }

  const repositoryMetadata = new Set([".gitattributes", ".gitignore", "LICENSE", "agent-assets.json"]);
  for (const absolutePath of entries.files) {
    const relativePath = relativePortable(root, absolutePath);
    if (
      !repositoryMetadata.has(relativePath) &&
      !relativePath.startsWith("mcp/") &&
      !relativePath.startsWith("plugins/") &&
      !declaredAssets.has(relativePath)
    ) {
      findings.push({ category: "maintained asset is not inventoried", relativePath });
    }
  }
  return findings;
}

function stateFinding(relativePath: string): Finding | undefined {
  const lowerPath = relativePath.toLowerCase();
  const segments = lowerPath.split("/");
  const basename = segments.at(-1) ?? "";
  if (segments.includes("node_modules")) {
    return { category: "dependency cache is repository-local state", relativePath };
  }
  if (segments.some((segment) => [".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__"].includes(segment))) {
    return { category: "test cache is repository-local state", relativePath };
  }
  if (segments.some((segment) => [".cache", "cache", "caches"].includes(segment))) {
    return { category: "cache is repository-local state", relativePath };
  }
  if (/(?:^|[-_.])cache(?:[-_.]|$)/.test(basename)) {
    return { category: "cache is repository-local state", relativePath };
  }
  if (segments.includes("logs") || lowerPath.endsWith(".log")) {
    return { category: "log is repository-local state", relativePath };
  }
  if (/\.(?:db|sqlite|sqlite3|wal)$/.test(lowerPath)) {
    return { category: "state database is repository-local state", relativePath };
  }
  if (
    lowerPath.endsWith(".jsonl") &&
    (segments.some((segment) => ["events", "history", "sessions"].includes(segment)) ||
      /^(?:events|history|sessions)(?:[-_.].*)?\.jsonl$/.test(basename))
  ) {
    return { category: "history or session log is repository-local state", relativePath };
  }
  if (basename === ".codex-global-state.json") {
    return { category: "agent state is repository-local state", relativePath };
  }
  return undefined;
}

async function checkSourceIntegrity(root: string, entries: RepositoryEntries): Promise<Finding[]> {
  const findings = entries.symlinks.map((absolutePath) => ({
    category: "symlink is not maintainable repository source",
    relativePath: relativePortable(root, absolutePath),
  }));
  const generatedByProject = new Map<string, string[]>();
  for (const absolutePath of entries.files) {
    const relativePath = relativePortable(root, absolutePath);
    const state = stateFinding(relativePath);
    if (state !== undefined) {
      findings.push(state);
    }
    const project = generatedProject(relativePath);
    if (project !== undefined) {
      const files = generatedByProject.get(project) ?? [];
      files.push(relativePath);
      generatedByProject.set(project, files);
    }
    if (path.basename(relativePath) === "artifact-provenance.json") {
      const provenanceDirectory = path.posix.dirname(relativePath);
      const provenanceProject = provenanceDirectory === "." ? "" : provenanceDirectory;
      if (!generatedByProject.has(provenanceProject)) {
        generatedByProject.set(provenanceProject, []);
      }
    }
  }
  for (const [project, generatedFiles] of generatedByProject) {
    findings.push(...(await checkArtifactProject(root, project, generatedFiles, entries)));
  }
  findings.push(...(await checkAgentAssetInventory(root, entries)));
  return findings;
}

async function checkFormat(root: string, entries: RepositoryEntries): Promise<Finding[]> {
  const findings: Finding[] = [];
  const decoder = new TextDecoder("utf-8", { fatal: true });
  for (const absolutePath of entries.files) {
    const relativePath = relativePortable(root, absolutePath);
    if (!(await pathIsOwnedFile(root, absolutePath, entries))) {
      findings.push({ category: "file path crosses a symlink", relativePath });
      continue;
    }
    if (binaryExtensions.has(path.extname(absolutePath).toLowerCase())) {
      continue;
    }
    const bytes = await readFile(absolutePath);
    if (bytes.includes(0)) {
      findings.push({ category: "text is not valid UTF-8", relativePath });
      continue;
    }
    let content: string;
    try {
      content = decoder.decode(bytes);
    } catch {
      findings.push({ category: "text is not valid UTF-8", relativePath });
      continue;
    }
    if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
      findings.push({ category: "text contains a UTF-8 BOM", relativePath });
    }
    const windowsCommand = absolutePath.toLowerCase().endsWith(".cmd") || absolutePath.toLowerCase().endsWith(".bat");
    const remainingLineEndings = windowsCommand ? content.replaceAll("\r\n", "") : content;
    const invalidCarriageReturn = windowsCommand
      ? remainingLineEndings.includes("\r") || remainingLineEndings.includes("\n")
      : content.includes("\r");
    if (invalidCarriageReturn) {
      findings.push({ category: "text uses a non-LF line ending", relativePath });
    }
    if (/[ \t]+(?=\r?$)/mu.test(content)) {
      findings.push({ category: "text contains trailing whitespace", relativePath });
    }
    if (content.length > 0 && !content.endsWith("\n")) {
      findings.push({ category: "text has no final newline", relativePath });
    }
  }
  return findings;
}

async function checkLicensePolicy(root: string, entries: RepositoryEntries): Promise<Finding[]> {
  const findings: Finding[] = [];
  const licensePath = path.join(root, "LICENSE");
  const license = entries.files.includes(licensePath) ? await readFile(licensePath) : Buffer.alloc(0);
  if (
    createHash("sha256").update(license).digest("hex") !== canonicalLicenseDigest ||
    !license.toString("utf8").includes("Copyright (c) 2026 xuelongling\n")
  ) {
    findings.push({ category: "license-root", relativePath: "LICENSE" });
  }

  for (const absolutePath of entries.files) {
    const relativePath = relativePortable(root, absolutePath);
    if (relativePath === "LICENSE" || relativePath === "pnpm-lock.yaml") {
      continue;
    }
    const extension = path.extname(relativePath).toLowerCase();
    if (extension === ".json" || relativePath === ".gitattributes" || relativePath === ".gitignore") {
      continue;
    }
    if (!spdxExtensions.has(extension)) {
      findings.push({ category: "license-coverage", relativePath });
      continue;
    }
    const content = await readFile(absolutePath, "utf8");
    if (
      !/^(?:\/\/|#|@?rem) SPDX-License-Identifier: MIT$/imu.test(content) &&
      !/^<!-- SPDX-License-Identifier: MIT -->$/mu.test(content)
    ) {
      findings.push({ category: "license-spdx", relativePath });
    }
  }
  return findings;
}

export async function checkRepository(command: RepositoryCheck, root: string): Promise<readonly Finding[]> {
  const entries = await repositoryEntries(root);
  let findings: Finding[];
  if (command === "format") {
    findings = await checkFormat(root, entries);
  } else if (command === "license-policy") {
    findings = await checkLicensePolicy(root, entries);
  } else if (command === "secret-scan") {
    findings = await scanSecrets(root, entries);
  } else {
    findings = await checkSourceIntegrity(root, entries);
  }
  return findings.sort(
    (left, right) => left.relativePath.localeCompare(right.relativePath) || left.category.localeCompare(right.category),
  );
}
