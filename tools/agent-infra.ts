// SPDX-License-Identifier: MIT

import { access, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

type Finding = {
  readonly category: string;
  readonly relativePath: string;
};

type ArtifactProvenance = {
  readonly schema_version: string;
  readonly artifacts: ReadonlyArray<{
    readonly path: string;
    readonly sources: readonly string[];
    readonly locks: readonly string[];
  }>;
};

type AgentAssetInventory = {
  readonly schema_version: string;
  readonly instructions: readonly string[];
  readonly contexts: readonly string[];
  readonly skills: ReadonlyArray<{ readonly id: string; readonly source: string }>;
  readonly configuration_templates: readonly string[];
  readonly hooks: readonly string[];
  readonly mcp_registry: string;
  readonly plugin_registry: string;
};

const ignoredDirectoryNames = new Set([".git", "node_modules"]);

async function listFiles(root: string, directory = root): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    if (entry.isDirectory() && ignoredDirectoryNames.has(entry.name)) {
      continue;
    }

    const absolutePath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await listFiles(root, absolutePath)));
    } else if (entry.isFile() || entry.isSymbolicLink()) {
      files.push(absolutePath);
    }
  }
  return files;
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
    `(?:^|[^A-Za-z0-9_])(?:${names.join("|")}|authorization)\\s*[:=]\\s*["']?(?!<|\\$\\{|%)[^\\s"']{8,}`,
    "i",
  );
}

function secretContentCategory(content: string): string | undefined {
  const knownToken = /(?:sk|gh[oprsu])-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}/;
  const privateKey = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/;
  const windowsAbsolute = new RegExp(
    String.raw`(?:^|[\s"'(=])(?:[A-Za-z]:[\\/]|\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9$._-]+\\)`,
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

async function scanSecrets(root: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const authenticationStateNames = new Set([
    "auth" + ".json",
    "oauth" + ".json",
    "credentials" + ".json",
  ]);

  for (const absolutePath of await listFiles(root)) {
    const relativePath = path.relative(root, absolutePath).replaceAll(path.sep, "/");
    const basename = path.basename(absolutePath).toLowerCase();
    const sessionStateName = /^(?:oauth[-_.]?)?(?:session|tokens?)(?:[-_.].*)?\.json$/;
    if (authenticationStateNames.has(basename) || sessionStateName.test(basename)) {
      findings.push({ category: "authentication state", relativePath });
      continue;
    }

    let content: string;
    try {
      content = await readFile(absolutePath, "utf8");
    } catch {
      continue;
    }
    const category = secretContentCategory(content);
    if (category !== undefined) {
      findings.push({ category, relativePath });
    }
  }

  return findings;
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

function relativePortable(root: string, absolutePath: string): string {
  return path.relative(root, absolutePath).replaceAll(path.sep, "/");
}

function isGeneratedMcpPath(relativePath: string): boolean {
  return /^mcp\/[^/]+\/(?:dist|build|out|generated)\/.+/.test(relativePath);
}

function isInside(parent: string, candidate: string): boolean {
  const relative = path.relative(parent, candidate);
  return relative !== "" && relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

async function checkMcpProject(
  root: string,
  projectName: string,
  generatedFiles: readonly string[],
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const projectRoot = path.join(root, "mcp", projectName);
  const provenancePath = path.join(projectRoot, "artifact-provenance.json");
  if (!(await fileExists(provenancePath))) {
    return generatedFiles.map((relativePath) => ({
      category: "generated MCP output is not declared",
      relativePath,
    }));
  }

  let provenance: ArtifactProvenance;
  try {
    provenance = JSON.parse(await readFile(provenancePath, "utf8")) as ArtifactProvenance;
  } catch {
    return [{ category: "invalid MCP artifact provenance", relativePath: relativePortable(root, provenancePath) }];
  }
  if (provenance.schema_version !== "1" || !Array.isArray(provenance.artifacts)) {
    return [{ category: "invalid MCP artifact provenance", relativePath: relativePortable(root, provenancePath) }];
  }

  const declaredOutputs = new Set<string>();
  for (const artifact of provenance.artifacts) {
    if (
      typeof artifact.path !== "string" ||
      !Array.isArray(artifact.sources) ||
      artifact.sources.length === 0 ||
      !Array.isArray(artifact.locks) ||
      artifact.locks.length === 0
    ) {
      findings.push({
        category: "invalid MCP artifact provenance",
        relativePath: relativePortable(root, provenancePath),
      });
      continue;
    }

    const outputPath = path.resolve(projectRoot, artifact.path);
    if (!isInside(projectRoot, outputPath)) {
      findings.push({ category: "MCP provenance path escapes project", relativePath: artifact.path });
      continue;
    }
    declaredOutputs.add(relativePortable(root, outputPath));

    for (const source of artifact.sources) {
      const sourcePath = path.resolve(projectRoot, source);
      if (!isInside(projectRoot, sourcePath) || !source.replaceAll("\\", "/").startsWith("src/")) {
        findings.push({ category: "invalid maintainable source path", relativePath: source });
      } else if (!(await fileExists(sourcePath))) {
        findings.push({ category: "missing source", relativePath: relativePortable(root, sourcePath) });
      }
    }

    for (const lock of artifact.locks) {
      const lockPath = path.resolve(projectRoot, lock);
      if (!isInside(projectRoot, lockPath)) {
        findings.push({ category: "invalid lock path", relativePath: lock });
      } else if (!(await fileExists(lockPath))) {
        findings.push({ category: "missing lock", relativePath: relativePortable(root, lockPath) });
      }
    }
  }

  for (const relativePath of generatedFiles) {
    if (!declaredOutputs.has(relativePath)) {
      findings.push({ category: "generated MCP output is not declared", relativePath });
    }
  }
  return findings;
}

async function readJsonObject(filePath: string): Promise<Record<string, unknown> | undefined> {
  try {
    const value: unknown = JSON.parse(await readFile(filePath, "utf8"));
    return typeof value === "object" && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

async function checkAgentAssetInventory(root: string): Promise<Finding[]> {
  const inventoryPath = path.join(root, "agent-assets.json");
  if (!(await fileExists(inventoryPath))) {
    return [];
  }

  const parsed = await readJsonObject(inventoryPath);
  if (parsed === undefined || parsed.schema_version !== "1") {
    return [{ category: "invalid agent asset inventory", relativePath: "agent-assets.json" }];
  }
  const inventory = parsed as AgentAssetInventory;
  const findings: Finding[] = [];
  const pathGroups: readonly (readonly string[])[] = [
    inventory.instructions,
    inventory.contexts,
    inventory.configuration_templates,
    inventory.hooks,
    [inventory.mcp_registry, inventory.plugin_registry],
  ];

  for (const group of pathGroups) {
    if (!Array.isArray(group)) {
      findings.push({ category: "invalid agent asset inventory", relativePath: "agent-assets.json" });
      continue;
    }
    for (const declaredPath of group) {
      if (typeof declaredPath !== "string") {
        findings.push({ category: "invalid agent asset inventory", relativePath: "agent-assets.json" });
        continue;
      }
      const absolutePath = path.resolve(root, declaredPath);
      if (!isInside(root, absolutePath)) {
        findings.push({ category: "inventoried asset escapes repository", relativePath: declaredPath });
      } else if (!(await fileExists(absolutePath))) {
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
      const sourcePath = path.resolve(root, skill.source);
      if (!isInside(root, sourcePath) || !(await fileExists(sourcePath))) {
        findings.push({ category: "missing inventoried asset", relativePath: skill.source });
        continue;
      }
      const content = await readFile(sourcePath, "utf8");
      if (!content.startsWith("---\n") || !content.includes(`\nname: ${skill.id}\n`) || !/\ndescription: .+\n/.test(content)) {
        findings.push({ category: "invalid skill frontmatter", relativePath: skill.source });
      }
    }
  }

  for (const hooksPath of Array.isArray(inventory.hooks) ? inventory.hooks : []) {
    const hooks = await readJsonObject(path.resolve(root, hooksPath));
    if (hooks === undefined || typeof hooks.hooks !== "object" || hooks.hooks === null || Array.isArray(hooks.hooks)) {
      findings.push({ category: "invalid hooks configuration", relativePath: hooksPath });
    }
  }

  const mcpRegistry = await readJsonObject(path.resolve(root, inventory.mcp_registry));
  if (mcpRegistry === undefined || mcpRegistry.schema_version !== "1" || !Array.isArray(mcpRegistry.servers)) {
    findings.push({ category: "invalid MCP registry", relativePath: inventory.mcp_registry });
  }
  const pluginRegistry = await readJsonObject(path.resolve(root, inventory.plugin_registry));
  if (pluginRegistry === undefined || pluginRegistry.schema_version !== "1" || !Array.isArray(pluginRegistry.plugins)) {
    findings.push({ category: "invalid plugin registry", relativePath: inventory.plugin_registry });
  }

  return findings;
}

async function checkSourceIntegrity(root: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const generatedByProject = new Map<string, string[]>();

  for (const absolutePath of await listFiles(root)) {
    const relativePath = relativePortable(root, absolutePath);
    const segments = relativePath.toLowerCase().split("/");
    if (segments.some((segment) => segment === ".cache" || segment === "cache" || segment === "caches")) {
      findings.push({ category: "cache is repository-local state", relativePath });
    }
    if (segments.includes("logs") || relativePath.toLowerCase().endsWith(".log")) {
      findings.push({ category: "log is repository-local state", relativePath });
    }
    if (isGeneratedMcpPath(relativePath)) {
      const projectName = relativePath.split("/")[1];
      const projectFiles = generatedByProject.get(projectName) ?? [];
      projectFiles.push(relativePath);
      generatedByProject.set(projectName, projectFiles);
    }
  }

  for (const [projectName, generatedFiles] of generatedByProject) {
    findings.push(...(await checkMcpProject(root, projectName, generatedFiles)));
  }
  findings.push(...(await checkAgentAssetInventory(root)));
  return findings;
}

async function checkFormat(root: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const decoder = new TextDecoder("utf-8", { fatal: true });

  for (const absolutePath of await listFiles(root)) {
    const relativePath = relativePortable(root, absolutePath);
    const bytes = await readFile(absolutePath);
    if (bytes.includes(0)) {
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
    if (content.includes("\r")) {
      findings.push({ category: "text uses a non-LF line ending", relativePath });
    }
    if (/[^\S\r\n]+$/mu.test(content)) {
      findings.push({ category: "text contains trailing whitespace", relativePath });
    }
    if (content.length > 0 && !content.endsWith("\n")) {
      findings.push({ category: "text has no final newline", relativePath });
    }
  }
  return findings;
}

function parseArguments(argv: readonly string[]): { command: string; root: string } {
  const [command, ...options] = argv;
  let root = process.cwd();
  for (let index = 0; index < options.length; index += 1) {
    if (options[index] === "--root" && options[index + 1] !== undefined) {
      root = path.resolve(options[index + 1]);
      index += 1;
    } else {
      throw new Error(`unknown option: ${options[index]}`);
    }
  }
  if (command === undefined) {
    throw new Error("a command is required");
  }
  return { command, root };
}

async function main(): Promise<number> {
  const { command, root } = parseArguments(process.argv.slice(2));
  let findings: Finding[];
  if (command === "secret-scan") {
    findings = await scanSecrets(root);
  } else if (command === "source-integrity") {
    findings = await checkSourceIntegrity(root);
  } else if (command === "format") {
    findings = await checkFormat(root);
  } else {
    throw new Error(`unknown command: ${command}`);
  }

  for (const finding of findings) {
    console.error(`${finding.category}: ${finding.relativePath}`);
  }
  return findings.length === 0 ? 0 : 1;
}

try {
  process.exitCode = await main();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 2;
}
