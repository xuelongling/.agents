// SPDX-License-Identifier: MIT

import { spawnSync } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

import type { Finding } from "./repository-policy.ts";

async function workflowFiles(root: string): Promise<readonly string[]> {
  const directory = path.join(root, ".github", "workflows");
  try {
    return (await readdir(directory))
      .filter((name) => name.endsWith(".yml") || name.endsWith(".yaml"))
      .sort()
      .map((name) => path.join(directory, name));
  } catch {
    return [];
  }
}

export async function checkWorkflowPolicy(root: string): Promise<readonly Finding[]> {
  const findings: Finding[] = [];
  for (const workflowPath of await workflowFiles(root)) {
    const relativePath = path.relative(root, workflowPath).replaceAll(path.sep, "/");
    const contents = await readFile(workflowPath, "utf8");
    const lines = contents.split("\n");
    const categories = new Set<string>();
    const report = (category: string) => categories.add(category);

    const rootBlock = (key: string): readonly string[] => {
      const start = lines.findIndex((line) => line === `${key}:`);
      if (start === -1) {
        return [];
      }
      const block: string[] = [];
      for (let index = start + 1; index < lines.length; index += 1) {
        if (lines[index] !== "" && !lines[index].startsWith(" ")) {
          break;
        }
        if (lines[index].trim() !== "" && !lines[index].trimStart().startsWith("#")) {
          block.push(lines[index]);
        }
      }
      return block;
    };

    const events = rootBlock("on");
    if (
      events.length !== 1 ||
      events[0] !== "  pull_request:" ||
      lines.some((line) => /^\s*pull_request_target\s*:/.test(line))
    ) {
      report("privileged-event");
    }

    const permissions = rootBlock("permissions");
    if (
      permissions.length !== 1 ||
      permissions[0] !== "  contents: read" ||
      lines.some((line) => /^\s+permissions\s*:/.test(line))
    ) {
      report("permissions");
    }

    if (/\$\{\{\s*secrets\.|^\s+secrets\s*:/m.test(contents)) {
      report("secret-context");
    }

    for (const line of lines) {
      const runner = /^\s+runs-on:\s*([^\s#]+)(?:\s+#.*)?$/.exec(line)?.[1];
      if (runner && runner !== "ubuntu-24.04" && runner !== "windows-2025") {
        report("moving-runner");
      }
      const match = /^\s+(?:-\s+)?uses:\s*["']?([^\s"'#]+)["']?(?:\s+#.*)?$/.exec(line);
      if (!match || match[1].startsWith("./")) {
        continue;
      }
      if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$/.test(match[1])) {
        report("unpinned-action");
      }
    }
    findings.push(...[...categories].sort().map((category) => ({ category, relativePath })));
  }
  return findings;
}

type BuildInputDeclaration = {
  readonly entries: ReadonlyArray<{ readonly path: string; readonly projectId: string }>;
  readonly schemaVersion: string;
};

function matrixFailure(message: string): Error {
  return new Error(`product-matrix-dispatch: ${message}`);
}

function git(root: string, arguments_: readonly string[]): string {
  const result = spawnSync("git", ["-C", root, ...arguments_], {
    encoding: "buffer",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw matrixFailure(result.stderr.toString("utf8").trim() || "git command failed");
  }
  return result.stdout.toString("utf8");
}

function changedPaths(root: string, base: string, head: string): ReadonlySet<string> {
  for (const [label, revision] of [
    ["base", base],
    ["head", head],
  ] as const) {
    if (!/^[0-9a-f]{40}$/.test(revision)) {
      throw matrixFailure(`${label} must be a complete commit OID`);
    }
    git(root, ["cat-file", "-e", `${revision}^{commit}`]);
  }

  const fields = git(root, ["diff", "--name-status", "-z", `${base}...${head}`, "--"])
    .split("\0")
    .filter(Boolean);
  const paths = new Set<string>();
  for (let index = 0; index < fields.length; ) {
    const status = fields[index++];
    if (!/^[ACDMRTUXB][0-9]*$/.test(status)) {
      throw matrixFailure(`unsupported Git diff status: ${status}`);
    }
    const pathCount = status.startsWith("R") || status.startsWith("C") ? 2 : 1;
    if (index + pathCount > fields.length) {
      throw matrixFailure("truncated Git diff record");
    }
    for (let pathIndex = 0; pathIndex < pathCount; pathIndex += 1) {
      paths.add(fields[index++].replaceAll("\\", "/"));
    }
  }
  return paths;
}

function validBuildInputPath(value: string): boolean {
  return (
    value !== "" &&
    !value.startsWith("/") &&
    !value.includes("\\") &&
    !value.split("/").some((segment) => segment === "" || segment === "." || segment === "..")
  );
}

export async function productMatrixRequest(
  root: string,
  base: string,
  head: string,
  buildInputsPath: string,
): Promise<{
  readonly productMatrix: { readonly matchedInputs: readonly string[]; readonly required: boolean };
  readonly schemaVersion: "1";
}> {
  let declaration: BuildInputDeclaration;
  try {
    declaration = JSON.parse(await readFile(buildInputsPath, "utf8")) as BuildInputDeclaration;
  } catch (error) {
    throw matrixFailure(`cannot read Build Input Set: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (declaration?.schemaVersion !== "1" || !Array.isArray(declaration.entries)) {
    throw matrixFailure("invalid Build Input Set declaration");
  }
  const identities = new Set<string>();
  for (const entry of declaration.entries) {
    if (
      typeof entry?.projectId !== "string" ||
      typeof entry.path !== "string" ||
      !validBuildInputPath(entry.path)
    ) {
      throw matrixFailure("invalid Build Input Set entry");
    }
    const identity = `${entry.projectId}\0${entry.path}`;
    if (identities.has(identity)) {
      throw matrixFailure("duplicate Build Input Set entry");
    }
    identities.add(identity);
  }

  const changed = changedPaths(root, base, head);
  const matchedInputs = declaration.entries
    .filter((entry) => entry.projectId === ".agents.git" && changed.has(entry.path))
    .map((entry) => entry.path)
    .sort();
  return {
    productMatrix: { matchedInputs, required: matchedInputs.length !== 0 },
    schemaVersion: "1",
  };
}
