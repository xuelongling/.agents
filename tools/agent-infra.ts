// SPDX-License-Identifier: MIT

import path from "node:path";
import process from "node:process";

import { checkWorkflowPolicy, productMatrixRequest } from "./ci-policy.ts";
import { checkRepository, type RepositoryCheck } from "./repository-policy.ts";

type AgentCommand = RepositoryCheck | "product-matrix-request" | "workflow-policy";

function parseArguments(argv: readonly string[]): {
  base?: string;
  buildInputs?: string;
  command: AgentCommand;
  head?: string;
  root: string;
} {
  const [command, ...options] = argv;
  let root = process.cwd();
  let base: string | undefined;
  let buildInputs: string | undefined;
  let head: string | undefined;
  for (let index = 0; index < options.length; index += 1) {
    const value = options[index + 1];
    if (value === undefined) {
      throw new Error(`missing value for option: ${options[index]}`);
    }
    if (options[index] === "--root") {
      root = path.resolve(value);
      index += 1;
    } else if (options[index] === "--base") {
      base = value;
      index += 1;
    } else if (options[index] === "--head") {
      head = value;
      index += 1;
    } else if (options[index] === "--build-inputs") {
      buildInputs = path.resolve(value);
      index += 1;
    } else {
      throw new Error(`unknown option: ${options[index]}`);
    }
  }
  if (
    command !== "format" &&
    command !== "license-policy" &&
    command !== "secret-scan" &&
    command !== "source-integrity" &&
    command !== "product-matrix-request" &&
    command !== "workflow-policy"
  ) {
    throw new Error(`unknown command: ${command ?? ""}`);
  }
  if (command === "product-matrix-request") {
    if (!base || !head || !buildInputs) {
      throw new Error("product-matrix-request requires --base, --head, and --build-inputs");
    }
  } else if (base || head || buildInputs) {
    throw new Error(`${command} does not accept product matrix options`);
  }
  return { base, buildInputs, command, head, root };
}

async function main(): Promise<number> {
  const { base, buildInputs, command, head, root } = parseArguments(process.argv.slice(2));
  if (command === "product-matrix-request") {
    console.log(JSON.stringify(await productMatrixRequest(root, base!, head!, buildInputs!)));
    return 0;
  }
  const findings =
    command === "workflow-policy" ? await checkWorkflowPolicy(root) : await checkRepository(command, root);
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
