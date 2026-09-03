// SPDX-License-Identifier: MIT

import path from "node:path";
import process from "node:process";

import { checkRepository, type RepositoryCheck } from "./repository-policy.ts";

function parseArguments(argv: readonly string[]): { command: RepositoryCheck; root: string } {
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
  if (command !== "format" && command !== "secret-scan" && command !== "source-integrity") {
    throw new Error(`unknown command: ${command ?? ""}`);
  }
  return { command, root };
}

async function main(): Promise<number> {
  const { command, root } = parseArguments(process.argv.slice(2));
  const findings = await checkRepository(command, root);
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
