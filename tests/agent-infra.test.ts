// SPDX-License-Identifier: MIT

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cliPath = path.join(repositoryRoot, "tools", "agent-infra.ts");

async function withFixture(
  files: Readonly<Record<string, string>>,
  run: (root: string) => void,
): Promise<void> {
  const root = await mkdtemp(path.join(tmpdir(), "tsfg-agent-infra-"));
  try {
    for (const [relativePath, content] of Object.entries(files)) {
      const destination = path.join(root, relativePath);
      await mkdir(path.dirname(destination), { recursive: true });
      await writeFile(destination, content, "utf8");
    }
    run(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function runCli(command: string, root: string) {
  return spawnSync(process.execPath, [cliPath, command, "--root", root], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
    },
  });
}

test("secret scan accepts non-secret configuration templates", async () => {
  await withFixture(
    {
      "codex/config.toml": "# Machine authentication remains user-owned.\n",
      "docs/policy.md": "Use environment placeholders for private values.\n",
    },
    (root) => {
      const result = runCli("secret-scan", root);
      assert.equal(result.status, 0, result.stderr);
    },
  );
});

test("secret scan rejects authentication state files", async () => {
  await withFixture({ ["auth" + ".json"]: "{}\n" }, (root) => {
    const result = runCli("secret-scan", root);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /authentication state/i);
  });
});

test("secret scan rejects credential values", async () => {
  const key = "client" + "_secret";
  await withFixture({ "codex/private.toml": `${key} = "not-a-placeholder"\n` }, (root) => {
    const result = runCli("secret-scan", root);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /credential value/i);
  });
});

test("secret scan rejects personal absolute paths", async () => {
  const personalPath = ["C:", "Users", "maintainer", "agent.log"].join("\\");
  await withFixture({ "codex/config.toml": `notes = "${personalPath}"\n` }, (root) => {
    const result = runCli("secret-scan", root);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /personal absolute path/i);
  });
});

test("secret scan rejects drive-rooted personal paths outside a user profile", async () => {
  const personalPath = ["E:", "workspaces", "private", "notes.md"].join("\\");
  await withFixture({ "docs/local.md": `location = "${personalPath}"\n` }, (root) => {
    const result = runCli("secret-scan", root);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /personal absolute path/i);
  });
});

test("secret scan rejects OAuth session files", async () => {
  await withFixture({ ["oauth" + "-session.json"]: "{}\n" }, (root) => {
    const result = runCli("secret-scan", root);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /authentication state/i);
  });
});

test("secret scan accepts environment-variable credential templates", async () => {
  const key = "client" + "_secret";
  const placeholder = "$" + "{MCP_CLIENT_SECRET}";
  await withFixture(
    { "mcp/example/config.toml": `${key} = "${placeholder}"\nbearer_token_env_var = "MCP_TOKEN"\n` },
    (root) => {
      const result = runCli("secret-scan", root);
      assert.equal(result.status, 0, result.stderr);
    },
  );
});

test("source integrity rejects dist-only MCP output", async () => {
  await withFixture({ "mcp/example/dist/server.js": "export {};\n" }, (root) => {
    const result = runCli("source-integrity", root);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /generated MCP output is not declared/i);
  });
});

test("source integrity accepts generated MCP output with source and locked provenance", async () => {
  await withFixture(
    {
      "mcp/example/src/server.ts": "export const name = \"example\";\n",
      "mcp/example/dist/server.js": "export const name = \"example\";\n",
      "mcp/example/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
      "mcp/example/artifact-provenance.json": `${JSON.stringify(
        {
          schema_version: "1",
          artifacts: [
            {
              path: "dist/server.js",
              sources: ["src/server.ts"],
              locks: ["pnpm-lock.yaml"],
            },
          ],
        },
        null,
        2,
      )}\n`,
    },
    (root) => {
      const result = runCli("source-integrity", root);
      assert.equal(result.status, 0, result.stderr);
    },
  );
});

test("source integrity rejects generated output with missing provenance inputs", async () => {
  await withFixture(
    {
      "mcp/example/dist/server.js": "export {};\n",
      "mcp/example/artifact-provenance.json": `${JSON.stringify(
        {
          schema_version: "1",
          artifacts: [
            {
              path: "dist/server.js",
              sources: ["src/server.ts"],
              locks: ["pnpm-lock.yaml"],
            },
          ],
        },
        null,
        2,
      )}\n`,
    },
    (root) => {
      const result = runCli("source-integrity", root);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /missing source/i);
      assert.match(result.stderr, /missing lock/i);
    },
  );
});

test("source integrity rejects caches and logs", async () => {
  await withFixture(
    {
      ".cache/state.json": "{}\n",
      "logs/agent.log": "local run\n",
    },
    (root) => {
      const result = runCli("source-integrity", root);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /cache/i);
      assert.match(result.stderr, /log/i);
    },
  );
});

test("format check accepts UTF-8 text with LF and a final newline", async () => {
  await withFixture({ "docs/clean.md": "# Clean\n\nPortable text.\n" }, (root) => {
    const result = runCli("format", root);
    assert.equal(result.status, 0, result.stderr);
  });
});

test("format check rejects BOM, CRLF, trailing whitespace, and missing final newline", async () => {
  await withFixture(
    {
      "docs/bom.md": "\uFEFF# BOM\n",
      "docs/crlf.md": "# CRLF\r\n",
      "docs/trailing.md": "trailing \n",
      "docs/unterminated.md": "unterminated",
    },
    (root) => {
      const result = runCli("format", root);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /UTF-8 BOM/i);
      assert.match(result.stderr, /line ending/i);
      assert.match(result.stderr, /trailing whitespace/i);
      assert.match(result.stderr, /final newline/i);
    },
  );
});

test("source integrity accepts a complete agent asset inventory", async () => {
  await withFixture(
    {
      "AGENTS.md": "# Instructions\n",
      "CONTEXT-MAP.md": "# Context map\n",
      "CONTEXT.md": "# Context\n",
      "codex/config.toml": "# Safe project configuration.\n",
      "codex/hooks.json": "{\"hooks\": {}}\n",
      "mcp/registry.json": "{\"schema_version\": \"1\", \"servers\": []}\n",
      "plugins/registry.json": "{\"schema_version\": \"1\", \"plugins\": []}\n",
      "skills/issues/SKILL.md": "---\nname: issues\ndescription: Track local issues.\n---\n\n# Issues\n",
      "agent-assets.json": `${JSON.stringify(
        {
          schema_version: "1",
          instructions: ["AGENTS.md", "CONTEXT-MAP.md"],
          contexts: ["CONTEXT.md"],
          skills: [{ id: "issues", source: "skills/issues/SKILL.md" }],
          configuration_templates: ["codex/config.toml"],
          hooks: ["codex/hooks.json"],
          mcp_registry: "mcp/registry.json",
          plugin_registry: "plugins/registry.json",
        },
        null,
        2,
      )}\n`,
    },
    (root) => {
      const result = runCli("source-integrity", root);
      assert.equal(result.status, 0, result.stderr);
    },
  );
});

test("source integrity rejects missing inventoried assets", async () => {
  await withFixture(
    {
      "agent-assets.json": `${JSON.stringify(
        {
          schema_version: "1",
          instructions: ["AGENTS.md"],
          contexts: [],
          skills: [],
          configuration_templates: [],
          hooks: [],
          mcp_registry: "mcp/registry.json",
          plugin_registry: "plugins/registry.json",
        },
        null,
        2,
      )}\n`,
    },
    (root) => {
      const result = runCli("source-integrity", root);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /missing inventoried asset/i);
    },
  );
});
