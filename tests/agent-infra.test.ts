// SPDX-License-Identifier: MIT

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cliPath = path.join(repositoryRoot, "tools", "agent-infra.ts");

async function withFixture(
  files: Readonly<Record<string, string | Uint8Array>>,
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

function sha256(content: string): string {
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

function inventoryFixture(): Record<string, string> {
  return {
    ".gitignore": "node_modules/\n.pytest_cache/\n",
    "AGENTS.md": "# Instructions\n",
    "CONTEXT-MAP.md": "# Context map\n",
    "CONTEXT.md": "# Context\n",
    "README.md": "# Agent Infrastructure\n",
    "codex/config.toml": "# Safe project configuration.\n",
    "codex/hooks.json": "{\"hooks\": {}}\n",
    "docs/adr/0005-agent-infrastructure.md": "# Decision\n",
    "docs/agents/policy.md": "# Policy\n",
    "mcp/registry.json": "{\"schema_version\": \"1\", \"servers\": []}\n",
    "plugins/registry.json": "{\"schema_version\": \"1\", \"plugins\": []}\n",
    "tests/policy.test.ts": "export {};\n",
    "tools/policy.ts": "export {};\n",
    "package.json": "{\"name\": \"fixture\"}\n",
    "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "tsconfig.json": "{}\n",
    "agent-assets.json": `${JSON.stringify(
      {
        schema_version: "1",
        instructions: ["AGENTS.md", "CONTEXT-MAP.md"],
        contexts: ["CONTEXT.md"],
        skills: [],
        configuration_templates: ["codex/config.toml"],
        hooks: ["codex/hooks.json"],
        support_documents: [
          "README.md",
          "docs/adr/0005-agent-infrastructure.md",
          "docs/agents/policy.md",
        ],
        tests: ["tests/policy.test.ts"],
        tooling: ["tools/policy.ts", "package.json", "pnpm-lock.yaml", "tsconfig.json"],
        mcp_registry: "mcp/registry.json",
        plugin_registry: "plugins/registry.json",
      },
      null,
      2,
    )}\n`,
  };
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
  await withFixture({ ...inventoryFixture(), "mcp/example/dist/server.js": "export {};\n" }, (root) => {
    const result = runCli("source-integrity", root);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /generated MCP output is not declared/i);
  });
});

test("source integrity accepts generated MCP output with source and locked provenance", async () => {
  const source = "export const name = \"example\";\n";
  const output = "export const name = \"example\";\n";
  const lock = "lockfileVersion: '9.0'\n";
  await withFixture(
    {
      ...inventoryFixture(),
      "mcp/example/src/server.ts": source,
      "mcp/example/dist/server.js": output,
      "mcp/example/pnpm-lock.yaml": lock,
      "mcp/example/artifact-provenance.json": `${JSON.stringify(
        {
          schema_version: "1",
          artifacts: [
            {
              path: "dist/server.js",
              digest: sha256(output),
              sources: [{ path: "src/server.ts", digest: sha256(source) }],
              locks: [{ path: "pnpm-lock.yaml", digest: sha256(lock) }],
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
  const output = "export {};\n";
  await withFixture(
    {
      ...inventoryFixture(),
      "mcp/example/dist/server.js": output,
      "mcp/example/artifact-provenance.json": `${JSON.stringify(
        {
          schema_version: "1",
          artifacts: [
            {
              path: "dist/server.js",
              digest: sha256(output),
              sources: [{ path: "src/server.ts", digest: sha256("missing source") }],
              locks: [{ path: "pnpm-lock.yaml", digest: sha256("missing lock") }],
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
      ...inventoryFixture(),
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
          support_documents: [],
          tests: [],
          tooling: [],
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
          support_documents: [],
          tests: [],
          tooling: [],
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

test("source integrity requires the agent asset inventory", async () => {
  await withFixture({ "README.md": "# Missing inventory\n" }, (root) => {
    const result = runCli("source-integrity", root);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /missing agent asset inventory/i);
  });
});

test("source integrity rejects maintained assets omitted from the inventory", async () => {
  await withFixture({ ...inventoryFixture(), "docs/agents/unlisted.md": "# Unlisted policy\n" }, (root) => {
    const result = runCli("source-integrity", root);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /asset is not inventoried/i);
    assert.match(result.stderr, /docs\/agents\/unlisted\.md/i);
  });
});

test("source integrity rejects tracked dependency caches and agent state databases", async () => {
  await withFixture(
    {
      ...inventoryFixture(),
      "node_modules/example/cache.js": "export {};\n",
      ".pytest_cache/state": "cached\n",
      "sessions/auth.sqlite": "SQLite fixture\n",
      "history/events.jsonl": "{}\n",
    },
    (root) => {
      assert.equal(spawnSync("git", ["init", "--quiet"], { cwd: root }).status, 0);
      assert.equal(
        spawnSync(
          "git",
          ["add", "--force", "node_modules/example/cache.js", ".pytest_cache/state", "sessions/auth.sqlite", "history/events.jsonl"],
          { cwd: root },
        ).status,
        0,
      );
      const result = runCli("source-integrity", root);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /dependency cache/i);
      assert.match(result.stderr, /test cache/i);
      assert.match(result.stderr, /state database/i);
      assert.match(result.stderr, /history or session log/i);
    },
  );
});

test("source integrity rejects a tracked symlink before reading its target", async () => {
  await withFixture(inventoryFixture(), (root) => {
    assert.equal(spawnSync("git", ["init", "--quiet"], { cwd: root }).status, 0);
    const blob = spawnSync("git", ["hash-object", "-w", "--stdin"], {
      cwd: root,
      encoding: "utf8",
      input: "../outside-private-file",
    });
    assert.equal(blob.status, 0, blob.stderr);
    assert.equal(
      spawnSync("git", ["update-index", "--add", "--cacheinfo", `120000,${blob.stdout.trim()},linked-config`], {
        cwd: root,
      }).status,
      0,
    );
    const result = runCli("source-integrity", root);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /symlink/i);
  });
});

test("source integrity rejects non-authoritative locks and source traversal", async () => {
  const output = "export {};\n";
  const source = "source\n";
  const lock = "not a lock\n";
  await withFixture(
    {
      ...inventoryFixture(),
      "mcp/example/dist/server.js": output,
      "mcp/example/source.txt": source,
      "mcp/example/notes.txt": lock,
      "mcp/example/artifact-provenance.json": `${JSON.stringify(
        {
          schema_version: "1",
          artifacts: [
            {
              path: "dist/server.js",
              digest: sha256(output),
              sources: [{ path: "src/../source.txt", digest: sha256(source) }],
              locks: [{ path: "notes.txt", digest: sha256(lock) }],
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
      assert.match(result.stderr, /maintainable source path/i);
      assert.match(result.stderr, /authoritative lock/i);
    },
  );
});

test("source integrity rejects digest drift in generated artifacts", async () => {
  const output = "export {};\n";
  const source = "source\n";
  const lock = "lockfileVersion: '9.0'\n";
  await withFixture(
    {
      ...inventoryFixture(),
      "plugins/example/dist/plugin.js": output,
      "plugins/example/src/plugin.ts": source,
      "plugins/example/pnpm-lock.yaml": lock,
      "plugins/example/artifact-provenance.json": `${JSON.stringify(
        {
          schema_version: "1",
          artifacts: [
            {
              path: "dist/plugin.js",
              digest: sha256("different output"),
              sources: [{ path: "src/plugin.ts", digest: sha256(source) }],
              locks: [{ path: "pnpm-lock.yaml", digest: sha256(lock) }],
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
      assert.match(result.stderr, /digest mismatch/i);
    },
  );
});

test("format check accepts CRLF only for Windows command scripts", async () => {
  await withFixture({ "scripts/verify.cmd": "@echo off\r\n", "scripts/verify.bat": "@echo off\r\n" }, (root) => {
    const result = runCli("format", root);
    assert.equal(result.status, 0, result.stderr);
  });
});

test("format check rejects UTF-16 text instead of treating it as binary", async () => {
  await withFixture({ "docs/utf16.md": Buffer.from("# UTF-16\n", "utf16le") }, (root) => {
    const result = runCli("format", root);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /UTF-8/i);
  });
});

test("secret scan rejects quoted credential keys and auth state databases", async () => {
  const key = "client" + "_secret";
  await withFixture(
    {
      "codex/private.json": `{\"${key}\": \"concrete-private-value\"}\n`,
      ["oauth" + ".sqlite"]: "SQLite fixture\n",
    },
    (root) => {
      const result = runCli("secret-scan", root);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /credential value/i);
      assert.match(result.stderr, /authentication state/i);
    },
  );
});
