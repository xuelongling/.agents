// SPDX-License-Identifier: MIT

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { lstat, mkdtemp, mkdir, readFile, readlink, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cliPath = path.join(repositoryRoot, "tools", "agent-infra.ts");
const materializerPath = path.join(repositoryRoot, "tools", "materialize-agent-workspace.ts");

async function withWorkflow(contents: string, run: (root: string) => void | Promise<void>): Promise<void> {
  const root = await mkdtemp(path.join(tmpdir(), "tsfg-agent-ci-"));
  try {
    const workflowDirectory = path.join(root, ".github", "workflows");
    await mkdir(workflowDirectory, { recursive: true });
    await writeFile(path.join(workflowDirectory, "agent-infrastructure-pr.yml"), contents, "utf8");
    await run(root);
  } finally {
    await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  }
}

function runCli(command: string, root: string, options: readonly string[] = []) {
  return spawnSync(process.execPath, [cliPath, command, "--root", root, ...options], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
    },
  });
}

function git(root: string, ...arguments_: readonly string[]): string {
  const result = spawnSync("git", arguments_, { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

async function initializeRepository(
  root: string,
  files: Readonly<Record<string, string>>,
  remoteUrl: string,
): Promise<string> {
  await mkdir(root, { recursive: true });
  git(root, "init", "--quiet");
  git(root, "config", "core.fsmonitor", "false");
  git(root, "config", "maintenance.auto", "false");
  git(root, "config", "gc.auto", "0");
  git(root, "config", "user.name", "tsfg fixture");
  git(root, "config", "user.email", "fixture@tsfg.invalid");
  git(root, "config", "remote.origin.url", remoteUrl);
  for (const [relativePath, contents] of Object.entries(files)) {
    const destination = path.join(root, ...relativePath.split("/"));
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, contents, "utf8");
  }
  git(root, "add", ".");
  git(root, "commit", "--quiet", "-m", "fixture");
  return git(root, "rev-parse", "HEAD");
}

async function materializationFixture(workspace: string): Promise<void> {
  await initializeRepository(
    path.join(workspace, ".agents"),
    {
      "AGENTS.md": "# candidate instructions\n",
      "codex/config.toml": "model = \"fixture\"\n",
      "codex/hooks.json": "{}\n",
    },
    "https://github.com/xuelongling/.agents.git",
  );
  await initializeRepository(
    path.join(workspace, "tsfg"),
    { "README.md": "# fixture product\n" },
    "https://github.com/xuelongling/tsfg.git",
  );
  await initializeRepository(
    path.join(workspace, ".repo", "manifests"),
    {
      "bootstrap/r00.xml": `<?xml version="1.0" encoding="UTF-8"?>
<manifest>
  <remote name="github-xuelongling" fetch="https://github.com/xuelongling/" />
  <project name="tsfg.git" path="tsfg" remote="github-xuelongling" revision="${"0".repeat(40)}" />
  <project name=".agents.git" path=".agents" remote="github-xuelongling" revision="${"0".repeat(40)}">
    <linkfile src="AGENTS.md" dest="AGENTS.md" />
    <linkfile src="codex/config.toml" dest=".codex/config.toml" />
    <linkfile src="codex/hooks.json" dest=".codex/hooks.json" />
  </project>
</manifest>
`,
    },
    "https://github.com/xuelongling/manifests.git",
  );
}

const workflow = (actionReference: string) => `# SPDX-License-Identifier: MIT
name: Agent Infrastructure PR
on:
  pull_request:
permissions:
  contents: read
jobs:
  agent-policy:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@${actionReference}
`;

test("workflow policy requires third-party actions to use a complete commit OID", async () => {
  for (const movingReference of ["v6", "latest"]) {
    await withWorkflow(workflow(movingReference), (root) => {
      const result = runCli("workflow-policy", root);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /unpinned-action/);
    });
  }

  await withWorkflow(workflow("d23441a48e516b6c34aea4fa41551a30e30af803"), (root) => {
    const result = runCli("workflow-policy", root);
    assert.equal(result.status, 0, result.stderr);
  });

  await withWorkflow(
    workflow("d23441a48e516b6c34aea4fa41551a30e30af803").replace(
      "    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
      "    uses: example/ci/.github/workflows/check.yml@v1",
    ),
    (root) => {
      const result = runCli("workflow-policy", root);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /unpinned-action/);
    },
  );
});

test("workflow policy keeps candidate execution on an unprivileged secret-free PR boundary", async () => {
  const pinned = "d23441a48e516b6c34aea4fa41551a30e30af803";
  const invalidWorkflows = [
    {
      category: "privileged-event",
      contents: workflow(pinned).replace("  pull_request:", "  pull_request_target:"),
    },
    {
      category: "permissions",
      contents: workflow(pinned).replace("contents: read", "contents: write"),
    },
    {
      category: "secret-context",
      contents: `${workflow(pinned)}        with:\n          token: \${{ secrets.CI_TOKEN }}\n`,
    },
    {
      category: "moving-runner",
      contents: workflow(pinned).replace("ubuntu-24.04", "ubuntu-latest"),
    },
  ];

  for (const fixture of invalidWorkflows) {
    await withWorkflow(fixture.contents, (root) => {
      const result = runCli("workflow-policy", root);
      assert.equal(result.status, 1, result.stderr);
      assert.match(result.stderr, new RegExp(fixture.category));
    });
  }
});

test("license policy requires canonical MIT provenance and SPDX on commentable source", async () => {
  const canonicalLicense = await readFile(path.join(repositoryRoot, "LICENSE"), "utf8");
  const fixtures = [
    {
      expected: /license-spdx/,
      files: { "LICENSE": canonicalLicense, "docs/policy.md": "# Policy\n" },
    },
    {
      expected: /license-root/,
      files: {
        "LICENSE": "MIT License\n\nCopyright (c) 2026 somebody else\n",
        "docs/policy.md": "<!-- SPDX-License-Identifier: MIT -->\n\n# Policy\n",
      },
    },
  ];
  for (const fixture of fixtures) {
    const root = await mkdtemp(path.join(tmpdir(), "tsfg-agent-license-"));
    try {
      for (const [relativePath, contents] of Object.entries(fixture.files)) {
        const destination = path.join(root, ...relativePath.split("/"));
        await mkdir(path.dirname(destination), { recursive: true });
        await writeFile(destination, contents, "utf8");
      }
      const result = runCli("license-policy", root);
      assert.equal(result.status, 1);
      assert.match(result.stderr, fixture.expected);
    } finally {
      await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  }

  await withWorkflow(workflow("d23441a48e516b6c34aea4fa41551a30e30af803"), async (root) => {
    await writeFile(path.join(root, "LICENSE"), canonicalLicense, "utf8");
    const result = runCli("license-policy", root);
    assert.equal(result.status, 0, result.stderr);
  });
});

test("product matrix is requested only for changed files explicitly in the Build Input Set", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "tsfg-agent-matrix-"));
  try {
    git(root, "init", "--quiet");
    git(root, "config", "core.fsmonitor", "false");
    git(root, "config", "maintenance.auto", "false");
    git(root, "config", "gc.auto", "0");
    git(root, "config", "user.name", "tsfg fixture");
    git(root, "config", "user.email", "fixture@tsfg.invalid");
    for (const relativePath of [
      "docs/agents/policy.md",
      "skills/example/SKILL.md",
      "mcp/example/README.md",
      "mcp/example/src/server.ts",
    ]) {
      const destination = path.join(root, ...relativePath.split("/"));
      await mkdir(path.dirname(destination), { recursive: true });
      await writeFile(destination, "baseline\n", "utf8");
    }
    git(root, "add", ".");
    git(root, "commit", "--quiet", "-m", "baseline");
    const base = git(root, "rev-parse", "HEAD");
    for (const relativePath of [
      "docs/agents/policy.md",
      "skills/example/SKILL.md",
      "mcp/example/README.md",
      "mcp/example/src/server.ts",
    ]) {
      await writeFile(path.join(root, ...relativePath.split("/")), "candidate\n", "utf8");
    }
    git(root, "add", ".");
    git(root, "commit", "--quiet", "-m", "candidate");
    const head = git(root, "rev-parse", "HEAD");
    const buildInputsPath = path.join(root, "build-inputs.json");
    const arguments_ = ["--base", base, "--head", head, "--build-inputs", buildInputsPath];

    await writeFile(
      buildInputsPath,
      '{"entries":[{"path":"eng/tsfg-build.mjs","projectId":"tsfg"}],"schemaVersion":"1"}\n',
      "utf8",
    );
    const excluded = runCli("product-matrix-request", root, arguments_);
    assert.equal(excluded.status, 0, excluded.stderr);
    assert.deepEqual(JSON.parse(excluded.stdout), {
      productMatrix: { matchedInputs: [], required: false },
      schemaVersion: "1",
    });

    await writeFile(
      buildInputsPath,
      '{"entries":[{"path":"mcp/example/src/server.ts","projectId":".agents.git"}],"schemaVersion":"1"}\n',
      "utf8",
    );
    const included = runCli("product-matrix-request", root, arguments_);
    assert.equal(included.status, 0, included.stderr);
    assert.deepEqual(JSON.parse(included.stdout), {
      productMatrix: { matchedInputs: ["mcp/example/src/server.ts"], required: true },
      schemaVersion: "1",
    });
  } finally {
    await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  }
});

test("CI materialization creates exact links or fails closed when link capability is missing", async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), "tsfg-agent-workspace-"));
  try {
    await materializationFixture(workspace);

    const result = spawnSync(process.execPath, [materializerPath, "--workspace", workspace], {
      cwd: repositoryRoot,
      encoding: "utf8",
      env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot },
    });
    if (result.status !== 0) {
      assert.match(result.stderr, /activation-link-capability/);
      assert.equal(await lstat(path.join(workspace, "AGENTS.md")).catch(() => undefined), undefined);
      assert.equal(await lstat(path.join(workspace, ".codex", "config.toml")).catch(() => undefined), undefined);
      assert.equal(await lstat(path.join(workspace, ".codex", "hooks.json")).catch(() => undefined), undefined);
      return;
    }
    const identity = JSON.parse(result.stdout);
    assert.match(identity.manifestRevision, /^[0-9a-f]{40}$/);
    assert.equal(identity.selectedManifest, "bootstrap/r00.xml");

    for (const [destination, source] of [
      ["AGENTS.md", ".agents/AGENTS.md"],
      [".codex/config.toml", ".agents/codex/config.toml"],
      [".codex/hooks.json", ".agents/codex/hooks.json"],
    ]) {
      const destinationPath = path.join(workspace, ...destination.split("/"));
      assert.equal((await lstat(destinationPath)).isSymbolicLink(), true);
      assert.notEqual(await readlink(destinationPath), "");
      assert.equal(await realpath(destinationPath), await realpath(path.join(workspace, ...source.split("/"))));
    }
  } finally {
    await rm(workspace, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  }
});

test("CI materialization rejects Agent Activation Surface content outside the candidate Git identity", async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), "tsfg-agent-identity-"));
  try {
    await materializationFixture(workspace);
    await writeFile(path.join(workspace, ".agents", "AGENTS.md"), "# drifted instructions\n", "utf8");

    const result = spawnSync(process.execPath, [materializerPath, "--workspace", workspace], {
      cwd: repositoryRoot,
      encoding: "utf8",
      env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot },
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /activation-content/);
    assert.equal(await lstat(path.join(workspace, "AGENTS.md")).catch(() => undefined), undefined);
  } finally {
    await rm(workspace, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  }
});

test("CI materialization rejects an activation parent redirected outside the workspace", async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), "tsfg-agent-parent-"));
  const outside = await mkdtemp(path.join(tmpdir(), "tsfg-agent-outside-"));
  try {
    await materializationFixture(workspace);
    await symlink(outside, path.join(workspace, ".codex"), "junction");
    const result = spawnSync(process.execPath, [materializerPath, "--workspace", workspace], {
      cwd: repositoryRoot,
      encoding: "utf8",
      env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot },
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /activation-link-parent/);
    assert.equal(await lstat(path.join(outside, "config.toml")).catch(() => undefined), undefined);
  } finally {
    await rm(workspace, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
    await rm(outside, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  }
});

test("repository PR workflow exposes distinct policy, activation, secret, test, and matrix checks", async () => {
  const contents = await readFile(
    path.join(repositoryRoot, ".github", "workflows", "agent-infrastructure-pr.yml"),
    "utf8",
  );
  for (const job of [
    "agent-policy",
    "agent-test",
    "agent-secret",
    "agent-activation-linux",
    "agent-activation-windows",
    "product-matrix-dispatch",
  ]) {
    assert.match(contents, new RegExp(`^  ${job}:$`, "m"));
  }
  const result = runCli("workflow-policy", repositoryRoot);
  assert.equal(result.status, 0, result.stderr);
});
