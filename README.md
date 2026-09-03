# tsfg Agent Infrastructure

This repository is the source of truth for tsfg Repo Workspace agent instructions and extensions. Workspace activation is intentionally separate and is assembled by the Integration Manifest.

## Verify a fresh clone

Install the locked development dependencies and run every repository-local gate:

```text
corepack pnpm@11.25.0 install --frozen-lockfile
corepack pnpm@11.25.0 verify
```

The repository requires Node.js 24.20.0 or newer within the Node 24 release line and pnpm 11.25.0.

The individual public checks are `format:check`, `typecheck`, `test`, `secret:scan`, and `source:check`. They read only this clone and do not read Codex login state or user configuration.

## Asset ownership

`agent-assets.json` inventories maintained workspace assets. The MCP and plugin registries are intentionally empty until a real workspace capability is approved. Machine authentication, personal plugin selection, OAuth sessions, and other user state remain outside this repository.

Generated MCP output may be checked in only when its MCP project contains `artifact-provenance.json`. Every output must name at least one maintainable file under that project's `src/` and at least one existing authoritative lock file. Repository validation rejects undeclared generated output, missing provenance inputs, caches, and logs.
