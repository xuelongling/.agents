# Agent Infrastructure Context

The Agent Infrastructure Repository owns maintainable agent policy and extension assets independently from their workspace activation.

## Language

**Agent Infrastructure Repository**:
The independent source repository for workspace agent instructions, context indexes, skills, MCP source, non-secret configuration templates, hooks, plugin metadata, and their tests.
_Avoid_: Agent Activation Surface, personal Codex home, product repository

**Agent Activation Surface**:
The workspace-root entries through which a trusted Codex session discovers managed Agent Infrastructure content.
_Avoid_: Agent Infrastructure Repository, copied workspace policy

**Agent Asset Inventory**:
The machine-readable list of maintained skills, MCP servers, hooks, configuration templates, and plugins owned by Agent Infrastructure.
_Avoid_: Personal plugin selection, generated cache

**Generated Agent Artifact**:
A checked-in runtime output whose provenance names its maintainable source and authoritative dependency locks in the same repository.
_Avoid_: Dist-only MCP, cache, log
