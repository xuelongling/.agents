# Workspace instructions

This repository provides the agent instructions and support assets for a Repo Workspace containing multiple independent Git repositories. Treat each child repository as a separate change boundary: discover its repository root before editing, run commands from that repository, and never combine unrelated repositories in one commit or worktree.

Use `.scratch/` for workspace-local specs, tickets, maps, experiments, and disposable artifacts. Keep repository source trees free of workspace-level scratch state.

Prefer parallel agents and separate Git worktrees when independent work can proceed concurrently. Give each agent one bounded ownership area, and integrate only after its repository-local checks pass.

Repository-specific `AGENTS.md` files may add narrower instructions. The nearest applicable instructions take precedence for repository-specific work.

## Agent skills

### Issue tracker

Issues, specs, and wayfinding state use local Markdown under the workspace-level `.scratch/`. See `.agents/docs/agents/issue-tracker.md`.

### Triage labels

Local tickets use the default Matt Pocock triage vocabulary. See `.agents/docs/agents/triage-labels.md`.

### Domain docs

This is a multi-context workspace: `.agents/CONTEXT-MAP.md` points to each repository's domain glossary, while workspace-wide ADRs live under `.agents/docs/adr/`. See `.agents/docs/agents/domain.md`.
