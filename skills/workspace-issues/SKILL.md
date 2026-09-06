---
name: workspace-issues
description: Track specs and tickets in the workspace-local Markdown issue tracker. Use when claiming, resolving, fetching, or mapping workspace issues; use the configured workflow for external issue trackers instead.
---

<!-- SPDX-License-Identifier: MIT -->

# Workspace Issues

Read [`../../docs/agents/issue-tracker.md`](../../docs/agents/issue-tracker.md) fully before changing tracker state.

Keep issue state under the workspace `.scratch/` tree. Treat each ticket's `Repository` field as its change boundary, and follow the nearest repository instructions before implementation.

When resolving a ticket, record the implementation result and verification evidence under `## Answer`, update the status, and update the effort map when it exists. Completion means every required state transition and wayfinding update is present.
