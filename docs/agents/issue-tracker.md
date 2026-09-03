# Issue tracker: local Markdown

Issues and specs for every repository in this workspace live under the workspace root at `.scratch/`. The workspace root is not a Git repository, so this state remains local without changing any child repository's `.gitignore`.

## Conventions

- One effort per directory: `.scratch/<effort-slug>/`
- The spec is `.scratch/<effort-slug>/spec.md`
- Implementation tickets are one file each at `.scratch/<effort-slug>/issues/<NN>-<slug>.md`, numbered from `01` in dependency order
- Put `Repository: <relative-repository-path>` near the top of every spec and ticket
- Record triage state with a `Status:` line near the top of each ticket
- Append conversation history under `## Comments`

## Publishing and fetching

When a skill says to publish to the issue tracker, create the appropriate file under `.scratch/<effort-slug>/`. When it says to fetch a ticket, read the referenced local file.

## Wayfinding

- **Map:** `.scratch/<effort-slug>/map.md`
- **Child ticket:** `.scratch/<effort-slug>/issues/<NN>-<slug>.md`
- **Type:** record `research`, `prototype`, `grilling`, or `task` on a `Type:` line
- **Blocking:** record dependencies as `Blocked by: NN, NN`; a ticket is unblocked when every listed ticket is `resolved`
- **Frontier:** choose the first numbered ticket that is open, unblocked, and unclaimed
- **Claim:** set `Status: claimed` before starting work
- **Resolve:** append the result under `## Answer`, set `Status: resolved`, then add a gist and link to the map's decisions-so-far

For implementation work, use a separate worktree inside the ticket's named repository when parallel changes could overlap.
