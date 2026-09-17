---
name: graphit-hub
description: 'Hub: locate ecosystem projects locally, then in the published catalog; resolve Hub artifacts and Graphit configuration. Public technologies need no Hub lookup.'
---

# Graphit Hub

`project_dir` is a runtime MCP argument, not persisted project identity. In docs, Task, Memory and handoffs save project identity plus repository-relative paths; never copy a machine-specific checkout root. Resolve the local root again on each host.

Use this skill for named ecosystem projects/systems, Hub artifacts and Graphit configuration. Known public libraries, frameworks, languages and APIs do not require Hub discovery: use established knowledge and official documentation for current or version-specific details. Honor an explicit request for a Hub artifact. Reuse verified identities and versions.

## Resolve, select, read

Before first unfamiliar cluster-to-module discovery, Hub context installation, artifact choice or recovery, read [discovery through useful evidence](references/discovery-cases.md). It fills local/global branches and failure outcomes. If the local resource is unavailable, call `graphit_module_skill` with `module: hub`, `reference: references/discovery-cases.md` and known `project_dir` when available. Reuse the reference across related calls.

1. For a named ecosystem project, call `graphit_cluster_projects` with the current initialized `project_dir`. Every returned project is Graphit-managed, including neighboring checkouts outside your working directory. Use its selected absolute `dir` as `project_dir` for that target's enabled AST, Knowledge, Memory, Task and other module reads. Explore it through Graphit, not native grep/glob/file walks. Read only the needed target skill/overrides with `graphit_module_skill`; reuse per-target instructions/evidence. The coordinating Task stays in its owning project; reading a neighbor does not authorize changes there. A known path never becomes an artifact ID. Cluster membership may overlap Hub; no initialized current project means local discovery is unavailable, not permission to invent a path.
2. Without a local match in that scope, call `graphit_hub_projects` to discover published projects visible to the caller. A catalog entry may expose AST/documentation artifacts, not a complete local checkout. Resolve its artifact, type and version; never turn its project ID into an invented filesystem path. Missing scoped results or unavailable Hub do not prove the project is absent.
3. Discover any supported artifact with `graphit_hub_search` using focused terms/type, or `graphit_hub_show` for a known ID. Read supported types from tool schemas/metadata; do not assume shorthand names or project identities are installable types. `graphit_hub_list` browses registry inventory. Retain publisher `project_id`, type and version; titles are discovery, not contents.
4. Read installed rule, skill, command or agent text with `graphit_hub_content` and selected `path`, starting with its entrypoint (such as `SKILL.md`). Omitted `path` returns every file. `project_dir` selects that project's claimed version; without it, use explicit `id@version`.
Report relevant findings. An obvious fit for the requested work can be announced and installed directly; a real ambiguity or tradeoff warrants a few relevant options and a selection question. Install the minimal missing artifact: Knowledge for contracts, AST for implementation, or the requested supported type. Read the relevant skill before using module tools; `graphit_hub_content` does not serve AST/Knowledge. Global AST/Knowledge installs use verified `id@version` as `context` without `project_dir`. Installation of runnable artifacts does not authorize their execution.

Illustrative branches: 'work on system XPTO' → cluster then Hub if unmatched; 'use React' → no mandatory Hub lookup; 'find a React skill' → artifact search with `type: skill`, inspect candidates, install an obvious requested fit or ask which materially different option to use. Adapt names to the request; unfamiliar ecosystem names are not automatically public technologies.
Pass `ai_optimized: true` where available. After a miss, try relevant aliases/project metadata and a qualified type filter or bounded category inventory; use another configured ecosystem source only when actually exposed. Follow `next_cursor` while resolution needs more pages; cluster discovery has no cursor. Distinguish a bounded search miss, an exhausted valid inventory with no match, and service/authentication failure. Report coverage and useful next options; never infer nonexistence or stop at the first miss.

## State changes

`graphit_hub_update` without `id` updates all artifacts; name the target. `graphit_hub_link`/`graphit_hub_unlink` change project claims, `graphit_hub_submit` publishes, and `graphit_hub_uninstall` removes an install. These changes require their own purpose in the requested work; discovering or installing context does not authorize publishing.

Before creating a reusable rule, skill, command or agent, use `graphit_hub_type-path` for its destination. For configuration, read the specific key with `graphit_config_get` or discover keys with `graphit_config_list`; change with `graphit_config_set`/`graphit_config_unset` only within the requested work. `graphit_cluster_get`/`graphit_cluster_set`/`graphit_cluster_unset` inspect or change project grouping.

Record resolved project/artifact identity, version and plan-relevant decisions in Task. Knowledge keeps project contracts; Memory keeps reusable operating decisions. Reference sources instead of copying artifact bodies.
