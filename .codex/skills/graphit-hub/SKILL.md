---
name: graphit-hub
description: 'Hub-first: resolve external APIs, dependencies, reusable artifacts, ecosystem projects, and Graphit configuration before model knowledge or web search.'
---

# Graphit Hub

Use this skill before relying on model knowledge or web search for an external library, framework, API, agent, reusable artifact, Graphit configuration, or another ecosystem project.

## Lookup order

1. For ecosystem projects, call `graphit_hub_projects` or `graphit_cluster_projects`; use the returned project id/path with that project's AST or wiki tools.
2. For artifacts, call `graphit_hub_list` when installed inventory may answer, otherwise `graphit_hub_search`. Search is discovery only.
3. Inspect selected artifact metadata with `graphit_hub_show`. Install only when the task needs its contents. Read installed rule, skill, command, or agent files with `graphit_hub_content`; query installed AST or knowledge contexts with their module tools.
4. If no relevant Hub artifact exists, use primary vendor documentation or web research and state that this is the fallback.

Never infer another project's path, read its files directly, or treat a search title as content. Registry calls without a project operate on globally installed artifacts; project linking is explicit.

## Mutations

`graphit_hub_install`, `graphit_hub_update`, and `graphit_hub_uninstall` manage installed artifacts. `graphit_hub_link`/`graphit_hub_unlink` change project claims. `graphit_hub_submit` publishes reusable work. Do not perform these state changes merely to inspect an artifact.

Use `graphit_hub_type_path` before creating a reusable rule, skill, command, or agent. Inspect configuration with `graphit_config_list` or `graphit_config_get`; use `graphit_config_set` or `graphit_config_unset` only when requested. `graphit_cluster_get`, `graphit_cluster_set`, and `graphit_cluster_unset` manage project grouping.

Tool index: `graphit_hub_search`, `graphit_hub_show`, `graphit_hub_content`, `graphit_hub_list`, `graphit_hub_install`, `graphit_hub_uninstall`, `graphit_hub_update`, `graphit_hub_link`, `graphit_hub_unlink`, `graphit_hub_submit`, `graphit_hub_projects`, `graphit_hub_type_path`, `graphit_cluster_projects`, `graphit_cluster_get`, `graphit_cluster_set`, `graphit_cluster_unset`, `graphit_config_list`, `graphit_config_get`, `graphit_config_set`, `graphit_config_unset`.
