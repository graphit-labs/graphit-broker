---
name: graphit-ast
description: 'AST-first: code discovery and structural analysis for symbols, relationships, impact, source selection, and code from installed contexts; read this skill before native search.'
---

# Graphit AST

Use this skill for code discovery, structure, relationships, impact analysis, or source held by a Graphit context. Graphit AST precedes native search; it does not prohibit focused reads after the graph has located current-project code.

## Workflow

1. Identify the target: current project (`project_dir`) or installed AST context (`context`). Resolve another repository through the Hub; never guess its path.
2. Before the first Cypher for that target, call `graphit_ast_schema`. Reuse that schema until the target changes.
3. If the question is exploratory, pair one exact `graphit_ast_query` with one `graphit_ast_search` on the same topic. If the question is already exact, query alone is enough.
4. Read only selected code with `graphit_ast_source` using an entity, line slice, or pattern. Imported source is readable only through this tool.
5. Before editing an entity, query its definition, callers/dependents, and test references. Expand only when the result shows wider impact.

## Query discipline

Use only labels, properties, and relationships returned by the schema. Common nodes include `File`, `Function`, `Method`, `Class`, and `Struct`; common edges include `CONTAINS`, `CALLS`, `IMPORTS`, `INHERITS`, and `REFERENCES`, but the live schema is authoritative. A planner rejection or missing property is a reason to reread the schema, not guess another field.

Search grounds the query; it is not evidence by itself. Query results establish structure. Source establishes behavior. Keep `project_dir` absolute and do not mix results from different targets.

## Fallbacks and freshness

Retry a database-open error once; it is commonly a transient lock. If the graph is absent, use `graphit_daemon_status` and then `graphit_ast_index`. Use `graphit_ast_embed` only when semantic embeddings are missing. Use native discovery when the required Graphit tool is unavailable to this agent or for unsupported/unindexed current-project text, and record the limitation. Native tools cannot read an imported context.

The daemon normally indexes edits. Call `graphit_sync` only when a decision requires proven freshness. The adapter stop hook dispatches completion sync asynchronously; do not duplicate it, wait for it, or sync after every edit.

## Administrative tools

`graphit_ast_list` lists contexts; `graphit_ast_install` and `graphit_ast_remove` manage them; `graphit_ast_export` exports a graph; `graphit_cluster_projects` resolves ecosystem projects. These mutate or move artifacts only when the user task requires it.

Tool index: `graphit_ast_search`, `graphit_ast_query`, `graphit_ast_schema`, `graphit_ast_source`, `graphit_ast_list`, `graphit_ast_index`, `graphit_ast_embed`, `graphit_ast_export`, `graphit_ast_install`, `graphit_ast_remove`, `graphit_cluster_projects`, `graphit_daemon_status`, `graphit_sync`.
