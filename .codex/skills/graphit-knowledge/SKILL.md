---
name: graphit-knowledge
description: 'Knowledge-first: project documentation, wiki retrieval, architecture, decisions, specifications, and provenance; use wiki tools before reading documentation files.'
---

# Graphit Knowledge

Use this skill for project documentation, architecture, decisions, specifications, provenance, or another project's wiki. Task lifecycle and backlog belong to Graphit Task; code structure belongs to Graphit AST; external systems must be resolved through Graphit Hub first.

## Reading knowledge

1. Search with `graphit_knowledge_search` for the current project or `graphit_wiki_search` across selected wikis. Search returns titles, not evidence.
2. Pick the smallest relevant set and read it with `graphit_wiki_source`; use a pattern or line slice for long pages. Use `preview: true` only when titles cannot disambiguate.
3. Use `graphit_wiki_xrefs` for provenance/relationships, `graphit_wiki_log` for change history, and `graphit_wiki_browse` or `graphit_knowledge_list` for catalogues.

A different project's documentation is queried with its returned `project_dir`; never walk or grep its docs tree. A missing result is not proof that a page is absent—use the catalogue or refine once before concluding.

## Maintenance

The daemon indexes `docs/` after writes. Use `graphit_knowledge_index` for explicit indexing options or a specific directory, `graphit_knowledge_sync` only for knowledge-only freshness, and `graphit_sync` when all module indexes must align. Check `graphit_daemon_status` on stale or locked reads. `graphit_knowledge_lint` and `graphit_knowledge_schema` are diagnostic. `graphit_knowledge_remove` without a context clears the project wiki, so use it only when the task explicitly requires removal. `graphit_wiki_embed` repairs semantic coverage.

Tool index: `graphit_knowledge_search`, `graphit_knowledge_index`, `graphit_knowledge_list`, `graphit_knowledge_lint`, `graphit_knowledge_schema`, `graphit_knowledge_remove`, `graphit_knowledge_sync`, `graphit_wiki_search`, `graphit_wiki_browse`, `graphit_wiki_xrefs`, `graphit_wiki_log`, `graphit_wiki_source`, `graphit_wiki_embed`, `graphit_cluster_projects`, `graphit_daemon_status`, `graphit_sync`.
