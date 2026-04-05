# Documentation System Templates

## Core Principle: Multi-Level Index Tree

AI's memory = a tree of indexes. Each level stores only pointers; only leaf nodes store content.
AI memory recovery path: read L0 → determine direction → read L1 → locate module → read L2 → find document → read L3 leaf.

```
L0: CLAUDE.md (≤100 lines) — top-level navigation, points to 5 categories
     │
L1: docs/xxx/INDEX.md (≤50 lines) — category index, points to module dirs
     │
L2: docs/xxx/module/INDEX.md (≤30 lines) — module index + timeline
     │
L3: docs/xxx/module/topic.md (≤150 lines) — leaf document, actual content
```

**Why multi-level?**
- Early project: few docs, L1 points directly to L3 leaves (two levels suffice)
- As project grows: L2 subdirectories naturally emerge under L1 (three/four levels)
- AI reads only 1 index level at a time → decides → reads the next level, minimizing token consumption

**Golden rules for index levels**:
1. Index files NEVER contain actual content — only pointers + one-line summaries
2. Each index file ≤ 50 lines (L1) or ≤ 30 lines (L2+)
3. Leaf documents ≤ 150 lines; split if exceeding and add entries in parent index
4. Timelines are recorded in L2 indexes (when was what added/changed)

---

## L0: CLAUDE.md Specification

The project's top-level navigation entry. Specification:
- Total lines ≤ 100
- Only contains: one-line description + category navigation (pointing to L1 INDEXes) + command quick-reference + skill quick-reference
- NEVER stores implementation details
- Uses relative path links

---

## L1: Category INDEX.md Specification

The INDEX.md in each `docs/xxx/` directory. Specification:
- ≤ 50 lines
- Lists all sub-modules/documents + one-line description + last updated date
- Small projects: point directly to leaf documents (L1 → L3)
- Large projects: point to module subdirectories (L1 → L2 → L3)

### L1 INDEX.md Template

```markdown
# [Category Name]

[One-line description]

## Module Navigation

| Module | Description | Updated |
|--------|-------------|---------|
| [auth/](./auth/INDEX.md) | Authentication & authorization | 2026-04 |
| [payment/](./payment/INDEX.md) | Payment core workflows | 2026-03 |
| [export/](./export/INDEX.md) | Data export features | 2026-04 |

<!-- For small projects, point directly to leaf docs -->
| [tech-stack.md](./tech-stack.md) | Tech stack overview | 2026-03 |
```

---

## L2: Module INDEX.md Specification

The INDEX.md in `docs/xxx/module/` directories. Specification:
- ≤ 30 lines
- Lists all leaf documents for this module
- **Includes a timeline**: records the module's evolution history so AI can judge which docs may be stale

### L2 INDEX.md Template

```markdown
# [Module Name]

[One-line description]

## Documents

| Document | Description |
|----------|-------------|
| [oauth2-flow.md](./oauth2-flow.md) | OAuth2 authorization flow |
| [rbac-model.md](./rbac-model.md) | RBAC permission model |
| [session-mgmt.md](./session-mgmt.md) | Session management strategy |

## Timeline

| Date | Event |
|------|-------|
| 2026-03-01 | Initial OAuth2 implementation |
| 2026-03-15 | Added RBAC permission model |
| 2026-04-02 | Refactored session mgmt to Redis-backed |
```

---

## L3: Leaf Document Specification

Where actual content lives. Specification:
- ≤ 150 lines; split if exceeding (add new entries in L2 index after splitting)
- Starts with frontmatter: title + last updated date + one-line summary
- This is the ONLY level that stores actual content

### Leaf Document Template

```markdown
# [Title]
> Last updated: {{DATE}} | Summary: {{one-line}}

## Content

(Actual content: architecture notes / implementation details / convention rules / pitfall records etc.)
```

---

## Auto-Scaling Rules

### When to upgrade from two levels to three

When an L1 INDEX.md has more than 10 entries, group them into subdirectories by function/module:

```
# Two levels (early project)
docs/implementation/INDEX.md → auth.md, payment.md, export.md

# Three levels (after project growth)
docs/implementation/INDEX.md → auth/INDEX.md, payment/INDEX.md, export/INDEX.md
  auth/INDEX.md → oauth2-flow.md, rbac-model.md, session-mgmt.md
```

### When to split a leaf document

When a leaf document exceeds 150 lines:
1. Split into multiple documents by sub-topic
2. Demote the original file to an L2 INDEX.md (keep the directory, move content out)
3. Update pointers in the parent index

---

## Category-Specific Structure

### architecture/

L1 INDEX → points directly to leaves (usually no L2 needed — architecture docs are stable in count)

| Leaf Document | Content |
|---------------|---------|
| system-overview.md | System positioning + core modules + relationships + data flow + design decisions |
| tech-stack.md | Language/framework/versions + key dependencies + infrastructure + deployment |
| db-schema.md | Core tables + relationships + indexes + query patterns |
| api-reference.md | API groups + core endpoints + auth + error codes |

### implementation/

L1 INDEX → L2 module subdirectories → L3 leaves (the category that grows most)

Each leaf document contains: module responsibilities + core classes/functions + key workflows + config items + caveats

### conventions/

L1 INDEX → points directly to leaves (convention docs are stable in count)

| Leaf Document | Content |
|---------------|---------|
| must-follow.md | Coding style + naming conventions + git commit + PR workflow + testing |
| must-not.md | Prohibited code patterns + prohibited dependency usage + prohibited operations |
| secure-coding.md | Injected from harness/references/secure-coding.md, tailored by tech stack |

### pitfalls/

L1 INDEX → grouped by tech stack/scenario → L3 leaves

Each entry contains: problem description → root cause → solution → prevention
Timeline recorded in L2 INDEX for tracking problem chronology.

### backlog/

L1 INDEX → points directly to leaves

| Leaf Document | Content |
|---------------|---------|
| optimization.md | Performance bottlenecks + architecture improvements + tech debt cleanup |
| features.md | Features to implement + priority + dependencies |
