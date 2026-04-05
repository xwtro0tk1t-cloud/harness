# Sub-Index Templates

Used to generate L1 category indexes and L2 module indexes.

---

## L1 Category Index Template (docs/xxx/INDEX.md)

Target ≤ 50 lines. Small projects point directly to leaf docs; large projects point to module subdirectories.

```markdown
# {{CATEGORY_NAME}}

{{One-line description}}

## Module Navigation

| Module | Description | Updated |
|--------|-------------|---------|
| [{{module}}/](./{{module}}/INDEX.md) | {{one-line description}} | {{YYYY-MM}} |

<!-- For small projects, point directly to leaf docs -->
| [{{doc}}.md](./{{doc}}.md) | {{one-line description}} | {{YYYY-MM}} |
```

---

## L2 Module Index Template (docs/xxx/module/INDEX.md)

Target ≤ 30 lines. Contains leaf document list + timeline.

```markdown
# {{MODULE_NAME}}

{{One-line description}}

## Documents

| Document | Description |
|----------|-------------|
| [{{topic}}.md](./{{topic}}.md) | {{one-line description}} |

## Timeline

| Date | Event |
|------|-------|
| {{YYYY-MM-DD}} | {{what happened}} |
```

---

## Scaling Rules

- L1 INDEX entries > 10 → group into subdirectories, upgrade to three levels
- Leaf document > 150 lines → split into multiple docs, demote original to L2 INDEX
- When adding docs: MUST update parent index entries and update date
- When removing docs: MUST clean up parent index pointers
