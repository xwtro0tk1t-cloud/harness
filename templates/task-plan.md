# Task Plan Template

Used for task plans in `.harness/plans/`. Three types share the same structure, tailor as needed.

**Important**: Each `### Phase` must have a `**Status:** pending/in_progress/complete` line below it.
This is the format required by planning-with-files' Stop hook (check-complete.sh) to check completion status.

---

```markdown
# {{TASK_TYPE}}: {{TASK_TITLE}}

**Type**: feature | bugfix | refactor | migration
**Priority**: P0 | P1 | P2 | P3
**Created**: {{DATE}}
**Status**: planning | in-progress | review | done

## Background

{{Why this task is needed, context information}}

## Objective

{{Expected state after completion, verifiable outcomes}}

## Risks & Rollback

| Risk | Impact | Rollback Plan |
|------|--------|--------------|
| {{risk}} | {{impact}} | {{rollback}} |

## Phases

### Phase 1: {{Name}}
**Status:** pending
- [ ] Task 1.1: {{description}} — {{file(s)}}
- [ ] Task 1.2: {{description}} — {{file(s)}}

### Phase 2: {{Name}}
**Status:** pending
- [ ] Task 2.1: {{description}} — {{file(s)}}

## Test Plan

- [ ] Unit tests: {{which scenarios to cover}}
- [ ] Integration tests: {{end-to-end flow}}
- [ ] Security checklist reviewed

## Documentation Updates

- [ ] CLAUDE.md docs tree (if new docs created)
- [ ] docs/implementation/{{module}}.md
- [ ] docs/architecture/api-reference.md (if new API)
- [ ] docs/architecture/db-schema.md (if new tables)

## Notes

{{Other information to record}}
```

### Status Format Notes

planning-with-files' `check-complete.sh` determines completion status by:
- Counting total `### Phase` headings
- Counting `**Status:** complete` occurrences
- Both equal = all complete

**Status values must use these exact formats** (colon touching asterisks, followed by space):
- `**Status:** pending` — Not started
- `**Status:** in_progress` — In progress
- `**Status:** complete` — Completed
