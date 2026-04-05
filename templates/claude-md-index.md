# CLAUDE.md Index Template

Use this template to generate the project's CLAUDE.md. Target ≤ 100 lines.

---

```markdown
# {{PROJECT_NAME}}

{{One-line project description}}

## Documentation Navigation

| Category | Path | Content |
|----------|------|---------|
| Architecture | [docs/architecture/](docs/architecture/INDEX.md) | System architecture, tech stack, DB, API |
| Implementation | [docs/implementation/](docs/implementation/INDEX.md) | Per-module implementation docs |
| Conventions | [docs/conventions/](docs/conventions/INDEX.md) | must-follow / must-not / secure-coding |
| Pitfalls | [docs/pitfalls/](docs/pitfalls/INDEX.md) | Categorized by tech stack |
| Backlog | [docs/backlog/](docs/backlog/INDEX.md) | Optimization directions / features to implement |

## Command Quick Reference

```bash
# Development
{{install_command}}
{{run_command}}

# Testing
{{test_command}}

# Build & Deploy
{{build_command}}
{{deploy_command}}
```

## Skill Quick Reference

| Skill | Purpose |
|-------|---------|
| {{skill_name}} | {{skill_description}} |

## Agent Team

| Role | Definition |
|------|-----------|
| {{role}} | [.harness/agents/{{role}}.md](.harness/agents/{{role}}.md) |
```
