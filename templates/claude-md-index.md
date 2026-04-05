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

## Skill Factory (Generate New Skills On Demand)

| Generator | Use Case | Invocation |
|-----------|----------|-----------|
| security-review-skill-creator | Project-specific security audit rules | "Generate a security audit skill for this project" |
| skill-creator | Codify workflows into Skills | "Create a skill for XX" |
| claudeception | Extract experience into Skills | "/claudeception" |

## Harness Commands

| Command | Description |
|---------|-------------|
| harness help | Command index + scenario quick ref |
| harness audit | Project health check |
| harness quality gate | Pre-commit quality gate |
| harness guide | Skill recommendation |

## Agent Team

| Role | Definition |
|------|-----------|
| {{role}} | [.harness/agents/{{role}}.md](.harness/agents/{{role}}.md) |

## Token Budget

- /compact at Phase completion boundaries; re-read task_plan.md after compact
- Large files (>300 lines): use offset+limit for segmented reading
- Structured output (JSON/tables) preferred over long-form prose
- Read indexes (INDEX.md) first, then read leaf docs on demand

## Behavior Rules

### MUST (Mandatory)
- MUST brainstorm before coding (HARD-GATE)
- MUST write tests before implementation (TDD)
- MUST security review before committing
- MUST NOT eval()/exec() with user input — CWE-95
- MUST NOT shell=True with user arguments — CWE-78
- MUST NOT f-string/format SQL concatenation — CWE-89
- MUST NOT commit .env / *.key / *.pem — CWE-798
- MUST NOT leave dead code / debug output
- MUST NOT claim done without verification

### Efficiency Rules
- /compact at Phase boundaries, not mid-task
- Re-read task_plan.md after compact
- Large files (>300 lines): use offset+limit

<!-- Enterprise mode appends:
### HOOK Enforcement (system-level, cannot be bypassed when enabled)
- git commit auto-check: secrets / sensitive files / commit format
- Code write auto-scan: eval/exec/shell=True/SQL concat/XSS/hardcoded credentials
- Dangerous command interception: data exfiltration / destructive operations / credential theft
-->
```
