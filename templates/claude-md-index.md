# CLAUDE.md Index Template

Use this template to generate the project's CLAUDE.md. Target ≤ 150 lines.

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

## Context Recovery (after /compact or new session)

Re-read in this order — do NOT re-read everything, read indexes then on-demand:
1. This file (CLAUDE.md) — already auto-loaded
2. task_plan.md lines 1-30 — current Phase + progress (auto via PreToolUse hook)
3. docs/architecture/INDEX.md — architecture map, read only if task touches architecture
4. The specific docs/ file for the module you are working on

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
- Before claiming "done" → run Standard quality gate (doc sync + code hygiene + progress)

### Documentation Sync (self-check after editing source code)
- After editing source code, check: does a corresponding doc in docs/ exist for this module?
  - If yes and the change affects its content (API, schema, config) → update it NOW
  - If unsure → note in progress.md for quality gate to verify later

### Before /compact (mandatory checkpoint)
- Update progress.md with current status and any uncommitted decisions
- Update task_plan.md Phase checkboxes to reflect actual progress
- Note any in-progress work that needs to be resumed after compact

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
