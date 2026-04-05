# Shared Skill Ecosystem Map

This document lists all reusable shared Skills, including purpose, installation method, and **enforcement mechanism**.
During Harness initialization, Skills are recommended based on project tech stack.

---

## Installation

```bash
# All skills install to ~/.claude/skills/ (user-level, shared across all projects)
cd ~/.claude/skills/
git clone <repo-url> <skill-name>

# After installation, Claude Code auto-loads on next session
# But some skills require additional hook configuration to enforce activation (see below)
```

---

## Infrastructure (Required for All Projects)

### superpowers — Behavior Control Methodology

**Source**: github.com/obra/superpowers (MIT, most popular Claude Code skill framework in the community)
**Installation**:
```bash
cd ~/.claude/skills/ && git clone https://github.com/obra/superpowers.git superpowers
```
**Included sub-Skills** (14):
- `brainstorming` — Must design before implementing (HARD-GATE)
- `writing-plans` — Break design into 2-5 minute subtasks
- `executing-plans` — Batch execute per plan
- `subagent-driven-development` — Parallel sub-Agent development
- `test-driven-development` — TDD (Iron Law: write failing test first)
- `systematic-debugging` — Structured debugging (Iron Law: find root cause first)
- `verification-before-completion` — Must verify before claiming done
- `using-git-worktrees` — Isolated workspaces
- `requesting-code-review` / `receiving-code-review` — Review workflow
- `writing-skills` — TDD approach to writing Skills
- `dispatching-parallel-agents` — Parallel task coordination
- `finishing-a-development-branch` — Branch finalization

**Enforcement mechanism**: SessionStart hook injects `using-superpowers` methodology into context on every new session
**Hook configuration**: superpowers ships with `hooks/hooks.json`, needs to be referenced in settings

---

### planning-with-files — Plan Persistence

**Source**: github.com/OthmanAdi/planning-with-files (Manus-style persistent planning)
**Installation**:
```bash
cd ~/.claude/skills/ && git clone https://github.com/OthmanAdi/planning-with-files.git planning-with-files
```
**Core features**:
- Creates 3 persistent files: `task_plan.md` (plan) / `findings.md` (findings) / `progress.md` (progress)
- Auto-recovers context after session loss via `session-catchup.py`
- `/plan` command starts planning flow
- `/plan:status` views current status

**Enforcement mechanism**: 4 Hooks continuously inject
| Hook Event | Purpose |
|-----------|---------|
| `UserPromptSubmit` | Display current plan status on every input |
| `PreToolUse` | Re-read task_plan.md before every tool call |
| `PostToolUse` (Write/Edit) | Remind to update progress.md after writes |
| `Stop` | Check all Phases are complete on exit |

**Security note**: PreToolUse hook repeatedly reads task_plan.md → don't write untrusted external content into it (use findings.md instead)

---

### claudeception — Knowledge Extraction & Auto Skill Generation

**Source**: github.com/blader/Claudeception (1400+ stars, meta-skill)
**Installation**:
```bash
cd ~/.claude/skills/ && git clone https://github.com/blader/Claudeception.git claudeception
# Install hook (recommended):
mkdir -p ~/.claude/hooks
cp ~/.claude/skills/claudeception/scripts/claudeception-activator.sh ~/.claude/hooks/
chmod +x ~/.claude/hooks/claudeception-activator.sh
```
**Core features**:
- Auto-extracts reusable knowledge from work sessions
- `/claudeception` command proactively triggers knowledge extraction
- Generates new SKILL.md to `.claude/skills/` or `~/.claude/skills/`
- Quality gates: must satisfy reusable, non-trivial, specific, verified, actionable (5 criteria)

**Trigger conditions**:
- Debugging issues >10 minutes that aren't documented
- Workarounds discovered through trial and error
- Project-specific non-obvious patterns
- Saying "save this experience as a skill" / "what did we learn?"

**Enforcement mechanism**: UserPromptSubmit hook injects "evaluate if there's extractable knowledge" reminder on every input

---

## Skill Factories

### skill-creator — General Skill Generator

**Location**: `~/.claude/skills/skill-creator/` (locally installed)
**Purpose**:
- Create new Skills from scratch ("create a skill for XX")
- Optimize existing Skill trigger accuracy
- Run evals to test Skill quality
- Baseline testing + variance analysis

### security-review-skill-creator — Security Audit Skill Generator

**Location**: `~/.claude/skills/security-review-skill-creator/` (locally installed)
**Purpose**:
- **Project mode**: Analyze project docs → generate project-specific audit rules
- **Generic mode**: Specify language+framework → generate generic audit Skill from reference library
**Generated audit Skills**:
- `security-review-skill-for-dex` — DEX (Go/Rust/Java)
- `security-review-skill-for-docker` — Docker/K8s
- `security-review-skill-for-onduty` — Python/TypeScript Web
- `security-review-skill-for-payroll` — Payroll system (PII)
- `security-review-skill-for-phemex-card` — Payment system (PCI DSS)
- `security-review-skill-for-terraform` — IaC/AWS

### superpowers:writing-skills — TDD Approach to Writing Skills

**Location**: superpowers built-in sub-Skill
**Purpose**: Create Skills using TDD (RED: baseline behavior without Skill → GREEN: behavior conforms with Skill → REFACTOR: close gaps)

---

## Development Aids

### frontend-design — Frontend Development

**Location**: `~/.claude/skills/frontend-design/` (locally installed)
**Triggers**: "build web component" / "create landing page" / "design dashboard"

### canvas-design — Visual Design

**Location**: `~/.claude/skills/canvas-design/` (locally installed)
**Triggers**: Generate PNG/PDF visual works

---

## Security

| Skill | Purpose | Installed |
|-------|---------|-----------|
| web-vuln-analyzer | Web vulnerability analysis (SQL/XSS/SSRF) | Yes |
| android-vuln-analyzer | Android security analysis | Yes |
| sca-ai-denoise | SCA vulnerability AI denoising (P0-P3) | Yes |
| supply-chain-audit | Multi-language supply chain poisoning detection | Yes |
| skills-audit | Third-party Skill security audit | Yes |

---

## Other

| Skill | Purpose | Installed |
|-------|---------|-----------|
| lark-skills | Lark/Feishu document read/write | Yes |
| security-scan-ops | Security scanning platform operations | Yes |

---

## Recommendations by Project Type

| Project Type | Required | Recommended |
|-------------|----------|-------------|
| All projects | superpowers + planning-with-files + claudeception | skill-creator |
| Web fullstack | + security-review-skill-creator | frontend-design, web-vuln-analyzer |
| Backend API | + security-review-skill-creator | sca-ai-denoise |
| Mobile | | android-vuln-analyzer |
| Infrastructure | | security-review-skill-for-docker/terraform |
| Security team | supply-chain-audit, skills-audit | sca-ai-denoise |

---

## Project-Specific Skills

Experience accumulated during development, codified as project-level Skills:

```
<project>/.claude/skills/<experience-name>/SKILL.md
```

**Generation methods** (choose one):
1. `/claudeception` → Auto-extract from debugging experience
2. `skill-creator` → Manually create ("create a skill for...")
3. Manually write SKILL.md (simplest approach)
