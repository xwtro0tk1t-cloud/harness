# Harness: Project Development Scaffold Meta-Skill

---
description: Use when the user wants to initialize a project development environment, establish a documentation system, set up an Agent Team, or says "harness", "project initialization", or "setup dev environment". Also automatically suggested at the first development session of a new project.
---

## Overview

Harness is a project development scaffold meta-skill. When invoked, it automatically: analyzes the project → installs/configures the shared Skill ecosystem → generates a documentation system → establishes an Agent Team → injects secure development standards.

**Core principles**:
1. **Assume beginner user** — Provide complete guidance, never skip steps
2. **Skills must be triggerable** — Not just installed, but hooks configured to ensure effectiveness
3. **Dual-layer enhancement + Skill auto-matching** — Hook (system-level) + CLAUDE.md (rule-level), Skill description assists automatic triggering
4. **Project-specific Skills stored separately** — Experience accumulated during development is saved to the project-level `.claude/skills/`
5. **Built-in security standards** — High-risk CWE defense + Agent behavior red lines

---

## Workflow (7 Steps)

### Step 1: Project Analysis

Scan the project root directory, determine the project type, and branch accordingly:

1. **Determine project type**: Existing project (has source files) vs new project (empty directory / only README)
2. **Language and framework detection**: Check package.json / go.mod / Cargo.toml / pyproject.toml / pom.xml etc. Identify primary language and framework. Record tech stack (used in Step 5 for tailoring coding conventions). New project: ask user for target tech stack
3. **Project structure analysis**: List top-level directories, identify core directories (src/ / cmd/ / internal/ etc.), check Dockerfile / CI configuration
4. **AI tool detection**: Detect current runtime → determine instruction file name (Claude Code→CLAUDE.md / Cursor→.cursorrules / Windsurf→.windsurfrules / Cline→.clinerules / Copilot→.github/copilot-instructions.md / Aider→CONVENTIONS.md / Continue→.continuerules / Devin→devin.md / Generic→AGENT.md). In subsequent steps, "CLAUDE.md" is replaced with the detected instruction file
5. **Existing documentation check**: Instruction file / docs/ / .harness/ / .claude/settings.json
6. **Output project profile** (confirm with the user): Language / Framework / Build tool / Test framework / Deployment method / Core modules

**Special handling for new projects**: Generate skeleton docs + `<!-- TODO: fill in -->` placeholders. Prompt the user: "After the project code is ready, re-run harness to supplement the documentation content"

---

### Step 2: Skill Ecosystem Installation & Hook Configuration (Core Step)

This is the most important step in Harness. It is not just about installing skills — hooks must also be configured to ensure they actually take effect.

**2.1 Check Installed Skills**: Scan `~/.claude/skills/`, compare against `references/skill-ecosystem.md` to display installation status ([✅/❌] for each core Skill)

**2.2 Install Bundled Skills**: Batch install `bundled-skills/` to `~/.claude/skills/` via symlink. Skills requiring additional configuration (web-vuln-analyzer needs Docker + API / android-vuln-analyzer needs toolchain / skills-audit optional API key) are guided interactively. Full list in `references/skill-ecosystem.md`

**2.2b Install External Core Skills**: Installation commands for superpowers / planning-with-files / claudeception are in `references/skill-ecosystem.md`. Plugin installs auto-register hooks; fallback git clone requires manual configuration

**2.3 Configure Hooks**:
- Core Skill hook mechanisms: superpowers SessionStart / planning-with-files 4 hooks / claudeception UserPromptSubmit — see `references/skill-ecosystem.md` for details
- **Enterprise Security Gate Hooks** (optional): pre-commit secret check / commit format validation / dangerous command interception / code write security scan — ask user whether to enable. See `references/hook-scripts.md` for details

**2.4 Skill Factory Usage Guide**: Show user usage scenarios for /claudeception, skill-creator, security-review-skill-creator, superpowers:writing-skills (3-line overview)

**2.5 Project-Specific Skill Check**: Check `.claude/skills/` and `~/.claude/skills/security-review-skill-for-*`, prompt to generate if no match found

---

### Step 3: Documentation System Generation (Deep Code Analysis)

**You must actually read the code — do not rely solely on CLAUDE.md/README.** Refer to `references/doc-templates.md`.

**3.0 Information Gathering** (MUST be completed before writing any documentation): Dispatch 3 Agents in parallel to gather core business analysis, frontend + infrastructure analysis, and history + documentation + test analysis. Collection points: application entry points, data models, configuration, auth, core business logic, API endpoints, frontend routing, deployment config, build scripts, git history, test coverage

**All docs/ content must come from the above gathering results — never fabricate content.** Mark uncertain content with `<!-- TODO: verify from code -->`

**3.1 AI Instruction File (Slim Index, ≤100 lines)**: Generate the corresponding instruction file based on the AI tool detected in Step 1. Use the `templates/claude-md-index.md` template. Content includes: one-line project description / docs/ navigation / common command quick reference / installed Skills quick reference / **behavior rules**

**Behavior rules** (extracted from `references/conventions.md` Part B and written into CLAUDE.md) cover: development workflow / security review / Review & verification / documentation & knowledge capture / Quality Gate / code hygiene / context recovery / Token efficiency / security red lines. See `references/conventions.md` for detailed rules

**If CLAUDE.md already exists**: Extract valuable content and migrate it to `docs/`, restructure as index format

**3.2 docs/ Multi-Level Directory**: architecture/ / implementation/ / conventions/ / pitfalls/ / backlog/, each subdirectory containing an INDEX.md. **Each sub-document ≤ 150 lines**. See `references/doc-templates.md` for detailed structure

---

### Step 4: Agent Team Design (Interactive)

Refer to `references/agent-teams.md`.

**4.0 Detect Existing Agent Teams** (CRITICAL): Check .harness/agents/ and running teammates. If already present, default is to KEEP — do NOT destroy running teammates. Only proceed to 4.1 if user explicitly chooses to reconfigure

**4.1 Confirm Role Assignments with the User**: You must ask the user for their desired role codenames, responsibilities, and invocation methods. Press Enter to use default 3 roles (Architect / Engineer / Tester)

**4.2 Generate Role Definitions**: Write to `.harness/agents/`, each role file containing Role / Responsibilities / Workflow / Constraints

**4.3 Runtime Mode Selection + 4.4 Write Trigger Methods**: Subagent Mode (general-purpose) / Agent Teams Mode (Claude Code experimental) / Configure Both. See `references/agent-teams.md` for detailed configuration and trigger methods

**Role-to-Skill binding**: Architect→brainstorming+writing-plans / Engineer→TDD+executing-plans / Tester→verification / All→claudeception+planning-with-files

---

### Step 5: Development Standards & Security Standards Injection

Write the following standards into `docs/conventions/`:

- **must-follow.md** — Inject from `references/conventions.md` Part A+B (coding standards + 8 Agent behavior rules)
- **must-not.md** — Prohibited practices checklist (no dead code / debug output / unused imports / no skipping tests / no skipping review)
- **coding-patterns.md** — Tailored from `references/lang-patterns.md` based on tech stack detected in Step 1
- **secure-coding.md** — Inject from `references/secure-coding.md` (15-item CWE defense + OWASP Top 10 + Agent red lines, **hard control**)

Append Token optimization rules to must-follow.md (from `references/conventions.md` Part D)

---

### Step 6: Planning Infrastructure

Create `.harness/` directory structure: agents/ / hooks/ (optional) / plans/ / templates/ (feature.md / bugfix.md / refactor.md). If planning-with-files is installed, configure `.harness/plans/` as the default plan directory. Templates derived from `templates/task-plan.md`

---

### Step 7: Output Confirmation & Usage Guide

Display initialization summary + command quick reference:

```
harness              — Project initialization (re-run to supplement missing parts)
harness help         — Command index + scenario quick reference
harness audit        — Project health check (scoring + remediation)
harness quality gate — Pre-commit quality gate
harness guide        — Skill recommendation (match by scenario)
harness cleanup      — Interactive temp file archive (never deletes)
harness resume       — Lightweight context recovery (after /compact)
harness handoff      — Deep context handoff (new agent takeover)
```

Beginner usage entry points: new feature → /plan + brainstorming + TDD + verification / Bug → systematic-debugging + claudeception / Security audit → security-review-skill-creator

---

### Step 8: Scenario Integration Verification

After initialization is complete, verify that 11 scenarios correctly trigger. Detailed scenario descriptions and safeguard mechanisms are in `references/scenario-verification.md`.

Verification checklist: feature development / bug debugging / plan execution / architecture adjustment / task completion / refactoring / PR review / dependency update / DB migration / hotfix / code hygiene

If a scenario does not trigger correctly, check: hooks configuration / CLAUDE.md behavior rules / Skill installation status

---

## Enhancement Mechanism Design

Harness uses dual-layer stacking + Skill auto-matching to ensure shared Skills are used correctly:

- **Layer 1: Hook (system-level, Claude Code only)** — SessionStart injects methodology / UserPromptSubmit shows plan / PreToolUse re-reads plan / PostToolUse reminds to update / Stop checks completion. Strongest guarantee, AI cannot bypass
- **Layer 2: CLAUDE.md Rules (directive-level, universal across all tools)** — MUST/MUST NOT text rules. Even if hooks are not configured, CLAUDE.md rules still take effect
- **Skill Auto-matching** — Precise descriptions let the AI automatically match and trigger the corresponding Skill

---

## Notes

- **Idempotent**: Repeated execution does not overwrite existing content — only supplements missing parts
- **Progressive**: Users can execute only a subset of steps
- **Non-destructive**: Existing content is never deleted, only reorganized
- **Interaction first**: Critical decision points must be confirmed interactively with the user
- **Hook safety**: The planning-with-files PreToolUse hook repeatedly reads task_plan.md — do not write untrusted external content into it

---

## Reference Files

| File | Purpose |
|------|---------|
| `references/skill-ecosystem.md` | Complete Skill ecosystem map (installation methods + purposes) |
| `references/doc-templates.md` | Documentation system templates (CLAUDE.md index / docs/ structure) |
| `references/agent-teams.md` | Agent Team framework (role definitions + runtime modes + extension guide) |
| `references/secure-coding.md` | Security standards (CWE + OWASP + Agent behavior red lines) |
| `references/conventions.md` | General development conventions (Git / Review / Test) |
| `references/lang-patterns.md` | Tech stack coding patterns quick reference (6 languages/frameworks) |
| `references/hook-scripts.md` | Enterprise Hook gate script templates (4 scripts + activation guide) |
| `references/scenario-verification.md` | 11 scenario integration verification detailed reference |
| `references/skill-guide.md` | Scenario → Skill recommendation matrix (data source for harness guide command) |
| `templates/claude-md-index.md` | CLAUDE.md slim index template |
| `templates/task-plan.md` | Task plan template |
| `templates/agent-role.md` | Agent role definition template |
