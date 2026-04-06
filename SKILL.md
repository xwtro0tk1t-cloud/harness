# Harness: Project Development Scaffold Meta-Skill

---
description: Use when the user wants to initialize a project development environment, establish a documentation system, set up an Agent Team, or says "harness", "project initialization", or "setup dev environment". Also automatically suggested at the first development session of a new project.
---

## Overview

Harness is a project development scaffold meta-skill. When invoked, it automatically: analyzes the project → installs/configures the shared Skill ecosystem → generates a documentation system → establishes an Agent Team → injects secure development standards.

**Core principles**:
1. **Assume beginner user** — Provide complete guidance, never skip steps
2. **Skills must be triggerable** — Not just installed, but hooks configured to ensure enforcement
3. **Three-layer enforcement** — Hook (system-level) + CLAUDE.md (rule-level) + Skill description (semantic-level)
4. **Project-specific Skills stored separately** — Experience accumulated during development is saved to the project-level `.claude/skills/`
5. **Built-in security standards** — High-risk CWE defense + Agent behavior red lines

---

## Workflow (7 Steps)

### Step 1: Project Analysis

Scan the project root directory, determine the project type, and branch accordingly:

```
1. Determine project type
   ├─ Existing project: has .py/.go/.java/.ts source files → follow "existing project" flow
   └─ New project: empty directory or only README / .gitignore → follow "new project" flow

2. Language and framework detection
   - Check package.json / go.mod / Cargo.toml / pyproject.toml / pom.xml / build.gradle etc.
   - Identify primary language (Python/Go/Java/Rust/TypeScript/JavaScript etc.)
   - Identify framework (FastAPI/Django/Gin/Spring/React/Vue/Next.js etc.)
   - Record primary tech stack (used in Step 5 for tailoring lang-patterns coding conventions)
   - New project: ask the user for the target tech stack

3. Project structure analysis
   - List top-level directory structure
   - Identify core directories like src/ / cmd/ / internal/ / lib/ / app/ / services/
   - Check for Dockerfile / docker-compose.yml / Makefile / CI configuration

4. AI tool detection
   - Detect current runtime environment (Claude Code / Cursor / Windsurf / Cline / Copilot / Aider / other)
   - Determine instruction file name:
     ┌─ Claude Code  → CLAUDE.md
     ├─ Cursor       → .cursorrules or .cursor/rules/*.md
     ├─ Windsurf     → .windsurfrules
     ├─ Cline        → .clinerules
     ├─ Copilot      → .github/copilot-instructions.md
     ├─ Aider        → CONVENTIONS.md
     ├─ Continue      → .continuerules
     ├─ Devin        → devin.md
     └─ Unknown/Generic → AGENT.md (universal AI Agent instruction file)
   - In subsequent steps, "CLAUDE.md" is replaced with the detected instruction file

5. Existing documentation check
   - Instruction file (CLAUDE.md/.cursorrules/...) → if present, evaluate whether to slim to index
   - docs/ → if present, keep and supplement gaps
   - .harness/ → if present, skip already-initialized parts
   - .claude/settings.json → check configured hooks (Claude Code only)

6. Output project profile (confirm with the user)
   - Language / Framework / Build tool / Test framework / Deployment method / Core modules
```

**Special handling for new projects**:
- Step 3 documentation: generate directory structure + skeleton docs with `<!-- TODO: fill in -->` placeholders
- Step 5 standards: inject in full (security standards do not depend on project content)
- Step 6 templates: generate in full (plan templates do not depend on project content)
- CLAUDE.md: generate a skeleton index with tech stack/commands to be filled in
- Prompt the user: "After the project code is ready, re-run harness to supplement the documentation content"

---

### Step 2: Skill Ecosystem Installation & Hook Configuration (Core Step)

This is the most important step in Harness. It is not just about installing skills — hooks must also be configured to ensure they actually take effect.

**2.1 Check Installed Skills**

Scan the `~/.claude/skills/` directory and display a complete inventory:

```
🔧 Infrastructure Skills (required for all projects):
  [✅/❌] superpowers      — Behavior control (thinking/planning/TDD/debugging methodology)
  [✅/❌] planning-with-files — Plan persistence (task_plan.md / findings.md / progress.md)
  [✅/❌] claudeception    — Knowledge extraction (auto-generate Skills from lessons learned)

🏭 Skill Factories (for generating new Skills):
  [✅/❌] skill-creator           — General-purpose Skill generator (codify workflows into Skills)
  [✅/❌] security-review-skill-creator — Security audit Skill generator (generate audit rules for a project)

🎨 Development Aids (recommended by tech stack):
  [✅/❌] frontend-design   — High-quality frontend UI generation (React/Vue/CSS)
  [✅/❌] canvas-design     — Visual design (PNG/PDF posters/charts)

🔒 Security (recommended for security-sensitive projects):
  [✅/❌] web-vuln-analyzer        — Web vulnerability analysis
  [✅/❌] android-vuln-analyzer    — Android vulnerability analysis
  [✅/❌] sca-ai-denoise           — SCA vulnerability denoising (P0-P3 severity grading)
  [✅/❌] supply-chain-audit       — Supply chain poisoning detection
  [✅/❌] skills-audit             — Third-party Skill security audit

📝 Other installed project Skills:
  [list remaining installed skills]
```

**2.2 Install Bundled Skills**

Harness includes the following Skills, installed to `~/.claude/skills/` via symlink:

```
🔧 Infrastructure Skills:
  [status] skill-creator                  — General-purpose Skill generator
  [status] security-review-skill-creator  — Security audit Skill generator

🔒 Security Skills:
  [status] security-review-skill-for-docker    — Docker/container security audit
  [status] security-review-skill-for-terraform — Terraform/IaC security audit
  [status] sca-ai-denoise                      — SCA vulnerability denoising (P0-P3 grading)
  [status] supply-chain-audit                  — Supply chain poisoning detection (8 languages)
  [status] skills-audit                        — Third-party Skill security audit
  [status] web-vuln-analyzer                   — Web vulnerability analysis [requires Docker]
  [status] android-vuln-analyzer               — Android vulnerability analysis [requires toolchain]

🛠 Harness Commands:
  [status] harness-help          — Command index + scenario quick ref
  [status] harness-audit         — Project health check
  [status] harness-quality-gate  — Pre-commit quality gate
  [status] harness-guide         — Skill recommendation guide
```

Installation: create symlinks for each bundled skill
```bash
# Batch install all bundled skills
for skill in ~/.claude/skills/harness-en/bundled-skills/*/; do
  name=$(basename "$skill")
  ln -sf "$skill" ~/.claude/skills/"$name"
done
```

**Skills requiring configuration** (interactive during install):

```
The following Skills require additional configuration:

1. web-vuln-analyzer — Requires Docker environment + API configuration
   Configure? [y/n] → y: guide .env setup → n: mark as "⚠️ Not available"

2. android-vuln-analyzer — Requires Android security toolchain (apktool/jadx/frida)
   Configure? [y/n] → y: show install commands → n: mark as "⚠️ Not available"

3. skills-audit — Optional ANTHROPIC_API_KEY for AI analysis mode
   Configure? [y/n] → y: guide configuration → n: basic features still available
```

Skills with skipped configuration are marked in the CLAUDE.md Skill quick reference as "⚠️ Not available — requires XX, say 'configure <skill-name>' to enable".

**2.2b Install External Core Skills**

The following core Skills are not bundled. Install using the method matching your AI tool:

**superpowers** — Behavior control (SessionStart hook injects methodology)

| AI Tool | Install Command |
|---------|----------------|
| Claude Code | `/plugin install superpowers@claude-plugins-official` |
| Cursor | `/add-plugin superpowers` |
| Gemini CLI | `gemini extensions install https://github.com/obra/superpowers` |
| Fallback (any) | `git clone https://github.com/obra/superpowers.git ~/.claude/skills/superpowers` |

**planning-with-files** — Plan persistence (4 hooks continuously inject plan into context)

| AI Tool | Install Command |
|---------|----------------|
| Claude Code | `/plugin marketplace add OthmanAdi/planning-with-files` then `/plugin install planning-with-files@planning-with-files` |
| Fallback (any) | `git clone https://github.com/OthmanAdi/planning-with-files.git && cp -r planning-with-files/skills/* ~/.claude/skills/` |

**claudeception** — Knowledge extraction (UserPromptSubmit hook reminds to evaluate extractable knowledge)

| AI Tool | Install Command |
|---------|----------------|
| All | `cd ~/.claude/skills/ && git clone https://github.com/blader/Claudeception.git claudeception` |

> **Note**: Plugin-installed skills (superpowers, planning-with-files) auto-register hooks. Fallback git clone installs require manual hook configuration in settings.json. claudeception always needs manual hook setup.

**2.3 Configure Hooks (Ensure Skills Actually Take Effect)**

**This is the key step.** Plugin-installed skills auto-register their hooks. For fallback installs, claudeception, and enterprise hooks, manual configuration is needed.

Hook mechanisms for the three core skills:

| Skill | Hook Event | Purpose | Registration |
|-------|-----------|---------|-------------|
| superpowers | `SessionStart` | Inject using-superpowers methodology at every new session/clear/compact | Auto (Plugin) |
| planning-with-files | `UserPromptSubmit` | Display current plan status on every user input | Auto (SKILL.md) |
| planning-with-files | `PreToolUse` | Re-read the first 30 lines of task_plan.md before every tool call | Auto (SKILL.md) |
| planning-with-files | `PostToolUse` | Remind to update progress.md after every write | Auto (SKILL.md) |
| planning-with-files | `Stop` | Check task completion status on exit | Auto (SKILL.md) |
| claudeception | `UserPromptSubmit` | Inject "evaluate whether there is extractable knowledge" on every input | Manual (settings.json) |

**Optional: Enterprise Security Gate Hooks** `[Optional/Enterprise]`

In addition to the core Skill hooks above, Harness provides 4 security gate hook scripts as optional enterprise templates.
Not enabled by default — in open-source mode, security relies on CLAUDE.md MUST/MUST NOT text rules.

Ask the user: "Enable enterprise security gates? (pre-commit secret check / commit format validation / dangerous command interception / code write security scan)"

| Hook | Function | Blocking | Status |
|------|----------|----------|--------|
| Hook A: pre-commit-gate | Check for sensitive files and hardcoded secrets before git commit | exit 1 blocks | Optional |
| Hook B: commit-msg-check | Validate Conventional Commit format | exit 1 blocks | Optional |
| Hook C: dangerous-cmd-guard | Block data exfiltration / destructive operations / credential theft | exit 1 blocks | Optional |
| Hook D: write-security-scan | Detect security anti-patterns after code writes | WARNING non-blocking | Optional |

- User says "yes" → Copy scripts from `references/hook-scripts.md` to `.harness/hooks/`, register in settings.json
- User says "no" → Skip, security standards still covered by CLAUDE.md text rules
- Full script source and configuration in `references/hook-scripts.md`

**Configuration method**: Add hook configuration in the project's `.claude/settings.json`.

Show the user the hook configuration to be added, and ask whether to write it automatically.

**2.4 Skill Factory Usage Guide**

Show the user usage scenarios for "generator"-type Skills:

```
💡 You can use the following Skills at any time to generate new Skills:

  /claudeception
    → After a pitfall, say "summarize this experience as a skill" to auto-generate a project-specific Skill
    → Saved to .claude/skills/ or ~/.claude/skills/

  skill-creator
    → "Help me create a skill for XX workflow"
    → Can codify any recurring workflow

  security-review-skill-creator
    → "Generate a security audit skill for this project"
    → Generates customized audit rules based on the project's tech stack
    → Examples of generated project skills: dex / docker / onduty / payroll / phemex-card / terraform

  superpowers:writing-skills
    → Built-in skill authoring methodology within superpowers (write Skills using TDD)
```

**2.5 Project-Specific Skill Check**

Check the project's `.claude/skills/` and list existing project-specific Skills.

Also scan `~/.claude/skills/security-review-skill-for-*` to check for a security audit Skill matching the current project:
- If none found → prompt: "Generate a security audit skill for this project? User says yes → invoke security-review-skill-creator"
- If found → display the existing Skill name

---

### Step 3: Documentation System Generation (Deep Code Analysis)

**This is the most time-consuming step. You must actually read the code — do not rely solely on CLAUDE.md/README.**

Refer to the templates in `references/doc-templates.md`.

**3.0 Information Gathering (MUST be completed before writing any documentation)**

Dispatch Agents in parallel to gather the following information as data sources for documentation:

```
Agent 1: Core Business Analysis
  - Application entry points — route registration, middleware, startup flow
    Python: main.py/app.py  Go: main.go/cmd/  Java: Application.java  Node: index.ts/app.ts
  - Data models — all tables/collections/structs, fields, relationships
    Python: models.py  Go: internal/model/  Java: entity/  Node: prisma/schema
  - Configuration — environment variables, config items, secret management
  - Authentication & authorization — JWT/OAuth/API Key/SSO/RBAC
  - Core business logic — service layer, data flow, key algorithms
  - API endpoints — endpoint list, request/response formats
    REST: route files  gRPC: .proto files  GraphQL: schema files

Agent 2: Frontend + Infrastructure Analysis
  - Frontend: package.json / go.mod / Cargo.toml — dependencies and scripts
  - Frontend: route configuration, page components, state management
  - Deployment: Dockerfile / docker-compose / K8s manifests / Helm charts
  - Proxy: nginx.conf / Caddy / Traefik configuration
  - Build: Makefile / scripts / CI configuration (.github/workflows, Jenkinsfile, .gitlab-ci.yml)

Agent 3: History + Documentation + Test Analysis
  - git log --oneline -50 — recent development activity and module evolution
  - README.md / existing docs/ — existing documentation content (avoid duplication)
  - tests/ — test file distribution, coverage scope, test framework
  - migrations/ / changelog — database/API version evolution
  - Config files — .env.example / deployment config templates
```

**All docs/ content must come from the above gathering results — never fabricate content.**
Mark uncertain content with `<!-- TODO: verify from code -->`.

**3.1 AI Instruction File (Slim Index, ≤100 lines)**

Based on the AI tool detected in Step 1, generate the corresponding instruction file:

| AI Tool | Instruction File | Notes |
|---------|-----------------|-------|
| Claude Code | `CLAUDE.md` | Markdown, supports docs/ links |
| Cursor | `.cursorrules` or `.cursor/rules/` | Plain text or split by rules |
| Windsurf | `.windsurfrules` | Plain text |
| Cline | `.clinerules` | Plain text |
| GitHub Copilot | `.github/copilot-instructions.md` | Markdown |
| Aider | `CONVENTIONS.md` | Markdown |
| Continue | `.continuerules` | Plain text |
| Devin | `devin.md` | Markdown |
| Generic/Unknown | `AGENT.md` | Markdown, universal AI Agent instruction file |

**Format adaptation rules**:
- Markdown tools (Claude Code / Copilot / Aider): use tables, links, code blocks
- Plain text tools (Cursor / Windsurf / Cline): remove Markdown link syntax, use indentation instead of tables
- Content is identical, only formatting differs

Generate using the `templates/claude-md-index.md` template. Content should include only:
- One-line project description
- `docs/` navigation directory (with hyperlinks)
- Common command quick reference (build / test / lint / run)
- Installed Skills quick reference (with usage scenarios)
- **Behavior rules** (extract key rules from the hook configuration in Step 2)

**Behavior rules** (written into CLAUDE.md to serve as a fallback even if hooks are not active):

Extract from `references/conventions.md` Part B and write into the "Behavior Rules" section of CLAUDE.md:

```markdown
## Behavior Rules (MUST FOLLOW)

### Development Workflow
- For new features/architecture changes/complex refactors, MUST brainstorm first (propose solutions → user approval → write design doc) before starting
  - HARD-GATE: Implementation code is forbidden until the design is approved (superpowers:brainstorming)
- For non-trivial tasks (>15min), MUST /plan to create a plan before writing code
- For new features/bug fixes, MUST write a failing test before writing the implementation (TDD)
- When debugging a bug, MUST use the systematic-debugging methodology — find the root cause first

### Security Review
- Before committing code changes, MUST execute the security review checklist (see docs/conventions/secure-coding.md)
- When modifying auth/authorization/encryption/API code, MUST use the security-review skill for auditing

### Review & Verification
- Before merging code changes, MUST go through Code Review (superpowers:requesting-code-review)
- MUST NOT claim "done" unless there is fresh verification evidence (tests pass + lint passes + security review passes)

### Documentation & Knowledge Capture
- When changing code, MUST synchronize updates to corresponding documentation (API → api-reference.md, Schema → db-schema.md...)
- **Documentation Sync self-check** (after editing source code):
  - Check: does a corresponding doc in docs/ exist for this module?
  - If yes and the change affects its content (API, schema, config) → update it NOW
  - If unsure → note in progress.md for quality gate to verify later
- For issues that took over 10 minutes to debug, MUST record to docs/pitfalls/ or generate a Skill via /claudeception
- After completing a task, MUST evaluate whether there is extractable knowledge (/claudeception)

### Quality Gate
- Before YOU (the AI) claim "done" / "complete" to the user → run Standard quality gate (doc sync + code hygiene + progress)
- When user explicitly requests "quality gate" / "ready to commit" / "pre-commit check" → run Full quality gate

### Code Hygiene
- MUST NOT leave commented-out code blocks (delete them — git has the history)
- MUST NOT leave debug print / console.log / temporary test scripts
- MUST NOT leave unused imports / variables / functions / dependencies
- MUST clean up junk files in the root directory (test scripts go in tests/, docs go in docs/)

### Context Recovery (after /compact or new session)
Re-read in this order — do NOT re-read everything, read indexes then on-demand:
1. This file (CLAUDE.md) — already auto-loaded
2. task_plan.md lines 1-30 — current Phase + progress
3. docs/architecture/INDEX.md — only if task touches architecture
4. The specific docs/ file for the module you are working on

### Token Efficiency
- /compact at Phase completion boundaries, not mid-task
- **Before /compact** (mandatory checkpoint):
  - Update progress.md with current status and any uncommitted decisions
  - Update task_plan.md Phase checkboxes to reflect actual progress
  - Note any in-progress work that needs to be resumed after compact
- After compact, MUST re-read task_plan.md
- Large files (>300 lines): use offset+limit for segmented reading
- Structured output (JSON/tables) preferred over long-form prose

### Security Red Lines
- MUST NOT eval()/exec() with user input — CWE-95
- MUST NOT shell=True with user arguments — CWE-78
- MUST NOT f-string/format SQL concatenation — CWE-89
- MUST NOT commit .env / *.key / *.pem — CWE-798
```

**If CLAUDE.md already exists**: extract valuable content and migrate it to `docs/`, restructure as index format, and confirm with the user.

**3.2 docs/ Multi-Level Directory**

```
docs/
├── architecture/
│   └── INDEX.md
│   ├── system-overview.md    → System architecture, module relationships, data flow
│   ├── tech-stack.md         → Tech stack, versions, rationale for choices
│   ├── db-schema.md          → Database schema (if applicable)
│   └── api-reference.md      → API reference (if applicable)
├── implementation/
│   └── INDEX.md
│   └── [module-name].md      → One document per core module
├── conventions/
│   └── INDEX.md
│   ├── must-follow.md        → Mandatory conventions
│   ├── must-not.md           → Prohibited practices
│   └── secure-coding.md      → Secure coding standards (with CWE + Agent red lines)
├── pitfalls/
│   └── INDEX.md
│   └── [topic].md            → Pitfall records categorized by tech stack
└── backlog/
    └── INDEX.md
    ├── optimization.md       → Performance/architecture optimization directions
    └── features.md           → Features to be implemented
```

**Documentation content source**: Extracted from project code/comments/README. Mark anything uncertain with `<!-- TODO: fill in -->`.
**Each sub-document ≤ 150 lines**.

---

### Step 4: Agent Team Design (Interactive)

Refer to `references/agent-teams.md`.

**4.0 Detect Existing Agent Teams (CRITICAL)**

Before designing or reconfiguring the Agent Team:
```
1. Check if .harness/agents/ already has role definitions
2. Check if Agent Teams mode is currently active (tmux panes / running teammates)
3. If BOTH exist:
   → Display current team: "Agent Team already configured: A(Architect), B(Engineer), C(Tester)..."
   → Ask: "Keep current team? [Y] Keep / [N] Reconfigure"
   → Default: KEEP — do NOT destroy running teammates
4. If only .harness/agents/ exists (no running teammates):
   → Ask: "Found existing role definitions. Update or keep? [K] Keep / [U] Update"
5. Only proceed to 4.1 if user explicitly chooses to reconfigure
```

**4.1 Confirm Role Assignments with the User**

Do not use default templates — **you must ask the user** for their desired role assignments:

```
Please define your Agent Team. Tell me:
1. The codename and responsibilities for each role
2. Which role is in the current session (primary Agent), and which are sub-Agents
3. How sub-Agents are invoked (subagent / worktree / manual switch)

Example (customizable):
  A — This session: planning, design, interaction, commits
  B — Sub-Agent: development, bug fixes, TDD
  C — Sub-Agent: testing, verification (no code changes)
  FE — Sub-Agent: frontend development
  BE — Sub-Agent: backend development

Or press Enter to use the default 3 roles (Architect / Engineer / Tester).
```

**4.2 Generate Role Definitions**

Write to `.harness/agents/`, with each role file containing:
- Role name and codename
- Responsibilities (specific list of duties)
- Workflow (workflow steps)
- Constraints (what the role can and cannot do)

**4.3 Runtime Mode Selection**

**Ask the user to choose the Agent Team runtime mode**:

```
Agent Team runtime modes:

  A) Subagent Mode (general-purpose, recommended)
     → Agent A is the controller, dispatches B/C via the Agent tool
     → Compatible with any LLM that supports tool use
     → Best for: daily development, short tasks

  B) Agent Teams Mode (Claude Code experimental feature)
     → 3 independent Claude Code sessions, displayed in tmux split panes
     → Built-in message system for communication, each with its own context window
     → Requires: Claude Code + tmux
     → Best for: long-running parallel work, complex tasks

  C) Configure Both (default)
     → Role definitions are universal, switch between modes at will

Choose mode [A/B/C]:
```

**4.4 Write Trigger Methods**

Role definitions (`.harness/agents/*.md`) are shared by both modes. Write the corresponding trigger methods into CLAUDE.md:

**Subagent Mode (written to CLAUDE.md)**:

```markdown
## Agent Team

| Agent | Role | Scope |
|-------|------|-------|
| A — Architect | Planning/Design/Interaction/Commits | Current session |
| B — Engineer | Development/Bug fixes/TDD | Subagent |
| C — Tester | Testing/Verification (no code changes) | Subagent |

Role definitions: `.harness/agents/`

### Triggering Subagents
# Natural language (recommended)
"Send Agent B to implement this feature"
"Have Agent C run a full test verification"

# Agent tool with role injection
"You are Agent B (Engineer). Read .harness/agents/agent-b-engineer.md for your responsibilities. Task: ..."

# Isolation mode (complex tasks)
Agent tool + isolation: "worktree"
```

**Agent Teams Mode (additional configuration)**:

If the user selected B or C, also needed:

1. Enable Agent Teams in `.claude/settings.json`:
```json
{
  "env": {
    "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1"
  }
}
```

2. (Optional) Configure display mode by adding to `~/.claude.json`:
```json
{
  "teammateMode": "tmux"
}
```
Options: `"auto"` (default — split panes in tmux, otherwise in-process), `"tmux"` (force split panes), `"in-process"` (all in the main terminal)

3. (Optional) Configure Agent Teams related hooks:
```json
{
  "hooks": {
    "TeammateIdle": [{ "hooks": [{ "type": "command", "command": "echo 'teammate idle'" }] }],
    "TaskCompleted": [{ "hooks": [{ "type": "command", "command": "echo 'task done'" }] }]
  }
}
```

**Note**: Teammates are created dynamically and are not predefined in settings.json. `.harness/agents/*.md` serves as reference documentation for role definitions.

4. Additionally write the Agent Teams trigger methods and quick-start commands into CLAUDE.md:
```markdown
### Mode B: Agent Teams Mode (Claude Code experimental feature)
# Prerequisite: settings.json has CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1 configured
# Recommended to launch in tmux for split-pane display
# In tmux mode, use Shift+Down to switch between teammates

**Quick start**: When the user says "launch the project-defined agent teams" or "start agent teams", Claude should execute:

1. Read all role definition files under `.harness/agents/`
2. Create a teammate for each role, using the role definition as that teammate's system instructions
3. Specific creation instructions (dynamically generated from roles in .harness/agents/):

Create N teammates to form the Agent Team. Each teammate must read their own role definition file upon startup:

Teammate "[role codename]":
  On startup, read .harness/agents/[role-file].md and act according to the responsibilities and workflow defined therein.
  Responsible for: [summary of responsibilities extracted from role definition].
```

**Note**: Agent Teams is an experimental feature of Claude Code and is not supported by other LLM tools. Role definition files (`.harness/agents/*.md`) remain universal and are shared by both modes.

**4.4 Role-to-Skill Binding**:

| Role | Required Skills |
|------|----------------|
| Architect | superpowers:brainstorming → writing-plans → /plan |
| Engineer | superpowers:test-driven-development → executing-plans |
| Tester | superpowers:verification-before-completion |
| All roles | claudeception (post-task evaluation) / planning-with-files (plan persistence) |

---

### Step 5: Development Standards & Security Standards Injection

Write the following standards into `docs/conventions/`. These standards cover **coding standards + Agent behavior control + security red lines**:

**must-follow.md** — Inject from `references/conventions.md` Part A+B:
- Coding standards (Git commit / testing / branching)
- **8 Agent behavior rules**:
  1. Security review gate — MUST execute the security review checklist before committing
  2. Mandatory code review — MUST go through superpowers:requesting-code-review before merging
  3. Living documentation — MUST synchronize updates to corresponding docs/ when changing code
  4. Pitfall recording — MUST record to pitfalls/ or /claudeception if debugging exceeds 10 minutes
  5. Code hygiene — MUST clean up dead code/debug output/temp files/unused dependencies
  6. Plan first — MUST /plan before writing code for non-trivial tasks
  7. TDD first — MUST write a failing test first for new features/bug fixes
  8. Verify before done — MUST NOT claim "done" unless there is fresh verification evidence

**must-not.md** — Prohibited practices checklist:
- Do not leave commented-out code blocks / debug output / unused imports
- Do not pile up temporary scripts in the root directory
- Do not write "TODO: update docs" and then forget
- Do not skip tests and commit directly
- Do not skip review and merge directly

**coding-patterns.md** — Tailored from `references/lang-patterns.md` based on detected tech stack:
- Based on the primary language/framework identified in Step 1, extract applicable sections from `references/lang-patterns.md`
- Example: Python project → extract Python section (security + idiomatic patterns + common pitfalls)
- Multi-language projects → extract all relevant language sections
- Write to `docs/conventions/coding-patterns.md`

**must-follow.md** append Token optimization rules — inject from `references/conventions.md` Part D:
- Model routing recommendations (Haiku/Sonnet/Opus by scenario)
- /compact strategy
- Context budget management
- Structured output first

**secure-coding.md** — Inject from `references/secure-coding.md` (**hard control, non-negotiable**):
- Part A: 15-item high-risk CWE defense checklist — all code changes must comply
- Part B: OWASP Top 10 coding standards (13 rules with code examples) — mandatory baseline when writing code
- Part C: **AI Agent security behavior red lines** — absolutely prohibited (reverse shell / C2 callback / intranet tunneling / data exfiltration / backdoor / privilege escalation)

**Security standards are hard controls**: These represent the most basic security baseline and must be written into CLAUDE.md behavior rules to ensure they take effect every session. Tailor applicable sections based on the project's tech stack, but tailored rules remain hard controls.

---

### Step 6: Planning Infrastructure

```
.harness/
├── agents/                 → Agent role definitions (generated in Step 4)
│   ├── architect.md
│   ├── engineer.md
│   ├── tester.md
│   └── [extended-roles].md
├── hooks/                  → [Optional] Enterprise security gate scripts (generated when Step 2.3 enabled)
│   ├── pre-commit-gate.sh
│   ├── commit-msg-check.sh
│   ├── dangerous-cmd-guard.sh
│   └── write-security-scan.sh
├── plans/                  → Task plans directory
│   └── .gitkeep
└── templates/              → Plan templates (derived from planning-with-files)
    ├── feature.md          → New feature plan
    ├── bugfix.md           → Bug fix plan
    └── refactor.md         → Refactoring plan
```

If planning-with-files is already installed, configure `.harness/plans/` as the default plan directory.
Templates are derived from `templates/task-plan.md`.

---

### Step 7: Output Confirmation & Usage Guide

Display the initialization summary + **beginner usage guide**:

```
✅ Harness initialization complete

📊 Project profile: [language] + [framework] | [N] core modules
🔧 Skill ecosystem: [N] Skills installed, [N] Hooks configured
📄 Documentation system: CLAUDE.md (index) + docs/ ([N] documents)
👥 Agent Team: [role list]
🔒 Security standards: docs/conventions/secure-coding.md (CWE + Agent red lines)
📋 Plan templates: .harness/templates/ ([N] templates)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📖 Beginner Usage Guide
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🚀 Start developing a new feature:
  1. /plan                          → Create a plan file (planning-with-files)
  2. "As Architect, design a solution"  → Trigger brainstorming skill
  3. "As Engineer, implement it"        → Trigger TDD + executing-plans
  4. "As Tester, verify it"             → Trigger verification skill

🐛 Fix a bug:
  1. /plan                          → Create a plan
  2. "As Engineer, debug this"      → Trigger systematic-debugging
  3. After fixing, auto-reminder → /claudeception → Extract lessons learned as a Skill

🔒 Security audit:
  1. "Generate a security audit skill for this project" → security-review-skill-creator
  2. Use the generated skill to audit code

📝 Capture knowledge:
  1. Say /claudeception at any time     → Extract knowledge from the current session
  2. "Summarize this pitfall as a skill" → Generate a project-specific Skill to .claude/skills/

🎨 Frontend development:
  1. "Help me design a Dashboard"       → Trigger frontend-design skill

🛠 Create a custom Skill:
  1. "Help me create a skill for XX"    → Trigger skill-creator

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📟 Harness Command Quick Reference
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  harness              — Project initialization (re-run to supplement missing parts)
  harness help         — Command index + scenario quick reference
  harness audit        — Project health check (scoring + remediation)
  harness quality gate — Pre-commit quality gate
  harness guide        — Skill recommendation (match by scenario)
```

---

### Step 8: Scenario Integration Verification

**After initialization is complete, you must verify that the following scenarios correctly trigger documentation updates.**

Present the verification checklist to the user and suggest confirming each item during the first development task:

```
Scenario 1: Feature Development Complete
  Trigger condition: Agent B finishes implementation, Agent C passes verification
  Expected behavior:
    ✅ Agent A updates docs/implementation/<module>.md
    ✅ Agent A updates docs/architecture/api-reference.md (if new APIs)
    ✅ Agent A updates docs/architecture/db-schema.md (if new tables)
    ✅ PostToolUse hook reminds to update progress.md
  Safeguard mechanism: CLAUDE.md behavior rule #3 + planning-with-files PostToolUse hook

Scenario 2: Debug Session Ends
  Trigger condition: An issue that took over 10 minutes to debug is resolved
  Expected behavior:
    ✅ Record to docs/pitfalls/<topic>.md
    ✅ Or /claudeception auto-extracts it as a Skill
  Safeguard mechanism: CLAUDE.md behavior rule #4 + claudeception UserPromptSubmit hook

Scenario 3: New Plan Created
  Trigger condition: User says /plan or starts a non-trivial task
  Expected behavior:
    ✅ Create task_plan.md + findings.md + progress.md in the project root
    ✅ UserPromptSubmit hook displays plan status on every input
    ✅ PreToolUse hook re-reads the plan before every tool call
  Safeguard mechanism: planning-with-files 4 hooks + CLAUDE.md behavior rule #7

Scenario 4: Architecture Adjustment
  Trigger condition: Modify database schema / add new module / adjust deployment architecture
  Expected behavior:
    ✅ Agent A brainstorms first, only proceeds after user approval
    ✅ Updates docs/architecture/system-overview.md
    ✅ Updates docs/architecture/tech-stack.md (if tech stack changes)
    ✅ Updates docs/architecture/db-schema.md (if schema changes)
  Safeguard mechanism: CLAUDE.md HARD-GATE rule + superpowers:brainstorming

Scenario 5: Task Completion Declaration
  Trigger condition: Agent is about to claim "done"
  Expected behavior:
    ✅ Must have fresh verification evidence (tests pass + lint passes)
    ✅ Stop hook checks whether all Phases are complete
  Safeguard mechanism: superpowers:verification-before-completion + planning-with-files Stop hook

Scenario 6: Refactoring
  Trigger condition: User requests module refactoring / extracting shared logic / restructuring code
  Expected behavior:
    ✅ Create a plan first (using .harness/templates/refactor.md template)
    ✅ Define Invariants (behavior unchanged, API unchanged, all tests pass)
    ✅ planning-with-files continuously tracks refactoring progress
    ✅ After refactoring, all existing tests must pass
  Safeguard mechanism: planning-with-files 4 hooks + refactor.md template constraints + superpowers TDD methodology

Scenario 7: PR Creation / Code Review
  Trigger condition: Code changes ready to commit or create a PR
  Expected behavior:
    ✅ Pre-commit self-check: tests pass + lint passes + docs synchronized
    ✅ Trigger superpowers:requesting-code-review methodology
    ✅ For security-sensitive changes (auth/crypto/API), remind to use security-review skill
  Safeguard mechanism: CLAUDE.md review rules + superpowers:requesting-code-review (injected at SessionStart)

Scenario 8: Dependency Update / SCA
  → Covered by the security scanning platform (SCA scan + sca-ai-denoise denoising)
  → Harness does not duplicate this effort

Scenario 9: DB Migration
  Trigger condition: Add/modify database table structure, create migration files
  Expected behavior:
    ✅ Create a plan first, including a rollback strategy
    ✅ Update docs/architecture/db-schema.md
    ✅ Remind about data backup (production environment)
    ✅ Migration files require review
  Safeguard mechanism: planning-with-files plan tracking + CLAUDE.md doc sync rules + "Never delete app-data volume" rule

Scenario 10: Hotfix / Emergency Fix
  → Shares all mechanisms with Scenario 1 (brainstorming can be skipped, but TDD + verification cannot)
  → Security scanning platform provides incremental scanning after changes

Scenario 11: Code Hygiene Cleanup
  Trigger condition: Temp files in root directory / unused imports / debug output / commented-out code discovered
  Expected behavior:
    ✅ Clean up dead code, temp scripts, debug output
    ✅ Do not accidentally delete code that is still in use (confirm if in doubt)
    ✅ claudeception evaluates whether the cleanup experience is worth capturing
  Safeguard mechanism: CLAUDE.md code hygiene 5 MUST NOT rules + claudeception knowledge extraction reminder
```

If any scenario does not trigger correctly, check:
1. Whether `.claude/settings.json` hooks are correctly configured
2. Whether CLAUDE.md behavior rules are written
3. Whether the corresponding Skill is installed in `~/.claude/skills/`

---

## Three-Layer Enforcement Mechanism Design

Harness uses three overlapping layers to ensure shared Skills are used correctly:

```
┌──────────────────────────────────────────────────┐
│  Layer 1: Hook (system-level enforcement)         │
│  SessionStart → Inject superpowers methodology    │
│  UserPromptSubmit → Show current plan + knowledge │
│                     extraction reminder            │
│  PreToolUse → Re-read task_plan.md               │
│  PostToolUse → Remind to update progress.md       │
│  Stop → Check task completion status              │
├──────────────────────────────────────────────────┤
│  Layer 2: CLAUDE.md Rules (directive-level        │
│           enforcement)                             │
│  "MUST use /plan" / "MUST TDD" / "MUST evaluate  │
│  knowledge"                                        │
│  Even if hooks are not configured, CLAUDE.md      │
│  rules still take effect                           │
├──────────────────────────────────────────────────┤
│  Layer 3: Skill Description (semantic-level       │
│           triggering)                              │
│  Precise descriptions let Claude automatically    │
│  match and trigger skills                          │
│  e.g.: "planning" triggers planning-with-files    │
│  "debugging" triggers systematic-debugging         │
└──────────────────────────────────────────────────┘
```

**Layer hierarchy**: Hook > CLAUDE.md > Description. Hook is the strongest guarantee (system-level), CLAUDE.md is the fallback, Description is for automatic matching.

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
| `references/agent-teams.md` | Agent Team framework (role definitions + extension guide) |
| `references/secure-coding.md` | Security standards (CWE + OWASP + Agent behavior red lines) |
| `references/conventions.md` | General development conventions (Git / Review / Test) |
| `references/lang-patterns.md` | Tech stack coding patterns quick reference (6 languages/frameworks) |
| `references/hook-scripts.md` | Enterprise Hook gate script templates (4 scripts + activation guide) |
| `references/skill-guide.md` | Scenario → Skill recommendation matrix (data source for harness guide command) |
| `templates/claude-md-index.md` | CLAUDE.md slim index template |
| `templates/task-plan.md` | Task plan template |
| `templates/agent-role.md` | Agent role definition template |
