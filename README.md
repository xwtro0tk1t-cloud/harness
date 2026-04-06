# Harness — AI Agent Development Guardrail System

> **Harness** is an AI Agent development guardrail Meta-Skill that establishes four layers of defense for any project in one command: knowledge management, architecture constraints, feedback loops, and entropy management.
>
> **Optimized for Claude Code**: Harness leverages Claude Code's unique Hook system (SessionStart / PreToolUse / PostToolUse / Stop) for system-level behavior enforcement — access controls the AI cannot bypass, not just "please follow the rules." Combined with the experimental Agent Teams feature, you can spin up multi-role collaboration (Architect / Engineer / Tester) in one prompt. All three enforcement layers (Hooks + instruction file + Skill psychological defense) are fully active on Claude Code, delivering the most complete guardrail experience.
>
> **Compatible with 9 AI coding tools**: Cursor, Windsurf, Cline, GitHub Copilot, Aider, Continue, Devin, and any tool supporting project-level instruction files (via `AGENT.md` as generic fallback). Layer 2 (instruction file rules) and Layer 3 (docs/ documentation) work universally across all tools, ensuring core guardrails remain effective regardless of your IDE.

---

## Why Do You Need Harness?

AI Agents write code fast, but "fast" brings four core problems:

| Problem | Symptom | Consequence |
|---------|---------|-------------|
| **Knowledge gaps** | Every new session starts from scratch with no project context | Repeated mistakes, violated conventions |
| **No constraints** | Bad code exists in the codebase, AI copies and produces more bad code | Security vulnerabilities, architecture decay |
| **No feedback** | "Confidently declares mission accomplished" when it's actually a mess | Production incidents, rework |
| **Entropy increase** | Writing fast = garbage piles up fast | Technical debt explosion, outdated documentation |

**Harness's solution**: Establish four layers of guardrails with a single command at project initialization, automatically effective in every subsequent development session.

But it's not just these 4 — we've identified **24 pain points** across 7 categories. Here's how Harness addresses each one ↓

---

## Roadmap: AI Development Pain Points & Harness Solutions

24 common pain points in AI-assisted development, organized by category. Each lists Harness's current solution, strength rating, and planned future enhancements. **[Detailed version with full problem descriptions and solution architecture →](references/roadmap.md)**

### Thinking & Planning

| # | Pain Point | Current Solution | Strength | Future Enhancement |
|---|-----------|-----------------|----------|-------------------|
| 1 | **AI codes before thinking** — jumps to implementation without understanding requirements | superpowers brainstorming HARD-GATE: no code until design approved | ★★★★★ | — |
| 2 | **Plans collapse mid-task** — AI forgets the plan halfway through | planning-with-files 4 Hooks: re-read task_plan.md before every tool call | ★★★★☆ | Auto-detect plan drift (compare actions vs plan) |
| 3 | **One-shot answers** — AI gives a single solution without exploring alternatives | superpowers brainstorming forces 2+ approaches with trade-offs | ★★★★☆ | — |
| 4 | **No adversarial review** — nobody challenges the AI's design | Challenger (C) agent role: CLAIM/CHALLENGE/VERIFICATION/VERDICT | ★★★☆☆ | Auto-invoke Challenger after Architect produces a plan |

### Memory & Context

| # | Pain Point | Current Solution | Strength | Future Enhancement |
|---|-----------|-----------------|----------|-------------------|
| 5 | **Context loss after /compact** — AI forgets decisions and progress | Compact checkpoint rule: must update progress.md + task_plan.md before compact | ★★★★☆ | Auto-checkpoint hook before compact |
| 6 | **New session cold start** — AI doesn't know the project | CLAUDE.md (≤150 lines) auto-loaded + docs/ B-tree index for on-demand deep reading | ★★★★★ | — |
| 7 | **Repeated mistakes across sessions** — same pitfall hit multiple times | claudeception extracts pitfalls into reusable Skills; docs/pitfalls/ records | ★★★★☆ | Auto-match pitfall Skills before coding starts |
| 8 | **Context window quality degradation** — output quality drops as context grows | Context Recovery 4-step protocol + Token Budget rules (offset+limit, structured output) | ★★★☆☆ | Token pressure monitoring + auto-compact suggestion |

### Quality Control

| # | Pain Point | Current Solution | Strength | Future Enhancement |
|---|-----------|-----------------|----------|-------------------|
| 9 | **"Done" without verification** — AI claims completion without evidence | superpowers verification Iron Law + Stop hook checks Phase completion | ★★★★★ | — |
| 10 | **No tests** — code ships without test coverage | superpowers TDD Iron Law: "NO CODE WITHOUT FAILING TEST FIRST" | ★★★★★ | — |
| 11 | **Skips code review** — AI produces code nobody reviews | superpowers code-review dispatches reviewer subagent | ★★★★☆ | Auto-trigger review on PR creation |
| 12 | **Security vulnerabilities introduced** — AI writes insecure code | 3-layer security: CWE defense in CLAUDE.md + secure-coding.md + security-review Skills | ★★★★☆ | Auto-security-scan on every commit (Enterprise hook) |

### Code Hygiene & Documentation

| # | Pain Point | Current Solution | Strength | Future Enhancement |
|---|-----------|-----------------|----------|-------------------|
| 13 | **Dead code accumulation** — commented-out code, unused imports pile up | CLAUDE.md 5 MUST NOT hygiene rules + quality gate Check #5 | ★★★★☆ | Lint integration in quality gate |
| 14 | **Documentation goes stale** — docs don't match code after changes | Three-tier doc sync: Lite (self-check) → Standard (dynamic grep) → Full (quality gate) | ★★★★☆ | PostToolUse hook for real-time doc sync reminder |
| 15 | **Root directory pollution** — test scripts, debug files accumulate | CLAUDE.md rule: temp files go in tests/, harness-audit checks root cleanliness | ★★★☆☆ | Auto-move detected temp files |
| 16 | **FIXME/HACK debt** — temporary fixes become permanent | CLAUDE.md rule: resolve within 1 week; harness-audit flags stale FIXMEs | ★★★☆☆ | Track FIXME age in quality gate |

### Hallucination & Reliability

| # | Pain Point | Current Solution | Strength | Future Enhancement |
|---|-----------|-----------------|----------|-------------------|
| 17 | **API hallucination** — AI invents non-existent APIs or library functions | Challenger role verifies claims against source/docs; superpowers Red Flags table | ★★★☆☆ | Auto-verify imports against installed packages |
| 18 | **Confident but wrong** — AI states incorrect facts with high confidence | Challenger VERDICT system (CONFIRMED/REFUTED/UNVERIFIED) + evidence requirement | ★★★☆☆ | Mandatory citation for architectural claims |
| 19 | **Blind copy-paste** — AI copies existing bad patterns in the codebase | CLAUDE.md MUST NOT rules + security standards block known bad patterns | ★★★☆☆ | Anti-pattern database from pitfall records |

### Collaboration & Workflow

| # | Pain Point | Current Solution | Strength | Future Enhancement |
|---|-----------|-----------------|----------|-------------------|
| 20 | **No role separation** — same AI does design, coding, testing, review | Agent Team: Architect / Challenger / Engineer / Tester with strict constraints | ★★★★☆ | Workflow orchestration (auto role transitions) |
| 21 | **Experience not captured** — hard-won knowledge lost after session ends | claudeception continuous learning + UserPromptSubmit hook evaluation | ★★★★☆ | Auto-extract on session end (not just /claudeception) |
| 22 | **No project health visibility** — don't know if guardrails are working | harness-audit: scan completeness of CLAUDE.md/docs/hooks/skills, output score | ★★★☆☆ | Trend tracking across audits |

### Security & Compliance

| # | Pain Point | Current Solution | Strength | Future Enhancement |
|---|-----------|-----------------|----------|-------------------|
| 23 | **Secret leaks in commits** — API keys, credentials committed to git | Enterprise Hook: pre-commit secret scan + CLAUDE.md MUST NOT .env/*.key/*.pem | ★★★★☆ | Default-on secret scanning (not Enterprise-only) |
| 24 | **Supply chain attacks** — malicious dependencies slip in | supply-chain-audit Skill (8 languages) + sca-ai-denoise for vulnerability triage | ★★★★☆ | Auto-audit on dependency changes |

**Overall**: 4 fully solved (★★★★★), 12 strong (★★★★☆), 8 partial (★★★☆☆), 0 unsolved. ★★★★★ = system-level enforcement, ★★★★☆ = strong with minor gaps, ★★★☆☆ = partial, enhancement planned.

---

## Four-Layer Guardrail Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Harness Guardrail System                │
├──────────────┬──────────────┬──────────────┬────────────┤
│  Guardrail 1 │  Guardrail 2 │  Guardrail 3 │ Guardrail 4│
│  Knowledge   │  Architecture│  Feedback    │  Entropy   │
│  Mgmt 📋    │  Constraints 🚧│  Loops 🔄  │  Mgmt 🧹  │
│              │              │              │            │
│  CLAUDE.md   │  Hook-based  │  TDD         │  Code      │
│  docs/ tree  │  enforcement │  Code Review │  hygiene   │
│  Agent Team  │  Security    │  Verification│  Doc sync  │
│  Skill       │  standards   │  gates       │  Pitfall   │
│  ecosystem   │  CWE defense │  Security    │  records   │
│              │  Behavior    │  review      │  Knowledge │
│              │  red lines   │              │  extraction│
└──────────────┴──────────────┴──────────────┴────────────┘
```

### Guardrail 1: Knowledge Management 📋

**Problem**: The AI Agent doesn't know your project's background, conventions, or habits.

**Harness's solution**:

**1. CLAUDE.md — The AI's Onboarding Manual**

After automatically analyzing the project, Harness generates a lean CLAUDE.md (≤150 lines) that serves as the AI's first reading material at the start of every session:

```markdown
# MyProject
One-line description

## Documentation Navigation
| Category | Path | Content |
|----------|------|---------|
| Architecture | docs/architecture/ | System architecture, tech stack, DB, API |
| Dev Conventions | docs/conventions/  | must-follow / must-not / secure-coding |
| Pitfall Records | docs/pitfalls/     | Categorized by tech stack |

## Behavior Rules (MUST FOLLOW)
- MUST brainstorm before writing code (HARD-GATE)
- MUST write tests before implementation (TDD)
- MUST security review before committing
- MUST NOT leave dead code / debug output
```

Why "slim down"? Because CLAUDE.md is read in full at every session. Stuffing 500 lines into it = wasted tokens + key information buried. Detailed content is split into docs/ sub-documents, **loaded on demand**.

**2. docs/ — Multi-Level Index Tree (AI's B-tree Memory)**

AI's memory isn't a pile of documents — it's an index tree. Each level stores only pointers; only leaf nodes store content:

```
L0: CLAUDE.md (≤150 lines)
     → 5 category pointers, zero actual content
     │
L1: docs/xxx/INDEX.md (≤50 lines)
     → Module list + one-line summary + last updated date
     │
L2: docs/xxx/module/INDEX.md (≤30 lines)
     → Leaf document list + timeline (when was what added/changed)
     │
L3: docs/xxx/module/topic.md (≤150 lines)
     → Actual content (the ONLY level with real content)
```

**AI memory recovery path**: read L0 → determine direction → read L1 → locate module → read L2 → find document → read L3. Only one index level is read at a time, minimizing token consumption.

**Auto-scaling**: Early projects: L1 points directly to leaves (two levels suffice). As the project grows, L2 subdirectories naturally emerge. When L1 INDEX exceeds 10 entries → upgrade to three levels. When a leaf exceeds 150 lines → auto-split.

```
docs/
├── architecture/INDEX.md     → system-overview.md, tech-stack.md, db-schema.md, api-reference.md
├── implementation/INDEX.md   → auth/INDEX.md, payment/INDEX.md, export/INDEX.md ...
│   └── auth/INDEX.md         → oauth2-flow.md, rbac-model.md, session-mgmt.md + timeline
├── conventions/INDEX.md      → must-follow.md, must-not.md, secure-coding.md
├── pitfalls/INDEX.md         → docker/INDEX.md, database/INDEX.md ... + timeline
└── backlog/INDEX.md          → optimization.md, features.md
```

**3. Agent Team — Role-Based Division of Labor**

Different roles read different docs and follow different constraints:

| Role | Responsibilities | Constraints |
|------|-----------------|-------------|
| **Architect (A)** | Planning, design, interaction, commits, docs | Must brainstorm → user approval → write design doc |
| **Challenger (C)** | Adversarial review of plans, designs, and claims | Never accept claims without evidence; verify API usage, thread safety, edge cases |
| **Engineer (E)** | Coding, fixes, refactoring | Must TDD, must not touch architecture-level config |
| **Tester (T)** | Write tests, verify | **Must not modify business code**, only report bugs |

Trigger methods:
- Natural language: `"Have Agent B implement this feature"` / `"Have Agent C run tests to verify"`
- Agent tool: `"You are Agent B (Engineer). Read .harness/agents/agent-b-engineer.md for your responsibilities. Task: ..."`
- Isolation mode: Agent tool + `isolation: "worktree"` (separate branch for complex tasks)

Extensible: Frontend / Backend / DevOps / DBA / Security.

**4. Skill Ecosystem — Reusable Capability Library**

Harness doesn't reinvent the wheel — it references and orchestrates existing open-source Skills:

```
~/.claude/skills/
├── superpowers/                 ← Behavior control methodology (14 sub-Skills)
├── planning-with-files/         ← Plan persistence
├── claudeception/               ← Knowledge extraction & automatic Skill generation
├── skill-creator/               ← General-purpose Skill generator
├── security-review-skill-creator/ ← Security audit Skill generator
├── frontend-design/             ← Frontend development
├── web-vuln-analyzer/           ← Web vulnerability analysis
├── sca-ai-denoise/              ← SCA vulnerability denoising
├── supply-chain-audit/          ← Supply chain poisoning detection
└── harness/                     ← This Skill (for project initialization)
```

---

### Guardrail 2: Architecture Constraints 🚧

**Problem**: Written rules alone aren't enough — AI will rationalize skipping them. You need an "access control system."

**Harness's solution: Three-layer enforcement mechanism (Open-Source vs Enterprise Mode)**

```
┌──────────────────────────────────────────────────────┐
│  Layer 1: Hooks — Access Control                     │
│                                                      │
│  ── Core Hooks (enabled by default) ──               │
│  SessionStart    → Auto-inject superpowers methodology│
│  UserPromptSubmit → Show plan status + knowledge     │
│                    extraction reminder                │
│  PreToolUse      → Re-read task_plan.md before every │
│                    tool call                          │
│  PostToolUse     → Remind to update progress after   │
│                    writes                             │
│  Stop            → Check completion status on exit   │
│                                                      │
│  ── Security Gate Hooks [Optional/Enterprise] ──     │
│  PreToolUse(Bash)  → git commit secret/sensitive     │
│                      file interception                │
│  PreToolUse(Bash)  → commit format validation        │
│  PreToolUse(Bash)  → dangerous command interception  │
│  PostToolUse(W/E)  → code security anti-pattern      │
│                      scan (WARNING)                   │
├──────────────────────────────────────────────────────┤
│  Layer 2: CLAUDE.md — Written Rules (instruction-    │
│           level, strongly persuasive)                 │
│                                                      │
│  MUST brainstorm → MUST /plan → MUST TDD             │
│  MUST security review → MUST code review             │
│  MUST NOT dead code → MUST NOT claim completion      │
│  without verification                                │
│  MUST NOT eval()/exec() with user input — CWE-95    │
│  MUST NOT shell=True with user args — CWE-78        │
│  MUST NOT f-string SQL concatenation — CWE-89       │
├──────────────────────────────────────────────────────┤
│  Layer 3: Skills — Psychological Constraints         │
│           (semantic-level, internalized behavior)     │
│                                                      │
│  Iron Laws: "NO CODE WITHOUT FAILING TEST FIRST"     │
│  Red Flags: 13 common "rationalized skip" excuses    │
│             → intercepted one by one                 │
│  HARD-GATE: No code allowed until design is approved │
└──────────────────────────────────────────────────────┘
```

**Open-Source Mode vs Enterprise Mode**:

| Mode | Layer 1 | Layer 2 | Layer 3 | Security Assurance |
|------|---------|---------|---------|-------------------|
| **Open-Source (default)** | Core Hooks (3 Skills) | MUST/MUST NOT text rules | Skill psychological defense | AI self-discipline + text rules |
| **Enterprise (optional)** | Core + 4 security gate Hooks | Same + HOOK enforcement layer | Same | System-level technical gates |

- **Open-Source Mode (default)**: Zero additional blocking — security relies on CLAUDE.md MUST/MUST NOT rules for AI self-discipline. Ideal for individual developers, open-source projects
- **Enterprise Mode (optional)**: Enables 4 security gate Hook scripts (pre-commit / commit-msg / dangerous-cmd / write-scan) for system-level enforcement. Ideal for enterprise teams, projects with high compliance requirements
- Enterprise mode Hook scripts are in `references/hook-scripts.md`; users choose whether to enable during Harness initialization Step 2

**Why stack three layers?**

- Hooks are the strongest safeguard: system-level enforcement, AI cannot skip them (Claude Code only)
- CLAUDE.md is the fallback: rules remain effective even without Hook configuration (universal across all AI tools)
- Skills are the psychological defense: superpowers' Iron Laws + Red Flags make the AI "automatically stop when tempted to skip"

**Security Standards (hard control, non-negotiable)**:

```
docs/conventions/secure-coding.md contains three parts, all mandatory baselines:

Part A: 15 high-risk CWE defenses (SQL injection/command injection/XSS/SSRF/deserialization...)
  → All code changes must comply, no exceptions

Part B: OWASP Top 10 coding standards (13 rules, with code examples)
  → Mandatory baselines when writing code

Part C: AI Agent security red lines:
  ❌ No reverse shells / C2 callbacks
  ❌ No intranet tunneling / port forwarding to external
  ❌ No data exfiltration / credential theft
  ❌ No backdoor installation / hidden user creation
  ❌ No privilege escalation / disabling security mechanisms
  ❌ No code obfuscation / supply chain poisoning
```

Security standards are written into CLAUDE.md behavior rules to ensure they take effect automatically at every session. For in-depth audits, the security-review skill is triggered for a full check.

---

### Guardrail 3: Feedback Loops 🔄

**Problem**: After finishing work, the AI doesn't know if it did well, and it will "confidently declare mission accomplished."

**Harness's solution: Multiple verification mechanisms**

```
Code complete
  │
  ├─ Automatic feedback: Tests
  │   TDD Iron Law → Every line of code has a corresponding test
  │   Finish code → Run tests immediately → Red/green light instant feedback
  │
  ├─ Agent reviews Agent: Code Review
  │   superpowers:requesting-code-review
  │   → Dispatch code-reviewer subagent (another AI reviews)
  │   → Checks: correctness / security / test coverage / performance / compatibility
  │
  ├─ Security Review
  │   → MUST execute security review checklist before committing
  │   → Has project-specific security-review skill → auto-audit
  │   → Doesn't have one → security-review-skill-creator generates one first
  │
  ├─ Completion Verification
  │   superpowers:verification-before-completion
  │   Iron Law: NO COMPLETION CLAIMS WITHOUT FRESH EVIDENCE
  │   → Tests pass + lint passes + security review passes → only then can claim "done"
  │
  └─ Debugging Feedback: Systematic Debugging
      superpowers:systematic-debugging
      Iron Law: NO FIXES WITHOUT ROOT CAUSE
      → 4 stages: root cause investigation → pattern analysis → hypothesis verification → implement fix
```

**superpowers' "anti-rationalization" design**:

The AI's biggest problem isn't not knowing the rules — it's **being skilled at finding excuses to skip rules**. superpowers addresses this with a "Red Flags table" — listing 13 common excuses and intercepting each one:

| AI's Inner Monologue | Reality |
|----------------------|---------|
| "This is just a simple problem" | Simple problems still need checking for applicable Skills |
| "Write code first, add tests later" | That's not TDD, that's "tests as an afterthought" |
| "Time is tight, skip Review" | Code shipped without Review takes even longer to fix later |
| "Rewriting from scratch is wasteful" | Sunk cost fallacy — the time has already been spent |

---

### Guardrail 4: Entropy Management 🧹

**Problem**: AI works fast = technical debt accumulates fast. Docs go stale, dead code piles up, experience isn't captured.

**Harness's solution: Continuous cleaning + knowledge crystallization**

**1. Code Hygiene (before every commit)**

```
MUST DO:
  ✅ Delete unused code (don't comment it out — git has history)
  ✅ Delete debug print / console.log
  ✅ Delete unused imports / variables / functions
  ✅ Delete temporary files (test scripts go in tests/)
  ✅ Clean up unused dependencies

MUST NOT:
  ❌ Don't leave "just in case" commented-out code
  ❌ Don't leave empty except/catch blocks
  ❌ Don't pile up scripts in the root directory
  ❌ Don't leave FIXME/HACK unresolved for more than 1 week
```

**2. Documentation Sync (three-tier quality gate)**

Documentation sync is enforced at three levels to balance thoroughness with speed:

| Level | Trigger | What Happens |
|-------|---------|-------------|
| **Lite** | After editing source code (CLAUDE.md behavior rule) | Self-check: does a matching doc in docs/ exist? If yes and content affected → update now |
| **Standard** | Claiming "done" or "complete" | Auto quality gate: dynamic scan of git diff + grep docs/ for references to changed modules |
| **Full** | "quality gate" or "ready to commit" | All 7 checks including tests, lint, security, doc sync, hygiene, progress, commit format |

The quality gate dynamically detects which docs need updating (no hardcoded file mappings) — it scans docs/ structure and greps for references to changed files.

**3. Pitfall Records (auto-triggered after debugging for >10 minutes)**

Choose either approach:

```
Approach A: Write to docs/pitfalls/
  ## Problem Title
  Symptom → Root Cause → Solution → Prevention

Approach B: /claudeception to generate a Skill
  → Automatically extract reusable knowledge from the pitfall experience
  → Generate .claude/skills/<pitfall-name>/SKILL.md
  → Next time a similar problem occurs, the Skill triggers automatically
```

**4. Knowledge Crystallization (claudeception — Continuous Learning System)**

```
Work session
  │
  ├─ UserPromptSubmit hook continuously reminds:
  │   "Is there any non-obvious knowledge extractable from this task?"
  │
  ├─ Trigger conditions:
  │   • Debugged for >10 minutes on a non-documented issue
  │   • Discovered a workaround through trial and error
  │   • Project-specific non-obvious pattern
  │
  ├─ Quality gate (all 5 criteria must be met):
  │   ✅ Reusable (not just useful this one time)
  │   ✅ Non-trivial (not something findable in documentation)
  │   ✅ Specific (has clear trigger conditions and steps)
  │   ✅ Verified (confirmed the solution works)
  │   ✅ Actionable (general enough to reuse, specific enough to execute)
  │
  └─ Output: new SKILL.md
      → Stored in .claude/skills/ (project-level)
      → Or ~/.claude/skills/ (user-level, shared across projects)
      → Automatically matched and triggered on similar problems next time
```

---

## Usage

### Initialization (One-Time)

In any project directory:

```
You: harness
```

Harness interactively executes 8 steps:

```
Step 1: Analyze project (language/framework/structure) → Display project profile → User confirms
Step 2: Install Skill ecosystem + configure Hooks → Three-layer enforcement ready
Step 3: Deep information gathering (3 parallel Agents read code/history/docs) → Generate CLAUDE.md + docs/
Step 4: Design Agent Team (interactive role selection + trigger methods)
Step 5: Inject development conventions + security standards
Step 6: Create .harness/ planning infrastructure
Step 7: Display summary + getting started guide
Step 8: Scenario integration verification (11 scenario coverage check)
```

Resulting project structure:

```
project/
├── CLAUDE.md                  ← Slim index + behavior rules
├── docs/                      ← Multi-level documentation system
│   ├── architecture/
│   ├── implementation/
│   ├── conventions/           ← must-follow + must-not + secure-coding
│   ├── pitfalls/              ← Pitfall records (accumulated during development)
│   └── backlog/
├── .harness/                  ← Agent Team + plan templates
│   ├── agents/
│   ├── plans/
│   └── templates/
└── .claude/settings.json      ← Hook configuration
```

### Daily Development (Automatically Effective Every Session)

After initialization, every subsequent development session automatically enters the guardrail system:

**Developing a new feature**:

```
You: Help me build a user export feature

Agent (auto-triggers brainstorming HARD-GATE):
  → Don't write code yet, let me understand the requirements
  → Clarifying questions: Export format? Data volume? Access control?
  → Propose 2 approaches + trade-offs
  → You choose an approach → Write design doc

Agent (auto-triggers writing-plans):
  → Split into 5 small tasks (2-5 minutes each)
  → Write to task_plan.md

Agent (auto-triggers TDD):
  → Write tests first: test_export_csv / test_export_permission / test_export_large_data
  → Tests red → Write implementation → Tests green

Agent (auto-triggers code-review):
  → Dispatch reviewer subagent for review
  → Review passes → security review → verification → done
```

**Fixing a bug**:

```
You: Users report the export feature is timing out

Agent (auto-triggers systematic-debugging):
  → Don't rush to change code, find the root cause first
  → 4 stages: investigate → analyze patterns → verify hypothesis → fix

Agent (after fix, claudeception hook triggers):
  → "This debugging session found that exporting large datasets needs streaming — record as a Skill?"
  → Generate .claude/skills/export-streaming-fix/SKILL.md
```

**Security audit**:

```
You: Generate a security audit skill for this project

Agent (triggers security-review-skill-creator):
  → Analyze project tech stack (Python + FastAPI + PostgreSQL)
  → Generate customized audit rules
  → Store in .claude/skills/security-review-skill-for-myproject/

You: Audit the code for security

Agent (triggers the generated audit Skill):
  → Audit item by item using project-specific rules
  → Output findings + remediation recommendations
```

---

## Skill Dependency Graph

Harness doesn't reinvent the wheel — it orchestrates existing open-source Skills to build the guardrail system:

```
                        ┌─────────────┐
                        │   Harness   │  ← Project initialization entry point
                        │  Meta-Skill │
                        └──────┬──────┘
                               │ orchestrates
           ┌───────────────────┼───────────────────┐
           │                   │                   │
    ┌──────▼──────┐    ┌──────▼──────┐    ┌──────▼──────┐
    │ superpowers  │    │ planning-   │    │claudeception│
    │  (obra)      │    │ with-files  │    │  (blader)   │
    │              │    │ (OthmanAdi) │    │             │
    │ 14 sub-Skills│    │             │    │ Knowledge   │
    │ brainstorming│    │ /plan cmd   │    │ extraction  │
    │ writing-plans│    │ 4 Hooks     │    │ Skill gen   │
    │ TDD          │    │ Session     │    │ Quality     │
    │ debugging    │    │ recovery    │    │ gates       │
    │ code-review  │    │             │    │             │
    │ verification │    │             │    │             │
    └──────────────┘    └─────────────┘    └─────────────┘
           │
           │ generates
    ┌──────▼──────────────────────────────────────┐
    │  Skill Factory                               │
    │  skill-creator → General Skill generation    │
    │  security-review-skill-creator → Security    │
    │                   audit generation           │
    │  superpowers:writing-skills → TDD-style      │
    │                   Skill writing              │
    │  claudeception → Extract Skills from         │
    │                   experience                 │
    └─────────────────────────────────────────────┘
           │
           │ outputs
        ┌──────▼──────────────────────────────────────┐
    │  Project-Specific Skills (.claude/skills/)   │
    │  security-review-skill-for-<project>         │
    │  <pitfall-name> Skill                        │
    │  <workflow-name> Skill                        │
    └──────────────────────────────────────────────┘
```

### Core Skills in Detail

| Skill | Source | Hook Mechanism | Guardrail Role |
|-------|--------|---------------|----------------|
| **superpowers** | [obra/superpowers](https://github.com/obra/superpowers) | SessionStart injects methodology | Guardrail 2 (constraints) + Guardrail 3 (feedback) |
| **planning-with-files** | [OthmanAdi/planning-with-files](https://github.com/OthmanAdi/planning-with-files) | 4 Hooks continuously inject plans | Guardrail 1 (knowledge) + Guardrail 4 (entropy) |
| **claudeception** | [blader/Claudeception](https://github.com/blader/Claudeception) | UserPromptSubmit reminder | Guardrail 4 (entropy) + Guardrail 1 (knowledge) |

### Skill Triggering: Automatic vs Manual

A core design goal of Harness is that **you don't need to manually invoke Skills during day-to-day development**. The three-layer mechanism (Hook + CLAUDE.md + Skill description) makes key methodologies take effect automatically in the background.

**Automatic Triggering (Hook + CLAUDE.md rules — no manual action needed)**

| Skill | Trigger Mechanism | What You Experience |
|-------|------------------|---------------------|
| superpowers (brainstorming) | SessionStart hook + CLAUDE.md HARD-GATE | Say "build a new feature" → Claude automatically asks requirements, proposes solutions, **refuses to write code directly** |
| superpowers (TDD) | SessionStart hook Iron Law | Claude automatically writes tests before implementation |
| superpowers (systematic-debugging) | SessionStart hook | Say "this bug" → Claude automatically follows root cause analysis instead of blind fixes |
| superpowers (verification) | SessionStart hook + Stop hook | Claude automatically runs verification before claiming "done" |
| planning-with-files | 4 Hooks full coverage | Every input shows plan status, re-reads plan before tool calls, reminds to update progress after writes |
| claudeception (evaluation) | UserPromptSubmit hook | On every input, Claude internally evaluates "is there extractable knowledge" but **won't interrupt you** |
| harness-quality-gate | CLAUDE.md commit rules | Claude auto-checks tests/lint/security/doc sync before commits |

**Manual Triggering (on-demand)**

| Skill | How to Trigger | Notes |
|-------|---------------|-------|
| superpowers (code-review) | "Help me review this code" | You must initiate; Claude dispatches a reviewer subagent |
| claudeception (generate Skill) | "/claudeception" or "summarize this as a skill" | Hook only evaluates; actual extraction requires you to say the word |
| security-review-skill-creator | "Generate a security audit skill for this project" | On-demand project-specific audit rule generation |
| skill-creator | "Help me create a skill for XX" | On-demand workflow codification |
| harness-audit | "harness audit" | On-demand project health check |
| harness-guide | "harness guide" or "recommend a skill" | On-demand Skill recommendation |

**In short**: Hooks handle the automatic, you handle the decisions. During daily coding, brainstorming/TDD/debugging/planning all work automatically — you only need to speak up when you want a review, want to capture experience, or want to generate a new Skill.

---

## Scenario Integration Coverage (11 Scenarios)

After Harness is set up, the following scenarios automatically receive protection:

### Fully Protected Scenarios (Hook + CLAUDE.md + Skill — all three layers)

| # | Scenario | Protection Mechanism |
|---|----------|---------------------|
| 1 | **Feature Development** | SessionStart injects methodology → planning 4 hooks track → CLAUDE.md TDD/Review rules → claudeception knowledge extraction |
| 2 | **Bug Debugging** | SessionStart injects systematic-debugging → planning tracks → claudeception pitfall reminder |
| 3 | **Plan Execution** | planning-with-files 4 hooks full coverage (display → re-read → remind to update → completion check) |
| 4 | **Architecture Changes** | CLAUDE.md HARD-GATE → superpowers brainstorming → docs/ sync rules |
| 5 | **Task Completion** | superpowers verification → planning Stop hook checks Phase completion |
| 6 | **Refactoring** | planning 4 hooks + .harness/templates/refactor.md (Invariants constraints) + TDD |
| 11 | **Code Hygiene** | CLAUDE.md 5 MUST NOT rules + claudeception reminder |

### Partially Protected Scenarios (CLAUDE.md + Skill semantic triggering)

| # | Scenario | Protection Mechanism | Notes |
|---|----------|---------------------|-------|
| 7 | **PR / Code Review** | CLAUDE.md review rules + superpowers:requesting-code-review | User-initiated, semantic-level is sufficient |
| 9 | **DB Migration** | planning tracks + CLAUDE.md doc sync rules | High-risk but low-frequency, plan constraints are sufficient |

### Scenarios Covered by Security Scanning Platform

| # | Scenario | Coverage Method |
|---|----------|----------------|
| 8 | **Dependency Updates / SCA** | Security scanning platform SCA scan + sca-ai-denoise denoising |
| 10 | **Hotfix / Emergency Fix** | Shares mechanism with Scenario 1 + security scanning platform incremental scan |

### End-to-End Development Workflow

```
New feature request
  │
  ▼
┌─────────────────────┐
│ 1. Brainstorming    │  ← superpowers HARD-GATE
│    Explore context   │     No code allowed until design is approved
│    Clarify needs     │
│    Propose approaches│
│    + trade-offs      │
│    User approves     │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 2. Writing Plans    │  ← superpowers + planning-with-files
│    Split into small  │     task_plan.md persisted
│    tasks             │     Hooks continuously inject status
│    2-5 min each      │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 3. TDD              │  ← superpowers Iron Law
│    Write failing test│     "NO CODE WITHOUT FAILING TEST"
│    Write minimal impl│
│    Tests pass        │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 4. Code Review      │  ← superpowers:requesting-code-review
│    Subagent reviews  │     Agent reviews Agent
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 5. Verification     │  ← superpowers Iron Law
│    Tests pass?       │     "NO COMPLETION WITHOUT EVIDENCE"
│    Lint passes?      │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 6. Knowledge Capture│  ← claudeception + pitfalls
│    Extractable       │     /claudeception or docs/pitfalls/
│    knowledge?        │     PostToolUse hook reminder
│    Docs need update? │
└─────────────────────┘
```

---

## Multi-AI Tool Compatibility

Harness is not limited to Claude Code — it's compatible with all major AI coding tools. During initialization, it auto-detects the current environment and generates the appropriate instruction file:

| AI Tool | Instruction File | Format |
|---------|-----------------|--------|
| Claude Code | `CLAUDE.md` | Markdown (tables/links/code blocks) |
| Cursor | `.cursorrules` or `.cursor/rules/*.md` | Plain text (indentation instead of tables) |
| Windsurf | `.windsurfrules` | Plain text |
| Cline | `.clinerules` | Plain text |
| GitHub Copilot | `.github/copilot-instructions.md` | Markdown |
| Aider | `CONVENTIONS.md` | Markdown |
| Continue | `.continuerules` | Plain text |
| Devin | `devin.md` | Markdown |
| Generic / Unknown | `AGENT.md` | Markdown |

**Same content, adapted format**: All instruction files contain the same project knowledge, behavior rules, and documentation navigation — only the format is adjusted per tool (Markdown tools get tables/links, plain text tools get indentation/lists).

**Three-layer enforcement portability**:
- **Layer 1 (Hooks)**: Claude Code only — other tools skip this layer
- **Layer 2 (Instruction file rules)**: Universal across all tools — only the filename differs
- **Layer 3 (docs/ documentation)**: Fully universal — all AI tools can read Markdown docs

---

## Command System

Harness provides 4 post-initialization commands, installed as independent Skills in `bundled-skills/`:

| Command | Trigger Words | Description |
|---------|--------------|-------------|
| `harness help` | "harness help", "harness commands", "what commands" | Command index + installed Skill inventory + scenario quick entries |
| `harness audit` | "harness audit", "project health check", "harness status" | Scan CLAUDE.md/docs/hooks/skill completeness, output score + remediation |
| `harness quality gate` | "quality gate", "ready to commit", or auto on "done" | 3 levels: Lite (doc sync), Standard (hygiene+docs+progress), Full (all 7 checks) |
| `harness guide` | "recommend skill", "which skill", "skill recommendation" | Read scenario→Skill recommendation matrix, match the best Skill |

---

## Bundled Skills

Harness packages 9 security/development Skills + 4 command Skills, deployed to `~/.claude/skills/` via symlink during installation:

```bash
# Batch install
for skill in ~/.claude/skills/harness-en/bundled-skills/*/; do
  name=$(basename "$skill")
  ln -sf "$skill" ~/.claude/skills/"$name"
done
```

| Category | Skill | Description | Config Required |
|----------|-------|-------------|----------------|
| 🏭 Factory | skill-creator | General Skill generator | None |
| 🏭 Factory | security-review-skill-creator | Security audit Skill generator | None (lark optional) |
| 🔒 Security | security-review-skill-for-docker | Docker/container security audit | None |
| 🔒 Security | security-review-skill-for-terraform | Terraform/IaC security audit | None |
| 🔒 Security | sca-ai-denoise | SCA vulnerability denoising | None |
| 🔒 Security | supply-chain-audit | Supply chain poisoning detection (8 langs) | None |
| 🔒 Security | skills-audit | Third-party Skill security audit | Optional ANTHROPIC_API_KEY |
| 🔒 Security | web-vuln-analyzer | Web vulnerability analysis | ⚠️ Docker + API keys |
| 🔒 Security | android-vuln-analyzer | Android vulnerability analysis | ⚠️ apktool/jadx/frida |
| 🛠 Command | harness-help | Help | None |
| 🛠 Command | harness-audit | Health check | None |
| 🛠 Command | harness-quality-gate | Quality gate | None |
| 🛠 Command | harness-guide | Skill recommendation | None |

Skills requiring configuration are interactively guided during Harness initialization Step 2; skipped ones are marked "Not available".

---

## File Manifest

```
~/.claude/skills/harness-en/
├── SKILL.md                              Main file (8-step workflow + 11 scenario integrations)
├── README.md                             This document
├── bundled-skills/                       Bundled Skills (symlink install)
│   ├── harness-help/SKILL.md             Command: help index
│   ├── harness-audit/SKILL.md            Command: project health check
│   ├── harness-quality-gate/SKILL.md     Command: pre-commit quality gate
│   ├── harness-guide/SKILL.md            Command: Skill recommendation guide
│   ├── skill-creator/                    General Skill generator
│   ├── security-review-skill-creator/    Security audit Skill generator
│   ├── security-review-skill-for-docker/ Docker security audit
│   ├── security-review-skill-for-terraform/ Terraform security audit
│   ├── sca-ai-denoise/                   SCA vulnerability denoising
│   ├── supply-chain-audit/               Supply chain poisoning detection
│   ├── skills-audit/                     Third-party Skill security audit
│   ├── web-vuln-analyzer/                Web vulnerability analysis (lite)
│   └── android-vuln-analyzer/            Android vulnerability analysis
├── references/
│   ├── skill-ecosystem.md                Full Skill ecosystem map + installation methods
│   ├── skill-guide.md                    Scenario → Skill recommendation matrix (harness guide data source)
│   ├── doc-templates.md                  Documentation system templates (CLAUDE.md / docs/)
│   ├── agent-teams.md                    Agent Team role framework
│   ├── secure-coding.md                  Security standards (CWE + OWASP + Agent red lines)
│   ├── conventions.md                    Dev conventions + Agent behavior rules (9 MUST rules) + Token optimization
│   ├── lang-patterns.md                  Tech stack coding patterns (6 languages/frameworks)
│   ├── hook-scripts.md                   Enterprise Hook gate scripts (4 scripts + activation guide)
│   └── roadmap.md                        AI development pain points & solutions (24 items, detailed)
└── templates/
    ├── claude-md-index.md                CLAUDE.md slim template (L0 index)
    ├── sub-index.md                      L1 category index + L2 module index templates
    ├── task-plan.md                      Task plan template
    └── agent-role.md                     Agent role definition template
```

---

## FAQ

**Q: What's the relationship between Harness and superpowers?**
A: superpowers is the underlying behavior control framework (14 sub-Skills), while Harness is the higher-level orchestrator — it installs superpowers, configures hooks, generates documentation, and assembles the Agent Team. Analogy: superpowers is the Linux kernel, Harness is the Ubuntu installer.

**Q: Do I need to say "harness" at every session?**
A: No. Harness only runs once during project initialization. After that, the three layers — Hooks + CLAUDE.md + Skills — take effect automatically at every session.

**Q: What if I don't want a particular guardrail?**
A: Harness is interactive — every step can be skipped. You can also run only specific steps (e.g., generate docs only without setting up an Agent Team).

**Q: Will re-running Harness overwrite my docs?**
A: No. Harness is idempotent — existing files are only supplemented, never overwritten; already-installed Skills are skipped.

**Q: Can I add my own conventions?**
A: Yes. Edit the files under docs/conventions/ directly, or add custom MUST/MUST NOT entries to the behavior rules section of CLAUDE.md.

**Q: How do I share pitfall experience across projects?**
A: Skills generated by claudeception can be stored in `~/.claude/skills/` (user-level), shared across all projects. Storing in `.claude/skills/` (project-level) limits them to the current project only.
# test
