# Harness Roadmap: AI Development Pain Points & Solutions

24 common pain points in AI-assisted development. For each: detailed problem description, Harness's current solution (how it works, which components), strength rating, and concrete future enhancement plans.

---

## Category 1: Thinking & Planning

### 1. AI Codes Before Thinking

**Problem**: Given "add user export feature", AI immediately writes code without understanding: export format? data volume? access control? pagination? This leads to repeated rework when requirements surface later.

**Current Solution**: superpowers brainstorming HARD-GATE
- SessionStart hook injects the brainstorming methodology at every session start
- HARD-GATE: Claude **refuses to write code** until design is approved
- Forces: clarifying questions → 2+ approaches with trade-offs → user picks → design doc written
- CLAUDE.md rule: "MUST brainstorm before coding (HARD-GATE)"
- Red Flags table intercepts rationalization: "This is just a simple problem" → "Simple problems still need requirement clarity"

**Strength**: ★★★★★ — System-level enforcement via Hook + psychological defense. AI literally cannot skip this.

**Future Enhancement**: — (Current solution is sufficient)

---

### 2. Plans Collapse Mid-Task

**Problem**: AI starts with a good plan (5 tasks), finishes task 1-2, then forgets the plan exists. Starts improvising, skips tasks, or re-does completed work. Especially bad after /compact or long conversations.

**Current Solution**: planning-with-files 4 Hooks
- **PreToolUse hook**: Re-reads `task_plan.md` before every tool call — plan is always fresh in context
- **UserPromptSubmit hook**: Shows current plan status + Phase progress on every user input
- **PostToolUse hook**: Reminds to update `progress.md` after file writes
- **Stop hook**: Checks whether the current Phase is actually complete before allowing "done"
- Plan persisted as files (task_plan.md / progress.md / findings.md) — survives /compact and new sessions

**Strength**: ★★★★☆ — Strong persistence + continuous injection. Minor gap: doesn't detect if actions diverge from plan.

**Future Enhancement**: Auto-detect plan drift
- Compare AI's actual tool calls (file edits, commands) against planned tasks
- If AI is editing files not mentioned in any task → warn: "This doesn't match your plan. Update plan or explain."
- Drift score: % of actions that map to planned tasks

---

### 3. One-Shot Answers — AI Gives a Single Solution Without Exploring Alternatives

**Problem**: AI picks the first approach that seems reasonable and runs with it. Doesn't consider: is there a simpler way? a more performant way? a more maintainable way? User gets one perspective, not the best one.

**Current Solution**: superpowers brainstorming
- Forces presentation of 2+ approaches with explicit trade-offs (complexity, performance, maintainability, time)
- User makes an informed choice, not AI's default choice
- Works especially well with Challenger (C) role who can question the selected approach

**Strength**: ★★★★☆ — Effective for feature development. Less consistently triggered for small fixes.

**Future Enhancement**: — (Current solution is sufficient for the target use case)

---

### 4. No Adversarial Review — Nobody Challenges the AI's Design

**Problem**: AI proposes a design, AI implements it, AI reviews it. Fox guarding the henhouse. Subtle flaws (thread safety, edge cases, scaling limits) go unnoticed because the same "mind" that created them reviews them.

**Current Solution**: Challenger (C) agent role in Agent Team
- Dedicated adversarial reviewer: NEVER accepts claims without evidence
- Output format: CLAIM → CHALLENGE → VERIFICATION → VERDICT (CONFIRMED / REFUTED / UNVERIFIED)
- Escalation: 2+ REFUTED → BLOCK, send back with specific issues
- Challenges with specifics: not "are you sure?" but "what happens with empty string input? concurrent access from two goroutines?"
- Verifies external claims: "this API supports X" → show the doc or test proving it

**Strength**: ★★★☆☆ — Powerful when used, but requires manual invocation ("have Challenger review this").

**Future Enhancement**: Auto-invoke Challenger after Architect produces a plan
- Architect completes design doc → system automatically dispatches Challenger agent
- Challenger reviews before Engineer starts coding
- Reduces "forgot to get a review" scenarios
- Workflow: Architect → auto-Challenger → Engineer (blocked until Challenger APPROVE)

---

## Category 2: Memory & Context

### 5. Context Loss After /compact

**Problem**: /compact compresses conversation history to free up context window. But it can lose: key decisions ("we decided to use streaming, not batch"), current progress ("task 3 of 5 done"), and uncommitted design rationale. AI resumes with amnesia.

**Current Solution**: Compact checkpoint rule (CLAUDE.md behavior rule)
- **Before /compact** (mandatory):
  1. Update `progress.md`: current status + any uncommitted decisions
  2. Update `task_plan.md`: Phase checkboxes reflect actual progress
  3. Note any in-progress work that needs to resume after compact
- **After /compact**: Re-read task_plan.md lines 1-30 to restore context
- planning-with-files PreToolUse hook automatically re-reads task_plan.md

**Strength**: ★★★★☆ — Effective when followed. Gap: relies on AI self-discipline to checkpoint before compact.

**Future Enhancement**: Auto-checkpoint hook before compact
- PreToolUse hook detects /compact command → auto-save progress.md + task_plan.md before executing
- Eliminate reliance on AI remembering to checkpoint
- Could also auto-detect "context pressure" (approaching limit) and suggest compact at Phase boundaries

---

### 6. New Session Cold Start

**Problem**: Every new Claude Code session starts from zero. AI doesn't know: project structure, conventions, tech stack, recent decisions, team preferences. First 5-10 minutes of every session are wasted on re-orientation.

**Current Solution**: CLAUDE.md (≤150 lines) + docs/ B-tree index
- CLAUDE.md auto-loaded at session start: project overview, doc navigation, command reference, behavior rules
- Kept slim (≤150 lines) so key info isn't buried — detailed content lives in docs/
- docs/ organized as multi-level index tree (L0→L1→L2→L3): read index → locate module → read leaf
- Context Recovery 4-step protocol:
  1. CLAUDE.md (auto-loaded)
  2. task_plan.md lines 1-30 (current Phase + progress)
  3. docs/architecture/INDEX.md (only if task touches architecture)
  4. Specific docs/ file for the module being worked on

**Strength**: ★★★★★ — Fully solved. AI has project context within seconds, token-efficient.

**Future Enhancement**: — (Current solution is sufficient)

---

### 7. Repeated Mistakes Across Sessions — Same Pitfall Hit Multiple Times

**Problem**: AI debugs a tricky issue for 20 minutes, finds the fix. Next session (or next week), hits the exact same issue and debugs for 20 minutes again. Hard-won knowledge is lost between sessions.

**Current Solution**: claudeception + docs/pitfalls/
- claudeception extracts debugging knowledge into reusable Skills (SKILL.md files)
- Skills stored in `~/.claude/skills/` (user-level, cross-project) or `.claude/skills/` (project-level)
- Skill description field enables semantic matching — when a similar problem surfaces, the skill auto-triggers
- UserPromptSubmit hook continuously evaluates: "is there extractable knowledge from this task?"
- docs/pitfalls/ for lighter-weight records: Symptom → Root Cause → Solution → Prevention

**Strength**: ★★★★☆ — Good extraction mechanism. Gap: relies on AI/user initiative to trigger extraction.

**Future Enhancement**: Auto-match pitfall Skills before coding starts
- When AI begins working on a module, auto-scan existing pitfall Skills for that module/tech stack
- Surface relevant pitfalls proactively: "Note: there's a known pitfall with streaming exports in this module"
- Reduce re-discovery of known issues

---

### 8. Context Window Quality Degradation

**Problem**: As conversation grows longer (80k+ tokens), AI output quality measurably degrades. Responses become more generic, miss project-specific details, and "forget" earlier conversation context. The 200k window isn't equally useful throughout.

**Current Solution**: Context Recovery protocol + Token Budget rules
- Context Recovery 4-step: ordered re-read after /compact or new session (don't re-read everything, read indexes then on-demand)
- Token Budget rules in CLAUDE.md:
  - /compact at Phase completion boundaries, not mid-task
  - Large files (>300 lines): use offset+limit for segmented reading
  - Structured output (JSON/tables) preferred over long-form prose
  - Read indexes (INDEX.md) first, then leaf docs on demand
- planning-with-files persists state as files — immune to context degradation

**Strength**: ★★★☆☆ — Provides guidelines but no automated enforcement. AI can still bloat context.

**Future Enhancement**: Token pressure monitoring + auto-compact suggestion
- Track approximate token usage during conversation
- At 60% capacity: suggest /compact at next Phase boundary
- At 80% capacity: warn that quality may be degrading
- Auto-suggest which conversation segments can be safely compacted
- Reference: GSD project uses isolated 200k contexts per "Wave" to avoid degradation entirely — a more aggressive approach we could learn from

---

## Category 3: Quality Control

### 9. "Done" Without Verification

**Problem**: AI says "I've implemented the feature and everything should work" without actually running tests, checking for compilation errors, or verifying the output. Confidently wrong.

**Current Solution**: superpowers verification Iron Law + Stop hook
- Iron Law: "NO COMPLETION CLAIMS WITHOUT FRESH EVIDENCE"
- Before claiming "done": tests must pass + lint must pass + security review must pass
- Stop hook (planning-with-files): checks whether current Phase tasks are actually complete
- CLAUDE.md rule: "Before claiming done → run Standard quality gate"

**Strength**: ★★★★★ — System-level enforcement. AI cannot claim completion without evidence.

**Future Enhancement**: — (Current solution is sufficient)

---

### 10. No Tests — Code Ships Without Test Coverage

**Problem**: AI writes implementation code, "forgets" to write tests, and declares done. Or writes tests after implementation that just validate the current (possibly buggy) behavior instead of specifying correct behavior.

**Current Solution**: superpowers TDD Iron Law
- "NO CODE WITHOUT FAILING TEST FIRST"
- Enforced via SessionStart hook: TDD methodology injected at every session
- Red Flags table intercepts: "Write code first, add tests later" → "That's not TDD, that's tests as an afterthought"
- Verification step requires tests to actually pass

**Strength**: ★★★★★ — System-level enforcement via psychological defense. Remarkably effective.

**Future Enhancement**: — (Current solution is sufficient)

---

### 11. Skips Code Review

**Problem**: AI writes code, tests pass, ships it. Nobody reviews for: architectural consistency, security implications, performance gotchas, readability, or whether it actually solves the right problem.

**Current Solution**: superpowers code-review
- `superpowers:requesting-code-review` dispatches a separate reviewer subagent
- Reviewer checks: correctness, security, test coverage, performance, compatibility
- Agent reviews Agent — different "perspective" from the implementer

**Strength**: ★★★★☆ — Effective when invoked. Gap: requires user to say "review this code."

**Future Enhancement**: Auto-trigger review on PR creation
- When user says "create PR" or pushes to a feature branch → auto-dispatch reviewer
- Block PR creation until review passes (or user explicitly overrides)

---

### 12. Security Vulnerabilities Introduced

**Problem**: AI writes `os.system(f"rm {user_input}")` or `query = f"SELECT * FROM users WHERE id={id}"` without thinking twice. Common CWE patterns slip in because AI prioritizes "make it work" over "make it safe."

**Current Solution**: Three-layer security defense
- **CLAUDE.md rules**: MUST NOT eval()/exec() with user input (CWE-95), MUST NOT shell=True with user args (CWE-78), MUST NOT f-string SQL (CWE-89), MUST NOT commit .env/*.key/*.pem (CWE-798)
- **docs/conventions/secure-coding.md**: 15 high-risk CWE defenses + OWASP Top 10 coding standards + AI Agent security red lines
- **security-review Skills**: Project-specific audit rules generated by security-review-skill-creator
- **Enterprise Hook** (optional): PostToolUse write-scan detects eval/exec/shell=True/SQL concat patterns in real-time

**Strength**: ★★★★☆ — Strong coverage of known patterns. Gap: Enterprise hooks are opt-in.

**Future Enhancement**: Default-on security scanning
- Move basic pattern detection (eval/exec/shell=True/SQL concat) from Enterprise-only to default
- PostToolUse hook scans every file write for top-5 CWE patterns
- WARNING level (not blocking) to avoid disrupting workflow

---

## Category 4: Code Hygiene & Documentation

### 13. Dead Code Accumulation

**Problem**: AI comments out old code "just in case," leaves unused imports, creates helper functions that end up unused, and doesn't clean up after refactoring. Codebase entropy increases with every session.

**Current Solution**: CLAUDE.md 5 MUST NOT hygiene rules + quality gate
- MUST NOT leave commented-out code (git has history)
- MUST NOT leave debug print/console.log
- MUST NOT leave unused imports/variables/functions
- MUST NOT leave temporary files outside tests/
- MUST NOT leave FIXME/HACK unresolved >1 week
- harness-quality-gate Check #5 (Code Hygiene) verifies these

**Strength**: ★★★★☆ — Rules are clear and quality gate checks them. Gap: no automated lint integration.

**Future Enhancement**: Lint integration in quality gate
- Quality gate auto-runs project linter (eslint/flake8/clippy/etc.) as part of Check #2
- Catches dead code that text rules might miss

---

### 14. Documentation Goes Stale

**Problem**: AI changes the API endpoint from `/api/users` to `/api/v2/users`, but doesn't update `docs/architecture/api-reference.md`. Over time, docs become actively misleading — worse than no docs.

**Current Solution**: Three-tier documentation sync
- **Lite** (after editing source code): CLAUDE.md behavior rule — self-check: does a matching doc exist? If yes and content affected → update now
- **Standard** (claiming "done"): Dynamic scan: `git diff --name-only HEAD` → grep docs/ for references to changed modules → flag unupdated docs
- **Full** (quality gate): All 7 checks including doc sync with special case detection (DB schema, API routes, build config)
- Key design: **no hardcoded file mappings** — dynamically greps docs/ structure to find references

**Strength**: ★★★★☆ — Dynamic detection works across any project. Gap: relies on AI executing the check.

**Future Enhancement**: PostToolUse hook for real-time doc sync reminder
- After every file write, hook checks if a matching doc reference exists in docs/
- Immediate reminder: "You edited api/routes.py — docs/architecture/api-reference.md references this module. Update needed?"
- Shift from "check at commit time" to "check at write time"

---

### 15. Root Directory Pollution

**Problem**: AI creates `test_quick.py`, `debug_output.log`, `fix_bug.py`, `temp_data.json` in the project root. Over time, root directory becomes a junk drawer that makes the project look unprofessional and confuses new developers.

**Current Solution**: CLAUDE.md rule + harness-audit
- Rule: temporary files go in tests/, debug files deleted after use
- harness-audit scans root directory for non-standard files (not in .gitignore, not config files)

**Strength**: ★★★☆☆ — Rules exist but enforcement is weak. AI often "forgets" in the moment.

**Future Enhancement**: Auto-detect and move temporary files
- PostToolUse hook: if a file is created in root and matches temp patterns (test_*, debug_*, temp_*, fix_*) → warn and suggest moving to tests/ or deleting

---

### 16. FIXME/HACK Debt

**Problem**: AI writes `# FIXME: handle edge case` or `# HACK: workaround for library bug` and never comes back to it. These accumulate silently. Six months later, codebase has 50 FIXMEs that nobody understands.

**Current Solution**: CLAUDE.md rule + harness-audit
- Rule: FIXME/HACK must be resolved within 1 week
- harness-audit flags stale FIXMEs/HACKs

**Strength**: ★★★☆☆ — Rule exists but no automated age tracking.

**Future Enhancement**: Quality gate tracks FIXME age
- `git blame` on FIXME lines → calculate age
- Quality gate warns on FIXMEs older than 7 days
- harness-audit reports FIXME inventory with ages

---

## Category 5: Hallucination & Reliability

### 17. API Hallucination — AI Invents Non-Existent APIs

**Problem**: AI writes `response = requests.get(url, retry=3)` (requests doesn't have a `retry` parameter) or `import pandas; df.to_parquet(compression='zstd')` (valid, but AI might hallucinate parameter names for less common libraries). Code looks correct but fails at runtime.

**Current Solution**: Challenger role + Red Flags table
- Challenger verifies claims against actual source code or documentation
- "This API supports X" → Challenger demands: show the doc or test proving it
- superpowers Red Flags: intercepts overconfident claims

**Strength**: ★★★☆☆ — Effective when Challenger is invoked. Not always triggered for small API calls.

**Future Enhancement**: Auto-verify imports against installed packages
- After writing import statements, auto-check: does this function/parameter actually exist?
- Run quick validation: `python -c "import X; help(X.function)"` or check type stubs
- Flag hallucinated APIs before they cause runtime errors

---

### 18. Confident But Wrong

**Problem**: AI states "PostgreSQL doesn't support UPSERT" (it does, since 9.5) or "This function is O(n)" (it's actually O(n²)) with the same confidence as correct statements. No hedging, no uncertainty markers. User trusts AI and makes decisions based on wrong facts.

**Current Solution**: Challenger VERDICT system
- Every claim gets: CONFIRMED (with evidence) / REFUTED (with counter-evidence) / UNVERIFIED
- Evidence requirement: no claim accepted without proof
- Escalation: 2+ REFUTED → BLOCK entire proposal

**Strength**: ★★★☆☆ — Strong framework, but only active when Challenger role is explicitly invoked.

**Future Enhancement**: Mandatory citation for architectural claims
- When AI makes claims about technology capabilities, performance characteristics, or compatibility → require a source (docs URL, test result, or source code reference)
- "I believe X because [source]" pattern enforced in design documents

---

### 19. Blind Copy-Paste of Bad Patterns

**Problem**: Codebase has an old function using `eval()` for JSON parsing. AI sees it, thinks "this is the project pattern," and writes 3 more functions using `eval()`. Bad patterns propagate because AI treats existing code as authoritative.

**Current Solution**: CLAUDE.md MUST NOT rules + security standards
- Explicit ban on known dangerous patterns (eval, exec, shell=True, SQL concat)
- secure-coding.md lists 15 CWE defenses as mandatory baselines

**Strength**: ★★★☆☆ — Covers known dangerous patterns. Gap: doesn't catch project-specific anti-patterns.

**Future Enhancement**: Anti-pattern database from pitfall records
- Automatically build a project-specific "don't do this" list from docs/pitfalls/ and claudeception Skills
- When AI is about to replicate a pattern that matches a known pitfall → warn: "This pattern was flagged as problematic: [link to pitfall]"

---

## Category 6: Collaboration & Workflow

### 20. No Role Separation

**Problem**: Same AI instance does requirements analysis, architecture design, implementation, testing, and code review. Like one person being architect, developer, QA, and reviewer — conflicts of interest everywhere. "I designed it, so of course my implementation is correct."

**Current Solution**: Agent Team with 4 base roles
- **Architect (A)**: Planning, design, docs — must brainstorm → user approval → design doc
- **Challenger (C)**: Adversarial review — never accepts claims without evidence, never modifies code
- **Engineer (E)**: Coding, fixes — must TDD, must not touch architecture-level config
- **Tester (T)**: Write tests, verify — must not modify business code, only report bugs
- Each role has strict behavioral constraints and different doc access
- Extensible: Frontend / Backend / DevOps / DBA / Security roles

**Strength**: ★★★★☆ — Clear separation when used. Gap: role transitions require manual orchestration.

**Future Enhancement**: Workflow orchestration (auto role transitions)
- Define workflow: Architect → Challenger → Engineer → Tester → Architect (review)
- System automatically transitions between roles at completion of each stage
- Block Engineer from starting until Challenger APPROVE on design
- Block "done" claim until Tester verifies

---

### 21. Experience Not Captured

**Problem**: AI spends 30 minutes debugging a subtle race condition in the export feature. Finds the fix. Session ends. Next developer (or next AI session) hits the same race condition. The debugging time was a one-time cost that benefited nobody else.

**Current Solution**: claudeception continuous learning
- UserPromptSubmit hook continuously evaluates: "is there extractable knowledge from this task?"
- Trigger conditions: debugged >10 minutes on non-documented issue, discovered workaround through trial-and-error, project-specific non-obvious pattern
- Quality gate: reusable + non-trivial + specific + verified + actionable
- Output: SKILL.md files with semantic description for auto-matching

**Strength**: ★★★★☆ — Good extraction mechanism. Gap: only triggers on explicit /claudeception or hook evaluation.

**Future Enhancement**: Auto-extract on session end
- When session ends (or user says "done for today"), automatically evaluate the session for extractable knowledge
- Don't wait for user to invoke /claudeception — proactively suggest: "This session had 2 extractable learnings. Create Skills?"

---

### 22. No Project Health Visibility

**Problem**: You set up all the guardrails, but how do you know they're working? Are docs actually being kept in sync? Are hooks properly configured? Has someone disabled a critical check? No dashboard, no metrics, no way to know.

**Current Solution**: harness-audit command
- Scans: CLAUDE.md exists and ≤150 lines, docs/ structure complete, .harness/ exists, core Skills installed, Hooks configured, security-review Skill generated, no .env tracked by git, root directory clean
- Output: checklist + score + remediation suggestions

**Strength**: ★★★☆☆ — Point-in-time snapshot. Gap: no trend tracking or continuous monitoring.

**Future Enhancement**: Trend tracking across audits
- Store audit results with timestamps
- Track: score over time, which checks regress, which improve
- Weekly summary: "Your harness health score dropped from 85 to 72 — doc sync degraded"

---

## Category 7: Security & Compliance

### 23. Secret Leaks in Commits

**Problem**: AI creates a `.env` file for testing, then accidentally `git add .` includes it. Or hardcodes an API key "just for testing" and forgets to remove it. Secrets in git history are nearly impossible to fully remove.

**Current Solution**: Enterprise Hook + CLAUDE.md rules
- **Enterprise Hook**: PreToolUse(Bash) intercepts `git commit` → scans for .env, *.key, *.pem, API key patterns
- **CLAUDE.md rule**: MUST NOT commit .env / *.key / *.pem (CWE-798)
- harness-audit checks: no .env tracked by git

**Strength**: ★★★★☆ — Strong with Enterprise hooks. Gap: open-source mode relies on text rules only.

**Future Enhancement**: Default-on secret scanning
- Move basic secret detection (high-entropy strings, known key patterns) from Enterprise-only to default
- Lightweight pre-commit check that doesn't require Enterprise mode
- Zero-config: works out of the box after `harness` initialization

---

### 24. Supply Chain Attacks — Malicious Dependencies

**Problem**: AI suggests `pip install cool-package` without checking: is this package legitimate? Has it been typosquatted? Does it have post-install hooks that exfiltrate data? AI treats all packages as equally trustworthy.

**Current Solution**: supply-chain-audit + sca-ai-denoise
- **supply-chain-audit**: Detects poisoning in 8 languages (Python .pth, npm postinstall, Go init() backdoors, Rust build.rs, Ruby extconf.rb, Java Maven plugins, PHP composer scripts)
- **sca-ai-denoise**: AI-powered triage of SCA vulnerability findings — P0-P3 risk classification, filters noise (DoS, local privilege escalation), focuses on actually exploitable vulns

**Strength**: ★★★★☆ — Comprehensive detection when invoked. Gap: not triggered automatically on dependency changes.

**Future Enhancement**: Auto-audit on dependency changes
- When AI modifies package.json / requirements.txt / go.mod / Cargo.toml → auto-trigger supply-chain-audit
- Check new dependencies for: known typosquats, suspicious post-install hooks, recent ownership changes
- Block commit if high-risk dependency detected

---

## Summary Matrix

| # | Pain Point | Strength | Status |
|---|-----------|----------|--------|
| 1 | AI codes before thinking | ★★★★★ | Solved |
| 2 | Plans collapse mid-task | ★★★★☆ | Strong, enhancing |
| 3 | One-shot answers | ★★★★☆ | Strong |
| 4 | No adversarial review | ★★★☆☆ | Partial, enhancing |
| 5 | Context loss after /compact | ★★★★☆ | Strong, enhancing |
| 6 | New session cold start | ★★★★★ | Solved |
| 7 | Repeated mistakes | ★★★★☆ | Strong, enhancing |
| 8 | Context quality degradation | ★★★☆☆ | Partial, enhancing |
| 9 | "Done" without verification | ★★★★★ | Solved |
| 10 | No tests | ★★★★★ | Solved |
| 11 | Skips code review | ★★★★☆ | Strong, enhancing |
| 12 | Security vulnerabilities | ★★★★☆ | Strong, enhancing |
| 13 | Dead code accumulation | ★★★★☆ | Strong, enhancing |
| 14 | Documentation goes stale | ★★★★☆ | Strong, enhancing |
| 15 | Root directory pollution | ★★★☆☆ | Partial, enhancing |
| 16 | FIXME/HACK debt | ★★★☆☆ | Partial, enhancing |
| 17 | API hallucination | ★★★☆☆ | Partial, enhancing |
| 18 | Confident but wrong | ★★★☆☆ | Partial, enhancing |
| 19 | Blind copy-paste | ★★★☆☆ | Partial, enhancing |
| 20 | No role separation | ★★★★☆ | Strong, enhancing |
| 21 | Experience not captured | ★★★★☆ | Strong, enhancing |
| 22 | No project health visibility | ★★★☆☆ | Partial, enhancing |
| 23 | Secret leaks | ★★★★☆ | Strong, enhancing |
| 24 | Supply chain attacks | ★★★★☆ | Strong, enhancing |

**Overall**: 4 fully solved (★★★★★), 12 strong (★★★★☆), 8 partial (★★★☆☆), 0 unsolved.

### Legend

- ★★★★★ = Fully solved with system-level enforcement — no planned changes
- ★★★★☆ = Strong solution with minor gaps — enhancement planned
- ★★★☆☆ = Partial solution — significant enhancement planned
- **Solved** = No further work needed
- **Strong, enhancing** = Works well, planned improvement
- **Partial, enhancing** = Works but has known gaps, active enhancement planned
