# General Development Conventions

This file contains two parts: coding conventions + Agent behavior rules.
During Harness initialization, these are injected into `docs/conventions/must-follow.md` and the CLAUDE.md behavior rules section.

---

## Part A: Coding Conventions

### Git Commit Convention

Format: `<type>(<scope>): <subject>`

Types:
- `feat` — New feature
- `fix` — Bug fix
- `refactor` — Refactoring (no behavior change)
- `docs` — Documentation changes
- `test` — Test-related
- `chore` — Build/tooling/dependency changes
- `perf` — Performance optimization
- `security` — Security fix

Rules:
- Subject no longer than 72 characters
- Use English, start with verb infinitive (add / fix / update / remove)
- One commit does one thing
- Don't commit .env / secrets / large binary files

### Testing Convention

- New features must have unit tests
- Bug fixes must have regression tests (write failing test first, then fix — TDD)
- Test naming: `test_<feature>_<scenario>_<expected_result>`
- Tests run independently, no dependency on execution order
- Mock external dependencies, don't mock internal logic

### Branch Management

- `main` / `master` — Production branch, only merge via PR
- `feature/<name>` — Feature branch
- `fix/<name>` — Fix branch
- `release/<version>` — Release branch (if needed)

---

## Part B: Agent Behavior Rules (MUST / MUST NOT Rules)

The following rules are written to the project CLAUDE.md "Behavior Rules" section to ensure the Agent follows them throughout the development process.
Combined with superpowers / planning-with-files / claudeception hooks for layered enforcement.

### 1. Security Review Gate

**Rule**: Any code change MUST undergo security review before commit/merge.

**Trigger conditions**:
- Before submitting a PR
- Before merging code
- When modifying authentication/authorization/encryption/input handling/API endpoint related code

**Execution method** (by priority):
1. If project has a corresponding `security-review-skill-for-<project>` → use that Skill for audit
2. If no dedicated Skill → use `security-review-skill-creator` to generate one first
3. Minimum requirement: manually check the CWE checklist in `docs/conventions/secure-coding.md`

**Checklist**:
- [ ] No SQL injection (parameterized queries)
- [ ] No command injection (subprocess without shell=True)
- [ ] No hardcoded secrets
- [ ] Input validated (type/length/range)
- [ ] Permissions checked (authentication + authorization)
- [ ] No SSRF (URL whitelist)
- [ ] Dependencies have no known critical vulnerabilities

### 2. Mandatory Code Review

**Rule**: Any non-trivial code change MUST go through review before merge.

**Execution method**:
- Use superpowers' `requesting-code-review` skill → auto-dispatch code-reviewer subagent
- Review checklist:
  1. Functional correctness — Is the logic right, are edge cases handled
  2. Security — Does it introduce OWASP Top 10 vulnerabilities
  3. Test coverage — Does new code have tests
  4. Readability — Clear naming, complex logic has comments
  5. Performance — N+1 queries, memory leaks, infinite loops
  6. Backward compatibility — Do API changes break callers
- After review, use `verification-before-completion` skill to verify fixes

**"Iron Law" (from superpowers)**:
> You cannot claim "done" unless there is fresh verification evidence. Skipping review and merging directly = violation.

### 3. Living Documentation

**Rule**: When code changes, MUST sync update corresponding documentation.

**Trigger → Update target**:
| Code Change Type | MUST Update Document |
|-----------------|---------------------|
| Add/delete API endpoints | `docs/architecture/api-reference.md` |
| Modify database schema | `docs/architecture/db-schema.md` |
| Add/modify core modules | `docs/implementation/<module>.md` |
| Modify architecture/dependencies | `docs/architecture/system-overview.md` + `tech-stack.md` |
| Modify config/environment variables | Corresponding deployment/config docs |
| Modify build/test commands | `CLAUDE.md` command quick-reference |

**Execution method**:
- After completing each set of code changes, check the table above and update corresponding docs
- If unsure which doc to update → read CLAUDE.md navigation to find the right path
- Documentation updates and code changes go in the same PR/commit

**MUST NOT**:
- Don't write "TODO: update docs" then forget
- Don't write architecture explanations in code comments (put them in docs/)
- Don't let docs drift from actual code behavior

### 4. Pitfall Recording

**Rule**: When encountering non-trivial issues (debugging >10 min / undocumented problems / trial-and-error), MUST record them.

**Two recording methods** (choose at least one):

**Method A: Write to `docs/pitfalls/`**
```markdown
## [Issue Title]

**Symptoms**: [What behavior, what error messages]
**Root Cause**: [What the actual cause was]
**Solution**: [How it was fixed]
**Prevention**: [How to avoid it in the future]
**Date**: YYYY-MM-DD
```

**Method B: Use claudeception to generate a project Skill**
- Say `/claudeception` or "save this debugging experience as a skill"
- claudeception auto-evaluates quality gates (reusable / non-trivial / specific / verified / actionable)
- Generates Skill to `.claude/skills/<pitfall-name>/SKILL.md`
- Next time a similar issue occurs, the Skill auto-triggers

**What counts as a "pitfall"**:
- Error messages that misled the investigation direction
- Behavior differs from documentation
- Issues caused by config/environment differences
- Dependency version compatibility issues
- Issues found during deployment that can't be reproduced in dev environment

### 5. Code Hygiene / Cleanup

**Rule**: Don't create junk; when you find junk, MUST clean it up.

**MUST DO**:
- Delete unused code (don't comment-preserve, just delete — git history has the record)
- Delete debug print / console.log / TODO temporary code
- Delete unused imports / variables / functions
- Delete generated temp files (test_output.log / debug_*.py / *.pyc)
- Delete outdated docs (if feature is deleted, corresponding docs are deleted too)
- Merge duplicate code (DRY — extract to shared function when 3+ identical patterns exist)

**MUST NOT**:
- Don't keep "just in case" commented-out code blocks
- Don't leave empty except/catch blocks
- Don't leave `# FIXME` / `# HACK` unresolved for more than 1 week
- Don't pile up test scripts in the root directory (put them in tests/)
- Don't leave unused dependencies (periodically clean requirements.txt / package.json)

**Cleanup timing**:
- Before merging each feature/fix branch, review once
- Weekly `make lint` + manual root directory scan
- Refactoring tasks specifically allocate a cleanup phase

### 6. Brainstorm Before Plan

**Rule**: New features / architecture changes / complex refactors MUST go through brainstorming first, with user-approved design before any implementation.

**HARD-GATE (from superpowers:brainstorming)**:
> Do NOT invoke any implementation skill until you have presented a design and the user has approved it.

**Brainstorming flow (6 steps)**:
1. **Explore project context** — Read relevant code and docs, understand current state
2. **Ask clarifying questions** — Confirm requirement boundaries and constraints with user
3. **Propose candidate solutions** — At least 2 options, list trade-offs
4. **Present design** — Include module breakdown, data flow, interface definitions
5. **User approval** — Only continue after user explicitly agrees to the plan
6. **Write design document** — Save to `docs/superpowers/specs/YYYY-MM-DD-<topic>-design.md`

**When to trigger brainstorming**:
- Adding a feature module
- Modifying architecture / major refactor
- Changes spanning multiple modules
- User says "help me think about how to do this" / "design this"

**When to skip** (go straight to planning):
- Clear bug fix (root cause known)
- Documentation updates
- Simple config changes
- User explicitly says "just do it"

### 7. Plan Before Code

**Rule**: Non-trivial tasks (estimated >15 minutes) MUST write a plan before writing code.

**After brainstorming produces design → enter planning phase**:

**Execution method** (two complementary paths):

**Path A: superpowers flow (stricter)**
```
brainstorming (design approved)
  → writing-plans (break into 2-5 min subtasks, each with file paths + code + verification steps)
  → executing-plans / subagent-driven-development (batch execute)
```
Best for: new features, complex refactors

**Path B: planning-with-files flow (lighter)**
```
/plan (create task_plan.md + findings.md + progress.md)
  → progress by Phase
  → update progress.md at each step
```
Best for: bug fixes, small changes, exploratory tasks

**Both can be used together**: superpowers manages "how to break down tasks", planning-with-files manages "state persistence".

### 7. TDD First (Test-Driven Development)

**Rule**: New features and bug fixes MUST write tests first.

**Flow**:
1. RED — Write a failing test
2. GREEN — Write minimal code to make the test pass
3. REFACTOR — Clean up code, keep tests green

**"Iron Law" (from superpowers)**:
> NO PRODUCTION CODE WITHOUT A FAILING TEST FIRST. Skipping tests and writing implementation directly = violation.

### 8. Verify Before Claiming Done

**Rule**: MUST NOT claim "done" unless there is fresh verification evidence.

**Verification checklist**:
- [ ] All tests pass (`make test` / `pytest`)
- [ ] Lint passes (`make lint` / `flake8`)
- [ ] Security review passes (security review checklist)
- [ ] Documentation updated
- [ ] No leftover debug code / TODOs

**"Iron Law" (from superpowers)**:
> NO COMPLETION CLAIMS WITHOUT FRESH VERIFICATION EVIDENCE. "I think it's fine" doesn't count as evidence.

---

## Part C: Rule Injection Locations

During Harness initialization, the above rules are injected to the following locations:

| Rule | Injected To | Enforcement Method |
|------|------------|-------------------|
| Security Review Gate | `CLAUDE.md` + `docs/conventions/must-follow.md` | CLAUDE.md MUST rule + security-review skill |
| Mandatory Code Review | `CLAUDE.md` | superpowers:requesting-code-review hook |
| Living Documentation | `docs/conventions/must-follow.md` | PostToolUse hook reminder |
| Pitfall Recording | `docs/conventions/must-follow.md` | claudeception UserPromptSubmit hook |
| Code Hygiene | `docs/conventions/must-not.md` | CLAUDE.md MUST NOT rules |
| Plan First | `CLAUDE.md` | planning-with-files PreToolUse hook |
| TDD First | `CLAUDE.md` | superpowers:test-driven-development |
| Verify Before Done | `CLAUDE.md` | superpowers:verification-before-completion |
