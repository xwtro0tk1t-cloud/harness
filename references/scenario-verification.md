# Scenario Integration Verification (Step 8 Detailed Reference)

After initialization is complete, you must verify that the following 11 scenarios correctly trigger documentation updates.

Present the verification checklist to the user and suggest confirming each item during the first development task.

---

## Scenario 1: Feature Development Complete

**Trigger condition**: Agent B finishes implementation, Agent C passes verification

**Expected behavior**:
- Agent A updates docs/implementation/\<module\>.md
- Agent A updates docs/architecture/api-reference.md (if new APIs)
- Agent A updates docs/architecture/db-schema.md (if new tables)
- PostToolUse hook reminds to update progress.md

**Safeguard mechanism**: CLAUDE.md behavior rule #3 + planning-with-files PostToolUse hook

---

## Scenario 2: Debug Session Ends

**Trigger condition**: An issue that took over 10 minutes to debug is resolved

**Expected behavior**:
- Record to docs/pitfalls/\<topic\>.md
- Or /claudeception auto-extracts it as a Skill

**Safeguard mechanism**: CLAUDE.md behavior rule #4 + claudeception UserPromptSubmit hook

---

## Scenario 3: New Plan Created

**Trigger condition**: User says /plan or starts a non-trivial task

**Expected behavior**:
- Create task_plan.md + findings.md + progress.md in the project root
- UserPromptSubmit hook displays plan status on every input
- PreToolUse hook re-reads the plan before every tool call

**Safeguard mechanism**: planning-with-files 4 hooks + CLAUDE.md behavior rule #7

---

## Scenario 4: Architecture Adjustment

**Trigger condition**: Modify database schema / add new module / adjust deployment architecture

**Expected behavior**:
- Agent A brainstorms first, only proceeds after user approval
- Updates docs/architecture/system-overview.md
- Updates docs/architecture/tech-stack.md (if tech stack changes)
- Updates docs/architecture/db-schema.md (if schema changes)

**Safeguard mechanism**: CLAUDE.md HARD-GATE rule + superpowers:brainstorming

---

## Scenario 5: Task Completion Declaration

**Trigger condition**: Agent is about to claim "done"

**Expected behavior**:
- Must have fresh verification evidence (tests pass + lint passes)
- Stop hook checks whether all Phases are complete

**Safeguard mechanism**: superpowers:verification-before-completion + planning-with-files Stop hook

---

## Scenario 6: Refactoring

**Trigger condition**: User requests module refactoring / extracting shared logic / restructuring code

**Expected behavior**:
- Create a plan first (using .harness/templates/refactor.md template)
- Define Invariants (behavior unchanged, API unchanged, all tests pass)
- planning-with-files continuously tracks refactoring progress
- After refactoring, all existing tests must pass

**Safeguard mechanism**: planning-with-files 4 hooks + refactor.md template constraints + superpowers TDD methodology

---

## Scenario 7: PR Creation / Code Review

**Trigger condition**: Code changes ready to commit or create a PR

**Expected behavior**:
- Pre-commit self-check: tests pass + lint passes + docs synchronized
- Trigger superpowers:requesting-code-review methodology
- For security-sensitive changes (auth/crypto/API), remind to use security-review skill

**Safeguard mechanism**: CLAUDE.md review rules + superpowers:requesting-code-review (injected at SessionStart)

---

## Scenario 8: Dependency Update / SCA

**Coverage**:
- Covered by the security scanning platform (SCA scan + sca-ai-denoise denoising)
- Harness does not duplicate this effort

---

## Scenario 9: DB Migration

**Trigger condition**: Add/modify database table structure, create migration files

**Expected behavior**:
- Create a plan first, including a rollback strategy
- Update docs/architecture/db-schema.md
- Remind about data backup (production environment)
- Migration files require review

**Safeguard mechanism**: planning-with-files plan tracking + CLAUDE.md doc sync rules + "Never delete app-data volume" rule

---

## Scenario 10: Hotfix / Emergency Fix

**Coverage**:
- Shares all mechanisms with Scenario 1 (brainstorming can be skipped, but TDD + verification cannot)
- Security scanning platform provides incremental scanning after changes

---

## Scenario 11: Code Hygiene Cleanup

**Trigger condition**: Temp files in root directory / unused imports / debug output / commented-out code discovered

**Expected behavior**:
- Clean up dead code, temp scripts, debug output
- Do not accidentally delete code that is still in use (confirm if in doubt)
- claudeception evaluates whether the cleanup experience is worth capturing

**Safeguard mechanism**: CLAUDE.md code hygiene 5 MUST NOT rules + claudeception knowledge extraction reminder

---

## Troubleshooting

If any scenario does not trigger correctly, check:
1. Whether `.claude/settings.json` hooks are correctly configured
2. Whether CLAUDE.md behavior rules are written
3. Whether the corresponding Skill is installed in `~/.claude/skills/`
