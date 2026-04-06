# Harness Quality Gate — Pre-Commit Quality Check

---
description: Triggered when the user says "quality gate", "pre-commit check", "ready to commit", "check before commit", "run quality checks", or "done"/"complete" (Standard level auto-trigger). Executes quality checks before code commits at three levels — Lite (doc sync reminder), Standard (hygiene + docs + progress), Full (all 7 checks).
---

## Check Levels

| Level | Trigger | Checks |
|-------|---------|--------|
| **Lite** | After editing source code (CLAUDE.md behavior rule) | Doc sync self-check only (zero cost) |
| **Standard** | Claiming "done" / "complete" | #4 Documentation Sync + #5 Code Hygiene + #6 Progress Update |
| **Full** | "quality gate" / "ready to commit" / "pre-commit check" | All 7 checks below |

When triggered at Standard level, run only checks #4, #5, #6 and output the report.
When triggered at Full level, run all checks in order. All must pass before recommending commit.

---

## Check Items

### 1. Tests Pass

```
Evidence-first check — avoid re-running if recently verified:

  1. Check progress.md for "tests passed" / "all tests pass" within current task
  2. Check git log --oneline -5 for test-related commits by Tester agent
  3. If evidence found AND no source code changed since then:
     → ✅ Tests passed (verified by Tester agent, no code changes since)
     → Skip re-run
  4. If no evidence or code changed since last test:
     → Detect project test framework and run tests:
       Python  → pytest -v (or project-configured test command)
       Node.js → npm test / yarn test
       Go      → go test ./...
       Rust    → cargo test
       Java    → mvn test / gradle test

Verdict:
  ✅ All passed (or recently verified — skip re-run)
  ❌ Failing tests → list failed cases, BLOCK commit
  ⚠️ No tests → remind "consider writing tests first"
```

### 2. Lint Passes

```
Evidence-first check — same as Tests:

  1. Check progress.md / recent output for "lint passed" / "no lint errors"
  2. If verified recently AND no code changed since → skip re-run
  3. Otherwise detect project linter config and run lint:
     Python  → flake8 / ruff / pylint (per project config)
     Node.js → eslint / prettier
     Go      → golangci-lint run
     Rust    → cargo clippy
     Java    → checkstyle / spotbugs

Verdict:
  ✅ No errors (or recently verified — skip re-run)
  ⚠️ Warnings only → list but don't block
  ❌ Errors found → BLOCK commit
```

### 3. Security Review

```
Check if changes touch security-sensitive areas:
  - Auth/authorization code changes → suggest using security-review skill
  - New database queries → check for SQL concatenation (CWE-89)
  - New shell calls → check for command injection (CWE-78)
  - New user input handling → check for XSS/SSRF
  - New dependencies → suggest running supply-chain-audit

Verdict:
  ✅ No security-sensitive changes, or review passed
  ⚠️ Security-sensitive changes → recommend review before commit
  ❌ Clear security issue found → BLOCK commit
```

### 4. Documentation Sync

```
Dynamically detect which docs need updating (do NOT hardcode file mappings):

  1. Run: git diff --name-only HEAD → list changed source files
  2. Scan docs/ directory structure to understand existing doc organization
  3. For each changed source file:
     - Search docs/ for references to the changed module/file name
       (grep the filename, class names, or function names in docs/)
     - If a matching doc exists AND was NOT also modified → flag ⚠️
  4. Special case detection (infer from project, not hardcode):
     - Changed files contain DB migration/schema patterns
       AND a db-schema doc exists → check if updated
     - Changed files contain API route/endpoint definitions
       AND an api-reference doc exists → check if updated
     - Changed files are build config (pyproject.toml/package.json/Cargo.toml/go.mod/Makefile)
       AND CLAUDE.md has a command section → check if commands changed

Verdict:
  ✅ Docs in sync, or no matching docs found
  ⚠️ May need updates → list the doc file + the source change that triggered it
```

### 5. Code Hygiene

```
Scan changed files:
  - No commented-out code blocks
  - No debug print / console.log
  - No unused imports
  - No temp test scripts in root directory
  - No hardcoded secrets/tokens

Verdict:
  ✅ Code is clean
  ⚠️ Hygiene issues found → list files and line numbers
```

### 6. Progress Update

```
If using planning-with-files:
  - Check if progress.md reflects current changes
  - Check task_plan.md Phase status

Verdict:
  ✅ Progress updated
  ⚠️ Progress files not updated → remind to update
  — Not using planning-with-files → skip
```

### 7. Commit Format

```
Recommend Conventional Commit format:
  feat: / fix: / refactor: / docs: / test: / chore:

If commit-msg-check hook is configured, this is handled automatically.
```

---

## Output Format

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚦 Quality Gate Check Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ✅ Tests passed (42 passed, 0 failed)
  ✅ Lint passed (0 errors, 2 warnings)
  ⚠️ Security review: new SQL query added, recommend checking parameterization
  ✅ Documentation in sync
  ⚠️ Code hygiene: src/utils.py:23 has debug print
  ✅ Progress updated
  ✅ Commit format ready

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Verdict: ⚠️ OK to commit, recommend fixing 2 warnings first
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Remediation suggestions:
1. src/service/query.py:45 — use parameterized query instead of f-string
2. src/utils.py:23 — remove print("DEBUG: ...")
```

---

## Verdict Logic

| Condition | Verdict |
|-----------|---------|
| All ✅ | 🟢 Ready to commit |
| Has ⚠️ no ❌ | 🟡 OK to commit, recommend fixing warnings |
| Has ❌ | 🔴 Not recommended, fix issues first |
