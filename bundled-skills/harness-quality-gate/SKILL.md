# Harness Quality Gate — Pre-Commit Quality Check

---
description: Triggered when the user says "quality gate", "pre-commit check", "ready to commit", "check before commit", or "run quality checks". Executes comprehensive quality checks before code commits.
---

## Behavior

Execute the following checks in order before code commit. All must pass before recommending commit.

---

## Check Items

### 1. Tests Pass

```
Detect project test framework and run tests:
  Python  → pytest -v (or project-configured test command)
  Node.js → npm test / yarn test
  Go      → go test ./...
  Rust    → cargo test
  Java    → mvn test / gradle test

Verdict:
  ✅ All passed
  ❌ Failing tests → list failed cases, BLOCK commit
  ⚠️ No tests → remind "consider writing tests first"
```

### 2. Lint Passes

```
Detect project linter config and run lint:
  Python  → flake8 / ruff / pylint (per project config)
  Node.js → eslint / prettier
  Go      → golangci-lint run
  Rust    → cargo clippy
  Java    → checkstyle / spotbugs

Verdict:
  ✅ No errors
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
Check if code changes require documentation updates:
  - New/removed API endpoints → docs/architecture/api-reference.md
  - Modified DB schema → docs/architecture/db-schema.md
  - New/modified modules → docs/implementation/<module>.md
  - Modified build commands → CLAUDE.md command quick reference

Verdict:
  ✅ Docs in sync, or no updates needed
  ⚠️ May need updates → list suggested docs to update
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
