# Harness Audit — Project Health Check

---
description: Triggered when the user says "harness audit", "project health check", "harness status", "check harness health", or "check project configuration". Scans the project's Harness configuration completeness and outputs a checklist + score + remediation suggestions.
---

## Behavior

Perform a comprehensive health check on the current project, outputting a checklist-format report.

---

## Checklist

### A. Infrastructure (max 25 points)

| # | Check Item | Points | Method |
|---|-----------|--------|--------|
| A1 | CLAUDE.md exists and ≤100 lines | 10 | Read file, check line count |
| A2 | docs/ directory complete (architecture/ + conventions/ + implementation/) | 10 | Check directory existence |
| A3 | .harness/ directory exists (agents/ + templates/) | 5 | Check directory existence |
| A4 | .claude/settings.json exists with hooks configured | 5 | Read and parse JSON |

### B. Skill Ecosystem (max 30 points)

| # | Check Item | Points | Method |
|---|-----------|--------|--------|
| B1 | Three core Skills installed (superpowers + planning-with-files + claudeception) | 15 | Scan ~/.claude/skills/ |
| B2 | Hooks correctly configured (SessionStart + UserPromptSubmit + PreToolUse + PostToolUse + Stop) | 10 | Read .claude/settings.json |
| B3 | Project security-review Skill generated | 5 | Scan ~/.claude/skills/security-review-skill-for-* |

### C. Bundled Skills (max 20 points)

| # | Check Item | Points | Method |
|---|-----------|--------|--------|
| C1 | Skill factories installed (skill-creator + security-review-skill-creator) | 5 | Scan ~/.claude/skills/ |
| C2 | Security Skills installed (sca-ai-denoise + supply-chain-audit + skills-audit) | 5 | Scan ~/.claude/skills/ |
| C3 | Configurable Skill status (web-vuln-analyzer / android-vuln-analyzer) | 5 | Check installation + config files |
| C4 | Command Skills installed (harness-help + harness-audit + harness-quality-gate + harness-guide + harness-cleanup + harness-resume + harness-handoff) | 5 | Scan ~/.claude/skills/harness-* |

### D. Code Hygiene (max 25 points)

| # | Check Item | Points | Method |
|---|-----------|--------|--------|
| D1 | No temp scripts in root directory (test_*.py / debug_*.py / fix_*.py) | 5 | Glob match |
| D2 | .env file not tracked by git | 5 | git ls-files --error-unmatch .env |
| D3 | No hardcoded secrets/tokens in tracked files | 5 | Grep common key patterns |
| D4 | docs/ has recent updates (within 30 days) | 5 | git log check |
| D5 | docs/ INDEX.md two-level structure complete (file-level + section-level ↳ prefix) | 5 | Read INDEX.md and check format |

> **Remediation**: For temp files found in D1, suggest user runs **harness cleanup** for interactive archiving (never deletes, only moves to archive/).

---

## Output Format

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🏥 Harness Project Health Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 Total Score: XX / 100

A. Infrastructure [XX/25]
  ✅ A1: CLAUDE.md exists (XX lines)
  ❌ A2: docs/ missing pitfalls/ directory
  ✅ A3: .harness/ complete
  ⚠️ A4: settings.json missing Stop hook

B. Skill Ecosystem [XX/30]
  ✅ B1: 3/3 core Skills installed
  ⚠️ B2: Missing PreToolUse hook
  ❌ B3: No project security audit Skill generated

C. Bundled Skills [XX/20]
  ✅ C1: 2/2 Skill factories installed
  ✅ C2: 3/3 security Skills installed
  ⚠️ C3: web-vuln-analyzer installed but not configured
  ✅ C4: 7/7 command Skills installed

D. Code Hygiene [XX/25]
  ❌ D1: Found 3 temp scripts in root directory
  ✅ D2: .env not tracked
  ✅ D3: No hardcoded secrets found
  ⚠️ D4: docs/ not updated in over 30 days

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔧 Remediation Suggestions (by priority)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. [High] Generate project security audit Skill
   → Say "generate a security audit skill for this project"

2. [Medium] Add PreToolUse hook
   → Add planning-with-files PreToolUse hook to .claude/settings.json

3. [Low] Clean up root directory temp scripts
   → Move test_*.py to tests/ directory
```

---

## Scoring Guide

| Score Range | Status | Recommendation |
|-------------|--------|---------------|
| 90-100 | 🟢 Healthy | Maintain good practices |
| 70-89 | 🟡 Good | Fix high-priority items |
| 50-69 | 🟠 Needs attention | Recommend completing infrastructure soon |
| <50 | 🔴 Needs repair | Recommend re-running `harness` initialization |
