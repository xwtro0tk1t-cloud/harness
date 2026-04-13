# Harness Handoff — Deep Context Transfer

---
description: Trigger when user says "harness handoff", "handoff context", "new agent takeover", "full project context", "load all context", "crash recovery", "transfer context", "project overview full". Provides deep context recovery (~8k tokens) for new agent handoff or crash recovery. Do NOT trigger for: "continue writing X function" (just code), "help me understand this file" (single file read), "what is this project" (too vague, use harness guide).
---

## Behavior

Provide deep context recovery for new agent handoff or crash recovery scenarios. Core principle: **Index-First, Fragment-on-Demand**.
For lightweight same-session /compact recovery, use `harness resume` (~3k tokens).

---

## Difference from Claude Code Default Behavior

Claude Code auto-loads only CLAUDE.md. This skill adds:
- a) task_plan Phase anchor (not just project overview)
- b) progress.md tail (recent activity context)
- c) docs/ INDEX tree (document navigation map)
- d) MEMORY.md project-specific memory
- e) .harness state (project scaffold status)
- f) git log (recent commit history)

---

## Read-tool Steps (1-5, deterministic file reads)

### Step 1: CLAUDE.md
- Read project CLAUDE.md
- If >300 lines → read tail 300 (recent conventions/rules are more valuable)

### Step 2: task_plan.md Phase Anchor
- Use regex `^#{1,3}\s.*([Pp]hase)` to locate current Phase
- Extract **±50 lines** around match
- WIP signals: unchecked `- [ ]`, 🚧, WIP, in progress, (doing)
- If no task_plan.md → skip

### Step 3: progress.md
- <500 lines → read all
- ≥500 lines → read tail 200

### Step 4: docs/ INDEX Tree
- Read `docs/INDEX.md` if exists
- Glob `docs/**/INDEX.md`, read up to **10** files
- If none → skip

### Step 5: MEMORY.md Best-Match
```
target = cwd.replace('/', '-').lstrip('-')
candidates = glob('~/.claude/projects/*/memory/MEMORY.md')
matches = [c for c in candidates if c.parents[1].name.lstrip('-') == target]
```
- `len == 1` → read it
- `len == 0` → skip
- `len > 1` → list candidates, ask user to choose

---

## Bash-tool Steps (6-7, may fail gracefully)

### Step 6: .harness/ Directory Check
```bash
test -d .harness && ls .harness/ || echo "No .harness directory"
```

### Step 7: git log
```bash
git log --oneline -20 2>/dev/null || echo "No git history or not a git repo"
```

---

## Output: 3-Segment Structured Summary

```
═══ Project Overview ═══
Main goal (from CLAUDE.md Project Overview or task_plan title)
Git status (recent 20 commits / "no git")
.harness status (contents / "none")

═══ Current Work ═══
Current Phase / latest commit / last stopped at / unfinished items

═══ Available Resources ═══
Document structure (docs/ INDEX tree)
Memory categories (MEMORY.md sections)
Harness state (.harness/ if present)

Next: Tell me what you want to do, I'll read specific doc fragments on demand
```

---

## Token Budget

Target **8-12k tokens**:
- CLAUDE.md ≤300 lines ≈ 2-3k
- task_plan Phase ±50 lines ≈ 2k
- progress tail 200 lines ≈ 2k
- 10 INDEX files ≈ 2-3k
- MEMORY.md ≈ 1-1.5k
- git log -20 ≈ 0.3k

**If exceeded**: truncate progress to 100 lines first, then INDEX to 5 files.

---

## Empty Rendering

- If a row field is empty → **omit the entire row**
- If all 3 rows in a segment are empty → **omit segment with its title**
- If everything is empty → print fallback:
  > No project context found. Say `harness` to initialize a new project.

## Graceful Degradation

Any file missing → output "Step skipped (file not found)" and continue. Never error out.
