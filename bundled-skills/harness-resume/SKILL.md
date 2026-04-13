# Harness Resume — Lightweight Context Recovery

---
description: Trigger when user says "harness resume", "resume context", "recover context", "load context", "resume after compact", "I want to continue where I left off", "restore work context". Lightweight same-session context recovery after /compact. Do NOT trigger for: "continue writing X function" (just code), "help me understand this file" (single file read), bare "resume" without context (too vague), "I'm new here" (use harness handoff instead).
---

## Behavior

Perform lightweight context recovery for the current project. Core principle: **Index-First, Fragment-on-Demand** — only load indexes, read fragments on demand.
This is for same-session /compact recovery only. For new agent handoff or crash recovery, use `harness handoff`.

---

## Steps

### Step 1: task_plan.md Phase Anchor

- If `task_plan.md` exists → Read the file
- Use regex `^#{1,3}\s.*([Pp]hase)` to locate current Phase heading (covers `#`/`##`/`###`)
- Extract **±30 lines** around the match (shrink to ±15 if token budget exceeded)
- WIP signals: unchecked `- [ ]`, 🚧, WIP, in progress, (doing)
- If no `task_plan.md` → skip, output "No task_plan.md found"

### Step 2: MEMORY.md Best-Match

Locate the project-specific MEMORY.md using this algorithm:

```
target = cwd.replace('/', '-').lstrip('-')
candidates = glob('~/.claude/projects/*/memory/MEMORY.md')
matches = [c for c in candidates if c.parents[1].name.lstrip('-') == target]
```

- `len == 1` → Read that file (first 50 lines, index section)
- `len == 0` → Skip
- `len > 1` → List candidates and ask user to choose

### Step 3: docs/ INDEX Tree

- Read `docs/INDEX.md` if it exists
- Glob `docs/**/INDEX.md`, read up to 5 files
- If no INDEX files → skip

### Step 4: Output Structured Summary

```
📍 Current Phase: [Phase name / status]
⏳ Unfinished: [unchecked items]
⏸ Last stopped at: [latest progress entry]
🧠 Relevant memory: [MEMORY.md relevant entries]
📚 Doc index: [INDEX tree summary]

Next: Tell me what you want to do, I'll read specific doc fragments on demand
```

---

## Token Budget

Target **3-5k tokens**:
- Phase ±30 lines ≈ 1-2k (shrink to ±15 if budget tight)
- MEMORY ≤50 lines ≈ 0.5-1k
- INDEX ≤5 files ≈ 0.5-1k

If exceeded, truncate Phase to ±15 lines first.

---

## Empty Rendering

- If a row field is empty → **omit the entire row**
- If all 4 core rows are empty → print fallback:
  > No work context found — this may be a new project. Say `harness` to start initialization.

## Graceful Degradation

Any file missing → skip that step, output "Step skipped (file not found)" and continue. Never error out.
