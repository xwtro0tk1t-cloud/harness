# Harness Cleanup — Interactive Temp File Archive

---
description: Trigger when user says "harness cleanup", "cleanup temp files", "archive temp files", "clean up root junk", "project cleanup", "archive junk files". Scans project root for temp files, interactively archives to archive/ directory. NEVER deletes — only moves. Do NOT trigger for: deleting files (this skill only moves), cleaning dependencies (use package manager), cleaning git history.
---

## Behavior

Scan project root directory only (not recursive) for temp/junk files. Interactively archive to `archive/YYYY-MM-DD/`.
**Never deletes** — only moves. Works with `harness-audit` (passive detection).

---

## Scan Scope & Exclusions

### Scan Scope
Project root directory only, no recursion.

### Static Exclusion List
```
archive/**  .git/**  node_modules/**  venv/**  .venv/**
dist/**  build/**  .harness/**  __pycache__/**
.pytest_cache/**  .mypy_cache/**  .tox/**  .eggs/**  *.egg-info/**
```

### Dynamic Exclusion List
```
archive*/  *_archive/  _archive*/
backup*/  *_backup/  _backup*/
old_*/  _old/  trash/  .trash/
```
- Self-marker: any directory containing README.md with first line "harness-cleanup archive" → exclude
- User extension: `.harness/cleanup-exclude-dirs` (one glob pattern per line)

---

## File Detection Rules

### Strong Signal (unconditional)
```
debug_*.py  fix_*.py  tmp_*  scratch_*  wip_*.py
*.bak  foo.py  bar.py  baz.py  qux.py
scratch_*.md  wip_*  NOTES.md  output.txt
```

### Weak Signal: test_*.py (conditional)

Check pytest testpaths in official precedence order:
1. `pytest.ini` — `testpaths` setting
2. `pyproject.toml` `[tool.pytest.ini_options]` — `testpaths`
3. `tox.ini` `[pytest]` — `testpaths`
4. `setup.cfg` `[tool:pytest]` — `testpaths`

**Additional signals** (raise threshold to 20): `noxfile.py` exists / `[tool.hatch.envs.*.scripts]` contains pytest / Makefile has pytest target

Logic:
- testpaths configured AND root test_*.py is outside testpaths → **strong signal** (unconditional)
- No config AND root has >10 test_*.py → suggest (heuristic threshold, adjust after pilot)
- Standard pytest project (testpaths points to tests/) → skip

---

## Dirty-Check (pre-archive state detection)

Use `git status --porcelain -- "$file" | cut -c1-2` to detect file git state:

| Code | Meaning | Color | Interaction |
|------|---------|-------|-------------|
| `""` | clean_tracked | 🟡 Yellow warning | "File is committed, can git rm after archive" |
| `??"` | untracked | 🟢 Green (primary target) | Archive directly |
| ` M`/`M `/`MM` | dirty_tracked | 🔴 Red warning | "Has uncommitted changes, consider committing first" |
| `A `/`AM` | staged | 🔴 Red strong warning | "Already staged, need to unstage before archiving" |
| Other | other | 🔴 Red | "Unknown state, please confirm before proceeding" |

**Important**: Do NOT use `git diff --quiet HEAD -- <file>` — it returns 0 for untracked files (misclassifies primary targets as clean).

---

## Interactive Flow

1. **List detected files** (grouped: strong signal / weak signal)
2. **Per file**: show dirty-check state + archive/skip option
3. **Bulk actions**: `[Archive All] [Skip All] [Review One by One]`
4. **.gitignore linkage**: if file is tracked, suggest `git rm --cached <file>`

---

## Archive Operation (race-safe)

```
1. dirty-check via porcelain
2. mkdir -p archive/YYYY-MM-DD/
3. flock archive/.lock
4. mv -n <file> archive/YYYY-MM-DD/<file>
5. If mv -n fails (name collision) → retry <file>.1, <file>.2, ...
6. Release lock
7. Generate archive/YYYY-MM-DD/README.md manifest
```

### Archive Manifest Template
```markdown
# Archive YYYY-MM-DD

| File | Original Path | State |
|------|--------------|-------|
| debug_auth.py | ./debug_auth.py | untracked |
```

---

## Archive Lifecycle

- Auto-generate README.md manifest in each archive directory
- Archive >90 days → INFO message "Consider deleting archive/YYYY-MM-DD/" (**never auto-delete**)
