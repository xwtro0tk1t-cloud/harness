# Hook Gate Scripts (Enterprise — Optional)

This file provides **complete source code + registration config + activation instructions** for 4 Claude Code Hook scripts.

> **Not enabled by default.** In open-source mode, security relies on CLAUDE.md MUST/MUST NOT text rules.
> Enterprise users can enable all or some Hooks on demand for system-level enforcement gates.

---

## How to Enable

1. Copy scripts to `.harness/hooks/` directory
2. Grant execute permission: `chmod +x .harness/hooks/*.sh`
3. Add corresponding hook config to `.claude/settings.json`
4. To disable: remove the hook config from settings.json

---

## Hook A: pre-commit-gate.sh

**Function**: Block sensitive files and hardcoded secrets before git commit
**Hook Event**: `PreToolUse` (matches `git commit` in Bash tool)

### Script Source

```bash
#!/bin/bash
# Hook A: Pre-commit Security Gate
# Block .env / *.key / *.pem / *credential* sensitive files
# Detect hardcoded secret patterns in staged diff

# Only intercept git commit commands
if ! echo "$TOOL_INPUT" | grep -q "git commit"; then
  exit 0
fi

BLOCKED_PATTERNS='\.env$|\.key$|\.pem$|\.p12$|\.pfx$|credential|secret.*=.*[A-Za-z0-9]|password.*=.*[A-Za-z0-9]'
SECRET_PATTERNS='AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[0-9a-zA-Z]{36}|sk-[0-9a-zA-Z]{48}|-----BEGIN (RSA |EC )?PRIVATE KEY-----|token.*=.*[A-Za-z0-9]{20,}'

# Check staged file names
STAGED_FILES=$(git diff --cached --name-only 2>/dev/null)
if [ -z "$STAGED_FILES" ]; then
  exit 0
fi

BLOCKED_FILES=$(echo "$STAGED_FILES" | grep -iE "$BLOCKED_PATTERNS" || true)
if [ -n "$BLOCKED_FILES" ]; then
  echo "❌ BLOCKED: Sensitive files detected in staged changes:"
  echo "$BLOCKED_FILES" | sed 's/^/  - /'
  echo ""
  echo "Remove them with: git reset HEAD <file>"
  exit 1
fi

# Check for secret patterns in staged diff
STAGED_DIFF=$(git diff --cached --unified=0 2>/dev/null)
SECRET_MATCHES=$(echo "$STAGED_DIFF" | grep -E "^\+" | grep -iE "$SECRET_PATTERNS" || true)
if [ -n "$SECRET_MATCHES" ]; then
  echo "❌ BLOCKED: Potential hardcoded secrets detected in staged diff:"
  echo "$SECRET_MATCHES" | head -5 | sed 's/^/  /'
  echo ""
  echo "Use environment variables or Secret Manager instead. See: CWE-798"
  exit 1
fi

exit 0
```

### Registration Config

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash .harness/hooks/pre-commit-gate.sh"
          }
        ]
      }
    ]
  }
}
```

---

## Hook B: commit-msg-check.sh

**Function**: Validate git commit message follows Conventional Commit format
**Hook Event**: `PreToolUse` (matches `git commit -m` in Bash tool)

### Script Source

```bash
#!/bin/bash
# Hook B: Commit Message Convention Check
# Validate conventional commit format: <type>(<scope>): <subject>

# Only intercept git commit with -m flag
if ! echo "$TOOL_INPUT" | grep -q 'git commit.*-m'; then
  exit 0
fi

# Extract commit message (supports single and double quotes)
MSG=$(echo "$TOOL_INPUT" | grep -oP '(-m\s+)(["'"'"'])(.*?)\2' | head -1 | sed "s/^-m\s*[\"']//" | sed "s/[\"']$//")

# If unable to extract message (e.g., heredoc), skip check
if [ -z "$MSG" ]; then
  exit 0
fi

# Conventional Commit regex
PATTERN='^(feat|fix|refactor|docs|test|chore|perf|security|ci|build|style|revert)(\(.+\))?: .{1,72}'

if ! echo "$MSG" | grep -qE "$PATTERN"; then
  echo "❌ BLOCKED: Commit message does not follow Conventional Commit format."
  echo ""
  echo "Expected: <type>(<scope>): <subject>"
  echo "Types: feat | fix | refactor | docs | test | chore | perf | security"
  echo "Example: feat(auth): add OAuth2 login support"
  echo ""
  echo "Your message: $MSG"
  exit 1
fi

exit 0
```

### Registration Config

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash .harness/hooks/commit-msg-check.sh"
          }
        ]
      }
    ]
  }
}
```

---

## Hook C: dangerous-cmd-guard.sh

**Function**: Block dangerous commands — data exfiltration, destructive operations, credential theft
**Hook Event**: `PreToolUse` (matches Bash tool)

### Script Source

```bash
#!/bin/bash
# Hook C: Dangerous Command Guard
# Block: data exfiltration / destructive operations / credential theft / reverse shell

INPUT="$TOOL_INPUT"

# === Data Exfiltration ===
# curl/wget POST to non-common domains
if echo "$INPUT" | grep -qE '(curl|wget).*(-X\s*POST|--data|--upload|-d\s)' ; then
  # Whitelist: common CI/CD and package registry domains
  if ! echo "$INPUT" | grep -qE '(github\.com|gitlab\.com|npmjs\.org|pypi\.org|localhost|127\.0\.0\.1)'; then
    echo "❌ BLOCKED: Potential data exfiltration detected."
    echo "Command appears to POST data to an external host."
    echo "If this is intentional, add the domain to the whitelist in .harness/hooks/dangerous-cmd-guard.sh"
    exit 1
  fi
fi

# === Reverse Shell ===
if echo "$INPUT" | grep -qE '(/dev/tcp/|/dev/udp/|nc\s+-e|ncat\s+-e|mkfifo.*nc|bash\s+-i.*>&)'; then
  echo "❌ BLOCKED: Reverse shell pattern detected."
  exit 1
fi

# === Internal Network Tunneling ===
if echo "$INPUT" | grep -qE '(ngrok|frpc?|cloudflared\s+tunnel|chisel|bore\s+local)'; then
  echo "❌ BLOCKED: Internal network tunneling tool detected."
  exit 1
fi

# === Credential File Access ===
if echo "$INPUT" | grep -qE '(cat|less|head|tail|cp|scp).*(/etc/shadow|/etc/passwd|\.ssh/id_|\.aws/credentials|\.kube/config)'; then
  echo "❌ BLOCKED: Credential file access detected."
  exit 1
fi

# === Destructive Operations (conservative matching) ===
if echo "$INPUT" | grep -qE 'rm\s+-rf\s+(/|/home|/etc|/var|\$HOME|\~/)'; then
  echo "❌ BLOCKED: Destructive command targeting critical path."
  exit 1
fi

# === Privilege Escalation ===
if echo "$INPUT" | grep -qE '(chmod\s+[u+]*s|chown\s+root|sudo\s+su|passwd\s+root)'; then
  echo "❌ BLOCKED: Privilege escalation pattern detected."
  exit 1
fi

exit 0
```

### Registration Config

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash .harness/hooks/dangerous-cmd-guard.sh"
          }
        ]
      }
    ]
  }
}
```

---

## Hook D: write-security-scan.sh

**Function**: Detect security anti-patterns after code writes, output WARNING (non-blocking)
**Hook Event**: `PostToolUse` (matches Write / Edit tools)

### Script Source

```bash
#!/bin/bash
# Hook D: Write-Time Security Pattern Scanner
# Detect security anti-patterns in code, output WARNING + CWE ID + fix suggestion
# Note: This hook does NOT block (exit 0), only outputs warnings

FILE_PATH="$TOOL_INPUT_FILE_PATH"

# If unable to get file path, skip
if [ -z "$FILE_PATH" ] || [ ! -f "$FILE_PATH" ]; then
  exit 0
fi

WARNINGS=""

# === Python Security Anti-Patterns ===
if [[ "$FILE_PATH" == *.py ]]; then
  # eval/exec
  if grep -nE '(eval|exec)\s*\(' "$FILE_PATH" | grep -v '^\s*#' | grep -v 'test' > /dev/null 2>&1; then
    WARNINGS+="⚠️  CWE-95: eval()/exec() detected — avoid with user input\n"
    WARNINGS+="   Fix: Use safe alternatives (ast.literal_eval for data, dedicated parsers for expressions)\n"
  fi
  # shell=True
  if grep -nE 'shell\s*=\s*True' "$FILE_PATH" | grep -v '^\s*#' > /dev/null 2>&1; then
    WARNINGS+="⚠️  CWE-78: subprocess with shell=True — command injection risk\n"
    WARNINGS+="   Fix: Use argument list: subprocess.run(['cmd', 'arg1', 'arg2'])\n"
  fi
  # SQL f-string
  if grep -nE "(f['\"].*SELECT|f['\"].*INSERT|f['\"].*UPDATE|f['\"].*DELETE|\.format\(.*SELECT)" "$FILE_PATH" | grep -v '^\s*#' > /dev/null 2>&1; then
    WARNINGS+="⚠️  CWE-89: Potential SQL injection via string formatting\n"
    WARNINGS+="   Fix: Use parameterized queries: db.execute('SELECT ... WHERE id = :id', {'id': val})\n"
  fi
  # Hardcoded secrets
  if grep -nE "(password|secret|api_key|token)\s*=\s*['\"][A-Za-z0-9]" "$FILE_PATH" | grep -viE '(example|placeholder|test|dummy|xxx|changeme)' > /dev/null 2>&1; then
    WARNINGS+="⚠️  CWE-798: Potential hardcoded credential\n"
    WARNINGS+="   Fix: Use environment variables: os.environ.get('SECRET_KEY')\n"
  fi
fi

# === JavaScript/TypeScript Security Anti-Patterns ===
if [[ "$FILE_PATH" == *.js ]] || [[ "$FILE_PATH" == *.ts ]] || [[ "$FILE_PATH" == *.tsx ]] || [[ "$FILE_PATH" == *.jsx ]]; then
  # eval
  if grep -nE '\beval\s*\(' "$FILE_PATH" | grep -v '^\s*//' > /dev/null 2>&1; then
    WARNINGS+="⚠️  CWE-95: eval() detected — code injection risk\n"
    WARNINGS+="   Fix: Use JSON.parse() for data, or a safe expression parser\n"
  fi
  # innerHTML
  if grep -nE '\.innerHTML\s*=' "$FILE_PATH" | grep -v 'DOMPurify' > /dev/null 2>&1; then
    WARNINGS+="⚠️  CWE-79: Direct innerHTML assignment — XSS risk\n"
    WARNINGS+="   Fix: Use DOMPurify.sanitize() or textContent\n"
  fi
  # SQL template literal
  if grep -nE '(query|execute|sql)\s*\(\s*`' "$FILE_PATH" > /dev/null 2>&1; then
    WARNINGS+="⚠️  CWE-89: SQL query with template literal — injection risk\n"
    WARNINGS+="   Fix: Use parameterized queries with your ORM/query builder\n"
  fi
fi

# === Universal Security Anti-Patterns ===
# Private key in source
if grep -nE 'BEGIN (RSA |EC )?PRIVATE KEY' "$FILE_PATH" > /dev/null 2>&1; then
  WARNINGS+="⚠️  CWE-798: Private key embedded in source code\n"
  WARNINGS+="   Fix: Store keys in Secret Manager, load at runtime\n"
fi

if [ -n "$WARNINGS" ]; then
  echo "🔒 Security scan warnings for: $FILE_PATH"
  echo -e "$WARNINGS"
  echo "Reference: docs/conventions/secure-coding.md"
fi

# Non-blocking — only output warnings
exit 0
```

### Registration Config

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "bash .harness/hooks/write-security-scan.sh"
          }
        ]
      }
    ]
  }
}
```

---

## Full settings.json Config (Enterprise Mode — All Enabled)

**Merge** the following hook configuration into the project's `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "bash .harness/hooks/pre-commit-gate.sh" },
          { "type": "command", "command": "bash .harness/hooks/commit-msg-check.sh" },
          { "type": "command", "command": "bash .harness/hooks/dangerous-cmd-guard.sh" }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          { "type": "command", "command": "bash .harness/hooks/write-security-scan.sh" }
        ]
      }
    ]
  }
}
```

---

## Enabling Individual Hooks

To enable only specific Hooks (e.g., only Hook D for code scanning), simply add the corresponding config to settings.json.

**Recommended progressive enablement**:
1. **Lowest friction**: Start with Hook D (write-security-scan) — warnings only, non-blocking
2. **Strengthen gates**: Add Hook A (pre-commit-gate) — prevent secret commits
3. **Standardize flow**: Add Hook B (commit-msg-check) — enforce commit message format
4. **Full protection**: Add Hook C (dangerous-cmd-guard) — block dangerous commands

---

## Customization

- **Modify whitelists**: Edit domain whitelists / file patterns in each script
- **Adjust detection rules**: Modify regex matching patterns
- **Add language support**: Add new language detection blocks in Hook D
- **Disable individual checks**: Comment out the corresponding detection section in the script
