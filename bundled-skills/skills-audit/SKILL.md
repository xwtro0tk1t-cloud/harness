---
name: skills-audit
description: Audit AI Agent skills for security vulnerabilities including malicious code, remote execution, credential leaks, and supply chain risks. Use when reviewing third-party skills, investigating suspicious behavior, or performing security assessments.
allowed-tools: Bash(python *), Read, Glob, Grep
disable-model-invocation: false
argument-hint: [skill-path] [--mode fast|standard|deep|expert]
---

# Security Audit for AI Agent Skills

You are conducting a security audit of an AI Agent skill. This skill executes a comprehensive analysis to detect malicious code, security vulnerabilities, and suspicious patterns.

## Task

Audit the skill at path: **$ARGUMENTS**

## Execution Steps

1. **Run static security scan**
   Execute the Python audit tool for static analysis:
   ```bash
   # Auto-detect skills-audit installation path
   AUDIT_SCRIPT=""
   for candidate in \
     ~/.claude/skills/skills-audit/skill_audit/cli_wrapper.py \
     ~/.claude/skills/skill-audit/skill_audit/cli_wrapper.py \
     "${SKILL_AUDIT_HOME:-}""/skill_audit/cli_wrapper.py"; do
     if [ -f "$candidate" ]; then
       AUDIT_SCRIPT="$candidate"
       break
     fi
   done

   if [ -z "$AUDIT_SCRIPT" ]; then
     echo "Error: Cannot find skills-audit installation"
     echo "Set SKILL_AUDIT_HOME environment variable to your skills-audit directory"
     exit 1
   fi

   python3 "$AUDIT_SCRIPT" "$ARGUMENTS"
   ```

   This will:
   - Extract skill artifacts (code, prompts, permissions)
   - Run static pattern matching (regex-based detection)
   - Check for obvious malicious patterns
   - Generate initial findings

2. **Perform AI semantic analysis** (if enabled)

   If the scan mode includes AI analysis (standard/deep/expert), perform deep semantic security analysis:

   a. **Read the skill code files** from the target path

   b. **Analyze for security vulnerabilities**:
      - **Remote Code Execution**: `eval()`, `exec()`, `subprocess`, `curl | bash`
      - **Credential Leaks**: Hardcoded API keys, passwords, tokens, .env files
      - **Data Exfiltration**: Suspicious network requests, file uploads
      - **Prompt Injection**: "Ignore previous instructions", role manipulation
      - **Supply Chain Risks**: Obfuscated code, dynamic imports, base64 encoding
      - **Privilege Escalation**: sudo, setuid, file permission changes
      - **Persistence Mechanisms**: cron jobs, shell profile modifications

   c. **Assess each finding**:
      - Severity: CRITICAL / HIGH / MEDIUM / LOW
      - Attack scenario: How can this be exploited?
      - Impact: What damage could be done? (CIA triad)
      - Remediation: How to fix it?

   d. **Filter false positives**:
      - Exclude findings from skills-audit's own detection patterns (patterns.py regex)
      - Downgrade benign file operations (e.g. deleting old output before regeneration)
      - Verify env var access patterns (using dotenv is recommended, not a vulnerability)

   e. **Output your analysis** in this format:
      ```
      AI SEMANTIC ANALYSIS FINDINGS:

      1. [SEVERITY] Finding Title
         - Location: file.py:line
         - Pattern: describe what you found
         - Risk: explain the security risk
         - Scenario: how an attacker could exploit this
         - Impact: potential damage
         - Recommendation: how to fix

      2. [SEVERITY] Finding Title
         ...
      ```

   f. **Integrate AI findings into the report** (CRITICAL STEP)

      After completing your AI analysis, integrate your findings into the audit report by running:

      ```bash
      # Use the detected AUDIT_SCRIPT path from step 1
      INTEGRATE_SCRIPT="$(dirname "$AUDIT_SCRIPT")/integrate_ai_findings.py"

      python3 "$INTEGRATE_SCRIPT" \
        "<report_path>" \
        '<ai_findings_json>'
      ```

      Where:
      - `<report_path>`: The path to the JSON report file (shown in step 1 output as "Detailed report saved to: ...")
      - `<ai_findings_json>`: Your AI analysis findings formatted as JSON array

      **JSON Format for ai_findings**:
      ```json
      [
        {
          "title": "Base64-Obfuscated Remote Code Execution",
          "severity": "CRITICAL",
          "category": "unsafe_execution",
          "description": "Base64-encoded command that downloads and executes arbitrary code",
          "location": "skill.md:28",
          "code_snippet": "echo 'L2Jpbi9iYXNoIC1jIC...' | base64 -D | bash",
          "risk": "Remote code execution with complete system compromise",
          "scenario": "User follows installation instructions, base64 decodes to malicious payload, executes with shell privileges",
          "impact": {
            "confidentiality": "CRITICAL",
            "integrity": "CRITICAL",
            "availability": "CRITICAL"
          },
          "impact_description": "Full system compromise, data theft, ransomware deployment",
          "recommendation": "BLOCK this skill entirely. Never execute obfuscated commands.",
          "cwe_ids": ["CWE-78", "CWE-94", "CWE-506"]
        }
      ]
      ```

      **Important**:
      - Convert ALL your AI analysis findings from step 2e into this JSON format
      - Include severity (CRITICAL/HIGH/MEDIUM/LOW), location, code snippets, risk, scenario, impact, and recommendations
      - This step MERGES your AI findings with static analysis findings and recalculates the overall risk score
      - **Webhook is NOT sent during this step** -- it will be sent after your comprehensive analysis

3. **Send final webhook notification** (optional, if notifications are configured)
   After completing comprehensive analysis (including false positive filtering), send the webhook:
   ```bash
   # Auto-detect skills-audit path
   AUDIT_DIR="$(dirname "$(dirname "$AUDIT_SCRIPT")")"
   python3 -c "
   import sys; sys.path.insert(0, '$AUDIT_DIR')
   from skill_audit.integrations import send_final_webhook
   send_final_webhook(report_path='<report_path>')
   "
   ```
   This ensures the webhook contains the final, accurate results after your analysis.

4. **Present comprehensive results to user**
   - Summarize the overall risk level and score (from integrated report)
   - List key findings with severity levels
   - Clearly mark any false positives that were filtered
   - For critical findings, include:
     - Title and severity
     - Evidence location and code snippet
     - Attack scenario and impact
     - Remediation recommendation
   - Provide the final decision recommendation
   - Reference the detailed JSON report path for full analysis

5. **If high-risk issues are found**:
   - Explain the security implications
   - Suggest concrete remediation steps
   - Recommend whether to BLOCK, REVIEW, or ALLOW the skill
   - Warn about potential damage if the skill is executed

## Scan Modes

### Deep Mode (Default)
- **Speed**: ~2-5 minutes
- **Coverage**: Full Claude AI analysis + static patterns + deep code understanding
- **Use**: Recommended for all skills
- **Command**: `/skills-audit /path/to/skill` (default) or `/skills-audit /path/to/skill --mode deep`
- **Note**: Includes comprehensive AI analysis by Claude

### Fast Mode
- **Speed**: ~1-2 seconds
- **Coverage**: Static pattern matching only
- **Use**: Quick check for obvious vulnerabilities
- **Command**: `/skills-audit /path/to/skill --mode fast`

### Standard Mode
- **Speed**: ~30 seconds - 2 minutes (depends on code size)
- **Coverage**: Claude AI semantic analysis + static patterns
- **Use**: Balanced speed and coverage
- **Command**: `/skills-audit /path/to/skill --mode standard`
- **Note**: Claude (you) will perform semantic analysis

### Expert Mode
- **Speed**: ~5-10 minutes
- **Coverage**: Complete analysis with all phases
- **Use**: Critical security reviews
- **Command**: `/skills-audit /path/to/skill --mode expert`
- **Note**: Maximum depth analysis performed by Claude

## Detection Capabilities

This audit detects:

- **Remote Code Execution**: `curl | bash`, `eval()`, `exec()`
- **Credential Leaks**: Hardcoded API keys, passwords, .env files
- **Network Exfiltration**: Suspicious HTTP/Socket connections
- **Supply Chain Risks**: Obfuscation, dynamic imports
- **Prompt Injection**: "Ignore previous instructions"
- **System Manipulation**: File deletion, permission changes

## Configuration

Edit `config/config.yml` (relative to skills-audit installation directory) to customize:

### Key Configuration Options

```yaml
# Report save location
claude_code:
  # Options: cwd (current directory), skill_dir (skill directory), temp (temp directory), custom
  report_location: custom
  custom_report_dir: ~/.claude/audit-reports

# Custom report naming
output:
  report_filename: "audit-{skill_name}-{timestamp}.json"
```

### Scan Mode Customization

```yaml
scan_modes:
  fast:
    enable_ai_analysis: false
    enable_static_analysis: true
    enable_deep_analysis: false
    enable_tip_check: false
  standard:
    enable_ai_analysis: true
    enable_static_analysis: true
    enable_deep_analysis: false
    enable_tip_check: false
  deep:
    enable_ai_analysis: true
    enable_static_analysis: true
    enable_deep_analysis: true
    enable_tip_check: true
```

## Notes

- **Default mode is deep** (includes AI + Static + Deep analysis by Claude)
- **For quick scans**, use `--mode fast` (static analysis only, 1-2 seconds)
- **AI analysis** in standard/deep/expert modes is performed by Claude directly (no API calls)
- **Reports saved to ~/.claude/audit-reports/** by default (configurable)
- **Use `--mode` flag** to override scan mode (the `--mode` parameter is authoritative)
- **Config file location**: `config/config.yml` relative to skills-audit installation directory
- **Webhook is deferred** until after Claude's comprehensive analysis (false positive filtering)
- **skills-audit itself is excluded** from scanning to avoid self-referential false positives
- **Works offline**: Static analysis works without internet; AI analysis uses current Claude session
