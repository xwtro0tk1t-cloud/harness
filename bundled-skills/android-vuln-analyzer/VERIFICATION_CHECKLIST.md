# SAST Verification Mandatory Checklist

## ⚠️ CRITICAL: Step 7 is NON-NEGOTIABLE

**Before marking ANY finding as "Complete", you MUST complete this checklist.**

---

## Phase 1: Static Analysis (Steps 1-6)

### Step 1-6 Completion
- [ ] Alert parsed and understood
- [ ] Code location identified with file:line
- [ ] Pattern validated (not just pattern match)
- [ ] Data flow fully traced (source → sink)
- [ ] Exploitability preliminarily assessed
- [ ] PoC code generated

**Note**: Steps 1-6 give you a HYPOTHESIS. Only Step 7 provides PROOF.

---

## Phase 2: Dynamic Verification (Step 7) 🔴 MANDATORY

### Pre-Flight Check

**Ask yourself**: Am I about to skip Step 7?

If YES, check your reason against this list:

| Your Reason | Is it Valid? | What You Should Do Instead |
|-------------|--------------|---------------------------|
| "Static analysis shows it's safe" | ❌ NO | Static can miss runtime issues - TEST IT |
| "Configuration comes from server" | ❌ NO | Verify: HTTPS? Pinning? Cache? - TEST IT |
| "It's third-party SDK code" | ❌ NO | App integrates it = app's risk - TEST IT |
| "Impact seems low" | ❌ NO | Let test results prove impact - TEST IT |
| "Would require backend access" | ❌ NO | Use MITM/Frida to simulate - TEST IT |
| "Too complex to test" | ❌ NO | Break it down into steps - TEST IT |
| "APK won't install/corrupted" | ✅ YES | Document error, mark as untestable |

**If you found yourself making ANY excuse above, you are doing it WRONG.**

### Setup Phase (REQUIRED)

- [ ] **Emulator started** and verified running
  ```bash
  emulator -avd <name> &
  adb wait-for-device
  adb shell getprop ro.build.version.sdk  # Verify
  ```

- [ ] **APK installed** successfully
  ```bash
  adb install -r target.apk
  adb shell pm list packages | grep <package>  # Verify
  ```

- [ ] **App launches** without crash
  ```bash
  adb shell monkey -p <package> -c android.intent.category.LAUNCHER 1
  ```

### Testing Phase (REQUIRED - Choose Based on Finding Type)

#### For "Server-Controlled" Configuration Issues:

- [ ] **Network interception attempted**
  ```bash
  # Start mitmproxy
  mitmproxy -s intercept_config.py

  # Configure proxy on emulator
  adb shell settings put global http_proxy 10.0.2.2:8080

  # Launch app and observe traffic
  ```

- [ ] **Transmission security verified**
  - [ ] Protocol checked: HTTP or HTTPS?
  - [ ] Certificate pinning tested: Present or absent?
  - [ ] Result documented with evidence

- [ ] **Local cache investigated**
  ```bash
  # Find config files
  adb shell "find /data/data/<package> -name '*config*'"

  # Check if writable/modifiable
  adb pull <config_file> .
  # Try modifying and pushing back
  ```

- [ ] **Runtime modification attempted**
  ```bash
  # Frida hook to intercept config
  frida -U -f <package> -l hook_config.js --no-pause

  # Try to override values
  ```

#### For Intent Injection Issues:

- [ ] **Malicious intent crafted**
  ```bash
  # Based on PoC from Step 6
  adb shell am start -n <component> --es <param> "<payload>"
  ```

- [ ] **App behavior observed**
  ```bash
  # Monitor logcat
  adb logcat -c && adb logcat | grep -i "<package>\|exploit\|error"
  ```

- [ ] **Impact documented**
  - [ ] Screenshot of vulnerable state
  - [ ] Logcat output showing exploit
  - [ ] Sensitive data captured (if any)

#### For WebView Issues:

- [ ] **PoC HTML hosted** (HTTPS required for Android 9+)
  ```bash
  # Option 1: GitHub Pages
  # Option 2: Valid HTTPS server
  python3 server.py  # With SSL cert
  ```

- [ ] **Trigger mechanism tested**
  ```bash
  # Intent, URL, or deeplink
  adb shell am start -a android.intent.action.VIEW -d "<url>"
  ```

- [ ] **WebView response captured**
  ```bash
  # Enable WebView debugging
  adb shell setprop log.tag.chromium DEBUG

  # Monitor WebView logs
  adb logcat | grep -i "chromium\|console\|bridge"
  ```

- [ ] **Data exfiltration verified or disproven**
  - [ ] Callback received with sensitive data? YES/NO
  - [ ] Network request to attacker server? YES/NO
  - [ ] Evidence saved (screenshot/log)

#### For SQL Injection Issues:

- [ ] **Injection payload executed**
  ```bash
  adb shell content query --uri "content://.../<payload>"
  ```

- [ ] **Database response captured**
  - [ ] Extra data returned? YES/NO
  - [ ] Error message revealed structure? YES/NO
  - [ ] Evidence documented

#### For Path Traversal Issues:

- [ ] **Traversal payload tested**
  ```bash
  adb shell am start -n <component> --es file "../../../../etc/hosts"
  ```

- [ ] **File access verified**
  - [ ] Accessed files outside intended directory? YES/NO
  - [ ] Sensitive files exposed? YES/NO

### Documentation Phase (REQUIRED)

- [ ] **Test results captured**
  - [ ] Logcat output saved
  - [ ] Screenshots taken
  - [ ] Network traffic logged (if applicable)

- [ ] **Evidence organized**
  ```bash
  verification_results/
  ├── logcat_output.txt
  ├── screenshot_exploit.png
  ├── network_capture.pcap
  └── test_results.md
  ```

- [ ] **Actual test results documented** (NOT assumptions)

**Template for documentation**:
```markdown
## Dynamic Verification Results

### Environment
- Emulator: Pixel 5 API 30
- Android Version: 11
- APK Version: 1.2.3
- Test Date: 2026-02-27

### Test 1: [Test Name]
**Tool**: [mitmproxy/frida/adb]
**Command**:
```bash
[exact command run]
```

**Expected Result**: [what you expected]
**Actual Result**: [what actually happened]
**Evidence**: [screenshot/log reference]

### Test 2: [Test Name]
[repeat for each test]

### Final Verdict
Based on above tests (NOT assumptions):
- [X] TRUE POSITIVE - Exploitable via [specific attack vector]
- [ ] FALSE POSITIVE - Protected by [specific security control]

**Justification**: [explain based on test results]
```

---

## Phase 3: Final Validation

### Verdict Validation Checklist

- [ ] **Verdict matches test results**
  - If you marked TRUE POSITIVE: Do you have evidence of successful exploit?
  - If you marked FALSE POSITIVE: Do you have evidence showing protection worked?

- [ ] **Not based on assumptions**
  - [ ] Your conclusion cites actual test results
  - [ ] You have evidence files saved
  - [ ] No phrases like "probably", "seems like", "should be"

- [ ] **Evidence supports conclusion**
  - [ ] Screenshots show what you claim
  - [ ] Logs contain the data you reference
  - [ ] PoC execution is documented

### Red Flag Self-Check

**Did you say any of these in your report?**

- [ ] "Not Required - Third-party code"
- [ ] "Not Required - Server controlled"
- [ ] "Not Required - Low impact"
- [ ] "Would require backend access"
- [ ] "Too complex to test dynamically"
- [ ] "Static analysis is sufficient"
- [ ] "Skipped due to time constraints"

**If ANY box is checked → Your verification is INVALID. Go back and do Step 7.**

### Completion Confirmation

**I hereby confirm**:

- [ ] I started an emulator (not imagined it)
- [ ] I installed the APK (not assumed it would work)
- [ ] I executed the PoC (not just wrote it)
- [ ] I captured evidence (not just described what would happen)
- [ ] My conclusion is based on WHAT I SAW, not what I THINK

**Only proceed if ALL boxes are checked.**

---

## Common Mistakes & Corrections

### Mistake #1: "Server-Controlled = Safe"

**Wrong Thinking**:
> "Static analysis shows config comes from server → It's safe → Skip testing"

**Why Wrong**:
- You don't know: HTTP vs HTTPS
- You don't know: Certificate pinning present?
- You don't know: Config cached locally?
- You don't know: Debug mode overrides?

**Correct Approach**:
```bash
# Test 1: Check transmission
mitmproxy → See if you can intercept

# Test 2: Check cache
adb shell find → See if config is cached

# Test 3: Check hooks
frida → See if you can override

# Then conclude based on RESULTS
```

### Mistake #2: "Third-Party = Not My Problem"

**Wrong Thinking**:
> "This is NetworkBench SDK, not Phemex code → Not our vulnerability"

**Why Wrong**:
- App integrates SDK → App's attack surface
- App trusts SDK → Must verify trust
- Supply chain = part of app security

**Correct Approach**:
Test it. Document risk. Note it's third-party. But STILL TEST IT.

### Mistake #3: Premature Conclusion

**Wrong Thinking**:
> "Data flow traced → Looks safe → Exploitability: Low → Done"

**Why Wrong**:
- Haven't tested if it actually works
- Haven't verified security controls
- Conclusion based on GUESS not PROOF

**Correct Approach**:
1. Complete static analysis (Steps 1-6)
2. Generate PoC
3. TEST THE POC (Step 7)
4. Let test results determine verdict

---

## Reference: Why Dynamic Verification Matters

### Case Study: The "Safe" Config That Wasn't

**Initial Assessment (WRONG)**:
```java
// Code analysis showed:
String serverUrl = NetworkConfig.getFromServer();
httpClient.connect(serverUrl);

// Conclusion: "Server controlled → Safe → Skip testing"
// Verdict: FALSE POSITIVE
```

**Dynamic Testing Revealed**:
```bash
# Test 1: Network inspection
$ mitmproxy
→ DISCOVERY: Config sent over HTTP (not HTTPS)!
→ DISCOVERY: No certificate pinning!

# Test 2: MITM attack
$ mitmproxy -s inject_malicious.py
→ SUCCESS: Injected evil.com as server URL
→ SUCCESS: App connected to attacker server!

# Test 3: Local cache
$ adb shell cat /data/data/app/files/config.json
→ DISCOVERY: Config cached in world-readable location!
→ SUCCESS: Modified cache, app used evil config!

# Actual Verdict: TRUE POSITIVE - CRITICAL
```

**Lesson**: Static said "safe", dynamic proved it was VULNERABLE.

**This is why Step 7 is MANDATORY.**

---

## Final Reminder

### Before You Submit Your Report

Ask yourself:

1. **Did I actually run the emulator?**
   - Not "I would run" → Did you RUN it?

2. **Did I actually install the APK?**
   - Not "it should install" → Did it INSTALL?

3. **Did I actually execute the exploit?**
   - Not "this would work" → Did you TRY it?

4. **Is my conclusion based on what I SAW or what I THINK?**
   - Saw it work → TRUE POSITIVE
   - Saw it blocked → FALSE POSITIVE
   - Didn't test → INCOMPLETE

**If you didn't test, you didn't verify. Period.**

---

## Checklist Summary

### All boxes must be checked:

**Setup**:
- [ ] Emulator running
- [ ] APK installed
- [ ] App launches

**Testing**:
- [ ] PoC executed
- [ ] Results observed
- [ ] Evidence captured

**Documentation**:
- [ ] Test results documented
- [ ] Evidence saved
- [ ] Verdict matches tests

**Validation**:
- [ ] No excuses made
- [ ] No assumptions in conclusion
- [ ] Ready to show evidence

**If ANY box is unchecked: Verification is INCOMPLETE.**

---

**Version**: 1.0
**Purpose**: Prevent skipping dynamic verification
**Applies to**: All SAST verification tasks
**Exceptions**: None (except APK installation failure)
