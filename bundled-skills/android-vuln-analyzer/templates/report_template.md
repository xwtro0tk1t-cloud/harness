# {{APP_NAME}} Security Vulnerability Report

**Report Date**: {{REPORT_DATE}}
**Analyst**: Claude Code Android Vulnerability Analyzer
**Target Version**: {{APP_VERSION}}
**Risk Level**: 🔴 **{{SEVERITY}}**

---

## Executive Summary

### TL;DR
{{TLDR}}

### Vulnerability Classification
- **Type**: {{VULN_TYPE}}
- **CWE**: {{CWE_ID}}
- **OWASP Mobile**: {{OWASP_CATEGORY}}
- **CVSS v3.1 Score**: **{{CVSS_SCORE}}** ({{CVSS_SEVERITY}})

### Impact Overview
{{IMPACT_SUMMARY}}

---

## Table of Contents
1. [Vulnerability Details](#vulnerability-details)
2. [Technical Analysis](#technical-analysis)
3. [Exploitation](#exploitation)
4. [Impact Assessment](#impact-assessment)
5. [CVSS Scoring](#cvss-scoring)
6. [Remediation](#remediation)
7. [References](#references)

---

## 1. Vulnerability Details

### 1.1 Description
{{DESCRIPTION}}

### 1.2 Affected Components
{{AFFECTED_COMPONENTS}}

### 1.3 Root Cause
{{ROOT_CAUSE}}

---

## 2. Technical Analysis

### 2.1 Call Chain
```
{{CALL_CHAIN}}
```

### 2.2 Vulnerable Code

#### Location 1: {{CODE_LOCATION_1}}
```java
{{VULNERABLE_CODE_1}}
```

**Issue**: {{ISSUE_1}}

#### Location 2: {{CODE_LOCATION_2}}
```java
{{VULNERABLE_CODE_2}}
```

**Issue**: {{ISSUE_2}}

### 2.3 Configuration Analysis

#### AndroidManifest.xml
```xml
{{MANIFEST_SNIPPET}}
```

**Security Issues**:
- {{MANIFEST_ISSUE_1}}
- {{MANIFEST_ISSUE_2}}

#### Network Security Config
```xml
{{NETWORK_CONFIG}}
```

---

## 3. Exploitation

### 3.1 Prerequisites
{{PREREQUISITES}}

### 3.2 Attack Vectors

#### Vector 1: {{VECTOR_1_NAME}}
{{VECTOR_1_DESCRIPTION}}

**Delivery Methods**:
- {{DELIVERY_METHOD_1}}
- {{DELIVERY_METHOD_2}}

#### Vector 2: {{VECTOR_2_NAME}}
{{VECTOR_2_DESCRIPTION}}

### 3.3 Proof of Concept

#### Step 1: {{POC_STEP_1_TITLE}}
```bash
{{POC_STEP_1_CODE}}
```

#### Step 2: {{POC_STEP_2_TITLE}}
```bash
{{POC_STEP_2_CODE}}
```

#### Step 3: {{POC_STEP_3_TITLE}}
```html
{{POC_STEP_3_CODE}}
```

### 3.4 Exploitation Results

**Screenshot Evidence**:
![Exploitation Result]({{SCREENSHOT_PATH}})

**Captured Data**:
```json
{{CAPTURED_DATA}}
```

---

## 4. Impact Assessment

### 4.1 Confidentiality Impact
{{CONFIDENTIALITY_IMPACT}}

**Data at Risk**:
- {{DATA_AT_RISK_1}}
- {{DATA_AT_RISK_2}}
- {{DATA_AT_RISK_3}}

### 4.2 Integrity Impact
{{INTEGRITY_IMPACT}}

**Possible Actions**:
- {{POSSIBLE_ACTION_1}}
- {{POSSIBLE_ACTION_2}}

### 4.3 Availability Impact
{{AVAILABILITY_IMPACT}}

### 4.4 Affected Users
{{AFFECTED_USERS}}

### 4.5 Business Impact
{{BUSINESS_IMPACT}}

---

## 5. CVSS Scoring

### CVSS v3.1: {{CVSS_SCORE}} ({{CVSS_SEVERITY}})

**Vector String**: `{{CVSS_VECTOR}}`

| Metric | Value | Reasoning |
|--------|-------|-----------|
| **Attack Vector (AV)** | {{AV_VALUE}} | {{AV_REASONING}} |
| **Attack Complexity (AC)** | {{AC_VALUE}} | {{AC_REASONING}} |
| **Privileges Required (PR)** | {{PR_VALUE}} | {{PR_REASONING}} |
| **User Interaction (UI)** | {{UI_VALUE}} | {{UI_REASONING}} |
| **Scope (S)** | {{S_VALUE}} | {{S_REASONING}} |
| **Confidentiality (C)** | {{C_VALUE}} | {{C_REASONING}} |
| **Integrity (I)** | {{I_VALUE}} | {{I_REASONING}} |
| **Availability (A)** | {{A_VALUE}} | {{A_REASONING}} |

**Score Breakdown**:
- Base Score: {{BASE_SCORE}}
- Temporal Score: {{TEMPORAL_SCORE}} (if applicable)
- Environmental Score: {{ENV_SCORE}} (if applicable)

---

## 6. Remediation

### 6.1 Immediate Actions (Critical) 🔴

#### Fix 1: {{FIX_1_TITLE}}
**Priority**: Critical
**Effort**: {{FIX_1_EFFORT}}

**Current Code**:
```java
{{FIX_1_BEFORE}}
```

**Fixed Code**:
```java
{{FIX_1_AFTER}}
```

**Implementation Steps**:
1. {{FIX_1_STEP_1}}
2. {{FIX_1_STEP_2}}
3. {{FIX_1_STEP_3}}

---

#### Fix 2: {{FIX_2_TITLE}}
**Priority**: Critical
**Effort**: {{FIX_2_EFFORT}}

**Current Code**:
```java
{{FIX_2_BEFORE}}
```

**Fixed Code**:
```java
{{FIX_2_AFTER}}
```

---

### 6.2 Defense in Depth (Recommended) 🟡

#### Additional Protection 1: {{DEFENSE_1_TITLE}}
{{DEFENSE_1_DESCRIPTION}}

```java
{{DEFENSE_1_CODE}}
```

#### Additional Protection 2: {{DEFENSE_2_TITLE}}
{{DEFENSE_2_DESCRIPTION}}

```java
{{DEFENSE_2_CODE}}
```

### 6.3 Monitoring & Detection

**Logging Recommendations**:
```java
{{LOGGING_CODE}}
```

**Alerts to Implement**:
- {{ALERT_1}}
- {{ALERT_2}}

### 6.4 Testing & Verification

**Test Cases**:
1. {{TEST_CASE_1}}
2. {{TEST_CASE_2}}
3. {{TEST_CASE_3}}

**Regression Testing**:
{{REGRESSION_TESTING}}

---

## 7. Timeline

| Date | Event |
|------|-------|
| {{DISCOVERY_DATE}} | Vulnerability discovered |
| {{ANALYSIS_START}} | Analysis began |
| {{POC_DEVELOPED}} | PoC developed and tested |
| {{VERIFICATION_DATE}} | Exploitation verified |
| {{REPORT_DATE}} | Report generated |

---

## 8. References

### Internal References
- Decompiled Source: `{{DECOMPILED_PATH}}`
- PoC Files: `{{POC_PATH}}`
- Screenshots: `{{SCREENSHOTS_PATH}}`

### External References
- **CWE-{{CWE_ID}}**: {{CWE_URL}}
- **OWASP Mobile {{OWASP_CATEGORY}}**: {{OWASP_URL}}
- **Android Security Best Practices**: https://developer.android.com/topic/security/best-practices

### Related Vulnerabilities
- {{RELATED_CVE_1}}
- {{RELATED_CVE_2}}

---

## 9. Appendices

### Appendix A: Full Call Stack
```
{{FULL_CALL_STACK}}
```

### Appendix B: Network Traffic
```
{{NETWORK_TRAFFIC}}
```

### Appendix C: Complete PoC Code
```
See attached files:
- poc.html
- exploit.sh
- test_payload.json
```

---

**Report Generated By**: Claude Code Android Vulnerability Analyzer v1.0
**Contact**: security@example.com
**Confidentiality**: {{CONFIDENTIALITY_LEVEL}}

---

## Disclaimer

This report is provided for authorized security testing and educational purposes only.
The information contained herein should only be used to improve the security posture
of the tested application. Unauthorized testing or exploitation is prohibited by law.
