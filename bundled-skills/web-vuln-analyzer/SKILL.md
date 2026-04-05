# Web Vulnerability Analysis Skill

> **Version 2.0 - AI Native Architecture**
>
> 你（Claude）直接决策，无需遵循复杂的规则路由。以下是参考指南。

## 🏗️ Architecture (AI Native)

```
Claude Code (你就是 LLM)
    │
    ├─ 简单任务 → 直接处理
    │   ├─ HTTP Client → XSS, IDOR 验证
    │   └─ Playwright → DOM XSS, CSRF, Open Redirect
    │
    └─ 复杂任务 → CAI Agent
            │
            ├─ 11 Agents (bug_bounty, redteam, blueteam...)
            ├─ MCP Bridge (execute_command → 59 Kali tools)
            └─ HexStrike Docker (localhost:8888)
```

## 🚨 核心原则

1. **专业任务必须调用 CAI** - 指纹识别、渗透测试、漏洞扫描等，不要用 curl 凑合
2. **认证优先** - 如果漏洞需要认证，先问用户要 credentials
3. **客户端漏洞用浏览器** - Open Redirect, DOM XSS, CSRF 必须用 Playwright
4. **简单验证可以直接做** - 单个 payload 验证、状态码检查

## 🤖 CAI Agent 调用规则（重要！）

**当用户要求以下任务时，必须调用 CAI Agent，不要自己用 curl/HTTP 凑合：**

### Agent 选择

| 任务类型 | 选择 Agent | 调用方式 |
|---------|-----------|---------|
| 指纹识别、侦察、recon | `bug_bounty_agent` | 见下方代码 |
| 渗透测试、攻击、exploit | `redteam_agent` | 见下方代码 |
| 漏洞扫描、安全检测 | `bug_bounty_agent` | 见下方代码 |
| 告警分析、蓝队、威胁分析 | `blueteam_agent` | 见下方代码 |
| 报告验证（有报告文件） | `bug_bounty_agent` | 见下方代码 |

### 调用方式

```bash
# 激活虚拟环境
source .venv/bin/activate

# 加载环境变量
source ~/.claude/skills/web-vuln-analyzer/docker/.env

# 调用 CAI Agent
cd ~/.claude/skills/web-vuln-analyzer
python -c "
import asyncio
import sys
sys.path.insert(0, 'tools')
sys.path.insert(0, 'vendor')

import litellm
litellm.drop_params = True

from cai_client import CAIClient

async def run():
    client = CAIClient()
    result = await client.run_async(
        agent_name='bug_bounty_agent',  # 或 redteam_agent, blueteam_agent
        prompt='识别 http://target.com 的技术指纹',
        target='http://target.com',
        max_turns=30  # 简单任务: 15-30, 渗透测试: 200
    )
    print('Success:', result.success)
    print('Output:', result.output)
    if result.error:
        print('Error:', result.error)

asyncio.run(run())
"
```

### ⚙️ 推荐配置（生产环境测试验证）

基于实际渗透测试经验，以下配置可避免超时和测试不完整问题：

| 任务类型 | max_turns | CAI_TIMEOUT | 说明 |
|---------|-----------|-------------|------|
| 指纹识别 | 15-30 | 300s | 快速识别技术栈 |
| 单漏洞验证 | 30 | 600s | 验证单个漏洞 |
| 标准渗透 | 50-100 | 600s | 常规安全评估 |
| 全面渗透 | **200** | **1800s** | 完整漏洞验证 |

**重要**: 在 `docker/.env` 中设置：
```bash
CAI_MAX_TURNS=200    # 允许充分测试
CAI_TIMEOUT=1800     # 30分钟超时
```

### 示例场景

| 用户输入 | Claude 行为 |
|---------|------------|
| `/web-vuln-analyze http://target.com "识别指纹"` | 调用 `bug_bounty_agent`，让它用 whatweb/nmap |
| `/web-vuln-analyze http://target.com` (无报告) | 调用 `redteam_agent`，自动渗透 |
| `/web-vuln-analyze http://target.com report.xml` | 调用 `bug_bounty_agent`，验证报告 |
| `/web-vuln-analyze http://target.com "SQL注入测试"` | 调用 `bug_bounty_agent`，让它用 sqlmap |

### ❌ 不要这样做

```bash
# 错误：自己用 curl 做指纹识别
curl -s -I http://target.com | grep Server  # ❌ 不专业

# 错误：自己规划 tasks 用 curl
Task 1: curl http://target.com  # ❌ 应该调用 CAI
Task 2: curl http://target.com/robots.txt  # ❌
```

### ✅ 正确做法

```bash
# 正确：调用 CAI Agent，让专业 agent 决定用什么工具
python -c "... client.run_async(agent_name='bug_bounty_agent', prompt='识别指纹', ...) ..."
# Agent 会自己调用 whatweb, nmap, wafw00f 等专业工具
```

---

## 📋 Tool Selection Reference

| Vulnerability | Tool | Why |
|--------------|------|-----|
| Open Redirect, CSRF | Playwright | 客户端行为 |
| DOM XSS, Clickjacking | Playwright | JavaScript 执行 |
| SQL Injection, XXE | **CAI Agent** → HexStrike | 专业工具 |
| SSRF, Command Injection | **CAI Agent** → HexStrike | 专业工具 |
| 指纹识别、侦察 | **CAI Agent** → HexStrike | 专业工具 |
| 渗透测试 | **CAI Agent** → HexStrike | 专业工具 |
| Simple XSS, IDOR | HTTP Client | 简单请求 |
| Info Disclosure | HTTP Client | 简单请求 |

---

## 📜 Legacy Workflow (参考)

以下是原有的决策树，现在由你（Claude）直接理解和执行，无需机械遵循：

```
┌─────────────────────────────────────┐
│  Parse Report → Extract vuln type   │
└─────────────┬───────────────────────┘
              │
              ▼
     ┌────────────────────┐
     │ 🔐 Check if needs  │
     │   authentication?  │
     └────────┬───────────┘
              │
        ┌─────┴─────┐
        │           │
        ▼           ▼
   ┌────────┐  ┌─────────┐
   │  YES   │  │   NO    │
   └───┬────┘  └────┬────┘
       │            │
       ▼            │
┌──────────────────┐│
│ Prompt user for  ││
│ auth credentials ││
│ (AskUserQuestion)││
└────────┬─────────┘│
         │          │
         └────┬─────┘
              │
              ▼
        ┌─────────────┐
        │ Vuln Type?  │
        └─────┬───────┘
              │
    ┌─────────┼─────────┬─────────────┐
    │         │         │             │
    ▼         ▼         ▼             ▼
┌────────┐ ┌────────┐ ┌──────────┐ ┌────────┐
│ Open   │ │ DOM    │ │   SQL    │ │ Simple │
│Redirect│ │ XSS    │ │Injection │ │  XSS   │
│ CSRF   │ │        │ │   XXE    │ │ IDOR   │
└───┬────┘ └───┬────┘ └─────┬────┘ └───┬────┘
    │          │            │          │
    ▼          ▼            ▼          ▼
┌────────────────┐ ┌──────────────┐ ┌───────────┐
│   BROWSER      │ │CAI → HexStrike│ │HTTP CLIENT│
│   Playwright   │ │  MCP Bridge   │ │  requests │
└────────────────┘ └──────────────┘ └───────────┘
```

**⚠️ CRITICAL RULES:**

0. **🔐 AUTHENTICATION CHECK (MUST DO FIRST!)**
   - **BEFORE any verification**, check if vulnerability requires authentication
   - Use `tools/auth_checker.py` to detect auth requirements
   - If auth required: **ASK USER for credentials BEFORE running verification**
   - Vulnerabilities that ALWAYS need auth:
     * IDOR (Insecure Direct Object Reference)
     * Broken Access Control
     * Privilege Escalation
     * Missing Authorization
   - **NEVER run verification with expired/missing credentials!**

1. **Open Redirect, DOM XSS, CSRF, Clickjacking** → **MUST use `/workspace/verify_with_browser.py`**
   - Why: Client-side behavior (JavaScript, Meta refresh)
   - Using HTTP requests = FALSE NEGATIVE!

2. **SQL Injection, XXE, SSRF, Command Injection** → Use HexStrike
   - Why: Need professional tools

3. **Simple XSS, IDOR, Info Disclosure** → HTTP Client OK
   - Why: Simple HTTP requests sufficient
   - **BUT**: If needs auth, ask for credentials first!

**❌ DO NOT:**
- Use HTTP requests for Open Redirect (will miss client-side redirects!)
- Skip the decision tree
- Assume HTTP client works for all vulnerabilities

**✅ DO:**
- Always check vulnerability type FIRST
- Use browser for client-side vulnerabilities
- Save screenshot evidence when using browser

---

## 🔐 Authentication Check (Step 0 - CRITICAL!)

**THIS MUST BE THE FIRST STEP** before any verification!

### Vulnerabilities That REQUIRE Authentication

| Vulnerability Type | Why Auth Needed | Example |
|-------------------|-----------------|---------|
| **IDOR** | Access other users' resources | `/api/user/123/payment` |
| **Broken Access Control** | Test authorization bypass | Admin-only endpoints |
| **Privilege Escalation** | Test role-based access | User → Admin escalation |
| **Missing Authorization** | Verify auth checks exist | Protected endpoints |
| **Account Takeover** | Test session hijacking | Session/cookie manipulation |

### Detection Process

1. **Read the report** and check for:
   - HTTP headers with auth tokens: `Authorization`, `Cookie`, `*-Auth-Token`, etc.
   - Vulnerability types that need auth (see table above)
   - Login requirements mentioned in validation steps

2. **Use auth_checker.py**:
   ```python
   from tools.auth_checker import AuthChecker

   checker = AuthChecker()
   result = checker.check_report(report_content)

   if result['needs_auth']:
       print(result['instructions'])  # Show user how to get credentials
       # STOP HERE and ask user for credentials
   ```

3. **Ask user for credentials** using `AskUserQuestion`:
   ```
   Q: "This vulnerability requires authentication to verify. Do you have valid credentials?"
   Options:
   - Yes, I can provide them now
   - Yes, but I need instructions on how to get them
   - No, please provide manual testing steps instead
   ```

4. **Wait for user to provide**:
   - Authentication tokens
   - Cookies
   - API keys
   - Or confirm they want manual testing only

### ❌ NEVER Do This

```python
# ❌ BAD: Using expired credentials from report
token = "eyJ0eXAiOi..."  # From report (expired!)
verify_idor(token)  # Will fail with 401
```

### ✅ Always Do This

```python
# ✅ GOOD: Check and ask for credentials first
checker = AuthChecker()
result = checker.check_report(report)

if result['needs_auth']:
    if result['credentials_expired']:
        # ASK USER for fresh credentials
        print("⚠️ Report credentials are expired")
        print("📋 How to get fresh credentials:")
        print(result['instructions'])

        # Use AskUserQuestion tool
        answer = ask_user_for_credentials()

        if answer == "no_credentials":
            generate_manual_testing_steps()
            return

    # Only proceed with valid credentials
    verify_with_auth(fresh_credentials)
```

### Example: IDOR Verification with Auth Check

```python
# Step 1: Read report
report = read_file("/path/to/idor-report.md")

# Step 2: Check auth requirements
checker = AuthChecker()
auth_info = checker.check_report(report)

# Step 3: If needs auth, STOP and ask user
if auth_info['needs_auth']:
    print("🔐 Authentication Required")
    print(f"   Type: {auth_info['auth_type']}")
    print(f"   Fields: {auth_info['auth_fields']}")

    if auth_info['credentials_expired']:
        print("⚠️  Credentials in report are EXPIRED")
        print("\n📋 To get fresh credentials:")
        print(auth_info['instructions'])

        # ASK USER (using AskUserQuestion tool)
        user_choice = ask_user_question(
            "Do you have valid authentication credentials?",
            options=[
                "Yes - I'll provide them now",
                "Show me how to get them",
                "No - Generate manual test steps instead"
            ]
        )

        if user_choice == "option_1":
            # Wait for user to provide credentials
            credentials = get_credentials_from_user()
        elif user_choice == "option_2":
            # Show detailed instructions
            show_detailed_instructions(auth_info)
            credentials = get_credentials_from_user()
        else:
            # Generate manual testing report
            generate_manual_testing_report(report)
            return

# Step 4: Only now run verification with valid credentials
verify_idor(target, credentials)
```

---

## Overview

A comprehensive web security testing framework built on Docker + Kali Linux + HexStrike AI, providing intelligent vulnerability analysis and penetration testing capabilities.

## ⚠️ CRITICAL: Verification Method Routing

**BEFORE verifying ANY vulnerability, you MUST determine the correct verification method:**

### 🌐 Browser-Required Vulnerabilities (MUST use Playwright)

These vulnerabilities **REQUIRE** browser automation because they depend on client-side behavior:

| Vulnerability Type | Why Browser Required | Example Behavior |
|-------------------|---------------------|------------------|
| **Open Redirect** | JavaScript/Meta refresh redirect | `window.location = url` |
| **DOM XSS** | JavaScript execution & DOM manipulation | `innerHTML = input` |
| **CSRF** | Form submission with cookies | `<form method="POST">` |
| **Clickjacking** | iframe rendering | `<iframe src="...">` |
| **PostMessage** | Cross-window communication | `window.postMessage()` |

**⚠️ WARNING**: Using HTTP requests for these will result in FALSE NEGATIVES!

**Script to use**: `/workspace/verify_with_browser.py`

**Example**:
```python
# For Open Redirect
python3 verify_with_browser.py
# Automatically tests with both Python requests AND real browser
# Shows discrepancy if client-side redirect exists
```

### 🔧 HexStrike-Required Vulnerabilities

Complex vulnerabilities requiring professional security tools:
- SQL Injection, XXE, SSRF, Command Injection, Path Traversal, Template Injection

### 📡 HTTP Client Sufficient

Simple vulnerabilities that can be tested with direct HTTP requests:
- Reflected XSS (simple), IDOR, Broken Access Control, Information Disclosure

---

## Architecture

```
Claude Code Skill (web-vuln-analyzer)
    ↓
1. Parse Report → Identify Vulnerability Type
    ↓
2. Route to Correct Method:
    - Browser-Required → verify_with_browser.py
    - HexStrike-Required → HexStrike MCP
    - Simple → HTTP Client
    ↓
3. Execute Verification & Generate Report
```

## 4 Operating Modes

### Mode 1: Security Report Verification

**Command**: `/web-vuln-analyze target /path/to/report`

**Purpose**: Verify vulnerabilities from existing security reports

**Supported Reports**:
- Burp Suite Scanner (XML/JSON)
- OWASP ZAP (XML/JSON)
- Manual reports (Markdown/Text)

**Workflow**:
1. **Parse Report** - Extract vulnerability type, target, payload
2. **⚠️ CRITICAL: Route Verification Method** - Choose verification approach:

   **🌐 BROWSER-REQUIRED** (MUST use Playwright):
   - Open Redirect / Unvalidated Redirect
   - DOM XSS / Client-side XSS
   - CSRF / Cross-Site Request Forgery
   - Clickjacking
   - PostMessage vulnerabilities
   - **Why**: These rely on client-side behavior (JavaScript redirects, DOM manipulation)
   - **Script**: Use `/workspace/verify_with_browser.py`

   **🔧 HEXSTRIKE-REQUIRED** (MUST use HexStrike):
   - SQL Injection / SQLi
   - XXE / XML External Entity
   - SSRF / Server-Side Request Forgery
   - Command Injection / OS Command Injection
   - Path Traversal / Directory Traversal
   - Template Injection / SSTI
   - **Why**: Need professional security tools

   **📡 HTTP-CLIENT** (Simple verification):
   - Reflected XSS (simple)
   - IDOR / Insecure Direct Object Reference
   - Broken Access Control
   - Information Disclosure
   - **Why**: Simple HTTP requests sufficient

3. **Execute Verification** - Run chosen method
4. **Generate Reports** - Create `prompt.md` and verification report

**Output**:
- `VERIFICATION_REPORT.md` - Detailed verification results
- `prompt.md` - Step-by-step reproduction guide
- `evidence/` - Screenshots and logs (browser verification)
- `/evidence/open_redirect_proof.png` - Screenshot (if browser-verified)

---

### Mode 2: SAST Report Verification

**Command**: `/web-vuln-analyze target /path/to/sast`

**Purpose**: Verify static analysis alerts with mandatory dynamic testing

**Supported Tools**:
- SonarQube
- Semgrep
- Checkmarx
- Fortify

**7-Step Verification Process**:
1. **Parse Alert** - Extract alert information from SAST report
2. **Locate Vulnerability** - Identify code location and data flow
3. **Pattern Validation** - Match against known vulnerability patterns
4. **Data Flow Analysis** - Trace data flow (source → sink)
5. **Exploitability Assessment** - Evaluate exploitability
6. **PoC Generation** - Generate verification payload
7. **Dynamic Verification** 🔴 **MANDATORY** - Execute live testing via HexStrike

**Output**:
- `VERIFICATION_REPORT.md` - Detailed verification analysis
- `FINAL_VERIFICATION_STATUS.md` - Final verdict
- `poc.py` / `poc.sh` - Proof of Concept scripts

---

### Mode 3: Automated Penetration Testing

**Command**: `/web-vuln-analyze target`

**Purpose**: Automated full-scope web security testing

**Based on**: Cyber Kill Chain for Web Applications

**4-Phase Testing Flow**:

#### Phase 1: Reconnaissance
- Subdomain enumeration (subfinder, amass)
- Port scanning (nmap -sV)
- Service fingerprinting (whatweb)
- Technology stack detection (wappalyzer)
- Directory enumeration (gobuster, dirb)
- Endpoint discovery (nuclei -t exposures)

#### Phase 2: Weaponization (Vulnerability Scanning)
- OWASP Top 10 scanning
  - SQL Injection (sqlmap)
  - XSS (nuclei -t xss)
  - XXE (nuclei -t xxe)
  - SSRF (nuclei -t ssrf)
  - And more...
- CVE scanning (nuclei -t cves)
- Misconfiguration detection (nikto)
- Sensitive file discovery (nuclei -t exposures)

#### Phase 3: Exploitation (Optional, Safe Only)
- Prioritize high-risk vulnerabilities
- Safe exploitation (non-destructive)
  - SQL Injection → Read database version
  - XSS → Prove JS execution
  - SSRF → Access internal addresses
- Generate PoC code

#### Phase 4: Reporting
- Executive Summary
  - Total vulnerabilities found
  - Risk level distribution
  - Key findings
- Detailed Findings
  - Vulnerability details
  - PoC and reproduction steps
  - Remediation advice
- Risk Scoring (CVSS)

**Output**:
- `PENTEST_REPORT.md` - Complete penetration test report
- `findings/` - Individual vulnerability details
- `evidence/` - Evidence files
- `pocs/` - PoC code collection

---

### Mode 4: Custom Testing

**Command**:
```bash
# Method A: User-provided pentesting skill file
/web-vuln-analyze target /path/to/pentestskill

# Method B: Natural language prompt
/web-vuln-analyze target "test for sql injection"
/web-vuln-analyze target "check authentication bypass on login page"
```

**Purpose**: Flexible custom security testing

**Method A: PentestSkill File**:
```yaml
# pentestskill.yaml example
name: "Custom Login Testing"
target: "https://example.com/login"

phases:
  - name: "SQL Injection Test"
    tool: "sqlmap"
    params:
      data: "username=admin&password=test"

  - name: "Brute Force Test"
    tool: "hydra"
    params:
      service: "http-post-form"
      username_list: "./users.txt"
      password_list: "./passwords.txt"
```

**Method B: Natural Language**:
- Parse user prompt
- Call HexStrike intelligent routing
- Execute tests and generate report

**Output**:
- `CUSTOM_TEST_REPORT.md` - Custom test report
- `evidence/` - Test evidence

---

## Authentication Support

Supports 4 authentication types:

1. **Cookie-based** - Most common web authentication
2. **JWT/Bearer Token** - API and modern web apps
3. **Basic Auth** - Traditional HTTP authentication
4. **Custom Header** - Custom authentication schemes

**Note**: OAuth 2.0 and API Key can be implemented via Custom Header

---

## Intelligent Tool Routing

### When HexStrike is Called (Complex Tools Needed)
- ✅ SQL Injection - Needs sqlmap's complex payloads
- ✅ XXE - Needs professional scanners
- ✅ SSRF - Needs complex bypass testing
- ✅ Deserialization - Needs specialized tools
- ✅ Full scanning - Needs multi-tool orchestration

### When Claude Handles It (Simple Verification)
- ❌ Simple XSS - Just send payload and check response
- ❌ IDOR - Just modify ID parameter
- ❌ Business logic flaws - Construct request sequences
- ❌ Simple auth bypass - Modify parameters

### When Playwright is Used (Browser Interaction)
- SPA sites requiring clicks/form filling
- JavaScript execution needed

---

## Key Files

### Core Infrastructure
- `docker/Dockerfile` - Kali + HexStrike image
- `docker/docker-compose.yml` - Service orchestration
- `docker/hexstrike-config.yaml` - HexStrike configuration
- `mcp-config/hexstrike-mcp.json` - MCP connection config

### Core Tools
- `tools/verification_router.py` - Intelligent router
- `tools/http_client.py` - HTTP client (simple verification)
- `tools/browser_automation.py` - Browser automation (SPA support)
- `tools/hexstrike_client.py` - HexStrike MCP client
- `tools/report_parser.py` - Report parser (Mode 1 & 2)
- `tools/auth_handler.py` - Authentication handler
- `tools/pentest_orchestrator.py` - Pentest orchestrator (Mode 3)
- `tools/prompt_generator.py` - prompt.md generator

### Hunt Guides
- `hunts/sast-verification.md` - SAST verification guide (from Android Skill)
- `hunts/hexstrike-when-to-use.md` - When to call HexStrike
- `hunts/false-positives.md` - False positive patterns

### Documentation
- `SKILL.md` - This file
- `ENVIRONMENT_SETUP.md` - Docker + HexStrike setup guide
- `VERIFICATION_CHECKLIST.md` - Step 7 mandatory checklist
- `FALSE_POSITIVES.md` - False positive pattern library
- `KNOWN_ISSUES.md` - Known issues and solutions

---

## Quick Start

```bash
# 1. Navigate to project directory
cd ~/.claude/skills/web-vuln-analyzer

# 2. Configure HexStrike API Key
cat > docker/.env << 'EOF'
ANTHROPIC_API_KEY=sk-ant-your-api-key-here
HEXSTRIKE_MODEL=claude-3-5-sonnet-20241022
EOF

# 3. Build and start environment
docker-compose up -d

# 4. Verify environment
curl http://localhost:5000/health

# 5. Test modes
/web-vuln-analyze http://dvwa.local /path/to/burp-report.xml  # Mode 1
/web-vuln-analyze http://dvwa.local /path/to/sonarqube.json   # Mode 2
/web-vuln-analyze http://dvwa.local                           # Mode 3
/web-vuln-analyze http://dvwa.local "test for sql injection"  # Mode 4
```

---

## Key Design Principles

### 1. Clear Division of Responsibility
- **Complex work → HexStrike** (via natural language prompts)
- **Simple work → Claude** (using http_client.py)
- **Browser operations → Playwright** (using browser_automation.py)

### 2. Minimal hunt.md Design
Only 3 core files needed:
1. `sast-verification.md` - 7-step verification (copied from Android Skill)
2. `hexstrike-when-to-use.md` - When to call HexStrike
3. `false-positives.md` - False positive judgment

### 3. 100% Reuse from Android Skill
- ✅ 7-step verification workflow (Mode 2)
- ✅ SAST verification methods
- ✅ VERIFICATION_CHECKLIST.md
- ✅ prompt.md generation
- ✅ KNOWN_ISSUES.md
- ✅ Directory structure and documentation style

### 4. Cost Optimization
- Simple verification doesn't call HexStrike → Save costs
- Only call HexStrike when professional tools needed
- Clear decision criteria

---

---

## 📖 Complete Example: Open Redirect Verification

### Scenario: Phemex Open Redirect Report

**Report**: `~/report/phemexwm-140/report.md`
**Vulnerability**: Open Redirect
**PoC**: `https://phemex.com/%5cgoogle.com/%2f%2e%2e`
**Expected**: Redirects to `google.com`

### Step-by-Step Execution

#### Step 1: Read Report
```bash
/web-vuln-analyze https://phemex.com ~/report/phemexwm-140/report.md
```

#### Step 2: Identify Vulnerability Type
```
Report parsed:
- Type: Open Redirect / Unvalidated Redirect
- Target: https://phemex.com
- PoC URL: https://phemex.com/%5cgoogle.com/%2f%2e%2e
```

#### Step 3: Route to Browser Verification ⚠️ CRITICAL

**Decision**: This is an Open Redirect → **MUST use browser**

**Reason**: Open Redirect often uses:
- JavaScript redirect (`window.location = ...`)
- Meta refresh tags (`<meta http-equiv="refresh">`)
- Client-side routing

**⚠️ Common Mistake**: Using HTTP requests will MISS client-side redirects!

#### Step 4: Execute Browser Verification

**Script**: `/workspace/verify_with_browser.py`

```python
# Automatically run
python3 /workspace/verify_with_browser.py

# Tests:
# 1. Python requests (baseline)
# 2. Real browser (Playwright Chromium)
# 3. Comparison
```

#### Step 5: Results

**Python requests Result**:
```
Final URL: https://phemex.com/404
Status: NOT VULNERABLE ❌ (FALSE NEGATIVE!)
```

**Browser Result**:
```
Final URL: https://www.google.com/
Status: VULNERABLE ✅ (CORRECT!)
Screenshot: /evidence/open_redirect_proof.png
```

#### Step 6: Generate Report

**Output Files**:
- `results/VERIFICATION_REPORT.md` - Full verification report
- `evidence/open_redirect_proof.png` - Screenshot of redirect
- `results/prompt.md` - Reproduction steps

**Report Excerpt**:
```markdown
## Verification Result: VULNERABLE ✅

### Method Used: Browser Automation (Playwright)

**Python requests**: phemex.com/404 (FALSE NEGATIVE)
**Real browser**: google.com (TRUE POSITIVE)

### Analysis

This is a **client-side redirect** vulnerability that can only be detected with a real browser. The vulnerability likely uses:
- JavaScript: `window.location.href = redirect_url`
- Or Meta refresh: `<meta http-equiv="refresh" content="0;url=...">`

**Impact**: High - Users can be redirected to phishing sites
```

### Key Takeaways

1. ✅ **Always use browser for Open Redirect**
2. ✅ **HTTP requests will miss client-side behavior**
3. ✅ **Playwright captures real-world exploitation**
4. ✅ **Screenshot provides proof**

---

## 🔧 故障排除

### Issue 1: Agent 执行超时
```
错误: Agent execution timed out after 300s
解决: 在 docker/.env 中设置 CAI_TIMEOUT=1800
```

### Issue 2: 渗透测试中途停止
```
症状: Agent 只验证了几个漏洞就停止了
解决: 在 docker/.env 中设置 CAI_MAX_TURNS=200
```

### Issue 3: CPU 100% 卡死 (已修复)
```
症状: CAI agent 挂起，CPU 100%
原因: vendor/cai/util.py 中的无限循环
解决: 已在代码中修复 (continue → pass)
```

### Issue 4: AWS WAF 阻挡测试
```
症状: SQL注入、XSS、路径遍历测试返回 403
解决:
  - 使用 WAF 绕过技术
  - 或在无 WAF 环境中测试
  - 注意: 命令注入、SSRF 外部请求可能仍然有效
```

### Issue 5: 重复 tool_result 错误 (已修复)
```
错误: tool_use without tool_result
原因: 消息历史中存在重复的 tool_result
解决: 已在 util.py 中添加去重逻辑
```

---

## Version

**Version**: 2.1
**Status**: Production Ready
**Last Updated**: 2026-03-05
**Changes**:
  - v2.1: 修复 CAI 框架无限循环、超时问题；优化配置参数 (CAI_MAX_TURNS=200, CAI_TIMEOUT=1800)
  - v2.0: AI Native Architecture
  - v1.1: Added intelligent verification routing (browser-first for client-side vulns)
