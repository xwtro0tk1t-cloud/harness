# Web Vulnerability Analyzer

AI Native 安全测试框架，基于 Docker + Kali Linux + CAI Framework，提供智能漏洞分析和渗透测试能力。

## 架构

```
Claude Code (你就是 LLM)
    │
    ├─ 简单任务 → HTTP Client / Playwright（直接处理）
    │
    └─ 复杂任务 → CAI Framework
                    ├─ 11 Agents (bug_bounty, redteam, blueteam...)
                    │      │
                    │      └─ MCP Bridge (3 tools)
                    │             │
                    │             └─ HexStrike Docker (59 Kali tools)
                    │
                    └─ LLM Backend
                         ├─ LiteLLM Proxy → Claude (推荐)
                         └─ Local Ollama → Qwen (免费，功能受限)
```

## Features

### 4 Operating Modes

1. **Mode 1: Security Report Verification** - Verify Burp Suite, ZAP reports
2. **Mode 2: SAST Report Verification** - 7-step verification for SonarQube, Semgrep
3. **Mode 3: Automated Penetration Testing** - Cyber Kill Chain based testing
4. **Mode 4: Custom Testing** - Natural language prompts

### Key Capabilities

- ✅ **AI Native Design** - Claude 直接决策，无规则路由
- ✅ **CAI Framework** - 11 个专业 Agent（bug_bounty, redteam, blueteam...）
- ✅ **MCP Bridge** - 连接 HexStrike 的 59 个 Kali 安全工具
- ✅ **Browser Automation** (Playwright) - DOM XSS, CSRF, Open Redirect
- ✅ **4 Authentication Types** (Cookie, JWT, Basic Auth, Custom Header)
- ✅ **One-command Setup** (`./setup.sh`) - 自动安装 Python 3.12 + 依赖
- ✅ **Docker-based** - HexStrike Kali 容器

## Quick Start

### Prerequisites

- Docker Desktop 20.10+
- **Python 3.12**（必须，3.14 不兼容 LiteLLM）
- 8GB+ RAM

### Installation

```bash
# 1. 进入项目目录
cd ~/.claude/skills/web-vuln-analyzer

# 2. 运行安装脚本（自动安装 Python 3.12 + 虚拟环境）
./setup.sh

# 3. 配置 API Key
vim docker/.env
# 填入你的 LiteLLM proxy 信息

# 4. 启动 HexStrike
cd docker && docker-compose --profile full up -d

# 5. 验证
source .venv/bin/activate
python tools/cai_client.py --health
```

### 配置说明

编辑 `docker/.env`，CAI 使用 **OpenAI 兼容 API**，3 个核心变量：

| Variable | 说明 |
|----------|------|
| `OLLAMA_API_BASE` | API base URL（**不带 /v1**，代码自动追加） |
| `OPENAI_API_KEY` | API key |
| `CAI_MODEL` | 模型名 |

#### 方式 A: LiteLLM Proxy（推荐）

```bash
OPENAI_API_KEY=sk-your-litellm-key
OLLAMA_API_KEY=sk-your-litellm-key
OLLAMA_API_BASE=https://your-litellm-proxy.com
CAI_MODEL=ollama_cloud/claude-haiku-4-5-20251001
```

> ⚠️ LiteLLM 用户：模型名**必须**有 `ollama_cloud/` 前缀（LiteLLM 路由约定）

#### 方式 B: 直连 API（DeepSeek / OpenAI / OpenRouter）

```bash
# DeepSeek 示例
OPENAI_API_KEY=sk-your-deepseek-key
OLLAMA_API_KEY=sk-your-deepseek-key
OLLAMA_API_BASE=https://api.deepseek.com
CAI_MODEL=deepseek-chat
```

> ⚠️ 直连 API 用户：模型名**不要**加 `ollama_cloud/` 前缀，直接写模型名。
> `OLLAMA_API_BASE` 必须是 **OpenAI 兼容端点**（不是 Anthropic 格式的 `/anthropic`）。

#### 方式 C: 本地 Ollama（免费，功能受限）

```bash
OPENAI_API_KEY=ollama
OLLAMA_API_KEY=ollama
OLLAMA_API_BASE=http://localhost:11434
CAI_MODEL=qwen2.5-coder:7b
```

#### 配置速查

| Provider | OLLAMA_API_BASE | CAI_MODEL | 前缀？ |
|----------|----------------|-----------|--------|
| LiteLLM Proxy | `https://proxy:4000` | `ollama_cloud/claude-haiku-4-5-20251001` | 需要 |
| DeepSeek | `https://api.deepseek.com` | `deepseek-chat` | 不需要 |
| OpenRouter | `https://openrouter.ai/api` | `anthropic/claude-3.5-sonnet` | 不需要 |
| OpenAI | `https://api.openai.com` | `gpt-4o` | 不需要 |
| Local Ollama | `http://localhost:11434` | `qwen2.5-coder:7b` | 不需要 |

### 常见问题

| 问题 | 错误信息 | 解决方案 |
|------|---------|---------|
| Python 3.14 不兼容 | `'typing.Union' has no attribute '__annotations__'` | 使用 Python 3.12（setup.sh 自动处理） |
| Provider 未指定 | `LLM Provider NOT provided` | 模型名加前缀：`ollama_cloud/model` |
| Proxy 不工作 | `Incorrect API key` | 使用 `ollama_cloud/` 前缀 + `OLLAMA_API_BASE` |
| Ollama 工具调用失败 | 输出 JSON 但不执行 | 换用 Claude via LiteLLM proxy |

详见 `./setup.sh --help` 或 [docs/INSTALLATION_GUIDE.md](docs/INSTALLATION_GUIDE.md)

## Usage

### Mode 1: Verify Security Report

```bash
# Verify Burp Suite report
/web-vuln-analyze http://target.com /path/to/burp-report.xml

# Verify OWASP ZAP report
/web-vuln-analyze http://target.com /path/to/zap-report.json

# Outputs:
# - VERIFICATION_REPORT.md
# - prompt.md (reproduction guide)
# - evidence/ (screenshots, logs)
```

### Mode 2: Verify SAST Alerts

```bash
# Verify SonarQube alerts
/web-vuln-analyze http://target.com /path/to/sonarqube.json

# Verify Semgrep findings
/web-vuln-analyze http://target.com /path/to/semgrep.json

# Outputs:
# - VERIFICATION_REPORT.md (7-step analysis)
# - FINAL_VERIFICATION_STATUS.md
# - poc.py / poc.sh
```

### Mode 3: Automated Penetration Test

```bash
# Full security scan
/web-vuln-analyze http://target.com

# Outputs:
# - PENTEST_REPORT.md
# - findings/ (individual vulnerabilities)
# - evidence/ (proof)
# - pocs/ (exploit code)
```

### Mode 4: Custom Testing

```bash
# Natural language prompt
/web-vuln-analyzer http://target.com "test for sql injection"

# Custom YAML skill
/web-vuln-analyzer http://target.com /path/to/custom-skill.yaml
```

### CAI 模式（AI Native）

```bash
# 使用 CAI 验证报告
/web-vuln-analyzer https://target.com ./report.xml --use-cai

# 指定 agent
/web-vuln-analyzer https://target.com --use-cai --agent redteam_agent

# 自定义测试（Claude 语义理解选择 agent）
/web-vuln-analyzer https://target.com "test SQL injection on login" --use-cai

# CTF 模式（LLM Handoff，发散探索）
/web-vuln-analyzer https://ctf.com --use-cai --pattern ctf --allow-exploit
```

**CAI 参数：**

| 参数 | 说明 |
|------|------|
| `--use-cai` | 启用 CAI |
| `--agent <name>` | 指定 agent: bug_bounty_agent / redteam_agent / blueteam_agent |
| `--pattern <name>` | 使用预定义 pattern: vuln_verify / pentest / ctf |
| `--safe-only` | 只验证，不 exploitation（默认） |
| `--source <dir>` | SAST 源码目录 |

## Architecture

### AI Native 设计

```
Claude Code (你就是 LLM - 直接决策，无规则路由)
    │
    ├─ 简单任务（直接处理，不调用任何外部工具）
    │   ├─ HTTP Client → XSS, IDOR 验证
    │   └─ Playwright → DOM XSS, CSRF, Open Redirect
    │
    └─ 复杂任务（需要专业工具）
        │
        └─ CAI Client (tools/cai_client.py)
            │
            ├─ 11 Agents:
            │   ├─ bug_bounty_agent  (漏洞挖掘)
            │   ├─ redteam_agent     (渗透测试)
            │   ├─ blueteam_agent    (蓝队防御)
            │   ├─ dfir_agent        (数字取证)
            │   ├─ reporting_agent   (报告生成)
            │   ├─ web_pentester     (Web 渗透)
            │   ├─ sast_agent        (SAST 分析)
            │   ├─ retester_agent    (漏洞重测)
            │   ├─ traffic_analyzer  (流量分析)
            │   ├─ memory_analyzer   (内存取证)
            │   └─ reverse_engineer  (逆向工程)
            │
            ├─ MCP Bridge (3 tools):
            │   ├─ execute_command      → 执行任意 Kali 命令
            │   ├─ list_available_tools → 列出可用工具
            │   └─ check_health         → 健康检查
            │
            └─ HexStrike Docker (localhost:8888)
                └─ 59 Kali 安全工具 (nmap, sqlmap, nuclei...)
```

### 为什么 MCP Bridge 只有 3 个工具？

```python
# AI Native 设计：1 个通用工具 = 无限能力
execute_command("nmap -sV -p 80,443 target.com")
execute_command("sqlmap -u 'url' --batch")
execute_command("nuclei -u target -t cves/")

# 不是 127 个独立工具：
# ❌ mcp.tool("run_nmap")(target, ports, flags...)
# ❌ mcp.tool("run_sqlmap")(url, method, data...)
```

LLM (Claude) 知道这些工具的用法，它自己组合命令。

### 设计原则

| 场景 | 驱动方式 | 原因 |
|------|---------|------|
| Agent 选择 | Claude | 语义理解，无需规则路由 |
| 命令组合 | Claude | 理解工具参数，灵活组合 |
| 结果分析 | Claude | 上下文理解，判断漏洞 |
| 安全边界 | 规则 | guardrails 强制执行 |

## Authentication Support

Supports 4 authentication types:

```python
from tools.auth_handler import AuthHandler

auth = AuthHandler()

# Cookie-based
auth.set_cookie("sessionid=abc123; csrftoken=xyz789")

# JWT/Bearer Token
auth.set_jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")

# Basic Auth
auth.set_basic_auth("username", "password")

# Custom Header
auth.set_custom_header("X-API-Key", "secret-key-123")
```

## Documentation

### Core Documentation

- [SKILL.md](SKILL.md) - Complete skill documentation (4 modes)
- [ENVIRONMENT_SETUP.md](ENVIRONMENT_SETUP.md) - Docker setup guide
- [VERIFICATION_CHECKLIST.md](VERIFICATION_CHECKLIST.md) - Step 7 mandatory checklist

### Hunt Guides

- [sast-verification.md](hunts/sast-verification.md) - 7-step SAST verification workflow
- [hexstrike-when-to-use.md](hunts/hexstrike-when-to-use.md) - Tool selection decision guide
- [false-positives.md](hunts/false-positives.md) - False positive pattern library

## Tool Selection Guide

| Vulnerability Type | Method | Reason |
|-------------------|--------|--------|
| SQL Injection | HexStrike | Complex payloads, blind injection |
| XXE | HexStrike | Specialized XML testing |
| SSRF | HexStrike | Complex bypass testing |
| **XSS (Simple)** | **HTTP Client** | **Simple payload testing** |
| **IDOR** | **HTTP Client** | **Parameter modification** |
| **Business Logic** | **HTTP Client** | **Request sequences** |
| **SPA XSS** | **Browser** | **JavaScript execution** |
| **DOM XSS** | **Browser** | **Client-side testing** |

See [hexstrike-when-to-use.md](hunts/hexstrike-when-to-use.md) for complete guide.

## Examples

### Example 1: Verify XSS (Simple)

```python
from tools.http_client import HTTPClient

client = HTTPClient()

result = client.verify_xss(
    target="http://target.com/search",
    params={
        'parameter': 'q',
        'method': 'GET'
    }
)

print(f"Vulnerable: {result.vulnerable}")
print(f"Confidence: {result.confidence}")
print(f"Evidence: {result.evidence}")
```

### Example 2: Verify SQL Injection (HexStrike)

```python
from tools.hexstrike_client import HexStrikeClient

client = HexStrikeClient()

result = client.test_sql_injection(
    target="http://target.com/product?id=1"
)

print(f"Vulnerable: {result.vulnerable}")
print(f"Tools used: {result.tools_used}")
print(f"Findings: {result.findings}")
```

### Example 3: Verify SPA XSS (Browser)

```python
from tools.browser_automation import BrowserAutomation

browser = BrowserAutomation()

result = browser.verify_spa_xss(
    target="http://spa-app.com",
    params={
        'input_selector': 'input[name="search"]',
        'submit_selector': 'button[type="submit"]',
        'payload': '<img src=x onerror=alert("XSS")>'
    }
)

print(f"Vulnerable: {result.vulnerable}")
print(f"Screenshots: {result.screenshots}")
```

## Testing Environment

Deploy vulnerable test applications:

```bash
# Start test targets
docker-compose --profile testing up -d

# Access test apps:
# DVWA: http://localhost:8080 (admin/password)
# Juice Shop: http://localhost:3000

# Test example
/web-vuln-analyze http://localhost:8080/vulnerabilities/sqli/?id=1
```

## Troubleshooting

### Container won't start

```bash
docker logs hexstrike-kali
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### HexStrike health check fails

```bash
# Check from inside container
docker exec hexstrike-kali curl http://localhost:5000/health

# Check logs
docker logs hexstrike-kali | tail -n 50
```

### API key error

```bash
# Verify .env file
cat docker/.env

# Restart to reload config
docker-compose down
docker-compose up -d
```

See [ENVIRONMENT_SETUP.md](ENVIRONMENT_SETUP.md) for complete troubleshooting guide.

## Project Structure

```
web-vuln-analyzer/
├── .venv/                        # Python 3.12 虚拟环境（必须）
├── setup.sh                      # 一键安装脚本
├── vendor/
│   └── cai/                      # CAI Framework 源码
├── requirements-cai.txt          # CAI 依赖列表
├── docker/
│   ├── .env                      # 环境配置（API keys）
│   ├── docker-compose.yml        # HexStrike 服务
│   └── agents.yml                # CAI Agent + Pattern 配置
├── tools/
│   ├── cai_client.py            # CAI 客户端（11 agents）
│   ├── hexstrike_mcp_bridge.py  # MCP Bridge（3 tools）
│   ├── http_client.py           # HTTP 验证
│   ├── browser_automation.py    # Playwright 自动化
│   ├── hexstrike_client.py      # HexStrike HTTP 客户端
│   └── auth_handler.py          # 4 种认证
├── hunts/                        # Hunt guides
├── workspace/                    # 工作目录
├── results/                      # 扫描结果
├── evidence/                     # 截图、日志
└── pocs/                         # PoC 脚本
```

## Known Issues & Solutions

### Issue 1: Python 3.14 不兼容

```
错误: 'typing.Union' object has no attribute '__annotations__'
原因: LiteLLM 与 Python 3.14 不兼容
解决: 使用 Python 3.12（setup.sh 自动安装）
```

### Issue 2: LLM Provider NOT provided

```
错误: You passed model=qwen2.5-coder:7b
原因: LiteLLM 需要 provider 前缀
解决: 使用 ollama/model 或 ollama_cloud/model
```

### Issue 3: 自定义 LLM Proxy 不工作

```
错误: Incorrect API key / Missing Anthropic API Key
原因: LiteLLM 识别 "claude" 关键字，直接调用 Anthropic API
解决: 使用 ollama_cloud/ 前缀 + OLLAMA_API_BASE
```

### Issue 4: Local Ollama Tool Calling 失败

```
现象: 模型输出 {"name": "tool", "arguments": {}} 但工具不执行
原因: Qwen 等小模型不完全支持 OpenAI tool calling 格式
解决: 使用 Claude via LiteLLM proxy
```

### Issue 5: 非 LiteLLM API 报 Provider 错误

```
错误: LLM Provider NOT provided for model ollama_cloud/deepseek-chat
原因: ollama_cloud/ 前缀是 LiteLLM 专用，直连 API 不需要
解决: 直连 API 不加前缀，如 CAI_MODEL=deepseek-chat
      OLLAMA_API_BASE 必须是 OpenAI 兼容端点（不是 /anthropic）
```

## Key Design Principles

### 1. Clear Division of Responsibility

- **Simple verification** → Claude handles (HTTP client)
- **Browser interaction** → Playwright
- **Complex security tools** → HexStrike

### 2. Mandatory Dynamic Verification

🔴 **Step 7 cannot be skipped** - All findings must be dynamically verified

### 3. Minimal Hunt Guides

Only 3 core files:
- `sast-verification.md` (from Android Skill)
- `hexstrike-when-to-use.md`
- `false-positives.md`

### 4. Cost Optimization

- Simple verification doesn't call HexStrike → Save API costs
- Only use professional tools when needed
- Clear decision criteria

## Performance

### Resource Usage

- **Quick scan**: ~5 minutes, 2GB RAM
- **Focused scan**: ~10 minutes, 4GB RAM
- **Full scan**: ~30 minutes, 8GB RAM

### Scan Modes

| Mode | Duration | Tools Used | Use Case |
|------|----------|-----------|----------|
| Quick | 5 min | nuclei, nikto | CI/CD pipelines |
| Focused | 10 min | Auto-selected | Specific vulnerability |
| Full | 30 min | All tools | Complete pentest |
| Expert | 45 min | AI + Traditional | High-value targets |

## Security Considerations

### Safe by Default

- ✅ Destructive commands disabled
- ✅ Localhost scanning blocked
- ✅ Rate limiting enabled
- ✅ Safe exploitation only (PoC verification)

### Container Isolation

- Network isolated
- Resource limited (CPU, memory)
- No elevated privileges

### API Key Protection

```bash
# Never commit .env
echo "docker/.env" >> .gitignore

# Use environment variables
export ANTHROPIC_API_KEY="sk-ant-..."
```

## Contributing

This is a Claude Code skill implementation. Contributions welcome:

1. Fork repository
2. Create feature branch
3. Test thoroughly
4. Submit pull request

## License

MIT License - See LICENSE file

## Version

- **Version**: 2.0 (AI Native)
- **Status**: Production Ready
- **Last Updated**: 2025-03-04
- **Python**: 3.12 (required)
- **Key Changes**:
  - 删除 verification_router.py, pentest_orchestrator.py（1310 行伪 AI 代码）
  - 集成 CAI Framework（11 agents）
  - MCP Bridge 连接 HexStrike（3 generic tools → 59 Kali tools）
  - 支持 LiteLLM Proxy + Local Ollama

## Support

### Resources

- Documentation: See `SKILL.md` and guides in `hunts/`
- Troubleshooting: See `ENVIRONMENT_SETUP.md`
- Known Issues: See `KNOWN_ISSUES.md`

### Getting Help

1. Check documentation
2. Review logs: `docker logs hexstrike-kali`
3. File issue with details

## Acknowledgments

- Based on Android Skill architecture
- Powered by HexStrike AI
- Built on Kali Linux
- Uses Playwright for browser automation

---

**Made with ❤️ for secure web applications**
