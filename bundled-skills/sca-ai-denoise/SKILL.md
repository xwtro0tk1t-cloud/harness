---
name: sca-ai-denoise
description: SCA 漏洞 AI 降噪与风险优先级评估。对 Grype/Snyk/Xray 等 SCA 工具的漏洞发现进行多维度风险评估，按 P0-P3 分级，过滤噪音（DoS、本地提权、低影响信息泄露），聚焦真正可利用的高风险漏洞。当用户需要对 SCA 扫描结果降噪、漏洞优先级排序、或供应链风险评估时使用。
---

# SCA AI Denoise — 漏洞风险优先级评估

对 SCA (Software Composition Analysis) 扫描结果进行 AI 驱动的风险评估与降噪。

**核心目标**：减少告警疲劳，让安全团队聚焦真正重要的漏洞。

## 输入格式

你会收到一组 SCA 漏洞发现（JSON 数组），每个条目包含：
- `index`: 漏洞索引
- `cve_id`: CVE 编号
- `package`: 包名@版本
- `severity`: CRITICAL/HIGH/MEDIUM/LOW
- `title`: 漏洞标题
- `description`: 漏洞描述（可能截断）

可能附带项目上下文：项目名称、语言、框架等。

## 优先级框架（严格标准）

### P0 — 立即处理（必须同时满足多个高风险条件）

| 条件组合 | 示例 |
|---------|------|
| RCE + 无需认证 + 远程攻击向量 | jackson-databind 反序列化 RCE |
| SQL 注入 + 无需认证 + 远程 | 数据库驱动 SQL 注入 |
| 认证绕过 + 严重影响 + 远程 | JWT 签名绕过 |
| 反序列化 + 公开 PoC/Exploit + 远程 | Log4Shell (CVE-2021-44228) |
| CVSS ≥ 9.5 + 公开 Exploit + 远程 + 无需认证 | |

**P0 必须严格**：仅当漏洞满足**多个**高风险条件时才标记为 P0。

### P1 — 本周修复（高严重性 + 可利用性）

| 条件组合 |
|---------|
| RCE + 远程 + 需要认证 |
| Critical 严重性 + 远程 + 公开 Exploit |
| Critical 严重性 + 远程 + 低攻击复杂度 |
| SQL 注入 / XXE / SSRF + 远程（即使需要认证） |
| High 严重性 + 远程 + 公开 PoC |
| CVSS ≥ 8.0 + 远程攻击向量 |

### P2 — 本月修复（有限攻击面或复杂度）

| 条件组合 |
|---------|
| Critical/High 严重性 + 仅本地攻击 |
| Critical/High 严重性 + 高攻击复杂度 |
| Medium 严重性 + 远程攻击向量 |
| XSS（通常需要用户交互） |
| High 严重性但无明确远程利用路径 |

### P3 — 噪音（可延迟或忽略）

| 条件组合 |
|---------|
| DoS/DDoS（除非关键互联网服务） |
| 本地提权（无远程攻击面） |
| Low 严重性漏洞 |
| Medium 严重性 + 仅本地攻击 |
| 需要复杂攻击链或用户交互 |
| 信息泄露且业务影响极小 |
| 仅开发/测试依赖中的漏洞（不在生产环境） |

## 评估维度

对每个漏洞评估以下 5 个维度：

### 1. 可利用性评估
- 是否有公开 PoC/Exploit？（检查描述中的 "exploit", "poc", "proof of concept"）
- 攻击复杂度？（LOW = 容易，HIGH = 困难）
- 利用前提条件？（用户交互、特定配置）
- 是否已有野外利用？

### 2. 攻击向量分析
- 攻击向量：NETWORK（远程）vs LOCAL vs ADJACENT
- 是否需要认证？（NONE = 无需认证）
- 是否暴露在互联网？（直接暴露 vs 内部服务）

### 3. 影响分类（优先级排序）
```
RCE > SQL 注入 > 认证绕过 > 反序列化 > SSRF > XSS > DoS > 信息泄露
```

### 4. 业务影响
- 关键路径依赖 vs 可选组件？
- 直接依赖 vs 深层传递依赖？
- 是否有可用修复版本？升级是否有破坏性变更？

### 5. 供应链风险
- 包维护状态（活跃维护 vs 已弃用）
- 已知恶意活动或 typosquatting
- 许可证合规问题

## 噪音过滤规则

以下情况默认标记为 P3：
- DoS 漏洞（除非关键互联网服务）
- 本地提权且无远程攻击面
- 高 CVSS 但需要特定边缘配置
- 认证后管理面板的 XSS
- 业务影响极小的信息泄露
- 开发/测试依赖中的漏洞

## 输出格式

根据调用方式，输出两种格式之一：

### 简洁模式（默认，用于自动化管线）

输出 JSON 数组，每个元素：
```json
[
  {
    "index": 0,
    "priority": "P0",
    "reason": "RCE via deserialization + unauthenticated + remote + public exploit available"
  }
]
```

**仅输出 JSON 数组，不要有其他文字。**

### 完整模式（用于人工审查）

输出完整评估报告：
```json
{
  "risk_score": 7.5,
  "risk_level": "high",
  "summary": "2 句话执行摘要，突出最高风险",
  "prioritized_vulnerabilities": {
    "P0": [{"cve": "CVE-XXX", "package": "pkg@ver", "cvss_score": 9.8, "vulnerability_type": "RCE", "justification": "满足 P0 条件：...", "recommendation": "升级到 X.Y.Z"}],
    "P1": [],
    "P2": [],
    "P3": []
  },
  "vulnerability_statistics": {"total": 50, "P0_count": 2, "P1_count": 5, "P2_count": 20, "P3_count": 23},
  "recommendations": ["前 3 条可执行建议"],
  "supply_chain_assessment": {"overall_health": "concerning|acceptable|good", "risk_factors": ["factor1"]}
}
```

## 关键原则

1. **P0 必须严格** — 仅当满足多个高风险条件时才分配 P0
2. **积极过滤噪音** — DoS、本地提权、信息泄露默认 P3
3. **关注真实可利用风险** — 不只看 CVSS 分数，考虑实际攻击场景
4. **提供具体理由** — 解释每个漏洞为什么获得该优先级
5. **可执行建议** — 给出具体升级命令和修复步骤
6. **优先关注无需认证 + 远程 + RCE** — 这是最高风险组合
