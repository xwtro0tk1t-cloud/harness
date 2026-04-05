# Security Review Skill 生成模板

生成 `security-review-skill-for-{{project_name}}` 时，使用以下结构：

---

## SKILL.md 模板

```markdown
---
name: security-review-skill-for-{{project_name}}
description: {{project_name}} 项目的安全代码审计。检测 {{main_vuln_types}}。当审计 {{project_name}} 代码、进行安全评审时使用。
---

# {{project_name}} Security Review

## 项目背景

{{project_overview}}

**技术栈**：{{tech_stack}}
**关键模块**：{{key_modules}}

## 审计方法

**核心原则**：宁可漏过也不误报，所有发现必须基于实际代码。

### Step 1: 侦察阶段
审计前先理解全局：
- 识别技术栈（语言、框架、数据库）
- 枚举所有 API 端点，生成端点-权限矩阵
- 检查外部依赖中的高风险库

### Step 2: 双轨审计

**Sink-driven（找危险代码）**：
适用于：注入、RCE、文件操作、SSRF
- 搜索危险函数模式
- 追踪数据流：Source → Propagation → Sink
- 验证是否有有效防御

**Control-driven（找缺失的安全控制）**：
适用于：认证、授权、业务逻辑
- 枚举端点，检查权限控制
- **缺失即脆弱**：应有认证/授权但没有 → 漏洞

### Step 3: 数据流分析
```
Import (外部依赖风险)
    ↓
Source (输入源) → Propagation (传播) → Sink (危险操作)
```

分析问题：
1. 数据**从哪来**？用户可控？
2. 中间**经过什么处理**？
3. 最终**到达哪里**？
4. **能被外部触发吗**？

### Step 4: 跨文件分析
遇到 wrapper 函数，不要直接报漏洞：
- 搜索所有调用该函数的地方
- 检查调用者传入的参数来源

### Step 5: 攻防对抗验证
**攻击方**：如何利用？构造攻击输入
**防御方**：有什么阻止？框架保护？权限控制？

### Step 6: 覆盖评估
确保关键维度都已检查：
- [ ] 注入（SQL/命令/模板）
- [ ] 认证（登录/会话/Token）
- [ ] 授权（端点权限/资源归属）
- [ ] 业务逻辑（状态机/竞态）

### 误报识别
- ORM 安全使用、参数化查询
- 框架自动转义
- 输入已验证
- 不可外部触发
- 测试代码

## 优先检查
{{priority_paths}}

## 通用漏洞检查

根据技术栈 {{tech_stack}}，检查以下漏洞：

### 注入类
{{injection_checks}}

### 认证授权
{{auth_checks}}

### 业务逻辑
{{business_logic_checks}}

## 深度漏洞模式

### 语言深度模式
{{language_deep_patterns}}

### 框架威胁面
{{framework_threat_surface}}

### 框架检查项
{{framework_checks}}

### 安全领域
{{security_domain_sections}}

## 误报过滤增强

{{false_positive_kill_switches}}

## 污点分析指南

### Sink 分类
{{sink_slot_types}}

### 追踪规则
{{taint_tracking_rules}}

## 项目特定检查

{{#if scanning_dimensions}}
### 扫描维度框架

{{scanning_dimensions}}
{{/if}}

### {{special_check_1_name}}

**背景**：{{special_check_1_background}}

{{#if special_check_1_invariants}}
**不变量**：
{{special_check_1_invariants}}
{{/if}}

**检查项**：
{{special_check_1_items}}

**代码模式**：
\`\`\`{{language}}
// 危险
{{dangerous_pattern_1}}

// 安全
{{safe_pattern_1}}
\`\`\`

{{#if mathematical_invariants}}
## 关键公式与不变量

{{mathematical_invariants}}
{{/if}}

{{#if state_machines}}
## 状态机定义

{{state_machines}}
{{/if}}

## 实战案例参考

{{#if project_audit_findings}}
### 项目已发现的安全问题

{{project_audit_findings}}
{{/if}}

{{#if industry_incidents}}
### 行业真实攻击案例

{{industry_incidents}}
{{/if}}

### 高频攻击模式
{{high_freq_attack_patterns}}

{{#if cross_dimensional_risks}}
### 跨维度关联风险

{{cross_dimensional_risks}}
{{/if}}

### 绕过技巧
{{bypass_techniques}}

## 输出格式

\`\`\`json
{
  "findings": [
    {
      "severity": "CRITICAL/HIGH/MEDIUM/LOW",
      "type": "漏洞类型",
      "location": "file:line",
      "description": "问题描述",
      "data_flow": "request.args['id'] → f-string → cursor.execute()",
      "reachability": "可从 /api/user 触发，无需认证",
      "attack_scenario": "攻击者可通过 id=1' OR '1'='1 获取所有数据",
      "defense_analysis": "未发现有效防护",
      "vulnerable_code": "有问题的代码",
      "remediation": "使用参数化查询"
    }
  ]
}
\`\`\`
```

---

## 变量说明

### 基础变量

| 变量 | 来源 | 示例 |
|------|------|------|
| `project_name` | 用户指定 | "支付系统" |
| `tech_stack` | 设计文档 | "Python + Django + PostgreSQL" |
| `main_vuln_types` | 分析得出 | "SQL 注入、越权、支付逻辑漏洞" |
| `priority_paths` | 代码结构分析 | "api/payment/, auth/, models/" |
| `special_check_*` | 业务文档提取 | 项目特定的安全检查项 |

### 参考资料裁剪变量

| 变量 | 来源 | 示例 |
|------|------|------|
| `language_deep_patterns` | `languages/*.md` 裁剪 | 语言深度 sink/source 列表、安全替代方案 |
| `framework_threat_surface` | `frameworks/*.md` 裁剪 | 框架特有威胁面概览 |
| `framework_checks` | `frameworks/*.md` 裁剪 | 框架安全检查清单 |
| `security_domain_sections` | `security/*.md` 裁剪 | 与项目业务相关的安全领域分析 |
| `false_positive_kill_switches` | `core/false_positive_filter.md` 裁剪 | Kill Switch 条件列表 |
| `sink_slot_types` | `core/sinks_sources.md` 裁剪 | Sink 分类（注入/RCE/文件/网络） |
| `taint_tracking_rules` | `core/taint_analysis.md` 裁剪 | 污点传播和追踪规则 |
| `high_freq_attack_patterns` | `wooyun/*.md` + `cases/` 裁剪 | 高频参数、常见攻击向量 |
| `bypass_techniques` | `core/bypass_strategies.md` 裁剪 | Top 绕过技巧摘要 |

### 深度分析变量（复杂项目使用）

| 变量 | 来源 | 示例 | 说明 |
|------|------|------|------|
| `scanning_dimensions` | 项目复杂度分析 | 六维扫描框架表 | 复杂项目（多语言/多服务）用，映射检查项到扫描维度 |
| `mathematical_invariants` | 风控/引擎文档提取 | `equity = balance + unrealizedPnl` | 数学公式、恒等式，用于公式校验检查 |
| `state_machines` | 流程文档提取 | Order: Created→Pending→Filled | 业务状态机定义，用于状态转换验证 |
| `special_check_*_invariants` | 文档提取 | `filledQty + remainingQty == originalQty` | 每个检查项的具体不变量 |
| `project_audit_findings` | 已有审计报告 | Bridge B1-B12, Engine E1-E12 | 项目已有的安全发现，直接纳入 |
| `industry_incidents` | 行业事故分析 | Balancer精度攻击, POPCAT操纵 | 与项目领域直接相关的行业攻击案例 |
| `cross_dimensional_risks` | 交叉分析 | Oracle操纵 + 清算 = 批量清算 | 跨维度复合攻击链 |

---

## 生成步骤

### Step 1: 读取项目文档（多遍提取）

**第一遍**：提取架构和技术栈
- 技术栈、框架、语言
- 服务架构（单体/微服务/多链）
- 关键中间件和依赖

**第二遍**：提取业务规则和公式
- 业务流程、状态机
- 数学公式（计算 equity/margin/liquidation 等）
- 不变量（恒等式、前置/后置条件）
- 经济参数（费率、阈值、限制）

**第三遍**：提取已有安全知识（关键！）
- 搜索审计报告、安全检查清单、事故分析
- 已发现漏洞 → 直接纳入 `project_audit_findings`
- 行业攻击案例 → 纳入 `industry_incidents`
- 安全检查清单 → 作为检查项来源

### Step 2: 选择参考资料

参考 `references/reference_index.yaml`：
- 根据语言选择 `languages/*.md` + `checklists/*.md` + `adapters/*.yaml`
- 根据框架选择 `frameworks/*.md`
- 根据业务关键词匹配 `security/*.md`（含领域特定如 DeFi/区块链）
- 始终包含 `core/` 核心文件 + `checklists/universal.md`
- 根据漏洞类型选择 `wooyun/*.md` 案例

### Step 3: 裁剪参考内容

**大小预算**（按项目复杂度动态调整）：
- 简单项目（单语言、单服务）：15-25KB
- 中等项目（2-3 语言、微服务）：25-35KB
- 复杂项目（多语言、跨链/多服务引擎）：35-50KB

**裁剪规则**：
- 语言文件：仅提取匹配框架章节，保留 sink 列表，每种漏洞类型 1 个危险+安全模式对
- 框架文件：威胁面概览 + 代码模式 + 检查清单
- 安全领域：仅提取项目语言的代码示例 + CWE 映射 + 审计清单
- Wooyun：高频参数 + top 3-5 绕过技巧 + 2-3 个案例摘要
- 核心文件：决策框架 + 查找表
- **优先级**：危险模式 > 安全模式 > 检测提示 > 攻击案例 > 修复建议

### Step 4: 生成 skill

- 填充模板变量（含裁剪后的参考内容）
- 包含完整审计方法论
- 添加项目特定代码模式示例
- 复杂项目：填充深度分析变量（不变量、状态机、已有发现、跨维度风险）

### Step 5: 对照验证

如果存在领域安全框架（如 DEX scan prompts、OWASP ASVS）：
- 逐项对照框架检查项 vs skill 覆盖度
- 未覆盖的检查项 → 回到源文档补充提取
- 标记每个框架检查项在 skill 中的对应位置

### Step 6: 测试和迭代

- 用测试代码验证检出效果
- 根据 FP/FN 调整检查规则
