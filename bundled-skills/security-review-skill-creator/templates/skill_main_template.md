# Security Review Skill 入口模板（模块化版）

生成 `security-review-skill-for-{{project_name}}` 的 SKILL.md 时使用此模板。
SKILL.md 是入口文件（~15-20KB），包含方法论、通用漏洞检查、深度模式和路由表，项目特定检查放在 checks/ 中。

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

## 审计模式

触发 skill 后，**首先**用 AskUserQuestion 询问用户审计模式：

**问题**: "选择审计模式"
**选项**:
1. **全量审计** — 扫描指定目录/模块的全部代码
2. **PR/分支审计** — 只扫描指定分支相对于基准分支的变更（如 `feature-branch` vs `main`）
3. **最近变更审计** — 扫描最近 N 天/N 个 commit 的变更

如果用户的 prompt 中已明确指定了模式（如 "审计 PR #123"、"扫描最近变更"），则跳过询问直接进入对应模式。

### 全量模式

按下方 Step 1-7 正常执行，扫描范围 = 用户指定的目录/模块。

### PR/分支模式

**Step 0: 确定 diff 范围**

用 AskUserQuestion 收集缺失信息（用户已提供的跳过）：
- **基准分支**（默认 `main`）
- **目标分支**（PR 分支名，或 `HEAD`）
- **代码目录**（项目根目录路径）

然后执行：
```bash
# 获取改动文件列表
git diff --name-only <base>...<target>

# 获取每个文件的具体 diff
git diff <base>...<target> -- <file>
```

**Step 0.1: 范围分析**

1. 将改动文件按路由表分类到模块（如 `x/bridge/` → bridge 模块）
2. 只加载相关模块的 checks/ 文件（不加载无关模块）
3. 对每个改动文件：
   a. Read 完整文件（理解上下文，不只看 diff）
   b. 从 diff 中识别变更的函数/方法签名
   c. Grep 调用链：项目中谁调用了这些函数？将调用方也纳入审计范围

然后从 Step 1 开始执行，但审计范围限定为：改动文件 + 调用链文件。

### 最近变更模式

**Step 0: 确定变更范围**

用 AskUserQuestion 收集：
- **时间范围**或 **commit 数量**（如 "最近 7 天" 或 "最近 10 个 commit"）
- **代码目录**

然后执行：
```bash
# 按时间
git log --since="7 days ago" --name-only --pretty=format: | sort -u

# 或按 commit 数
git log -10 --name-only --pretty=format: | sort -u
```

后续流程与 PR/分支模式的 Step 0.1 相同。

---

## 审计方法

**核心原则**：宁可漏过也不误报，所有发现必须基于实际代码。

### Step 1: 侦察阶段 — 识别语言和模块

审计前先理解全局，**确定代码的语言和所属模块**：

1. **识别代码语言**：通过文件扩展名自动判定
2. **按语言匹配模块**：根据路由表确定需加载的 checks/ 和正则组
3. **模块特定侦察**：
   - 枚举所有 API 端点，生成端点-权限矩阵
   - 检查外部依赖中的高风险库
   - 识别服务间通信边界（用于跨服务攻击链分析）
- **diff/PR 模式下**：侦察范围限定为改动文件及其调用链涉及的模块

<!-- 生成指令（多语言项目）：
  如果项目涉及多种语言，Step 1 必须生成"语言→模块→checks→正则组"的映射表。
  示例：
  | 检测到的语言 | 所属模块 | 加载 checks/ | 正则组 |
  |-------------|---------|-------------|--------|
  | Go | backend | backend-security.md | Go 正则 |
  | Java | api-server | api-security.md | Java 正则 |
  这样用户只审计某个模块时，不会执行其他语言的正则。
-->

### Step 2: 正则扫描（按语言路由执行）

审计前**必须**执行正则扫描，但**只执行匹配当前代码语言的正则组**。

**语言路由规则**：
- 根据 Step 1 识别的语言，选择对应的正则组
- 只扫描该语言的文件（如 Go 正则只扫 `*.go`，Java 正则只扫 `*.java`+`*.xml`）
- **全量审计**时：按语言分组依次执行全部正则

**执行方式**：
1. 根据 Step 1 确定的语言，选择对应正则组
2. 逐条执行 Grep，仅扫描该语言的文件
3. 对每个匹配逐一分析：真阳性 → 报告，误报 → 标注原因跳过
4. 零匹配的正则 → 记录为"该类型不存在"
- **diff/PR 模式下**：正则扫描范围限定为改动文件 + 调用链文件（不扫全量）

<!-- 生成指令（多语言项目）：
  审计正则速查部分必须按语言分组，每组标注适用文件扩展名。
  示例：
  #### Go 正则（`*.go` 文件）
  #### Java 正则（`*.java` + `*.xml` 文件）
  #### JS/TS 正则（`*.js`/`*.ts`/`*.tsx` 文件）
  这样 Step 2 执行时可根据当前审计语言只选对应组。
-->

**为什么必须**：人工阅读代码容易遗漏分散在多文件中的通用模式（如 SSRF、硬编码凭据、pprof 暴露）。
正则扫描 30 秒即可覆盖全部代码，漏掉 = 审计缺陷。

### Step 3: 双轨审计

**Sink-driven（找危险代码）**：
适用于：注入、RCE、文件操作、SSRF
- 基于 Step 2 的正则匹配结果，追踪数据流：Source → Propagation → Sink
- 验证是否有有效防御

**Control-driven（找缺失的安全控制）**：
适用于：认证、授权、业务逻辑
- 枚举端点，检查权限控制
- **缺失即脆弱**：应有认证/授权但没有 → 漏洞

### Step 4: 数据流分析
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

### Step 5: 跨文件/跨服务/跨语言分析
遇到 wrapper 函数，不要直接报漏洞：
- 搜索所有调用该函数的地方
- 检查调用者传入的参数来源

**跨服务攻击链分析**（多服务项目必须考虑）：

当发现一个模块的漏洞时，立即检查：
1. **上游是否可触发**：该漏洞的输入从哪个服务来？上游是否可被操纵？
2. **下游是否放大**：该漏洞的输出流向哪个服务？是否会导致下游更严重的后果？
3. **信任边界是否验证**：跨服务数据传递时，消费方是否验证了来源？

**示例**：审计 API 层发现 Actuator 信息泄露(MEDIUM) → 检查泄露的凭据是否可访问后端服务 → 若可直接调用内部 RPC → 升级为 CRITICAL

<!-- 生成指令（多服务项目）：
  对于微服务/多服务架构，Step 5 必须包含：
  1. 服务间数据流图：列出哪些服务是数据的生产者/消费者
  2. 必查跨服务路径：如 前端→API→后端→数据库 的完整链路
  3. 跨服务攻击链参考：放在 known-issues/attack-patterns.md 中
  4. 信任边界检查矩阵：每个服务边界的验证要求
-->

### Step 6: 攻防对抗验证
**攻击方**：如何利用？构造攻击输入
**防御方**：有什么阻止？框架保护？权限控制？

### Step 7: 覆盖评估
确保关键维度都已检查：
- [ ] 注入（SQL/命令/模板）
- [ ] 认证（登录/会话/Token）
- [ ] 授权（端点权限/资源归属）
- [ ] 业务逻辑（状态机/竞态）
- [ ] **跨服务攻击链**（单模块漏洞与其他模块组合是否升级？）

### 误报识别
- ORM 安全使用、参数化查询
- 框架自动转义
- 输入已验证
- 不可外部触发
- 测试代码

## 优先检查
{{priority_paths}}

## 通用漏洞检查

<!-- 生成指令：必须 Read references/general_vulns.md + references/checklists/universal.md 提取内容。
  通用漏洞检查必须覆盖 OWASP Top 10 全部类别 + 该语言的特有漏洞。
  每个类别至少 1 个危险模式 + 1 个安全模式代码示例（使用项目的语言）。
  不可只列 3-5 个类别就结束——需完整覆盖。
-->

根据技术栈 {{tech_stack}}，检查以下漏洞：

### 注入类
<!-- 必须覆盖：SQL/NoSQL、命令注入、SSTI、XSS、LDAP、XPath、ES 查询注入等该语言适用的全部注入类型 -->
{{injection_checks}}

### 认证授权
<!-- 必须覆盖：JWT/Session、密码存储、OAuth/OIDC、RBAC/ABAC、IDOR、CSRF 等 -->
{{auth_checks}}

### 数据保护
<!-- 必须覆盖：敏感数据泄露、加密弱算法、不安全随机数、日志脱敏、错误信息泄露 -->
{{data_protection_checks}}

### 文件与资源
<!-- 必须覆盖：路径遍历、文件上传、SSRF、资源耗尽/DoS、不安全反序列化 -->
{{file_resource_checks}}

### 配置与部署
<!-- 必须覆盖：调试模式、默认凭据、CORS 配置、HTTP 安全头、依赖漏洞 -->
{{config_deploy_checks}}

### 业务逻辑
{{business_logic_checks}}

## 深度漏洞模式

### 语言深度模式
<!-- 生成指令：必须 Read references/languages/{lang}.md 提取以下内容，禁止仅凭自身知识编写：
  1. 完整 Sink 函数列表（每个 sink 含函数签名 + 危险原因）
  2. 安全替代方案
  3. 该语言特有漏洞类型的完整列表（如 Python: SSTI/pickle/ReDoS/eval/exec/yaml.load 等）
  4. 每种类型 ≥1 个危险代码 + ≥1 个安全代码示例
  如果项目有多种语言，每种语言各一个子节。
-->
{{language_deep_patterns}}

### 审计正则速查（Step 2 必须执行）

以下正则在 Step 2 正则扫描阶段**必须逐条执行** Grep，不可跳过：
<!-- 生成指令：必须 Read references/adapters/{lang}.yaml（如有）和 references/languages/{lang}.md
  提取所有正则模式。如果参考文件中没有该语言的 adapter，则从 languages/{lang}.md 的
  "检测正则"或"审计模式"章节提取。正则必须覆盖以下所有类别（该语言适用的）：
  - SQL 注入 / NoSQL 注入
  - 命令注入 / 代码执行
  - SSRF / 外部请求
  - 路径遍历 / 文件操作
  - 反序列化 / 不安全解析
  - 硬编码凭据 / 密钥泄露
  - 不安全随机数
  - 调试/开发模式
  - SSTI（模板注入）
  - XSS（前端语言）
  - 原型污染（JavaScript）
  - 不安全的正则（ReDoS）
  - CORS 配置
  - 日志敏感信息泄露
  - 认证/授权相关
  如果项目有多种语言，每种语言的正则分组列出。
  最终正则数量参考：单语言 ≥15 条，双语言 ≥25 条。
-->
{{audit_regex_patterns}}

> 执行方式：对每条正则，Grep 搜索目标目录全部代码文件。匹配结果逐一分析。零匹配 = 该类型安全。

### 框架威胁面
<!-- 生成指令：必须 Read references/frameworks/{framework}.md 提取以下内容：
  1. 框架特有攻击面（如 FastAPI 路由未绑定依赖 → 跳过认证）
  2. 框架安全配置检查清单
  3. 框架提供的安全保护（用于误报过滤）
  如果项目有多个框架，每个框架各一个子节。
-->
{{framework_threat_surface}}

## 误报过滤增强

{{false_positive_kill_switches}}

## 污点分析指南

### Sink 分类
{{sink_slot_types}}

### 追踪规则
{{taint_tracking_rules}}

{{#if scanning_dimensions}}
## 扫描维度框架

{{scanning_dimensions}}
{{/if}}

## 审计路由

根据审计目标，**必须**先 Read 对应检查文件再开始审计。路由自动根据代码语言和模块路径确定。

<!-- 生成指令（多语言项目）：
  路由表必须包含两部分：
  1. **自动路由规则**：代码路径模式 → 语言 → checks → 正则组
     示例：
     | 代码路径模式 | 语言 | 加载 checks/ | 正则组 |
     |-------------|------|-------------|--------|
     | backend/*.go | Go | backend-security.md | Go |
     | api/*.java | Java | api-security.md | Java |
     | web/*.ts | TS | web-security.md | JS/TS |

  2. **手动路由表**（按审计目标）：
     | 审计目标 | 读取文件 | 语言 | 正则组 |
     |---------|---------|------|--------|

  单语言项目可省略语言列。
-->

{{routing_table}}

已知问题对照：审计完成后 Read `known-issues/prior-findings.md` 逐项验证。

## 输出格式

\`\`\`json
{
  "scan_mode": "full | pr | recent_changes",
  "diff_scope": {
    "base": "main",
    "target": "feature-branch",
    "changed_files": ["path/to/file1.go", "path/to/file2.go"],
    "related_files": ["path/to/caller.go"]
  },
  "findings": [
    {
      "severity": "CRITICAL/HIGH/MEDIUM/LOW",
      "type": "漏洞类型",
      "location": "file:line",
      "in_diff": true,
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
> `in_diff`: 漏洞是否在本次变更的 diff 行中（true = diff 引入，false = 调用链中的既有问题）
```

---

## 变量说明

### 基础变量（保留在 SKILL.md 中）

| 变量 | 来源 | 示例 |
|------|------|------|
| `project_name` | 用户指定 | "DEX" |
| `project_overview` | 设计文档 | 项目架构描述 |
| `tech_stack` | 设计文档 | "Go + C++ + Rust + Java" |
| `key_modules` | 设计文档 | "dexd, orchestratord, engine" |
| `main_vuln_types` | 分析得出 | "重入、签名绕过、共识违规" |
| `priority_paths` | 代码结构分析 | 优先审计路径表 |
| `injection_checks` | `general_vulns.md` + `languages/*.md` 裁剪 | 注入类检查（SQL/NoSQL/命令/SSTI/XSS 等，含代码示例） |
| `auth_checks` | `general_vulns.md` + `frameworks/*.md` 裁剪 | 认证授权检查（JWT/Session/OAuth/RBAC/IDOR/CSRF） |
| `data_protection_checks` | `general_vulns.md` + `languages/*.md` 裁剪 | 数据保护检查（敏感数据泄露/弱加密/不安全随机数/日志脱敏） |
| `file_resource_checks` | `general_vulns.md` + `languages/*.md` 裁剪 | 文件与资源检查（路径遍历/文件上传/SSRF/反序列化/DoS） |
| `config_deploy_checks` | `general_vulns.md` + `frameworks/*.md` 裁剪 | 配置与部署检查（调试模式/默认凭据/CORS/HTTP安全头/依赖漏洞） |
| `business_logic_checks` | 通用 + 文档提取 | 业务逻辑检查 |
| `language_deep_patterns` | `languages/*.md` 裁剪 | 语言深度 sink/source |
| `audit_regex_patterns` | `languages/*.md` + `adapters/*.yaml` | Step 2 必须执行的审计正则（按语言生成） |
| `framework_threat_surface` | `frameworks/*.md` 裁剪 | 框架威胁面 |
| `false_positive_kill_switches` | `core/false_positive_filter.md` 裁剪 | Kill Switch 条件 |
| `sink_slot_types` | `core/sinks_sources.md` 裁剪 | Sink 分类表 |
| `taint_tracking_rules` | `core/taint_analysis.md` 裁剪 | 污点追踪规则 |
| `scanning_dimensions` | 复杂项目 | 六维扫描框架（可选） |
| `routing_table` | checks/ 文件列表 | 审计目标→文件映射表 |

### 移到 checks/ 的变量

| 变量 | 新位置 |
|------|--------|
| `special_check_*` | checks/<module>-security.md |
| `mathematical_invariants` | checks/ 对应文件中 |
| `state_machines` | checks/ 对应文件中 |

### 移到 known-issues/ 的变量

| 变量 | 新位置 |
|------|--------|
| `project_audit_findings` | known-issues/prior-findings.md |
| `industry_incidents` | known-issues/industry-attacks.md |
| `high_freq_attack_patterns` | known-issues/attack-patterns.md |
| `cross_dimensional_risks` | known-issues/attack-patterns.md |
| `bypass_techniques` | known-issues/attack-patterns.md |

---

## 生成步骤

### Step 1: 提取 SKILL.md 内容

从项目文档和参考资料中填充入口模板变量。SKILL.md 目标 15-20KB（含完整通用检查和深度模式）。

### Step 2: 生成 checks/ 文件

按模块分组规则将项目特定检查分到 checks/ 文件中：
1. **组件亲缘**：同一服务/模块的检查放一起
2. **大小目标**：每文件 1-5KB
3. **自包含**：每个文件开头含模块背景
4. **命名**：kebab-case

### Step 3: 生成 known-issues/ 文件

- prior-findings.md：完整保留已发现漏洞（不裁剪）
- industry-attacks.md：与项目领域直接相关的行业攻击案例
- attack-patterns.md：速查表 + 跨维度风险 + 绕过技巧

### Step 4: 生成路由表

根据 checks/ 文件列表生成审计目标→文件映射，填入 SKILL.md 的 `{{routing_table}}`。
