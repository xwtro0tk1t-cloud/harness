---
name: security-review-skill-creator
description: 生成安全审计 skill。两种模式：(1) 项目模式——根据项目文档生成定制化审计 skill；(2) 通用模式——仅指定语言+框架，从参考资料库生成通用审计 skill。当用户想创建安全审计 skill、生成审计规则、或提到"生成安全审计skill"、"创建code review skill"、"生成 Java 审计 skill"时使用。
---

# Security Review Skill Creator

生成安全审计 Skill，支持两种模式：

| 模式 | 输入 | 产出 | 适用场景 |
|------|------|------|---------|
| **项目模式** | 项目文档（飞书/本地） | `security-review-skill-for-{project}` | 有设计文档、审计报告的特定项目 |
| **通用模式** | 语言 + 框架（如 "Java + Spring"） | `security-review-skill-for-{lang}-{framework}` | 无项目文档，需要通用语言/框架审计能力 |

**核心目标**：
1. **继承 skill-creator 方法论**：Draft → Test → Grade → Improve
2. **安全审计专业性**：从文档/参考资料提取安全关注点，生成检查规则

**设计理念**：生成的 skill 是一个 **prompt-based 审计指南**，指导 Claude 如何审计代码。不依赖外部工具，Claude 直接阅读代码并应用检查规则。

**多语言/多服务项目增强**（从 DEX 项目实践中提炼）：
1. **语言智能路由**：正则扫描和 checks 加载按代码语言自动路由，审计 Java 代码不执行 Go 正则
2. **跨服务攻击链分析**：单模块 MEDIUM 漏洞 + 跨服务组合 = CRITICAL，必须分析服务间信任边界
3. **信任边界矩阵**：列出所有服务间数据流方向和验证要求，确保每个边界都被审计覆盖

## 工作流程

### 模式判定

收到用户请求后，**首先判定模式**：

| 信号 | 模式 |
|------|------|
| 用户提供了项目文档（飞书链接/本地文件/项目描述） | **项目模式** |
| 用户只说 "生成 Java + Spring 审计 skill" / "Go 通用审计" | **通用模式** |
| 不确定 | 用 AskUserQuestion 询问："有项目文档吗？还是生成通用语言审计 skill？" |

### 项目模式流程

```
┌─────────────────────────────────────────────────────────────────┐
│                    项目模式 (Project Mode)                        │
├─────────────────────────────────────────────────────────────────┤
│  1. 收集项目文档 (lark-reader / 本地文件) — 多遍提取             │
│     - 第一遍：架构 + 技术栈                                      │
│     - 第二遍：业务规则 + 公式 + 状态机                            │
│     - 第三遍：已有审计报告 + 安全检查清单 + 攻击案例              │
│           ↓                                                      │
│  2. 提取安全关注点                                                │
│     - 技术栈 → 语言特定漏洞模式                                   │
│     - 业务流程 → 业务逻辑检查项                                   │
│     - 权限模型 → 越权检测规则                                     │
│     - 领域特定 → 公式/不变量/状态机 (DeFi/IoT/...)               │
│     - 已有安全知识 → 审计发现/行业事故                            │
│           ↓                                                      │
│  2.5 【强制】Read 参考资料 (reference_index.yaml)                │
│     - 语言 → Read languages/*.md + checklists/*.md + adapters/   │
│     - 框架 → Read frameworks/*.md                                │
│     - 业务 → Read security/*.md (竞态/OAuth/GraphQL/DeFi/...)    │
│     - 案例 → Read wooyun/ + cases/                               │
│     - 核心 → Read core/ (污点分析/误报过滤) [始终加载]            │
│     - 通用 → Read checklists/universal.md + coverage_matrix.md   │
│     ⚠️ 禁止跳过！禁止仅凭自身知识替代参考文件内容！              │
│           ↓                                                      │
│  2.6 验证覆盖度（对照 coverage_matrix.md）                       │
│           ↓                                                      │
│  3. 生成 security-review-skill-for-xxx                          │
│     - 通用漏洞检查 (从 languages/ + checklists/ 提取)            │
│     - 深度漏洞模式 (从 languages/ + frameworks/ 提取)            │
│     - 审计正则速查 (从 adapters/ + languages/ 提取)              │
│     - 项目特定检查 (从文档提取，含公式/不变量/状态机)             │
│     - 已有审计发现 + 行业攻击案例                                 │
│     - 误报过滤 + 污点分析 (从 core/ 提取)                        │
│           ↓                                                      │
│  4. 创建测试用例 + 评估 + 迭代改进                                │
│           ↓                                                      │
│  5. 输出最终 skill (SKILL.md ~15-20KB + checks/ + known-issues/) │
└─────────────────────────────────────────────────────────────────┘
```

### 通用模式流程

```
┌─────────────────────────────────────────────────────────────────┐
│                    通用模式 (Generic Mode)                        │
├─────────────────────────────────────────────────────────────────┤
│  1. 解析用户指定的语言 + 框架                                     │
│     - 如 "Java + Spring" → lang=java, framework=spring           │
│     - 如 "Go 通用" → lang=go, framework=无                       │
│           ↓                                                      │
│  2. 【全量加载】Read 参考资料 (reference_index.yaml)             │
│     - 语言 → Read languages/{lang}.md（含全部 specialized）      │
│       + checklists/{lang}.md + adapters/{lang}.yaml              │
│     - 框架 → Read frameworks/{framework}.md                      │
│     - 核心 → Read core/ [始终加载]                                │
│     - 通用 → Read checklists/universal.md + coverage_matrix.md   │
│     - 案例 → Read wooyun/ 中与该语言高相关的类别                  │
│       + cases/real_world_vulns.md                                │
│     ⚠️ 通用模式下 references 是唯一内容来源，更需完整加载！       │
│           ↓                                                      │
│  3. 生成 security-review-skill-for-{lang}-{framework}           │
│     - 通用漏洞检查 (从 references 全量提取，少裁剪)              │
│     - 深度漏洞模式 (从 languages/ 完整提取 Sink 列表)            │
│     - 审计正则速查 (从 adapters/ 完整提取)                       │
│     - 框架威胁面 (从 frameworks/ 完整提取)                       │
│     - 误报过滤 + 污点分析 (从 core/ 提取)                        │
│     - checks/ 按安全维度分组（D1注入/D2认证/...）                │
│     - known-issues/ 填入语言+框架通用案例                        │
│           ↓                                                      │
│  4. 创建测试用例 + 评估 + 迭代改进                                │
│           ↓                                                      │
│  5. 输出最终 skill (SKILL.md ~15-20KB + checks/ + known-issues/) │
└─────────────────────────────────────────────────────────────────┘
```

## 核心方法论

### 1. 迭代循环 (Draft → Test → Iterate)

生成的 security-review-skill 需要经过：
- **Draft**：根据项目文档生成初始版本
- **Test**：在测试代码上运行，评估检测效果
- **Iterate**：根据评估结果改进

### 2. 评估框架

使用 `agents/security_grader.md` 进行评估：

| 维度 | 指标 | 说明 |
|------|-----|------|
| 检出率 | Recall | 真实漏洞被检出的比例 |
| 精确率 | Precision | 报告中真实漏洞的比例 |
| 定位准确 | Location | 漏洞行号是否准确 |

### 3. 测试用例格式

```json
{
  "skill_name": "security-review-skill-for-xxx",
  "evals": [
    {
      "id": 1,
      "name": "sql-injection-basic",
      "prompt": "审计这段代码的安全问题",
      "files": ["test_cases/vuln_sql.py"],
      "ground_truth": {
        "vulnerabilities": [
          {"type": "sql_injection", "location": "vuln_sql.py:15", "severity": "CRITICAL"}
        ],
        "safe_patterns": [
          {"location": "vuln_sql.py:30", "reason": "使用参数化查询"}
        ]
      },
      "expectations": [
        "检测到 SQL 注入漏洞",
        "正确定位到 vuln_sql.py:15",
        "不将 vuln_sql.py:30 标记为漏洞"
      ]
    }
  ]
}
```

### 4. Description 优化

生成的 skill 需要有准确的 description 以正确触发：

**原则**：
- 使用祈使句：「Use this skill for...」
- 关注用户意图，而非实现细节
- 简洁：< 200 词
- 区分度：与其他 skill 区分

**示例**：
```yaml
# 好
description: 审计 XXX 项目的代码安全，检测 SQL 注入、XSS、越权等漏洞。当需要审计 XXX 代码、进行安全评审、或检查 XXX 项目漏洞时使用。

# 差
description: 一个安全扫描工具
```

## 参考资料库

生成 skill 时可引用的深度参考资料（来自 code-audit 知识库）：

| 类别 | 目录 | 文件数 | 用途 |
|------|------|--------|------|
| 语言漏洞模式 | `references/languages/` | 18 | 语言特定的 sink/source、深度漏洞模式（Java 含 7 个专题） |
| 框架安全指南 | `references/frameworks/` | 14 | 框架特有威胁面、安全配置、检查清单 |
| 安全领域分析 | `references/security/` | 24 | 竞态条件、业务逻辑、OAuth、GraphQL、LLM 等深度分析 |
| 审计检查清单 | `references/checklists/` | 11 | D1-D10 维度检查项 + 判定规则 |
| Wooyun 真实案例 | `references/wooyun/` | 9 | 88,636 个真实漏洞的统计和案例 |
| 核心审计模块 | `references/core/` | 6 | 污点分析、误报过滤、绕过策略、敏感操作矩阵 |
| 语言适配器 | `references/adapters/` | 5 | YAML 格式的语言特定配置 |
| 实战漏洞 | `references/cases/` | 1 | 真实世界漏洞案例集 |

### 参考文件选择流程

根据 `references/reference_index.yaml` 的六层映射自动选择：

1. **语言层**：项目主语言 → `languages/*.md` + `checklists/*.md` + `adapters/*.yaml`
2. **框架层**：项目框架 → `frameworks/*.md`
3. **业务层**：文档关键词 → `security/*.md`（支付→竞态+业务逻辑，OAuth→认证授权）
4. **核心层**：始终包含 `core/taint_analysis.md` + `core/false_positive_filter.md` + `core/sensitive_operations_matrix.md`
5. **案例层**：漏洞类型 → `wooyun/*.md`
6. **通用层**：始终包含 `checklists/universal.md` + `checklists/coverage_matrix.md` + `cases/real_world_vulns.md`

**选择示例**（Java + Spring Boot + 支付系统）：
- 语言：`languages/java.md` + 7 个 Java 专题 + `checklists/java.md` + `adapters/java.yaml`
- 框架：`frameworks/spring.md` + `frameworks/mybatis_security.md`
- 业务：`security/business_logic.md` + `security/race_conditions.md` + `security/authentication_authorization.md`
- 核心：`core/taint_analysis.md` + `core/false_positive_filter.md` + `core/sensitive_operations_matrix.md`
- 案例：`wooyun/sql-injection.md` + `wooyun/logic-flaws.md`
- 通用：`checklists/universal.md` + `checklists/coverage_matrix.md` + `cases/real_world_vulns.md`

### 参考裁剪规则

生成的 skill 总量按复杂度动态调整，SKILL.md 包含完整的通用漏洞检查和深度模式，checks/ 和 known-issues/ 承载补充检查：

#### 项目模式大小参考

| 项目类型 | SKILL.md | checks/ 合计 | known-issues/ 合计 | 总计 | 示例 |
|---------|----------|-------------|-------------------|------|------|
| 简单（单语言、单服务） | 12-15KB | 5-15KB | 0-5KB | 20-30KB | Django Web 应用 |
| 中等（2-3 语言、微服务） | 15-20KB | 10-20KB | 3-8KB | 30-45KB | FastAPI + React + Redis |
| 复杂（多语言、跨链/多引擎） | 18-25KB | 15-25KB | 5-10KB | 40-60KB | DEX（Go + C++ + Rust + Java + 跨链桥） |

#### 通用模式大小参考

| 技术栈 | SKILL.md | checks/ 合计 | known-issues/ 合计 | 总计 | 示例 |
|--------|----------|-------------|-------------------|------|------|
| 单语言 | 15-20KB | 8-15KB | 3-5KB | 25-35KB | Go 通用审计 |
| 语言+框架 | 18-25KB | 10-18KB | 3-6KB | 30-45KB | Java + Spring 审计 |
| 语言+多框架 | 20-28KB | 12-20KB | 4-8KB | 35-50KB | Java + Spring + MyBatis 审计 |

**通用模式裁剪策略**（与项目模式的核心区别）：

| 来源 | 项目模式 | 通用模式 |
|------|---------|---------|
| 语言文件（20-40KB） | 重度裁剪：仅提取匹配框架章节，每种漏洞 1 个代码对 | **轻度裁剪**：保留大部分 Sink 列表、漏洞类型、代码示例。仅跳过与其他语言交叉的重复内容 |
| 框架文件（15-30KB） | 威胁面概览 + 检查清单，跳过 CVE 深度 | **中度裁剪**：保留威胁面 + 安全配置 + CVE 速查。框架是通用 skill 的核心价值 |
| 安全领域（18KB+） | 仅提取项目语言代码示例 | **按框架关联选择**：Spring→认证授权+API安全，Express→XSS+CSRF 等 |
| Wooyun/案例 | 项目相关的 top 3-5 | **语言相关的 top 10**：更多案例（通用 skill 的案例覆盖是价值点） |
| 核心文件 | ~1KB 决策框架 | **同项目模式** |
| 已有审计发现 | 完整保留 | **无**（通用模式无项目发现） |

**项目模式裁剪优先级**：已有审计发现 > 公式/不变量 > 危险模式 > 安全模式 > 检测提示 > 攻击案例 > 修复建议

**通用模式裁剪优先级**：Sink/Source 列表 > 审计正则 > 框架威胁面 > 危险+安全代码对 > 案例 > 检测提示

## 生成的 Skill 包含什么

### Tier 1 — SKILL.md（入口，每次审计都加载）

#### 1. 审计模式选择 + 方法论（7 步）

生成的 skill 支持三种审计模式，触发时通过 AskUserQuestion 让用户选择：

| 模式 | 触发场景 | 扫描范围 |
|------|---------|---------|
| **全量审计** | "审计 x/bridge 模块" | 指定目录全部代码 |
| **PR/分支审计** | "审计 feature-branch" / "审计 PR" | `git diff` 改动文件 + 调用链 |
| **最近变更审计** | "扫描最近 7 天变更" | `git log --since` 改动文件 + 调用链 |

PR/分支模式和最近变更模式会先执行 **Step 0**：
1. `git diff --name-only` 获取改动文件列表
2. 按路由表分类到模块 → 只加载相关 checks/
3. 对每个改动文件：Read 完整文件 + 识别变更函数 + Grep 调用链
4. 审计范围 = 改动文件 + 调用链文件

**方法论 7 步**（三种模式共用，diff/PR 模式仅缩小范围）：
- **Step 1 侦察阶段**：技术栈识别、攻击面映射、端点-权限矩阵
- **Step 2 正则扫描（必须执行）**：用"审计正则速查"中的所有正则 Grep 代码，逐一分析匹配结果
- **Step 3 双轨审计**：Sink-driven + Control-driven
- **Step 4 数据流分析**：Import → Source → Propagation → Sink
- **Step 5 跨文件分析**：遇到 wrapper 函数要查调用者
- **Step 6 攻防对抗验证**：攻击方证实 + 防御方证伪
- **Step 7 覆盖评估**：确保关键维度都已检查
- **反幻觉原则**：宁可漏过也不误报，基于实际代码

#### 2. 通用漏洞检查
基于 `references/general_vulns.md` + `references/languages/*.md` + `references/checklists/universal.md`，必须覆盖 6 个子类：
- **注入类**：SQL/NoSQL、命令注入、SSTI、XSS、LDAP 等（从 languages/ 提取语言特定 sink）
- **认证授权**：JWT/Session、密码存储、OAuth、RBAC、IDOR、CSRF
- **数据保护**：敏感数据泄露、弱加密、不安全随机数、日志脱敏、错误信息泄露
- **文件与资源**：路径遍历、文件上传、SSRF、反序列化、资源耗尽/DoS
- **配置与部署**：调试模式、默认凭据、CORS、HTTP 安全头、依赖漏洞
- **业务逻辑**：价格篡改、优惠券滥用、状态机跳跃、竞态条件

#### 3. 深度漏洞模式 + 审计正则
基于 `references/languages/` + `references/frameworks/` + `references/security/` 裁剪：
- **语言深度 Sink/Source**：从语言文件提取完整危险函数列表和安全替代方案
- **审计正则速查**：从语言文件 + adapters 提取的必执行正则列表，供 Step 2 逐条 Grep。这是通用漏洞检测的核心机制，确保 SQL 注入/命令执行/SSRF/硬编码凭据/unsafe 等通用模式不被遗漏
- **框架威胁面**：框架特有攻击面（如 Spring Actuator、Django admin、Express 中间件）
- **安全领域分析**：根据业务类型裁剪的深度安全分析

#### 4. 误报过滤 + 污点分析
基于 `references/core/`：
- **Kill Switch 条件**：框架保护识别、安全 API 白名单
- **污点分析规则**：Sink 分类 + 追踪规则
- **常见误报模式**

#### 5. 审计路由表
映射审计目标→需要读取的 checks/ 文件，指导 Claude 按需加载模块检查

#### 6. 输出格式
JSON schema 定义审计结果结构

### Tier 2 — checks/（按需读取）

从项目文档提取（参考 `references/document_extraction.md`）：
- 每个文件覆盖一个审计维度（按模块亲缘关系分组）
- 包含：模块背景、不变量、检查项、代码模式（危险 vs 安全）
- **业务流程安全**：支付、审批、权限变更等高风险操作
- **数据保护**：敏感字段识别、脱敏要求
- **权限模型**：角色定义、资源归属、越权检测点
- 复杂项目：公式/不变量/状态机

### Tier 3 — known-issues/（对照参考时读取）

- **prior-findings.md**：项目已有的安全发现（最高价值，完整保留）
- **industry-attacks.md**：与项目领域直接相关的行业攻击案例
- **attack-patterns.md**：攻击模式速查表 + 跨维度关联风险 + 绕过技巧

## 使用步骤

---

### 通用模式步骤（无项目文档）

当用户只指定语言+框架时，执行以下简化流程：

#### Generic Step 1: 解析技术栈

从用户输入中提取：
- **语言**：Java / Python / Go / JavaScript / PHP / Ruby / Rust / C++ / ...
- **框架**：Spring / Django / FastAPI / Express / Gin / Laravel / Rails / ...
- **补充**：如用户提到 ORM（MyBatis/Hibernate）、中间件（Redis/Kafka）等，也纳入

#### Generic Step 2: 全量加载参考资料

根据 `references/reference_index.yaml`，加载该语言+框架的**全部**参考文件：

```
L1 语言: Read languages/{lang}.md + 全部 specialized（如 Java 含 7 个专题）
         + checklists/{lang}.md + adapters/{lang}.yaml
L2 框架: Read frameworks/{framework}.md（每个框架都读）
L4 核心: Read core/taint_analysis.md + core/false_positive_filter.md
         + core/sensitive_operations_matrix.md
L5 案例: Read wooyun/ 中与该语言高频相关的类别（SQL注入/命令执行/文件上传等）
         + cases/real_world_vulns.md
L6 通用: Read checklists/universal.md + checklists/coverage_matrix.md
```

**与项目模式的区别**：
- **L3 业务层跳过**（无项目文档→无业务关键词匹配）
- references 是**唯一内容来源**，裁剪力度更轻
- 语言 specialized 文件**全部加载**（项目模式可能只加载部分）

#### Generic Step 3: 生成 Skill

使用 `templates/skill_main_template.md` 生成 SKILL.md，但有以下差异：

| 区域 | 项目模式 | 通用模式 |
|------|---------|---------|
| 项目背景 | 具体项目描述 | "通用 {lang} + {framework} 安全审计" |
| 通用漏洞检查 | 裁剪到项目相关 | **完整覆盖** OWASP Top 10 全部类别 |
| 深度漏洞模式 | 裁剪 Sink 列表 | **完整** Sink/Source 列表 + 所有漏洞类型 |
| 审计正则 | 按项目语言选 | **完整**提取 adapter 中的所有正则 |
| 框架威胁面 | 按项目框架选 | **完整**提取框架文件内容 |
| checks/ | 按项目模块分 | **按安全维度分**（见下方） |
| known-issues/ | 项目审计发现 | 语言+框架通用案例 |

**通用模式 checks/ 分组规则**（按安全维度而非项目模块）：

```
checks/
├── injection-security.md       # D1 注入类（SQL/命令/SSTI/XSS 等）深度检查
├── auth-security.md            # D2/D3 认证授权（JWT/OAuth/RBAC/IDOR）深度检查
├── data-crypto-security.md     # D7 数据保护 + 加密（弱算法/硬编码密钥/随机数）
├── file-network-security.md    # D5/D6 文件操作 + 网络（路径遍历/SSRF/反序列化）
├── config-dependency.md        # D8/D10 配置 + 供应链（调试模式/CORS/CVE 依赖）
└── business-logic.md           # D9 业务逻辑（竞态/状态机/Mass Assignment）
```

每个 check 文件包含：
- 该维度的**完整检查清单**（从 `checklists/{lang}.md` 对应 D 段落提取）
- **判定规则**（什么算漏洞、什么是安全的）
- **更多代码示例**（比 SKILL.md 中更详细的危险+安全模式）
- **框架特定注意事项**

**通用模式 known-issues/ 内容**：

```
known-issues/
├── common-vulnerabilities.md   # 该语言+框架的高频漏洞案例（从 wooyun/ + cases/ 提取）
└── attack-patterns.md          # 通用攻击模式速查 + 绕过技巧
```

#### Generic Step 4: 测试 + 迭代

同项目模式的 Step 3-5。

---

### 项目模式步骤（有项目文档）

#### Step 1: 收集项目文档（多遍提取）

```bash
# 从飞书读取（可选：如需读取飞书文档，安装 lark-skills）
# (Optional: install lark-skills if you need to read Feishu documents)
node <lark-skills-dir>/bin/read-doc.mjs "https://xxx.larksuite.com/wiki/设计文档"

# 或直接提供本地文件
cat /path/to/design-doc.md
```

**第一遍：架构和技术栈**
- 服务架构、语言、框架、中间件
- 关键模块和依赖

**第二遍：业务规则和公式**（对领域特定项目尤其重要）
- 业务流程、状态机定义
- 数学公式（equity/margin/liquidation 等）
- 不变量（恒等式、前置/后置条件）
- 经济/风控参数

**第三遍：已有安全知识**（关键步骤！）
- 搜索项目 wiki 中的审计报告、安全检查清单、事故分析
- 关键词：audit, security review, vulnerability, 漏洞, 安全检查, 事故
- 已发现漏洞 → 直接纳入 skill
- 团队整理的行业攻击案例 → 纳入行业参考

> **为什么重要**：项目已有的安全分析是最高价值输入——比通用参考精准得多。
> 跳过这一步 = 遗漏项目最核心的安全知识。

#### Step 2: 生成初始 Skill

提供文档内容后，我会：
1. 分析技术栈、业务流程、安全要求
2. **识别领域**：标准 Web / 区块链 DeFi / IoT / 其他 → 决定提取深度和维度
3. **强制加载参考资料**（见下方协议）
4. **裁剪参考内容**：按项目复杂度动态调整预算
5. 提取项目特定的安全关注点（含公式、不变量、状态机）
6. 整合已有审计发现和行业攻击案例
7. **按模块化结构生成** `security-review-skill-for-xxx`

#### 强制参考加载协议（MANDATORY）

**此步骤不可跳过。** 禁止仅凭自身知识填充通用漏洞检测内容——必须从参考文件中提取，确保覆盖完整。

根据 `references/reference_index.yaml`，按项目技术栈确定需要 Read 的文件列表，然后**逐一 Read 并提取内容**。

**Step 2a: 确定文件列表**

对照 reference_index.yaml 六层映射，列出所有需要加载的文件：

| 层 | 条件 | 文件 | 提取目标 |
|---|------|------|---------|
| L1 语言 | 每种项目语言 | `languages/{lang}.md` + `checklists/{lang}.md` + `adapters/{lang}.yaml`（如有） | Sink/Source 列表、审计正则、通用漏洞模式、危险+安全代码对 |
| L2 框架 | 每个项目框架 | `frameworks/{framework}.md` | 框架威胁面、安全配置、框架特有漏洞 |
| L3 业务 | 匹配关键词 | `security/*.md` | 领域深度安全分析 |
| L4 核心 | **始终** | `core/taint_analysis.md` + `core/false_positive_filter.md` + `core/sensitive_operations_matrix.md` | 污点分析规则、误报过滤、敏感操作矩阵 |
| L5 案例 | 匹配漏洞类型 | `wooyun/*.md` | 真实攻击案例、绕过技巧 |
| L6 通用 | **始终** | `checklists/universal.md` + `checklists/coverage_matrix.md` + `cases/real_world_vulns.md` | 通用检查维度、覆盖度矩阵 |

**Step 2b: 逐文件 Read 并提取**

对列表中的每个文件执行 Read，提取以下内容到生成的 skill 中：

**从 `languages/{lang}.md` 必须提取**：
- [ ] 完整的危险 Sink 函数列表（不可省略）
- [ ] 对应的安全替代方案
- [ ] 该语言特有的漏洞类型（如 Python 的 SSTI/pickle/ReDoS，JS 的原型污染/eval）
- [ ] 每种漏洞类型至少 1 个危险 + 1 个安全代码示例

**从 `adapters/{lang}.yaml` 或 `languages/{lang}.md` 的正则部分必须提取**：
- [ ] 所有审计正则模式 → 放入 SKILL.md 的"审计正则速查"（Step 2 必须执行的正则列表）
- [ ] 正则必须覆盖：SQL注入、命令注入、SSRF、路径遍历、反序列化、硬编码凭据、不安全随机数、调试模式、SSTI 等该语言适用的全部类型

**从 `checklists/{lang}.md` 必须提取**：
- [ ] 语言特定的检查维度
- [ ] 判定规则（什么情况算漏洞、什么情况是安全的）

**从 `frameworks/{framework}.md` 必须提取**：
- [ ] 框架特有攻击面（如 FastAPI 的路由依赖注入遗漏、Django admin 暴露、Express 中间件顺序）
- [ ] 框架安全配置检查清单
- [ ] 框架特有的误报模式（框架已有的安全保护）

**从 `security/*.md` 必须提取**：
- [ ] 与项目业务相关的深度安全分析
- [ ] 该项目语言的代码示例（跳过其他语言的示例）
- [ ] CWE 映射和审计清单

**从 `core/*.md` 必须提取**：
- [ ] 污点分析的 Source → Sink 追踪规则
- [ ] 误报过滤的 Kill Switch 条件
- [ ] 敏感操作分类矩阵

**从 `checklists/universal.md` + `checklists/coverage_matrix.md` 必须提取**：
- [ ] 通用安全检查维度（确保不遗漏）
- [ ] 覆盖度对照矩阵（用于 Step 7 覆盖评估）

**Step 2c: 验证覆盖度**

生成 skill 前，对照检查：

```
[ ] 每种项目语言的 languages/ 文件已 Read？
[ ] 每种项目框架的 frameworks/ 文件已 Read？
[ ] 审计正则覆盖了所有语言的全部通用漏洞类型？
[ ] Sink/Source 列表是否完整（来自参考文件而非自行编写）？
[ ] 误报过滤规则是否来自 core/false_positive_filter.md？
[ ] 覆盖度矩阵是否对照了 checklists/coverage_matrix.md？
```

**任何一项为否 → 回到 Step 2b 补读对应文件。**

#### 生成输出

- SKILL.md（使用 `templates/skill_main_template.md`）：方法论 + 路由表
- checks/*.md（使用 `templates/skill_check_template.md`）：按模块分组的检查文件
- known-issues/*.md（使用 `templates/skill_known_issues_template.md`）：已知问题和攻击案例

### Step 3: 创建测试用例

创建包含已知漏洞的测试代码：
- **漏洞代码**：包含特定漏洞的代码片段
- **安全代码**：不应被标记的正常代码
- **期望结果**：ground truth

### Step 4: 运行测试并评估

使用 Security Grader（见 `agents/security_grader.md`）评估：

```json
{
  "security_metrics": {
    "true_positives": 8,
    "false_positives": 2,
    "false_negatives": 1,
    "precision": 0.80,
    "recall": 0.89,
    "f1_score": 0.84
  }
}
```

### Step 5: 迭代改进

根据评估结果：
- **高误报 (FP)**：添加框架保护识别、调整检测条件
- **漏检 (FN)**：补充检测模式、添加更多危险函数
- **定位不准**：改进代码模式描述

### Step 5.5: 对照验证（推荐）

如果存在领域安全框架，逐项对照检查覆盖度：

| 领域 | 参考框架 | 说明 |
|------|---------|------|
| Web 应用 | OWASP ASVS | 应用安全验证标准 |
| DeFi/DEX | DEX scan prompts (`skills/prompts/security/dex/`) | 六维扫描框架 |
| 智能合约 | OWASP Smart Contract Top 10 | 链上合约安全 |
| API | OWASP API Security Top 10 | API 安全 |

**对照方法**：
1. 列出参考框架的所有检查维度
2. 标记每个维度在 skill 中的对应检查项
3. 未覆盖的维度 → 回到源文档补充提取
4. 发现遗漏的常见原因：
   - 文档中有但提取时遗漏（回第一遍补读）
   - 文档中无但领域必需（从参考资料补充）
   - 已有审计报告中有但未整合（回第三遍补读）

### Step 6: 优化 Description

使用内置的 Description 优化方法论（参考 skill-creator 原则）：

**优化原则**：
1. **祈使句**：使用 "Use this skill for..." 或 "审计 XXX 项目的..."
2. **关注意图**：描述用户想做什么，而非实现细节
3. **简洁**：< 200 词
4. **区分度**：与其他 skill 区分，避免误触发

**验证方法**：
```
应触发：
  ✓ "审计这个项目的代码安全"
  ✓ "检查 XXX 项目有没有漏洞"
  ✓ "code review XXX"
  ✓ "XXX 项目安全扫描"

不应触发：
  ✗ "帮我写一个 SQL 查询"（不是审计）
  ✗ "通用代码审查"（不是安全审计）
  ✗ "扫描 YYY 项目"（不是目标项目）
```

**示例对比**：
```yaml
# 好
description: 审计 XXX 项目的代码安全，检测 SQL 注入、XSS、越权等漏洞。
            当需要审计 XXX 代码、进行安全评审、或检查 XXX 项目漏洞时使用。
            支持 Python/Java/Go 代码。

# 差
description: 一个安全扫描工具
```

## 输出结构

### 项目模式输出

```
security-review-skill-for-{project}/
├── SKILL.md                    # 入口（方法论 + 通用检查 + 路由表）~15-20KB
├── checks/                     # 模块检查文件（按项目模块分组，按需读取）
│   ├── <module>-security.md    # 每个 1-5KB
│   └── ...
├── known-issues/               # 已知问题（对照时读取）
│   ├── prior-findings.md       # 项目已发现漏洞
│   ├── industry-attacks.md     # 行业攻击案例
│   └── attack-patterns.md      # 速查表 + 绕过技巧
└── evals/                      # 可选：测试用例
    ├── evals.json
    └── test_cases/
```

### 通用模式输出

```
security-review-skill-for-{lang}-{framework}/
├── SKILL.md                    # 入口（方法论 + 完整通用检查 + 路由表）~15-25KB
├── checks/                     # 安全维度检查文件（按 D 维度分组，按需读取）
│   ├── injection-security.md   # D1 注入深度检查
│   ├── auth-security.md        # D2/D3 认证授权深度检查
│   ├── data-crypto-security.md # D7 数据保护 + 加密
│   ├── file-network-security.md# D5/D6 文件 + 网络
│   ├── config-dependency.md    # D8/D10 配置 + 供应链
│   └── business-logic.md       # D9 业务逻辑
├── known-issues/               # 通用案例（对照时读取）
│   ├── common-vulnerabilities.md # 语言+框架高频漏洞案例
│   └── attack-patterns.md      # 攻击模式速查 + 绕过技巧
└── evals/                      # 可选：测试用例
    ├── evals.json
    └── test_cases/
```

### 分层设计（两种模式通用）

**Tier 1 — SKILL.md（每次审计都加载）**:
- 项目/技术栈背景
- 审计模式选择（全量/PR/最近变更）+ 方法论（7步）
- 通用漏洞检查（注入/认证/数据保护/文件资源/配置部署/业务逻辑）
- 深度漏洞模式（语言 Sink + 框架威胁面 + 审计正则）
- 误报过滤 + 污点分析
- 输出格式
- **审计路由表**（映射审计目标→检查文件）

**Tier 2 — checks/（按需读取）**:
- 项目模式：按项目模块分组（如 vault-security.md、bridge-security.md）
- 通用模式：按安全维度分组（如 injection-security.md、auth-security.md）
- 包含：背景、检查清单、判定规则、代码模式（危险 vs 安全）

**Tier 3 — known-issues/（对照参考时读取）**:
- 项目模式：prior-findings.md（项目已发现漏洞，最高价值）+ industry-attacks.md + attack-patterns.md
- 通用模式：common-vulnerabilities.md（语言+框架高频案例）+ attack-patterns.md

### 审计路由表规范

SKILL.md 中必须包含路由表，格式示例：
```markdown
## 审计路由
根据审计目标，**必须**先 Read 对应检查文件再开始审计：

| 审计目标 | 读取文件 |
|---------|---------|
| vault / 资金安全 | checks/vault-security.md |
| bridge / 跨链 | checks/bridge-security.md |
| 全量审计 | 按优先级依次读取所有 checks/ |

已知问题对照：Read known-issues/prior-findings.md
```

### 模块分组规则

将项目特定检查（`special_check`）分组到 checks/ 文件时：
1. **组件亲缘**：同一服务/模块的检查放一起
2. **大小目标**：每文件 1-5KB；<1KB 合并，>5KB 拆分
3. **自包含**：每个文件开头含模块背景，无需依赖其他 check 文件
4. **命名**：kebab-case，如 `vault-security.md`、`bridge-security.md`

## 内置组件

### 生成模板

| 组件 | 路径 | 说明 |
|------|------|------|
| 入口模板 | `templates/skill_main_template.md` | 生成 SKILL.md（方法论 + 路由表） |
| 检查文件模板 | `templates/skill_check_template.md` | 生成 checks/*.md |
| 已知问题模板 | `templates/skill_known_issues_template.md` | 生成 known-issues/*.md |
| 旧版模板 | `templates/skill_template_legacy.md` | 旧版单文件模板（备用） |

### 参考资料

| 组件 | 路径 | 说明 |
|------|------|------|
| 审计方法论 | `references/architecture_patterns.md` | 渐进分析、数据流、跨文件、误报消除 |
| 文档提取指南 | `references/document_extraction.md` | 如何从项目文档提取安全信息 |
| 通用漏洞库 | `references/general_vulns.md` | OWASP + 业务逻辑 + 语言特定模式（概览层） |
| Security Grader | `agents/security_grader.md` | 评估 skill 的检出效果 |
| 参考索引 | `references/reference_index.yaml` | 六层选择映射（语言→框架→业务→核心→案例→通用） |
| 语言漏洞模式 | `references/languages/` (18 files) | 深度语言漏洞模式（Java 含 7 专题、反序列化等） |
| 框架安全指南 | `references/frameworks/` (14 files) | Spring/Django/Flask/Express 等框架特有安全问题 |
| 安全领域分析 | `references/security/` (24 files) | 竞态、业务逻辑、OAuth、GraphQL、LLM 等 |
| 审计检查清单 | `references/checklists/` (11 files) | D1-D10 维度检查 + 判定规则 + 通用覆盖矩阵 |
| Wooyun 案例 | `references/wooyun/` (9 files) | 88,636 个真实漏洞的统计、攻击模式和案例 |
| 核心审计模块 | `references/core/` (6 files) | 污点分析、误报过滤、绕过策略、敏感操作矩阵 |
| 语言适配器 | `references/adapters/` (5 files) | YAML 格式的语言特定检查配置 |
| 实战漏洞 | `references/cases/` (1 file) | 真实世界漏洞案例集 |
