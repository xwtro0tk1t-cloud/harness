# 文档安全信息提取指南

从项目文档中提取生成 security-review-skill 所需的关键信息。

## 提取什么

从项目文档中识别以下信息：

| 信息类型 | 用途 | 在哪找 |
|---------|------|--------|
| **技术栈** | 决定检查哪些语言特定漏洞 | 设计文档、README |
| **业务流程** | 识别高风险操作 | PRD、需求文档 |
| **领域特定模型** | 提取公式、状态机、不变量 | 风控文档、引擎设计、协议规范 |
| **权限模型** | 设计越权检测点 | 设计文档、权限表 |
| **敏感数据** | 定义保护要求 | 数据字典、ER 图 |
| **已有安全知识** | 纳入已发现漏洞和攻击案例 | 审计报告、安全检查清单、事故分析 |

## 1. 技术栈 → 语言特定检查

### 语言 → 参考文件映射

| 语言 | 重点检查 | 参考文件 | 检查清单 | 适配器 |
|------|---------|---------|---------|--------|
| Java | SpEL 注入、反序列化、JNDI、XXE、Fastjson | `languages/java.md` + 7 个专题 | `checklists/java.md` | `adapters/java.yaml` |
| Python | SQL 注入、SSTI、pickle 反序列化、eval/exec | `languages/python.md` + 反序列化专题 | `checklists/python.md` | `adapters/python.yaml` |
| Go | SQL 拼接、text/template、并发竞态、unsafe | `languages/go.md` | `checklists/go.md` | `adapters/go.yaml` |
| JavaScript | 原型污染、ReDoS、child_process、eval | `languages/javascript.md` | `checklists/javascript.md` | `adapters/javascript.yaml` |
| PHP | SQL 注入、反序列化、文件包含、命令注入 | `languages/php.md` + 反序列化专题 | `checklists/php.md` | `adapters/php.yaml` |
| Ruby | ERB 注入、反序列化、命令注入、mass assignment | `languages/ruby.md` | `checklists/ruby.md` | — |
| Rust | unsafe 块、FFI 边界、内存安全、panic | `languages/rust.md` | `checklists/rust.md` | — |
| C/C++ | 缓冲区溢出、格式化字符串、UAF、整数溢出 | `languages/c_cpp.md` | `checklists/c_cpp.md` | — |
| .NET | 反序列化、LINQ 注入、ViewState、SignalR | `languages/dotnet.md` | `checklists/dotnet.md` | — |

### 框架 → 参考文件映射

| 框架 | 参考文件 | 关键威胁面 |
|------|---------|-----------|
| Spring / Spring Boot | `frameworks/spring.md` | SpEL、Actuator 暴露、CSRF、反序列化 |
| MyBatis | `frameworks/mybatis_security.md` | ${}占位符 SQL 注入、动态 SQL |
| Java Web 通用 | `frameworks/java_web_framework.md` | Servlet 安全、Filter 绕过 |
| Django | `frameworks/django.md` | ORM raw/extra、CSRF、模板注入 |
| Flask | `frameworks/flask.md` | SSTI、secret_key、调试模式 |
| FastAPI | `frameworks/fastapi.md` | Pydantic 绕过、依赖注入、CORS |
| Express | `frameworks/express.md` | 中间件顺序、原型污染、NoSQL 注入 |
| Koa | `frameworks/koa.md` | 中间件安全、ctx 滥用 |
| NestJS/Fastify | `frameworks/nest_fastify.md` | 装饰器绕过、schema 验证 |
| Gin | `frameworks/gin.md` | 绑定验证、中间件顺序、并发 |
| Laravel | `frameworks/laravel.md` | Eloquent 注入、Blade 模板、mass assignment |
| Rails | `frameworks/rails.md` | mass assignment、ERB、Active Record |
| Rust Web | `frameworks/rust_web.md` | Actix/Axum 安全、unsafe 边界 |
| .NET | `frameworks/dotnet.md` | Razor 注入、EF Core、Identity |

**文档关键词**：技术选型、系统架构、Tech Stack、框架

## 2. 业务流程 → 业务逻辑检查

| 业务类型 | 安全检查项 | 安全领域参考文件 |
|---------|-----------|----------------|
| **支付/金融** | 金额服务端计算、防重放、原子操作、竞态 | `security/business_logic.md` + `security/race_conditions.md` |
| **用户认证** | 密码存储、会话管理、MFA、暴力破解 | `security/authentication_authorization.md` |
| **OAuth/SSO** | PKCE、state 参数、redirect_uri 验证 | `security/oauth_oidc_saml.md` |
| **文件处理** | 文件类型验证、路径规范化、上传/下载 | `security/file_operations.md` |
| **审批流程** | 状态转换验证、角色检查、竞态 | `security/business_logic.md` |
| **优惠/营销** | 使用次数限制、条件验证、竞态利用 | `security/business_logic.md` + `security/race_conditions.md` |
| **API 接口** | 限流、认证、输入验证、版本控制 | `security/api_security.md` |
| **GraphQL** | 深度限制、批量查询、内省控制 | `security/graphql.md` |
| **LLM/AI** | Prompt 注入、输出过滤、权限隔离 | `security/llm_security.md` |
| **Serverless** | 冷启动注入、临时凭证、事件注入 | `security/serverless.md` |
| **移动端** | 本地存储、证书校验、组件暴露 | `security/mobile_security.md` |
| **微服务** | 服务间信任、mTLS、权限传播 | `security/cross_service_trust.md` |
| **消息队列** | 消息伪造、反序列化、死信处理 | `security/message_queue_async.md` |
| **实时通信** | WebSocket 认证、消息注入、频道越权 | `security/realtime_protocols.md` |
| **定时任务** | 任务注入、权限提升、并发冲突 | `security/scheduled_tasks.md` |
| **网关/代理** | Host 头注入、路径混淆、缓存投毒 | `security/api_gateway_proxy.md` + `security/cache_host_header.md` |
| **加密** | 弱算法、密钥管理、随机数 | `security/cryptography.md` |
| **前端 SPA** | XSS、CSRF、token 存储、CSP | `security/frontend_frameworks.md` |
| **依赖管理** | 已知漏洞、供应链攻击、锁文件 | `security/dependencies.md` + `security/infra_supply_chain.md` |

**文档关键词**：业务流程、用户故事、支付、订单、审批、GraphQL、WebSocket、OAuth

### 领域特定业务场景

以上 16 种场景覆盖标准 Web 应用。若项目属于以下专业领域，需额外提取领域特定信息：

#### 区块链 / DeFi / 链上应用

**触发关键词**：blockchain, cosmos, ethereum, solana, bridge, validator, consensus, vault, liquidity, oracle, DEX, DeFi, 链上, 共识, 跨链, 撮合, 清算, 保证金

| 业务类型 | 安全检查项 | 说明 |
|---------|-----------|------|
| **共识确定性** | 禁止非确定性操作（time.Now、map遍历、goroutine竞态、float64、rand）、确定性排序、状态哈希一致 | 所有节点对同一区块执行必须产生完全相同的状态 |
| **跨链桥** | 签名验证（quorum >2/3、去重、validator身份）、消息幂等、decimal精度转换、reorg处理、finality等待、状态机完整性 | 跨链资产转移是最高价值攻击目标 |
| **撮合引擎** | 订单状态机（Created→Pending→Filled/Cancelled）、部分成交不变量、撮合确定性、价格优先级 | 订单生命周期的每个状态转换都需验证 |
| **清算 / ADL** | 清算触发公式、破产价格计算、ADL排名确定性、穿仓处理、insurance fund | 公式实现必须与设计文档严格一致 |
| **风控参数** | Open Interest 上限、PnL 折扣（liquidity factor）、Mark Price 防操纵、杠杆限制 | 参数绕过 = 经济攻击向量 |
| **Vault / 资金池** | Share 精度（first depositor attack）、舍入方向（mint向下/burn向上）、重入防护、CEI模式 | 资金安全最高优先级 |
| **Oracle / 喂价** | 多源验证、偏差阈值、新鲜度检查、TWAP 防操纵 | 价格操纵可触发批量清算 |
| **经济模型** | 多账户协同操纵、浮盈扩仓链、低流动性代币风险、手续费计算方向 | 经济激励 = 攻击动力 |
| **密钥管理** | 验证者私钥隔离、HSM/KMS、不记日志、不硬编码 | 私钥泄露 = 资金被盗 |
| **无Gas链** | Nonce频率限制、重放防护、资源滥用控制 | 无Gas = 需要替代的反滥用机制 |

**领域特定提取重点**：
1. **数学公式**：equity/margin/liquidation/ADL 计算公式 → 生成公式校验检查项
2. **状态机**：deposit/withdraw/order 完整生命周期 → 生成状态转换验证检查项
3. **不变量**：filledQty + remainingQty == originalQty 等恒等式 → 生成不变量断言检查项
4. **经济参数**：fee rate、liquidity factor、max leverage 等 → 生成参数边界检查项

#### 其他专业领域扩展

以上模式可推广到其他专业领域。当项目属于非标准 Web 场景时，应：
1. 识别领域特有的安全模型（如区块链的共识安全、医疗的 HIPAA 合规）
2. 提取领域特有的数学公式和不变量
3. 搜索领域内已知攻击案例（如 DeFi 的 Rekt 数据库、桥攻击历史）
4. 映射到领域特有的安全检查维度

## 2.5 已有安全知识提取

**在提取业务流程之后、选择参考资料之前**，搜索项目文档中已有的安全分析成果。

### 搜索关键词

```
audit, security review, vulnerability, 漏洞, 安全检查, 安全审计,
事故分析, incident, post-mortem, 攻击, exploit, finding, 风险评估
```

### 提取目标

| 文档类型 | 提取内容 | 用途 |
|---------|---------|------|
| **审计报告** | 已发现漏洞（严重性、位置、描述） | 直接纳入 skill 的「已发现问题」章节 |
| **安全检查清单** | 检查项列表 | 直接作为 skill 的检查项来源 |
| **行业事故分析** | 攻击手法、损失、教训 | 纳入「行业真实攻击案例」章节 |
| **代码审查记录** | Review 发现的问题 | 补充 skill 的检测模式 |
| **风控/风险文档** | 风险参数、阈值、公式 | 生成参数校验检查项 |

### 为什么重要

项目团队已有的安全分析是**最高价值输入**——比任何通用参考都精准，因为它们：
- 针对项目实际代码和架构
- 包含团队已验证的攻击路径
- 反映项目特有的安全优先级

**如果跳过这一步，生成的 skill 将遗漏项目最核心的安全知识。**

## 2.7 漏洞类别 → 实战案例选择

根据项目技术栈和业务类型，选择对应的 Wooyun 真实漏洞案例作为参考：

| 漏洞类别 | 触发条件 | Wooyun 案例文件 |
|---------|---------|----------------|
| SQL 注入 | 使用数据库、ORM raw 查询 | `wooyun/sql-injection.md` |
| 文件上传 | 有文件上传功能 | `wooyun/file-upload.md` |
| 命令执行 | 调用系统命令、exec 类函数 | `wooyun/command-execution.md` |
| 逻辑漏洞 | 支付、审批、状态机 | `wooyun/logic-flaws.md` |
| 越权访问 | 多角色、资源归属 | `wooyun/unauthorized-access.md` |
| XSS | 用户输入展示、富文本 | `wooyun/xss.md` |
| 信息泄露 | API 返回敏感数据、错误信息 | `wooyun/info-disclosure.md` |
| 目录遍历 | 文件读取/下载功能 | `wooyun/file-traversal.md` |

**选择规则**：根据项目业务流程和检查重点，选择 2-4 个最相关的案例文件。

## 3. 权限模型 → 越权检测

提取以下信息：
- **角色**：admin, operator, user, guest
- **资源归属**：user_id, owner_id, tenant_id
- **权限点**：哪些操作需要什么权限

生成检查规则：
- 资源访问是否校验 owner
- 敏感操作是否校验角色
- 权限变更是否有审计

**文档关键词**：权限设计、RBAC、角色、管理员

## 4. 敏感数据 → 保护要求

| 敏感级别 | 数据类型 | 检查项 |
|---------|---------|--------|
| 极敏感 | 密码、密钥、Token | 加密存储、不记日志 |
| 高敏感 | 身份证、手机号 | 脱敏显示、访问控制 |
| 中敏感 | 交易记录、余额 | 权限校验 |

**文档关键词**：数据模型、敏感字段、加密、脱敏

## 输出示例

提取完成后，整理为：

```yaml
project_name: "XXX 项目"
tech_stack: ["Python", "Django", "PostgreSQL"]

# 决定通用检查项
language_checks:
  - SQL 注入 (Django raw/extra)
  - SSTI (Jinja2)

# 项目特定检查
business_checks:
  - name: "支付金额验证"
    description: "金额必须服务端计算，不能信任客户端"
    pattern: "request.json['amount']"

  - name: "订单状态校验"
    description: "状态变更必须验证当前状态"
    pattern: "order.status = 'paid'"

# 领域特定提取（如适用）
domain_specific:
  domain: null  # 或 "blockchain_defi", "medical", "iot" 等
  formulas: []  # 数学公式列表
  state_machines: []  # 状态机定义
  invariants: []  # 不变量列表
  economic_parameters: []  # 经济/风控参数

# 已有安全知识
existing_security_knowledge:
  audit_reports: []  # 已有审计报告的发现
  security_checklists: []  # 团队整理的安全检查清单
  incident_analysis: []  # 行业事故分析
  known_issues: []  # 已知问题列表

# 越权检测点
auth_checks:
  - pattern: "Order.query.get(id)"
    check: "是否校验 user_id"
  - pattern: "@admin_required"
    check: "敏感操作是否有此装饰器"

# 选中的参考文件（根据技术栈和业务自动匹配）
selected_references:
  language:
    primary: languages/python.md
    specialized: [languages/python_deserialization.md]
    checklist: checklists/python.md
    adapter: adapters/python.yaml
  framework: [frameworks/django.md]
  security_domains:
    - security/business_logic.md      # 支付业务
    - security/race_conditions.md     # 并发竞态
    - security/authentication_authorization.md  # 用户认证
  core:
    - core/taint_analysis.md
    - core/false_positive_filter.md
    - core/sensitive_operations_matrix.md
  wooyun:
    - wooyun/sql-injection.md         # SQL 注入案例
    - wooyun/logic-flaws.md           # 逻辑漏洞案例
  always:
    - checklists/universal.md
    - checklists/coverage_matrix.md
    - cases/real_world_vulns.md
```
