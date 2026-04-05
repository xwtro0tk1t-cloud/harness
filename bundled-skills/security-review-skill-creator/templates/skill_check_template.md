# Security Review Skill 检查文件模板

每个 `checks/*.md` 文件使用此模板生成。每个文件覆盖一个审计维度，自包含。

---

## checks/*.md 模板

```markdown
# {{module_name}} Security Checks

> 项目：{{project_name}} | 模块：{{module_scope}} | 技术栈：{{module_tech_stack}}

{{#if module_background}}
## 模块背景

{{module_background}}
{{/if}}

{{#each checks}}
## {{this.name}} ({{this.severity}})

**背景**：{{this.background}}

{{#if this.invariants}}
**不变量**：
{{this.invariants}}
{{/if}}

{{#if this.formulas}}
**关键公式**：
{{this.formulas}}
{{/if}}

**检查项**：
{{this.items}}

{{#if this.attack_scenarios}}
**攻击场景**：
{{this.attack_scenarios}}
{{/if}}

**代码模式**：
\`\`\`{{this.language}}
{{this.code_patterns}}
\`\`\`
{{/each}}
```

---

## 变量说明

| 变量 | 说明 | 示例 |
|------|------|------|
| `module_name` | 模块名称 | "Vault", "Bridge", "Trading Engine" |
| `project_name` | 项目名 | "DEX" |
| `module_scope` | 模块范围 | "x/bridge/keeper/, orchestratord/" |
| `module_tech_stack` | 模块技术栈 | "Go (Cosmos SDK)" |
| `module_background` | 模块背景介绍 | 模块架构、核心流程、数据流 |
| `checks` | 检查项数组 | 每项包含 name/severity/background/items/code_patterns |
| `checks[].invariants` | 不变量 | 数学恒等式、安全约束 |
| `checks[].formulas` | 关键公式 | 清算公式、PnL 计算公式 |
| `checks[].attack_scenarios` | 攻击场景 | 描述攻击者如何利用 |

## 分组规则

1. **组件亲缘**：同一服务/模块的检查放一起
2. **大小目标**：每文件 1-5KB；<1KB 合并到相近模块，>5KB 拆分
3. **自包含**：每个文件开头含模块背景，无需依赖其他 check 文件
4. **命名**：kebab-case，如 `vault-security.md`、`bridge-security.md`

## 示例分组

| 文件名 | 包含的检查项 | 大小目标 |
|--------|-------------|---------|
| vault-security.md | Vault 重入 + Share 精度 + RBAC | ~3KB |
| bridge-security.md | 签名验证 + 状态机 + 跨链一致性 | ~5KB |
| trading-engine.md | FFI + PnL + OI + 清算 + 订单 | ~6KB |
| consensus-determinism.md | time.Now/map/float/goroutine | ~2KB |
| access-control.md | Nonce + 密钥 + 跨服务信任 | ~2KB |
