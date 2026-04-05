# Security Review Skill 已知问题模板

生成 `known-issues/` 目录下三个文件的模板。

---

## prior-findings.md 模板

已发现漏洞是**最高价值内容**，完整保留不裁剪。

```markdown
# {{project_name}} 已发现安全问题

> 来源：{{findings_source}}（如：AI 审计报告、渗透测试报告、Bug Bounty）

{{#each finding_groups}}
## {{this.group_name}}

| # | 严重性 | 漏洞 | 位置 | 描述 |
|---|--------|------|------|------|
{{#each this.findings}}
| {{this.id}} | {{this.severity}} | {{this.title}} | {{this.location}} | {{this.description}} |
{{/each}}
{{/each}}
```

---

## industry-attacks.md 模板

与项目领域直接相关的行业真实攻击案例。

```markdown
# {{project_domain}} 行业攻击案例

> 仅收录与 {{project_name}} 架构直接相关的攻击

{{#each attack_categories}}
## {{this.category_name}}

| 事件 | 损失 | 攻击手法 | {{project_name}} 教训 |
|------|------|---------|---------|
{{#each this.incidents}}
| {{this.name}} | {{this.loss}} | {{this.method}} | {{this.lesson}} |
{{/each}}
{{/each}}
```

---

## attack-patterns.md 模板

速查表 + 跨维度关联风险 + 绕过技巧。

```markdown
# {{project_name}} 攻击模式参考

## 攻击模式速查表

| 攻击类型 | 手法 | 检查点 |
|---------|------|--------|
{{#each attack_patterns}}
| {{this.type}} | {{this.method}} | {{this.checkpoint}} |
{{/each}}

## 跨维度关联风险

单独看可能是 MEDIUM，组合起来可能是 CRITICAL：

| 组合 | 维度1 | + 维度2 | = 复合攻击 | 严重性 |
|------|-------|---------|-----------|--------|
{{#each cross_dimensional_risks}}
| {{this.combo}} | {{this.dim1}} | {{this.dim2}} | {{this.attack}} | {{this.severity}} |
{{/each}}

**审计时**：发现一个维度的问题后，立即检查关联维度是否存在放大条件。

{{#if cross_service_attack_chains}}
## 跨服务/跨语言组合攻击链

单一服务的 MEDIUM 问题，跨服务组合后可能升级为 CRITICAL：

{{#each cross_service_attack_chains}}
### 攻击链 {{@index}}: {{this.name}} ({{this.severity}})

```
{{this.chain_steps}}
```
**前提**：{{this.prerequisites}}
{{/each}}

## 跨模块审计检查矩阵

审计单个模块时，**必须检查**该模块的输出是否被其他模块信任消费：

| 产出模块 | 消费模块 | 信任边界 | 检查项 |
|---------|---------|---------|--------|
{{#each trust_boundary_matrix}}
| {{this.producer}} | {{this.consumer}} | {{this.boundary}} | {{this.check}} |
{{/each}}

**关键原则**：**每个服务边界都是攻击面**。一个服务的输出是下一个服务的输入——如果上游被攻破，下游不能盲信。
{{/if}}

## 绕过技巧

{{#each bypass_techniques}}
{{@index}}. **{{this.name}}**: {{this.description}}
{{/each}}
```

---

## 变量说明

| 变量 | 说明 | 必须 |
|------|------|------|
| `project_name` | 项目名 | 是 |
| `project_domain` | 项目领域 | 是 |
| `findings_source` | 审计发现来源 | 是 |
| `finding_groups` | 按模块分组的已发现漏洞 | 是 |
| `attack_categories` | 按类型分组的行业攻击案例 | 是 |
| `attack_patterns` | 攻击模式速查表 | 是 |
| `cross_dimensional_risks` | 跨维度关联风险（同模块内） | 是 |
| `cross_service_attack_chains` | 跨服务/跨语言组合攻击链（多服务项目） | 多服务时是 |
| `trust_boundary_matrix` | 服务间信任边界检查矩阵 | 多服务时是 |
| `bypass_techniques` | 绕过技巧列表 | 是 |
