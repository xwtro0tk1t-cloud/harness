# Harness vs OpenHarness 对比

> **用途**：用户问"对比一下我们项目和 OpenHarness"时，读本文档回答。
> **最后更新**：2026-04-07
> **OpenHarness 来源**：https://github.com/HKUDS/OpenHarness

## TL;DR

两者同名不同路：
- **我们的 Harness** = **AI Agent 开发护栏 Meta-Skill**（寄生在 Claude Code / Cursor 上的轻量 Markdown + Hook 方案）
- **OpenHarness** = **AI Agent 运行时基础设施 Python 框架**（自己就是一个完整的 Agent Runtime，类似重造了一个 Claude Code）

两者不是竞品。OpenHarness 是 Runtime，我们是叠加在 Runtime 上的护栏层。

## 核心定位对比

| 维度 | 我们的 Harness | OpenHarness |
|------|--------------|-------------|
| **定位** | AI Agent 开发护栏 Meta-Skill | AI Agent 运行时基础设施 |
| **载体** | Markdown Skills + Hooks（轻量） | Python 框架（重量级完整 runtime） |
| **宿主** | Claude Code / Cursor / 任意 AI IDE | 自己就是宿主（独立 CLI + TUI） |
| **安装方式** | 复制到 `~/.claude/skills/` | `pip install openharness` |
| **运行方式** | 寄生（靠宿主的 Hook 和 Skill 机制） | 独立进程 + 自带 Agent Loop |
| **文件数量** | 几十个 .md 文件 | 数千行 Python 代码 |

## 架构对比

**OpenHarness 12 层架构**（全栈自研）：
```
L1 HITL → L2 Conversation → L3 Planning → L4 Guardrails
L5 Orchestration → L6 Skills → L7 Tooling → L8 Context
```
自带：Agent Loop、Tool Registry（43+ 工具）、Permission Checker、Hook Executor、Swarm 协调、Memory、API Client（多 Provider）、TUI。

**我们的 Harness 四层护栏**（寄生增强）：
```
Hook 层（系统级强制） → CLAUDE.md 规则层 → Skill description 语义层 → Quality Gate 检查层
```
不实现 runtime，依赖宿主（Claude Code）的 Tool / Skill / Hook 机制。

## 功能模块对比

| 模块 | 我们的 Harness | OpenHarness |
|------|--------------|-------------|
| **权限模型** | CLAUDE.md 文本规则 + shell hook | `PermissionChecker` 代码级（3 模式 + 路径 glob + 命令 pattern） |
| **Hook 机制** | PreToolUse/PostToolUse shell 脚本 | 6 种事件 × 4 种实现（shell/webhook/LLM/subagent） |
| **Skill 系统** | Markdown Skills（依赖宿主发现机制） | 自研 SkillRegistry + YAML frontmatter |
| **多 Agent** | Agent Team 角色定义（A/B/C/D） | Swarm 子系统（TeamRegistry + 邮箱 + 权限继承） |
| **记忆** | MEMORY.md 索引 + 文件 | MEMORY.md + 语义搜索 |
| **工具库** | 依赖宿主 | 自带 43+ 工具（Bash/Read/Write/Edit/Glob/Grep/Agent/…） |
| **API 支持** | 依赖宿主 | Anthropic / OpenAI / Copilot / 国产模型 |
| **Eval 方法论** | 三级 Quality Gate 检查 | harness-eval skill（在陌生项目上做真实 API 测试） |
| **Token 管理** | CLAUDE.md 行为规则（Phase boundary compact） | 自动 micro-compact + LLM summarization |

## 值得我们借鉴的设计

1. **权限分级模式**（FULL_AUTO / DEFAULT / PLAN）
   - 我们目前只有静态文本规则，可加"模式切换"概念
   - Plan 模式：只读，用于规划/Review

2. **工具 read-only 声明**
   - 每个工具声明 `is_read_only()`，只读工具永远放行
   - 我们的 Hook 可借鉴，对 Read/Grep/Glob 跳过安全检查

3. **Hook 四种实现**
   - 我们目前只有 shell hook
   - webhook / LLM hook / subagent hook 是可加的增强方向

4. **团队权限继承**
   - Leader 授予 teammate `AllowedPath`，teammate 不能超越授权
   - 比我们目前的 Agent Team 只有角色定义更安全

5. **Auto-Compaction 策略**
   - 先 micro-compact（清空旧工具结果），不够再 LLM summarization
   - 比 /compact 更精细

6. **在陌生项目上做 Eval**
   - harness-eval skill 要求在"没见过的项目"上测试
   - 我们的 Quality Gate 可以加类似的 E2E 验证机制

## 不需要借鉴的部分

- **完整 Runtime**：我们是寄生层，不需要自造 Agent Loop / API Client / TUI
- **43+ 工具实现**：Claude Code 已经有
- **Plugin 系统**：Claude Code 已有 plugin/skill 机制
- **多 Provider 抽象**：宿主已处理

## 技术栈对比

**OpenHarness**：anthropic / openai / mcp / pydantic / typer / textual / httpx / React+Ink（TUI）

**我们的 Harness**：纯 Markdown + Bash hook + YAML 配置

## 结论

| 场景 | 推荐方案 |
|------|---------|
| 想自己造 Agent Runtime / 自己控制 Loop | OpenHarness |
| 在 Claude Code / Cursor 上加护栏 | 我们的 Harness |
| 要多 AI IDE 兼容 | 我们的 Harness（AGENT.md 通用协议） |
| 要跨 Provider（Kimi / GLM 等） | OpenHarness |
| 要企业级权限 / 审计 | OpenHarness（或我们的 Harness 未来借鉴） |

两者互补：OpenHarness 提供 runtime 底座，我们的 Harness 提供护栏方法论。未来可以把我们的 Harness 方法论 port 到 OpenHarness 上作为 bundled skills。
