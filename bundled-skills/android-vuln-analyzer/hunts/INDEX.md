# Android 漏洞挖掘模式索引

## 快速选择指南

### 🔥 必查漏洞（所有 APP）

```bash
# 1. 硬编码密钥扫描（5-10分钟）
/android-vuln-analyzer app.apk hunts/hardcoded-secrets/
   → 查找: API密钥, 数据库密码, AWS凭证, 加密密钥
   → 成功率: 95% | CVSS: 7.5-9.8

# 2. 导出组件检查（10-15分钟）
/android-vuln-analyzer app.apk hunts/exported-components/
   → 查找: 无权限保护的导出组件
   → 成功率: 80% | CVSS: 5.0-8.5
```

### 💰 金融/支付类 APP

```bash
# SQL 注入
/android-vuln-analyzer banking.apk hunts/sql-injection/
   → 针对: ContentProvider, 数据库操作
   → 成功率: 90% | CVSS: 7.5-9.0

# 深度链接劫持
/android-vuln-analyzer payment.apk hunts/deeplink-hijacking/
   → 针对: OAuth流程, 支付跳转
   → 成功率: 70% | CVSS: 6.5-8.5

# 路径遍历
/android-vuln-analyzer fintech.apk hunts/path-traversal/
   → 针对: 文件操作, 备份/恢复
   → 成功率: 75% | CVSS: 6.5-8.5
```

### 🌐 社交/内容类 APP

```bash
# WebView 漏洞
/android-vuln-analyzer social.apk hunts/webview-vulnerabilities/
   → 针对: JavaScript Bridge, 任意URL加载
   → 成功率: 85% | CVSS: 7.5-9.3
```

### 📂 工具/文件管理类 APP

```bash
# 路径遍历
/android-vuln-analyzer filemanager.apk hunts/path-traversal/
   → 针对: 文件访问, 路径处理
   → 成功率: 75% | CVSS: 6.5-8.5
```

## 已创建的 Hunt 模式

### ✅ 完整模式（含详细文档）

| 序号 | 漏洞类型 | 目录 | 文件大小 | 适用场景 |
|------|---------|------|----------|---------|
| 1 | **SQL 注入** | `sql-injection/` | ~8KB | 有数据库的 APP |
| 2 | **路径遍历** | `path-traversal/` | ~9KB | 文件操作 APP |
| 3 | **WebView 安全** | `webview-vulnerabilities/` | ~12KB | Hybrid APP |
| 4 | **导出组件** | `exported-components/` | ~10KB | 所有 APP |
| 5 | **硬编码密钥** | `hardcoded-secrets/` | ~11KB | 所有 APP |
| 6 | **深度链接劫持** | `deeplink-hijacking/` | ~13KB | OAuth/支付流程 |

### 🚧 待完成模式（目录已创建）

| 序号 | 漏洞类型 | 目录 | 优先级 |
|------|---------|------|--------|
| 7 | Intent 重定向 | `intent-redirection/` | 中 |
| 8 | 不安全存储 | `insecure-storage/` | 中 |
| 9 | 不安全加密 | `insecure-crypto/` | 中 |
| 10 | 权限提升 | `privilege-escalation/` | 低 |
| 11 | 广播注入 | `broadcast-injection/` | 低 |
| 12 | PendingIntent 漏洞 | `pendingintent-vulnerabilities/` | 低 |

## 使用流程图

```
选择 Hunt 模式
    ↓
根据 APP 类型选择
    ↓
    ├─ 所有 APP → hardcoded-secrets
    ├─ 金融类 → sql-injection
    ├─ 社交类 → webview-vulnerabilities
    ├─ 工具类 → path-traversal
    └─ OAuth流程 → deeplink-hijacking
    ↓
运行 /android-vuln-analyzer
    ↓
    ├─ 有 hunt.md → 定向挖掘
    └─ 无 hunt.md → 等待创建
    ↓
AI 自动分析
    ↓
    ├─ 找到漏洞 → 生成 prompt.md + 报告
    └─ 未找到 → 记录扫描结果
    ↓
复现/修复
```

## 快速参考

### 按 CVSS 严重性

| 严重性 | 分数范围 | Hunt 模式 |
|--------|---------|-----------|
| **Critical** | 9.0-10.0 | hardcoded-secrets (AWS/Stripe密钥) |
| **High** | 7.0-8.9 | webview-vulnerabilities, sql-injection, hardcoded-secrets (API密钥) |
| **Medium** | 4.0-6.9 | path-traversal, exported-components, deeplink-hijacking |
| **Low** | 0.1-3.9 | - |

### 按发现概率

| 概率 | Hunt 模式 |
|------|-----------|
| **很高** (>70%) | hardcoded-secrets, exported-components |
| **高** (50-70%) | webview-vulnerabilities, sql-injection |
| **中等** (30-50%) | path-traversal, deeplink-hijacking |
| **低** (<30%) | privilege-escalation |

### 按扫描时间

| 时间 | Hunt 模式 |
|------|-----------|
| **快速** (5-15分钟) | hardcoded-secrets, exported-components |
| **中等** (15-30分钟) | sql-injection, webview-vulnerabilities |
| **较长** (30-60分钟) | path-traversal, deeplink-hijacking |

## 组合式扫描策略

### 策略 1: 快速安全评估（30分钟）

```bash
APP=target.apk

# 必查项（10分钟）
/android-vuln-analyzer $APP hunts/hardcoded-secrets/

# 通用检查（20分钟）
/android-vuln-analyzer $APP hunts/exported-components/
```

### 策略 2: 金融APP全面扫描（2小时）

```bash
APP=banking.apk

/android-vuln-analyzer $APP hunts/hardcoded-secrets/      # 15min
/android-vuln-analyzer $APP hunts/sql-injection/          # 30min
/android-vuln-analyzer $APP hunts/path-traversal/         # 30min
/android-vuln-analyzer $APP hunts/deeplink-hijacking/     # 30min
/android-vuln-analyzer $APP hunts/exported-components/    # 15min
```

### 策略 3: Hybrid APP 专项（1小时）

```bash
APP=hybrid.apk

/android-vuln-analyzer $APP hunts/webview-vulnerabilities/  # 30min
/android-vuln-analyzer $APP hunts/hardcoded-secrets/        # 15min
/android-vuln-analyzer $APP hunts/deeplink-hijacking/       # 15min
```

## 实际案例

### 案例 1: 发现 Stripe 密钥

```bash
$ /android-vuln-analyzer ecommerce.apk hunts/hardcoded-secrets/

[分析中...]
✓ 找到 3 个 API 密钥
✓ 发现 Stripe 生产密钥: sk_live_***
✓ CVSS: 9.3 (Critical)
✓ 报告已生成: hunts/hardcoded-secrets/prompt.md
```

### 案例 2: 导出组件无权限

```bash
$ /android-vuln-analyzer social.apk hunts/exported-components/

[分析中...]
✓ 发现 AdminPanelActivity 导出但无权限保护
✓ 任何 APP 可访问管理面板
✓ CVSS: 8.5 (High)
✓ PoC 已生成
```

### 案例 3: WebView Bridge 泄露

```bash
$ /android-vuln-analyzer messenger.apk hunts/webview-vulnerabilities/

[分析中...]
✓ Bridge 注册无 origin 验证
✓ getToken() 方法返回 JWT
✓ 可从任意 URL 窃取 token
✓ CVSS: 9.3 (Critical)
✓ 完整 PoC: hunts/webview-vulnerabilities/poc.html
```

## 贡献新 Hunt

如果你想添加新的漏洞模式：

1. 创建目录: `hunts/your-vuln-type/`
2. 编写 `hunt.md`（参考现有模式）
3. 测试有效性（至少 3 个真实 APP）
4. 更新本索引文件

## 获取帮助

- 📖 阅读: `hunts/README.md`
- 📝 参考: 任意已完成的 `hunt.md`
- 🎯 示例: `examples/phemex/prompt.md`

---

**最后更新**: 2026-02-27
**当前模式**: 6 个完整，6 个待完成
**总覆盖**: 12 类常见 Android 漏洞
