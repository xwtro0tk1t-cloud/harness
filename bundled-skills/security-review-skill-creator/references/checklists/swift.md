# Swift/iOS 安全审计语义提示 (Semantic Hints)

> 本文件为覆盖率矩阵 (`coverage_matrix.md`) 的补充。
> **仅对未覆盖的维度按需加载对应 `## D{N}` 段落**，无需全量加载。
> LLM 自行决定搜索策略（Grep/Read/LSP/代码推理均可）。

## D1: 注入

**关键问题**:
1. SQL: 是否使用 `sqlite3_exec()` / raw SQL 拼接？（安全: `sqlite3_bind_text()` 参数化 / GRDB / CoreData）
2. WebView: `evaluateJavaScript()` 是否接受用户输入？`WKScriptMessageHandler` 处理器是否验证消息来源？
3. NSPredicate: `NSPredicate(format: "name = '\(userInput)'")` 是否拼接？（安全: `NSPredicate(format: "name = %@", userInput)`）
4. URL 构造: `URL(string: userInput)` 是否直接用于网络请求或 `openURL`？
5. Format string: `String(format: userInput)` 是否存在？（格式字符串漏洞）
6. Regular expression: `NSRegularExpression(pattern: userInput)` ReDoS 风险？

**易漏场景**:
- `sqlite3_exec(db, "DELETE FROM t WHERE id = \(userId)", nil, nil, nil)` SQL 注入
- `webView.evaluateJavaScript("setData('\(userData)')") { ... }` JS 注入
- `NSPredicate(format: "name CONTAINS '\(searchTerm)'")` predicate 注入
- `URL(string: "\(baseURL)/\(userPath)")` URL 注入/SSRF

**判定规则**:
- `sqlite3_exec` + 字符串插值 + 用户输入 = **Critical (SQL 注入)**
- `evaluateJavaScript` + 用户输入 = **High (XSS)**
- NSPredicate 字符串插值 = **High (predicate 注入)**
- GRDB / CoreData `%@` 参数 = **安全**

## D2: 认证

**关键问题**:
1. LAContext: `evaluatePolicy` 使用 `.deviceOwnerAuthenticationWithBiometrics` 还是 `.deviceOwnerAuthentication`？后者包含 passcode fallback。
2. Keychain 认证: `SecAccessControlCreateWithFlags` 是否绑定 `.biometryCurrentSet`？（换指纹后失效）
3. Sign in with Apple: `ASAuthorizationAppleIDProvider` 回调是否验证 `identityToken` 的签名和过期？
4. Token 存储: 访问令牌存储位置？UserDefaults（危险）vs Keychain（安全）？
5. 会话管理: app 进入后台时是否清除内存中的敏感数据？

**易漏场景**:
- `LAContext().evaluatePolicy(.deviceOwnerAuthentication)` 允许 passcode fallback
- Token 存储在 `UserDefaults.standard.set(token, forKey: "auth_token")` 明文
- 后台 → 前台时不重新验证 token 过期
- Sign in with Apple 仅检查 `credential.user` 不验证 JWT

**判定规则**:
- UserDefaults 存储 token/密码 = **High (不安全存储)**
- LAContext 无 `biometryCurrentSet` 绑定 = **Medium (生物认证可绕过)**
- 不验证 Apple ID Token 签名 = **High (伪造身份)**
- Keychain + SecAccessControl = **安全**

## D3: 授权 / URL Scheme

**关键问题**:
1. URL Scheme: `func application(_:open:options:)` 是否验证 source application 和 URL 参数？
2. Universal Links: `apple-app-site-association` 配置是否正确？域名验证？
3. URL 参数注入: deep link 的 query parameter 是否验证后再使用？
4. App Group: shared container 权限是否过宽？存储的数据是否敏感？
5. Extension 通信: `NSExtensionContext` 输入是否验证？

**易漏场景**:
- `func application(_:open url:options:) -> Bool { navigateTo(url.path!) }` 无验证直接导航
- `url.queryItems?.first(where: { $0.name == "action" })?.value` 未验证 → 执行任意 action
- Universal Link fallback 到 Safari 时泄露参数（HTTP 而非 HTTPS）

**判定规则**:
- URL Scheme 无来源验证 + 执行敏感操作 = **High**
- URL parameter 未验证直接用于导航/操作 = **High (URL 注入)**
- apple-app-site-association 配置错误 = **Medium**
- App Group shared container 含明文敏感数据 = **Medium**

## D4: 数据存储

**关键问题**:
1. UserDefaults: 是否存储敏感数据（token, 密码, PII, 生物特征）？
2. Keychain: `kSecAttrAccessible` 级别是否正确？`kSecAttrAccessibleAlways` = 始终可访问 = 危险。
3. CoreData / SQLite: 数据库是否加密（SQLCipher）？敏感字段是否单独加密？
4. File Protection: `NSFileProtectionComplete` 是否用于敏感文件？
5. 缓存: URLCache / NSCache / 图片缓存是否包含敏感数据？
6. Backup: iTunes/iCloud 备份是否包含未加密的敏感数据？

**易漏场景**:
- `UserDefaults.standard.set(creditCard, forKey: "card")` 明文信用卡
- `kSecAttrAccessibleAfterFirstUnlock` 用于高敏感数据（设备解锁一次后即可访问）
- CoreData SQLite 文件无加密，备份到 iCloud
- `URLSession` 默认缓存响应（含 token 的 API 响应可能被缓存）

**判定规则**:
- UserDefaults 存储敏感数据 = **High**
- `kSecAttrAccessibleAlways` / `kSecAttrAccessibleAlwaysThisDeviceOnly` = **High (已废弃，不安全)**
- 未加密 SQLite + 含 PII = **Medium**
- `NSFileProtectionNone` + 敏感文件 = **High**
- Keychain + `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` = **安全**

## D5: WKWebView 安全

**关键问题**:
1. JavaScript 注入: `evaluateJavaScript` 是否传入用户数据？是否有 CSP？
2. JS→Native 通信: `WKScriptMessageHandler` 处理器是否验证消息内容和来源？
3. Navigation: `WKNavigationDelegate` 的 `decidePolicyFor` 是否白名单过滤 URL？
4. Cookie: `WKWebsiteDataStore` 是否与 native 共享 session？cookie 是否正确隔离？
5. File 协议: 是否允许 `file://` URL？`allowFileAccessFromFileURLs` 是否开启？

**易漏场景**:
- `webView.evaluateJavaScript("document.title = '\(userInput)'")` XSS
- `WKScriptMessageHandler` 处理 `withdraw` / `transfer` 消息不验证来源页面
- `decidePolicyFor` 缺失或不过滤 → WebView 可加载任意 URL
- `WKWebViewConfiguration().preferences.javaScriptEnabled = true` + 加载第三方 URL

**判定规则**:
- `evaluateJavaScript` + 用户输入插值 = **High (XSS)**
- `WKScriptMessageHandler` 处理敏感操作 + 无来源验证 = **Critical**
- 无 `WKNavigationDelegate` + 加载外部 URL = **Medium**
- 仅加载 bundle 内 HTML + JS disabled = **安全**

## D6: 网络安全

**关键问题**:
1. ATS: `NSAllowsArbitraryLoads = true` 是否必要？是否可缩小到 exception domain？
2. TLS: `URLAuthenticationChallenge` 的 `ServerTrust` 验证是否正确？是否直接 `useCredential`？
3. 证书固定: 是否使用 TrustKit / 手动 pin？pin 过期策略？
4. 请求日志: Alamofire `EventMonitor` 是否在 release 打印请求 body？
5. SSRF: 用户输入是否用于 `URL(string:)` 构造？

**易漏场景**:
- `NSAllowsArbitraryLoads = true` 允许 HTTP 明文（MitM 风险）
- `urlSession(_:didReceive challenge:) { completionHandler(.useCredential, ...)  }` 信任任何证书
- Alamofire `ServerTrustPolicy.disableEvaluation` 禁用证书验证

**判定规则**:
- `NSAllowsArbitraryLoads = true` + 传输敏感数据 = **High**
- 信任所有证书 / 禁用 evaluation = **Critical (MitM)**
- 无证书固定 + 高价值应用 = **Medium**
- ATS 仅 exception 特定域名 + 合理理由 = **可接受**

## D7: 加密

**关键问题**:
1. 密钥硬编码: 加密密钥是否写死在代码？应使用 Keychain 或 Secure Enclave。
2. 弱算法: MD5/SHA1 用于密码或签名？CommonCrypto 配置错误？
3. 弱随机: `arc4random()` (无 `_uniform`) 或 `srand/rand` 用于安全场景？
4. AES: CCCrypt 的 IV 是否为零/固定？模式是否为 ECB？
5. Secure Enclave: 是否利用 SE 生成密钥（`kSecAttrTokenIDSecureEnclave`）？

**判定规则**:
- 硬编码密钥 = **High**
- MD5/SHA1 哈希密码 = **High**
- ECB 模式 / 固定 IV = **Medium**
- Secure Enclave + Keychain = **安全**

## D8: 后台与隐私

**关键问题**:
1. 后台截图: `applicationDidEnterBackground` / `sceneDidEnterBackground` 是否遮盖敏感 UI？
2. Pasteboard: 敏感数据是否写入 `UIPasteboard.general`？（跨设备 Universal Clipboard）
3. 通知: Push notification payload 是否包含敏感数据（明文可见于锁屏）？
4. 后台定位: 是否过度收集位置数据？
5. ATT (App Tracking Transparency): 是否正确请求追踪授权？

**易漏场景**:
- 银行 app 进入后台时未遮盖余额界面 → 截图可见
- `UIPasteboard.general.string = bankAccountNumber` 跨 app 可读
- `{ "aps": { "alert": "Your OTP is 123456" } }` 锁屏显示 OTP

**判定规则**:
- 敏感 UI 无后台遮盖 = **Medium (信息泄露)**
- 敏感数据写入系统 Pasteboard = **Medium**
- 推送明文含 OTP/密码 = **High**

## D9: 第三方依赖

**关键问题**:
1. CocoaPods / SPM / Carthage 依赖是否有已知 CVE？
2. 第三方 SDK: 是否请求过多权限？是否有已知数据收集行为？
3. Binary framework: 未开源的 .xcframework 是否可信？

**判定规则**:
- 已知 CVE 且可利用 = **按 CVE 等级**
- 第三方 SDK 未经审查 + 请求敏感权限 = **Medium**

## D10: 配置与越狱

**关键问题**:
1. 越狱检测: 是否实现？方法是否可靠？（文件检测、sandbox 完整性、符号链接）
2. 调试保护: `ptrace(PT_DENY_ATTACH)` 是否使用？
3. 代码签名: 是否验证应用完整性？
4. Entitlements: 是否有过宽的 entitlement（如 `com.apple.security.app-sandbox = false`）？
5. Minimum deployment target: 是否支持过老的 iOS 版本（缺少安全特性）？

**判定规则**:
- 金融 app 无越狱检测 = **Medium**
- Sandbox 禁用 = **Critical**
- 支持 iOS < 13（缺少现代安全 API）= **Low**
- App Attest / DeviceCheck 正确使用 = **安全**
