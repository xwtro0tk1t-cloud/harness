# Swift/iOS Security Audit

> Swift/iOS 代码安全审计模块 | **双轨并行完整覆盖**
> 适用于: Swift, iOS, macOS, iPadOS, watchOS, tvOS, UIKit, SwiftUI, Combine, Alamofire, Moya, Vapor

---

## 审计方法论

### 双轨并行框架

```
                    Swift/iOS 代码安全审计
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
         ▼                 ▼                 ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  轨道A (50%)    │ │  轨道B (40%)    │ │  补充 (10%)     │
│  控制建模法     │ │  数据流分析法   │ │  配置+依赖审计  │
│                 │ │                 │ │                 │
│ 缺失类漏洞:     │ │ 注入类漏洞:     │ │ • 硬编码凭据    │
│ • ATS禁用       │ │ • WebView注入   │ │ • Info.plist    │
│ • 证书固定缺失  │ │ • URL Scheme注入│ │ • Entitlements  │
│ • Keychain配置  │ │ • SQL注入       │ │ • 第三方SDK     │
│ • 生物识别绕过  │ │ • 路径遍历      │ │                 │
│ • 截图泄露      │ │ • 反序列化      │ │                 │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

### 两轨核心公式

```
轨道A: 缺失类漏洞 = 敏感操作 - 应有控制
轨道B: 注入类漏洞 = Source → [无净化] → Sink
```

**参考文档**: `references/core/security_controls_methodology.md`, `references/core/data_flow_methodology.md`

---

# 轨道A: 控制建模法 (缺失类漏洞)

## A1. 敏感操作枚举

### 1.1 快速识别命令

```bash
# URL Scheme 处理 - 外部输入入口
grep -rn "func application.*open.*url\|func scene.*openURLContexts\|UIApplication.*open(" --include="*.swift"

# Universal Links 处理
grep -rn "NSUserActivity\|webpageURL\|userActivity.*webpageURL" --include="*.swift"

# WKWebView 操作
grep -rn "WKWebView\|evaluateJavaScript\|WKScriptMessageHandler\|WKUserContentController" --include="*.swift"

# Keychain 操作
grep -rn "SecItemAdd\|SecItemUpdate\|SecItemCopyMatching\|SecItemDelete\|kSecAttrAccessible" --include="*.swift"

# 网络请求
grep -rn "URLSession\|URLRequest\|Alamofire\|AF\.request\|Moya" --include="*.swift"

# 文件操作
grep -rn "FileManager\|Data.*write\|contentsOfFile\|NSData.*writeToFile" --include="*.swift"

# 数据库操作
grep -rn "sqlite3_exec\|sqlite3_prepare\|GRDB\|FMDB\|CoreData\|NSPredicate" --include="*.swift"

# 生物识别
grep -rn "LAContext\|evaluatePolicy\|biometryType\|canEvaluatePolicy" --include="*.swift"

# 剪贴板操作
grep -rn "UIPasteboard\|generalPasteboard\|\.string\s*=" --include="*.swift"

# 加密操作
grep -rn "CryptoKit\|CommonCrypto\|SecKey\|CCCrypt\|kCCAlgorithm" --include="*.swift"

# 推送通知 payload
grep -rn "didReceiveRemoteNotification\|userNotificationCenter.*didReceive\|UNNotificationContent" --include="*.swift"

# Extension / App Group
grep -rn "NSExtensionContext\|NSItemProvider\|UserDefaults.*suiteName\|FileManager.*containerURL" --include="*.swift"

# Info.plist 敏感配置
grep -rn "NSAllowsArbitraryLoads\|NSExceptionDomains\|CFBundleURLTypes\|LSApplicationQueriesSchemes" Info.plist
```

### 1.2 输出模板

```markdown
## iOS敏感操作清单

| # | 入口/函数 | 类型 | 敏感类型 | 位置 | 风险等级 |
|---|-----------|------|----------|------|----------|
| 1 | application(_:open:options:) | URL Scheme | 外部输入 | AppDelegate.swift:32 | 高 |
| 2 | evaluateJavaScript() | WebView | 代码执行 | WebVC.swift:67 | 严重 |
| 3 | SecItemAdd() | Keychain | 凭据存储 | KeychainHelper.swift:15 | 高 |
```

---

## A2. 安全控制建模

### 2.1 iOS安全控制实现方式

| 控制类型 | UIKit | SwiftUI | 通用实现 |
|----------|-------|---------|----------|
| **URL Scheme 验证** | application(_:open:) | onOpenURL | sourceApplication/host 白名单 |
| **ATS (传输安全)** | Info.plist | Info.plist | NSAppTransportSecurity |
| **证书固定** | URLSessionDelegate | URLSessionDelegate | TrustKit, Alamofire ServerTrustManager |
| **Keychain 安全** | Security.framework | Security.framework | kSecAttrAccessibleWhenUnlockedThisDeviceOnly |
| **生物识别** | LAContext | LAContext | deviceOwnerAuthenticationWithBiometrics |
| **截图保护** | applicationDidEnterBackground | scenePhase | 遮盖敏感 UI |
| **越狱检测** | FileManager 检测 | FileManager 检测 | 多维度检测组合 |
| **数据保护** | NSFileProtectionComplete | NSFileProtectionComplete | Data Protection API |

### 2.2 控制矩阵模板 (iOS)

```yaml
敏感操作: application(_:open:options:) URL Scheme Handler
位置: AppDelegate.swift:32
类型: 外部输入处理

应有控制:
  输入验证:
    要求: 验证 URL scheme/host/path/参数
    实现: 白名单验证 sourceApplication 和 URL 各组件
    验证: 检查是否有对 url.host, url.path, url.queryItems 的验证

  授权控制:
    要求: 敏感操作需再次认证
    实现: 对涉及支付/账户操作的 deep link 要求用户确认

  数据验证:
    要求: URL 参数不直接用于敏感操作
    验证: 参数不进入 WebView/数据库/文件操作
```

---

## A3. 控制存在性验证

### 3.1 iOS关键控制验证清单

```markdown
## 控制验证: [入口名称]

| 控制项 | 应有 | 代码实现 | 结果 |
|--------|------|----------|------|
| URL 输入验证 | 必须 | host/path 白名单 | ✅/❌ |
| ATS 配置 | 必须 | NSAppTransportSecurity | ✅/❌ |
| 证书固定 | 推荐 | ServerTrustManager | ✅/❌ |
| Keychain 级别 | 必须 | kSecAttrAccessible | ✅/❌ |
| 截图保护 | 推荐 | Background 遮盖 | ✅/❌ |
| 日志清理 | 必须 | 无敏感数据打印 | ✅/❌ |

### 验证命令
```bash
# 检查 ATS 配置
grep -A 10 "NSAppTransportSecurity" Info.plist

# 检查 Keychain 访问级别
grep -rn "kSecAttrAccessible" --include="*.swift"

# 检查截图保护
grep -rn "applicationDidEnterBackground\|sceneDidEnterBackground" --include="*.swift" -A 15
```
```

### 3.2 常见缺失模式 → 漏洞映射

| 缺失控制 | 漏洞类型 | CWE | iOS检测方法 |
|----------|----------|-----|-------------|
| 无 URL Scheme 验证 | URL Scheme 劫持 | CWE-939 | 检查 open url handler 是否有白名单 |
| ATS 禁用 | 中间人攻击 | CWE-295 | 检查 Info.plist NSAllowsArbitraryLoads |
| 无证书固定 | TLS 拦截 | CWE-295 | 检查 URLSessionDelegate 或 TrustKit |
| Keychain 级别错误 | 数据泄露 | CWE-922 | 检查 kSecAttrAccessibleAlways |
| 无截图保护 | 敏感信息泄露 | CWE-200 | 检查 background 回调是否遮盖 UI |
| 无越狱检测 | 运行环境不可信 | CWE-693 | 检查越狱检测逻辑 |
| 生物识别配置不当 | 认证绕过 | CWE-287 | 检查 LAPolicy 配置 |

---

# 轨道B: 数据流分析法 (注入类漏洞)

> **核心公式**: Source → [无净化] → Sink = 注入类漏洞
> **工具**: Xcode Analyzer, SwiftLint 安全规则

## B1. iOS/Swift Source (用户可控输入)

```swift
// === URL Scheme 输入 ===
func application(_ app: UIApplication, open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
    url.host                    // Source: URL host
    url.path                    // Source: URL path
    url.queryItems              // Source: URL 参数
    url.fragment                // Source: URL fragment
}

// === Universal Links ===
func application(_ application: UIApplication,
                 continue userActivity: NSUserActivity,
                 restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void) -> Bool {
    userActivity.webpageURL     // Source: Universal Link URL
}

// === SwiftUI Deep Link ===
.onOpenURL { url in
    url.host                    // Source
    url.pathComponents          // Source
}

// === 剪贴板 ===
UIPasteboard.general.string     // Source: 系统剪贴板
UIPasteboard.general.url        // Source: 剪贴板 URL
UIPasteboard.general.image      // Source: 剪贴板图片

// === 网络响应 ===
URLSession.shared.dataTask(with: url) { data, response, error in
    data                        // Source: 服务器返回数据
}
AF.request(url).responseJSON { response in
    response.value              // Source: Alamofire 响应
}

// === 文件输入 ===
UIDocumentPickerViewController  // Source: 用户选择的文件
FileManager.default.contents(atPath:)  // Source: 共享容器文件

// === Extension 输入 ===
extensionContext?.inputItems    // Source: Extension 接收的数据
NSItemProvider.loadItem()       // Source: 共享数据

// === 推送通知 ===
func application(_ application: UIApplication,
                 didReceiveRemoteNotification userInfo: [AnyHashable: Any]) {
    userInfo                    // Source: 推送 payload
}

// === QR 码 / NFC / 蓝牙 ===
AVCaptureMetadataOutput        // Source: 扫码结果
NFCNDEFReaderSession           // Source: NFC 数据
CBPeripheral                   // Source: BLE 数据

// === 用户输入控件 ===
UITextField.text               // Source: 文本输入
UITextView.text                // Source: 多行文本
UISearchBar.text               // Source: 搜索输入
```

## B2. iOS/Swift Sink (危险操作)

| Sink 类型 | 漏洞 | CWE | 危险函数 |
|-----------|------|-----|----------|
| WebView 加载 | XSS/代码注入 | CWE-79 | `WKWebView.load()`, `loadHTMLString()`, `evaluateJavaScript()` |
| URL 打开 | URL Scheme 劫持 | CWE-939 | `UIApplication.shared.open()`, `canOpenURL()` |
| 文件操作 | 路径遍历 | CWE-22 | `FileManager.createFile()`, `Data.write(to:)`, `contentsOfFile:` |
| Keychain 写入 | 数据泄露 | CWE-922 | `SecItemAdd()` with wrong `kSecAttrAccessible` |
| 数据库 | SQL 注入 | CWE-89 | `sqlite3_exec()`, raw SQL string, `NSPredicate(format:)` |
| 网络请求 | SSRF | CWE-918 | `URLSession`, `URL(string:)`, `AF.request()` |
| 反序列化 | 反序列化漏洞 | CWE-502 | `NSKeyedUnarchiver.unarchiveObject()`, `JSONDecoder`, `PropertyListDecoder` |
| 剪贴板写入 | 数据泄露 | CWE-200 | `UIPasteboard.general.string = sensitive` |
| 日志 | 敏感数据泄露 | CWE-532 | `NSLog()`, `print()`, `os_log()`, `Logger()` |
| UserDefaults | 明文存储 | CWE-312 | `UserDefaults.set(sensitiveData)` |
| 进程执行 | 命令执行 | CWE-78 | `Process()`, `NSTask` (macOS) |
| 动态调度 | 方法注入 | CWE-470 | `NSClassFromString()`, `perform(#selector)`, `value(forKey:)` |
| NSPredicate | 谓词注入 | CWE-943 | `NSPredicate(format: userInput)` |
| HTML 渲染 | XSS | CWE-79 | `NSAttributedString(data:options:[.documentType: .html])` |

---

## 识别特征

```swift
// Swift/iOS 项目识别
import UIKit
import SwiftUI
import Foundation

// 文件结构
├── MyApp.xcodeproj / MyApp.xcworkspace
├── MyApp/
│   ├── AppDelegate.swift / App.swift (SwiftUI)
│   ├── SceneDelegate.swift
│   ├── Info.plist
│   ├── MyApp.entitlements
│   ├── Models/
│   ├── Views/
│   ├── ViewModels/
│   ├── Services/
│   ├── Networking/
│   └── Utils/
├── Podfile / Package.swift / Cartfile
└── MyAppTests/
```

---

## iOS/Swift 特定漏洞

### 1. URL Scheme 劫持 (CWE-939)

```swift
// ❌ 危险: 无验证的 URL Scheme handler
func application(_ app: UIApplication, open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
    let action = url.host  // 攻击者可构造任意 URL
    if action == "transfer" {
        let amount = url.queryItems?["amount"]  // 直接使用未验证参数
        let to = url.queryItems?["to"]
        performTransfer(to: to!, amount: amount!)  // 资金操作无确认!
    }
    return true
}

// ✓ 安全: 验证来源 + 参数白名单 + 用户确认
func application(_ app: UIApplication, open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
    // 1. 验证来源应用 (iOS 9+)
    guard let sourceApp = options[.sourceApplication] as? String,
          allowedSourceApps.contains(sourceApp) else {
        return false
    }

    // 2. 验证 scheme 和 host
    guard url.scheme == "myapp",
          let host = url.host,
          allowedActions.contains(host) else {
        return false
    }

    // 3. 敏感操作要求用户确认
    if host == "transfer" {
        showConfirmationAlert(for: url)  // 用户必须手动确认
    }

    return true
}

// 搜索模式
// func application.*open.*url|\.onOpenURL|openURLContexts
```

### 2. Universal Links 绕过 (CWE-939)

```swift
// ❌ 危险: Universal Links handler 无验证
func application(_ application: UIApplication,
                 continue userActivity: NSUserActivity,
                 restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void) -> Bool {
    guard let url = userActivity.webpageURL else { return false }
    // 直接解析URL路径执行操作, 未验证域名
    let path = url.path
    navigateTo(path: path)  // 攻击者可能构造恶意路径
    return true
}

// ✓ 安全: 严格验证域名和路径
func application(_ application: UIApplication,
                 continue userActivity: NSUserActivity,
                 restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void) -> Bool {
    guard userActivity.activityType == NSUserActivityTypeBrowsingWeb,
          let url = userActivity.webpageURL,
          let host = url.host,
          host == "www.myapp.com" || host == "myapp.com" else {
        return false
    }

    // 路径白名单
    let allowedPaths = ["/product/", "/profile/", "/share/"]
    guard allowedPaths.contains(where: { url.path.hasPrefix($0) }) else {
        return false
    }

    navigateTo(url: url)
    return true
}

// apple-app-site-association 配置检查:
// 确保 "paths" 不使用 "*" 通配符, 限制具体路径

// 搜索模式
// NSUserActivity|webpageURL|continue.*userActivity
```

### 3. ATS (App Transport Security) 禁用 (CWE-295)

```swift
// ❌ 危险: 完全禁用 ATS (Info.plist)
// <key>NSAppTransportSecurity</key>
// <dict>
//     <key>NSAllowsArbitraryLoads</key>
//     <true/>                              // 允许所有HTTP明文传输!
// </dict>

// ❌ 危险: 特定域名禁用 TLS 验证
// <key>NSExceptionDomains</key>
// <dict>
//     <key>api.example.com</key>
//     <dict>
//         <key>NSExceptionAllowsInsecureHTTPLoads</key>
//         <true/>                          // 该域名允许HTTP!
//         <key>NSExceptionMinimumTLSVersion</key>
//         <string>TLSv1.0</string>         // 过旧TLS版本!
//     </dict>
// </dict>

// ✓ 安全: 保持 ATS 默认启用, 仅在必要时添加例外
// <key>NSAppTransportSecurity</key>
// <dict>
//     <key>NSExceptionDomains</key>
//     <dict>
//         <key>legacy-api.example.com</key>
//         <dict>
//             <key>NSExceptionMinimumTLSVersion</key>
//             <string>TLSv1.2</string>     // 最低 TLS 1.2
//             <key>NSExceptionRequiresForwardSecrecy</key>
//             <true/>                       // 要求前向安全
//         </dict>
//     </dict>
// </dict>

// 搜索模式
// NSAllowsArbitraryLoads|NSExceptionAllowsInsecureHTTPLoads|NSAllowsLocalNetworking
```

### 4. Keychain 访问级别错误 (CWE-922)

```swift
// ❌ 危险: 使用已废弃的 kSecAttrAccessibleAlways
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "userToken",
    kSecValueData as String: tokenData,
    kSecAttrAccessible as String: kSecAttrAccessibleAlways  // 设备锁定时也可访问!
]
SecItemAdd(query as CFDictionary, nil)

// ❌ 危险: AfterFirstUnlock 在锁屏后仍可访问
let query: [String: Any] = [
    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock  // 锁屏后可被恶意进程读取
]

// ✓ 安全: 使用严格的访问控制
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "userToken",
    kSecValueData as String: tokenData,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,  // 仅设备解锁+本设备
    kSecAttrAccessControl as String: SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        .biometryCurrentSet,  // 需要当前注册的生物识别
        nil
    )!
]
SecItemAdd(query as CFDictionary, nil)

// 搜索模式
// kSecAttrAccessibleAlways|kSecAttrAccessibleAlwaysThisDeviceOnly|kSecAttrAccessibleAfterFirstUnlock
```

### 5. WKWebView 注入 (CWE-79)

```swift
// ❌ 危险: 用户输入直接拼接到 JavaScript
func handleSearch(query: String) {
    let js = "document.getElementById('search').value = '\(query)'"  // XSS!
    webView.evaluateJavaScript(js)  // query 含 ' 或 JS 代码即可注入
}

// ❌ 危险: 加载用户可控的 HTML
func displayContent(html: String) {
    webView.loadHTMLString(html, baseURL: nil)  // 用户可注入恶意 HTML/JS
}

// ❌ 危险: WKScriptMessageHandler 无验证
func userContentController(_ userContentController: WKUserContentController,
                           didReceive message: WKScriptMessage) {
    if message.name == "action" {
        let body = message.body as! String
        performAction(body)  // 网页 JS 可调用原生方法!
    }
}

// ❌ 危险: 允许任意导航
func webView(_ webView: WKWebView,
             decidePolicyFor navigationAction: WKNavigationAction,
             decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
    decisionHandler(.allow)  // 允许所有URL导航，包括 file://
}

// ✓ 安全: 参数化 + 输入转义
func handleSearch(query: String) {
    let sanitized = query
        .replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "'", with: "\\'")
        .replacingOccurrences(of: "\"", with: "\\\"")
        .replacingOccurrences(of: "\n", with: "\\n")
    let js = "document.getElementById('search').value = '\(sanitized)'"
    webView.evaluateJavaScript(js)
}

// ✓ 安全: WKScriptMessageHandler 白名单验证
func userContentController(_ userContentController: WKUserContentController,
                           didReceive message: WKScriptMessage) {
    guard message.name == "action",
          let body = message.body as? [String: Any],
          let actionName = body["name"] as? String,
          allowedActions.contains(actionName) else {
        return
    }
    performAction(actionName, params: body)
}

// ✓ 安全: 导航白名单
func webView(_ webView: WKWebView,
             decidePolicyFor navigationAction: WKNavigationAction,
             decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
    guard let url = navigationAction.request.url,
          let host = url.host,
          allowedDomains.contains(host),
          url.scheme == "https" else {
        decisionHandler(.cancel)
        return
    }
    decisionHandler(.allow)
}

// 搜索模式
// evaluateJavaScript|loadHTMLString|WKScriptMessageHandler|WKUserContentController
```

### 6. 后台截图泄露 (CWE-200)

```swift
// ❌ 危险: 未在进入后台时遮盖敏感 UI
// iOS 在 app 进入后台时自动截图用于任务切换器
// 敏感信息(密码、银行卡、个人数据)会出现在截图中

// ✓ 安全: UIKit - 进入后台时添加遮盖视图
class AppDelegate: UIResponder, UIApplicationDelegate {
    var privacyView: UIView?

    func applicationDidEnterBackground(_ application: UIApplication) {
        let blurEffect = UIBlurEffect(style: .light)
        let blurView = UIVisualEffectView(effect: blurEffect)
        blurView.frame = UIApplication.shared.windows.first?.frame ?? .zero
        blurView.tag = 999
        UIApplication.shared.windows.first?.addSubview(blurView)
    }

    func applicationWillEnterForeground(_ application: UIApplication) {
        UIApplication.shared.windows.first?.viewWithTag(999)?.removeFromSuperview()
    }
}

// ✓ 安全: SwiftUI - 使用 scenePhase
@main
struct MyApp: App {
    @Environment(\.scenePhase) var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .overlay(
                    scenePhase == .background ? PrivacyOverlay() : nil
                )
        }
    }
}

// 搜索模式
// applicationDidEnterBackground|sceneDidEnterBackground|scenePhase.*background
```

### 7. 剪贴板泄露 (CWE-200)

```swift
// ❌ 危险: 敏感数据写入系统剪贴板
UIPasteboard.general.string = userToken      // Token 泄露!
UIPasteboard.general.string = creditCardNumber  // 卡号泄露!

// ❌ 危险: 密码输入框未禁用复制
passwordTextField.isSecureTextEntry = true
// 但没有禁用长按菜单中的 "复制" 选项

// ✓ 安全: 使用本地剪贴板或过期设置
// iOS 14+: 设置过期时间
if #available(iOS 14.0, *) {
    UIPasteboard.general.setItems(
        [[UIPasteboard.typeAutomatic: sensitiveData]],
        options: [.expirationDate: Date().addingTimeInterval(60)]  // 60秒后过期
    )
}

// ✓ 安全: 使用私有剪贴板 (App Group 内)
let privatePasteboard = UIPasteboard(name: UIPasteboard.Name("com.myapp.private"), create: true)
privatePasteboard?.string = sensitiveData

// ✓ 安全: 禁用密码字段的复制
class SecureTextField: UITextField {
    override func canPerformAction(_ action: Selector, withSender sender: Any?) -> Bool {
        if action == #selector(copy(_:)) || action == #selector(paste(_:)) ||
           action == #selector(cut(_:)) {
            return false
        }
        return super.canPerformAction(action, withSender: sender)
    }
}

// 搜索模式
// UIPasteboard\.general\.(string|setItems|setValue)|\.general\.string\s*=
```

### 8. 越狱检测绕过 (CWE-693)

```swift
// ❌ 危险: 单一检测方法 (易被 hook 绕过)
func isJailbroken() -> Bool {
    return FileManager.default.fileExists(atPath: "/Applications/Cydia.app")
}

// ✓ 安全: 多维度检测 (提高绕过难度)
func isJailbroken() -> Bool {
    // 1. 检测越狱文件
    let jailbreakPaths = [
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash", "/usr/sbin/sshd", "/etc/apt",
        "/private/var/lib/apt/", "/usr/bin/ssh"
    ]
    for path in jailbreakPaths {
        if FileManager.default.fileExists(atPath: path) { return true }
    }

    // 2. 检测是否可以写入系统目录
    let testPath = "/private/jailbreak_test_\(UUID().uuidString)"
    do {
        try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
        try FileManager.default.removeItem(atPath: testPath)
        return true  // 非越狱设备无法写入
    } catch { }

    // 3. 检测是否可以打开 Cydia URL Scheme
    if let url = URL(string: "cydia://package/com.test"),
       UIApplication.shared.canOpenURL(url) {
        return true
    }

    // 4. 检测动态库注入 (Frida, Substrate)
    let suspiciousLibs = ["FridaGadget", "frida-agent", "libcycript", "MobileSubstrate"]
    for lib in suspiciousLibs {
        if let _ = dlopen(lib, RTLD_NOLOAD) { return true }
    }

    // 5. 检测 fork() 是否可用 (沙箱完整性)
    let forkResult = fork()
    if forkResult >= 0 {
        if forkResult > 0 { kill(forkResult, SIGTERM) }
        return true
    }

    return false
}

// 搜索模式
// isJailbroken|fileExists.*Cydia|canOpenURL.*cydia|MobileSubstrate
```

### 9. 证书固定缺失 (CWE-295)

```swift
// ❌ 危险: 完全信任任何证书
func urlSession(_ session: URLSession,
                didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    // 信任任何服务器证书 — 中间人攻击!
    let credential = URLCredential(trust: challenge.protectionSpace.serverTrust!)
    completionHandler(.useCredential, credential)
}

// ❌ 危险: Alamofire 禁用证书验证
let manager = Session(
    serverTrustManager: ServerTrustManager(
        evaluators: ["api.example.com": DisabledTrustEvaluator()]  // 禁用验证!
    )
)

// ✓ 安全: URLSession 公钥固定
func urlSession(_ session: URLSession,
                didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
          let serverTrust = challenge.protectionSpace.serverTrust,
          let serverCert = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
        completionHandler(.cancelAuthenticationChallenge, nil)
        return
    }

    // 比对公钥哈希
    let serverPublicKey = SecCertificateCopyKey(serverCert)
    let serverKeyData = SecKeyCopyExternalRepresentation(serverPublicKey!, nil)!
    let serverKeyHash = SHA256.hash(data: serverKeyData as Data)

    if pinnedKeyHashes.contains(serverKeyHash.description) {
        let credential = URLCredential(trust: serverTrust)
        completionHandler(.useCredential, credential)
    } else {
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}

// ✓ 安全: Alamofire 公钥固定
let manager = Session(
    serverTrustManager: ServerTrustManager(
        evaluators: [
            "api.example.com": PublicKeysTrustEvaluator(
                keys: pinnedPublicKeys,
                performDefaultValidation: true,
                validateHost: true
            )
        ]
    )
)

// 搜索模式
// didReceive.*challenge.*useCredential|DisabledTrustEvaluator|ServerTrustPolicy\.disableEvaluation
```

### 10. Extension 数据泄露 (CWE-200)

```swift
// ❌ 危险: App Group 共享容器中存储敏感数据且无加密
let sharedDefaults = UserDefaults(suiteName: "group.com.myapp.shared")
sharedDefaults?.set(userToken, forKey: "auth_token")     // 明文存储 Token!
sharedDefaults?.set(creditCard, forKey: "payment_info")  // 明文存储支付信息!

// ❌ 危险: 共享容器文件权限过宽
let containerURL = FileManager.default.containerURL(
    forSecurityApplicationGroupIdentifier: "group.com.myapp.shared"
)!
let fileURL = containerURL.appendingPathComponent("sensitive_data.json")
try data.write(to: fileURL)  // 所有 Group 成员均可读取

// ✓ 安全: 共享数据加密存储
let sharedDefaults = UserDefaults(suiteName: "group.com.myapp.shared")
let encryptedToken = try CryptoKit.AES.GCM.seal(
    tokenData,
    using: encryptionKey
).combined!
sharedDefaults?.set(encryptedToken, forKey: "auth_token_encrypted")

// ✓ 安全: 使用 Keychain 共享而非 UserDefaults
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "shared_token",
    kSecAttrAccessGroup as String: "TEAM_ID.com.myapp.shared",
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecValueData as String: tokenData
]
SecItemAdd(query as CFDictionary, nil)

// 搜索模式
// UserDefaults.*suiteName|containerURL.*forSecurityApplicationGroupIdentifier|kSecAttrAccessGroup
```

### 11. 生物识别绕过 (CWE-287)

```swift
// ❌ 危险: 仅客户端验证, 无后端绑定
let context = LAContext()
context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                        localizedReason: "验证身份") { success, error in
    if success {
        self.unlockSensitiveData()  // 仅依赖本地结果, Frida 可直接 hook
    }
}

// ❌ 危险: 使用 deviceOwnerAuthentication 降级到密码
let context = LAContext()
context.evaluatePolicy(.deviceOwnerAuthentication,  // 允许密码降级!
                        localizedReason: "验证身份") { success, error in
    // 攻击者知道设备密码即可通过
}

// ✓ 安全: Keychain + 生物识别绑定
// 1. 存储凭据时绑定生物识别
let accessControl = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    [.biometryCurrentSet, .privateKeyUsage],  // 绑定当前生物识别
    nil
)!

let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "auth_credential",
    kSecValueData as String: credentialData,
    kSecAttrAccessControl as String: accessControl,
    kSecUseAuthenticationContext as String: LAContext()
]
SecItemAdd(query as CFDictionary, nil)

// 2. 读取时系统自动触发生物识别
let readQuery: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "auth_credential",
    kSecReturnData as String: true,
    kSecUseOperationPrompt as String: "验证身份以访问数据"
]
var result: AnyObject?
let status = SecItemCopyMatching(readQuery as CFDictionary, &result)
// 如果生物识别失败, SecItemCopyMatching 返回错误, 数据不可读取

// 搜索模式
// LAContext|evaluatePolicy|deviceOwnerAuthentication|biometryCurrentSet
```

### 12. SQL 注入 (CWE-89)

```swift
// ❌ 危险: 字符串拼接构造 SQL
let query = "SELECT * FROM users WHERE name = '\(userName)'"  // SQLi!
sqlite3_exec(db, query, nil, nil, nil)

// ❌ 危险: FMDB 字符串拼接
let result = db.executeQuery(
    "SELECT * FROM users WHERE id = \(userId)", values: nil  // SQLi!
)

// ❌ 危险: NSPredicate 格式化字符串注入
let predicate = NSPredicate(format: "name == '\(userInput)'")  // Predicate 注入!
fetchRequest.predicate = predicate

// ✓ 安全: 参数化查询
var stmt: OpaquePointer?
sqlite3_prepare_v2(db, "SELECT * FROM users WHERE name = ?", -1, &stmt, nil)
sqlite3_bind_text(stmt, 1, userName, -1, nil)

// ✓ 安全: FMDB 参数化
let result = db.executeQuery(
    "SELECT * FROM users WHERE id = ?", values: [userId]
)

// ✓ 安全: GRDB 参数化
let users = try User.filter(Column("name") == userName).fetchAll(db)

// ✓ 安全: NSPredicate 参数化
let predicate = NSPredicate(format: "name == %@", userInput)
fetchRequest.predicate = predicate

// 搜索模式
// sqlite3_exec.*\\(|"SELECT.*\\(|NSPredicate\(format:.*\\\\(
```

### 13. 明文存储敏感数据 (CWE-312)

```swift
// ❌ 危险: UserDefaults 存储敏感信息
UserDefaults.standard.set(password, forKey: "user_password")  // 明文!
UserDefaults.standard.set(token, forKey: "auth_token")        // 明文!
UserDefaults.standard.set(apiKey, forKey: "api_key")          // 明文!

// ❌ 危险: plist 文件存储
let dict = ["password": password, "token": token]
(dict as NSDictionary).write(to: plistURL, atomically: true)  // 明文!

// ✓ 安全: 使用 Keychain
func saveToKeychain(key: String, data: Data) -> OSStatus {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: key,
        kSecValueData as String: data,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    SecItemDelete(query as CFDictionary)  // 删除旧值
    return SecItemAdd(query as CFDictionary, nil)
}

// ✓ 安全: 加密后存储
let sealedBox = try AES.GCM.seal(sensitiveData, using: symmetricKey)
UserDefaults.standard.set(sealedBox.combined, forKey: "encrypted_data")

// 搜索模式
// UserDefaults.*password|UserDefaults.*token|UserDefaults.*secret|UserDefaults.*apiKey
```

### 14. 日志泄露 (CWE-532)

```swift
// ❌ 危险: 打印敏感信息到日志
NSLog("User token: %@", authToken)        // 系统日志可被其他 app 读取 (旧版iOS)!
print("Password: \(password)")            // Debug 日志
os_log("API Key: %{public}@", apiKey)     // public 级别日志可被设备日志读取

// ❌ 危险: 网络请求/响应日志包含敏感数据
print("Request headers: \(request.allHTTPHeaderFields)")  // 可能包含 Authorization
print("Response: \(String(data: data, encoding: .utf8))")  // 可能包含 token

// ✓ 安全: 使用 private 级别日志
os_log("Auth event for user: %{private}@", log: .default, type: .info, userId)

// ✓ 安全: Release 构建禁用日志
#if DEBUG
print("Debug info: \(debugData)")
#endif

// ✓ 安全: 自定义 Logger 过滤敏感字段
func safeLog(_ message: String) {
    #if DEBUG
    let sanitized = message
        .replacingOccurrences(of: #"(token|password|secret)[:=]\s*\S+"#,
                              with: "$1=***REDACTED***",
                              options: .regularExpression)
    os_log("%{private}@", log: .default, type: .info, sanitized)
    #endif
}

// 搜索模式
// NSLog\(.*password|NSLog\(.*token|print\(.*password|print\(.*secret|os_log.*public.*token
```

### 15. 不安全的随机数 (CWE-338)

```swift
// ❌ 危险: 使用不安全的随机数生成器
let token = String(arc4random())           // arc4random 输出范围有限
let otp = String(Int.random(in: 0...9999))  // Swift Random 用于安全场景不够
srand48(Int(Date().timeIntervalSince1970))  // 种子可预测
let value = drand48()                       // 可预测!

// ✓ 安全: 使用密码学安全随机数
var bytes = [UInt8](repeating: 0, count: 32)
let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
guard status == errSecSuccess else { /* handle error */ return }
let secureToken = Data(bytes).base64EncodedString()

// ✓ 安全: CryptoKit
let symmetricKey = SymmetricKey(size: .bits256)

// 搜索模式
// arc4random\b(?!_uniform)|srand\(|srand48|drand48|rand\(\)
```

### 16. 反序列化漏洞 (CWE-502)

```swift
// ❌ 危险: NSKeyedUnarchiver 不安全的反归档
let object = NSKeyedUnarchiver.unarchiveObject(with: untrustedData)  // 已废弃, 不安全!

// ❌ 危险: NSCoding 无类型约束
let object = try NSKeyedUnarchiver.unarchivedObject(
    ofClass: NSObject.self,  // 过宽的类型
    from: untrustedData
)

// ❌ 危险: Codable 解码不受信任数据无校验
let decoder = JSONDecoder()
let config = try decoder.decode(AppConfig.self, from: untrustedData)
// 如果 AppConfig 包含 URL/path 字段, 可被攻击者控制

let plistDecoder = PropertyListDecoder()
let settings = try plistDecoder.decode(Settings.self, from: untrustedPlistData)

// ✓ 安全: 严格类型约束
let object = try NSKeyedUnarchiver.unarchivedObject(
    ofClasses: [AllowedClass1.self, AllowedClass2.self],  // 严格白名单
    from: trustedData
)

// ✓ 安全: Codable 解码后验证
let decoder = JSONDecoder()
let config = try decoder.decode(AppConfig.self, from: data)
guard config.baseURL.hasPrefix("https://"),
      allowedDomains.contains(URL(string: config.baseURL)?.host ?? "") else {
    throw ValidationError.invalidConfig
}

// 搜索模式
// NSKeyedUnarchiver\.unarchiveObject|unarchivedObject.*ofClass.*NSObject|PropertyListDecoder.*untrusted
```

### 17. 路径遍历 (CWE-22)

```swift
// ❌ 危险: 用户输入直接用于文件路径
let fileName = urlQueryItem.value!  // 用户可控
let filePath = documentsDirectory.appendingPathComponent(fileName)
let data = try Data(contentsOf: filePath)  // ../../../etc/passwd

// ❌ 危险: 共享容器文件操作
let sharedURL = FileManager.default.containerURL(
    forSecurityApplicationGroupIdentifier: "group.com.myapp"
)!
let fileURL = sharedURL.appendingPathComponent(userProvidedName)
try sensitiveData.write(to: fileURL)  // 可遍历到容器外

// ✓ 安全: 路径验证
func safePath(base: URL, userInput: String) throws -> URL {
    let sanitized = userInput
        .replacingOccurrences(of: "..", with: "")
        .replacingOccurrences(of: "/", with: "")

    let target = base.appendingPathComponent(sanitized)
    let resolvedTarget = target.standardized

    // 确保解析后的路径仍在基目录下
    guard resolvedTarget.path.hasPrefix(base.standardized.path) else {
        throw SecurityError.pathTraversal
    }

    return resolvedTarget
}

// 搜索模式
// appendingPathComponent.*user|contentsOfFile.*user|Data\(contentsOf.*user
```

### 18. SSRF (CWE-918)

```swift
// ❌ 危险: 用户可控 URL 直接请求
let urlString = request.queryItems?["url"]  // 用户可控
let url = URL(string: urlString!)!
let task = URLSession.shared.dataTask(with: url)  // SSRF!
task.resume()

// ❌ 危险: 图片加载使用用户 URL
let imageURL = URL(string: userProvidedURLString)!
let data = try Data(contentsOf: imageURL)  // 可请求内网资源
imageView.image = UIImage(data: data)

// ✓ 安全: URL 白名单验证
func validateURL(_ urlString: String) throws -> URL {
    guard let url = URL(string: urlString),
          let host = url.host,
          url.scheme == "https",
          allowedDomains.contains(host) else {
        throw SecurityError.invalidURL
    }

    // 检查是否解析到内网地址
    let hostRef = CFHostCreateWithName(nil, host as CFString).takeRetainedValue()
    CFHostStartInfoResolution(hostRef, .addresses, nil)
    // ... 验证解析的 IP 不是内网地址

    return url
}

// 搜索模式
// URL\(string:.*user|URLSession.*dataTask.*user|Data\(contentsOf:.*user
```

---

## Swift 语言特定漏洞

### 1. Force Unwrap 崩溃 (CWE-755)

```swift
// ❌ 危险: 强制解包可导致 app 崩溃 (DoS)
let value = dictionary["key"]!          // key 不存在时崩溃
let url = URL(string: userInput)!       // 无效 URL 时崩溃
let data = try! JSONDecoder().decode(Model.self, from: response)  // 解码失败崩溃
let result = someOptional as! SpecificType  // 类型不匹配崩溃
let first = array.first!               // 空数组崩溃

// ✓ 安全: 安全解包
guard let value = dictionary["key"] else { return }
guard let url = URL(string: userInput) else { return }

do {
    let data = try JSONDecoder().decode(Model.self, from: response)
} catch {
    handleError(error)
}

if let result = someOptional as? SpecificType {
    use(result)
}

guard let first = array.first else { return }

// 搜索模式
// try!|as!|\.first!|\.last!|\[.*\]!|\.force
```

### 2. String Interpolation 注入 (CWE-89/CWE-943)

```swift
// ❌ 危险: SQL 字符串插值
let query = "SELECT * FROM users WHERE name = '\(userInput)'"  // SQLi via interpolation

// ❌ 危险: NSPredicate 字符串插值
let pred = NSPredicate(format: "name == '\(userInput)'")  // Predicate injection

// ❌ 危险: URL 字符串插值
let urlStr = "https://api.example.com/search?q=\(userInput)"  // URL injection
let url = URL(string: urlStr)

// ❌ 危险: HTML 字符串插值
let html = "<div>\(userInput)</div>"  // XSS
webView.loadHTMLString(html, baseURL: nil)

// ✓ 安全: 使用参数化方法
// SQL: 参数化查询 (见 #12)
// NSPredicate: %@ 占位符
let pred = NSPredicate(format: "name == %@", userInput)
// URL: URLComponents
var components = URLComponents(string: "https://api.example.com/search")!
components.queryItems = [URLQueryItem(name: "q", value: userInput)]
let url = components.url

// 搜索模式
// NSPredicate\(format:.*\\\\(|"SELECT.*\\\\(|"INSERT.*\\\\(|loadHTMLString.*\\\\(
```

### 3. ARC 循环引用 (CWE-401)

```swift
// ❌ 危险: 闭包强引用导致内存泄漏 (可能泄露敏感数据)
class NetworkManager {
    var token: String = "sensitive_token"

    func fetchData() {
        URLSession.shared.dataTask(with: url) { data, response, error in
            // self 被闭包强引用, NetworkManager 永不释放
            // token 留在内存中可被内存转储工具提取
            self.processData(data)
        }.resume()
    }
}

// ❌ 危险: delegate 强引用
class ViewController: UIViewController {
    let manager = SomeManager()

    override func viewDidLoad() {
        manager.delegate = self  // 如果 SomeManager.delegate 是 strong, 循环引用
    }
}

// ✓ 安全: 使用 weak/unowned 打破循环
class NetworkManager {
    func fetchData() {
        URLSession.shared.dataTask(with: url) { [weak self] data, response, error in
            guard let self = self else { return }
            self.processData(data)
        }.resume()
    }
}

// 搜索模式
// \{[^}]*\bself\b(?!.*\[weak self\])|\{[^}]*\bself\.(?!.*\[weak)
```

### 4. Unsafe Pointer 越界 (CWE-119)

```swift
// ❌ 危险: UnsafeRawPointer 操作可能越界
let buffer = UnsafeMutableRawPointer.allocate(byteCount: 100, alignment: 1)
buffer.storeBytes(of: largeValue, toByteOffset: 98, as: UInt64.self)  // 越界写入!

// ❌ 危险: UnsafeMutableBufferPointer 无边界检查
let ptr = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: 10)
ptr[15] = 0xFF  // 越界访问, 未定义行为!

// ❌ 危险: withUnsafeBytes 类型混淆
data.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
    let value = ptr.load(fromByteOffset: 0, as: UInt64.self)  // data < 8 字节时越界
}

// ✓ 安全: 边界检查
guard data.count >= MemoryLayout<UInt64>.size else {
    throw DataError.insufficientData
}
data.withUnsafeBytes { ptr in
    let value = ptr.load(fromByteOffset: 0, as: UInt64.self)
}

// 搜索模式
// UnsafeRawPointer|UnsafeMutablePointer|UnsafeBufferPointer|withUnsafeBytes|withUnsafeMutableBytes
```

### 5. @objc 暴露 (CWE-749)

```swift
// ❌ 危险: @objc 暴露的方法可被 Objective-C runtime 调用
class SecretManager: NSObject {
    @objc func getAPIKey() -> String {   // 可被 Method Swizzling 或 Frida hook
        return "sk-secret-api-key-12345"
    }

    @objc dynamic func validateLicense() -> Bool {  // dynamic 更容易被 hook
        return performValidation()
    }
}

// ❌ 危险: perform(#selector) 动态调度
let result = target.perform(NSSelectorFromString(userInput))  // 方法注入!

// ❌ 危险: NSClassFromString 动态类创建
let cls = NSClassFromString(userProvidedClassName) as? NSObject.Type  // 任意类实例化
let instance = cls?.init()

// ✓ 安全: 避免不必要的 @objc 暴露
class SecretManager {  // 不继承 NSObject
    private func getAPIKey() -> String {  // private, 无 @objc
        return KeychainHelper.getValue(for: "api_key")  // 从 Keychain 获取
    }
}

// ✓ 安全: 白名单动态调度
let allowedSelectors: Set<String> = ["actionA", "actionB"]
guard allowedSelectors.contains(selectorName) else { return }
target.perform(NSSelectorFromString(selectorName))

// 搜索模式
// NSClassFromString|NSSelectorFromString|perform\(#selector|@objc.*dynamic|value\(forKey:.*user
```

### 6. Codable 反序列化不受信任数据 (CWE-502)

```swift
// ❌ 危险: 直接解码不受信任的远程配置
struct RemoteConfig: Codable {
    let apiEndpoint: String    // 攻击者可控制 API 地址
    let updateURL: String      // 攻击者可控制更新地址
    let jsToExecute: String    // 攻击者可注入 JS 代码
}

let config = try JSONDecoder().decode(RemoteConfig.self, from: remoteData)
webView.evaluateJavaScript(config.jsToExecute)  // RCE!
let url = URL(string: config.apiEndpoint)!
URLSession.shared.dataTask(with: url)           // SSRF!

// ✓ 安全: 解码后验证所有字段
let config = try JSONDecoder().decode(RemoteConfig.self, from: remoteData)
guard let url = URL(string: config.apiEndpoint),
      url.scheme == "https",
      allowedDomains.contains(url.host ?? "") else {
    throw ConfigError.invalidEndpoint
}
// 不允许远程配置中包含可执行代码

// 搜索模式
// JSONDecoder\(\)\.decode|PropertyListDecoder\(\)\.decode.*remote|\.decode.*untrusted
```

---

## iOS 配置安全审计

### Info.plist 安全检查

```bash
# ATS 禁用检测
grep -A 5 "NSAppTransportSecurity" */Info.plist
grep "NSAllowsArbitraryLoads" */Info.plist
grep "NSExceptionAllowsInsecureHTTPLoads" */Info.plist
grep "NSAllowsLocalNetworking" */Info.plist

# URL Scheme 注册
grep -A 10 "CFBundleURLTypes" */Info.plist
grep "CFBundleURLSchemes" */Info.plist

# 权限声明 (Privacy)
grep "NSCamera\|NSMicrophone\|NSLocation\|NSContacts\|NSCalendars\|NSPhotoLibrary" */Info.plist

# 导出合规
grep "ITSAppUsesNonExemptEncryption" */Info.plist

# 后台模式
grep -A 5 "UIBackgroundModes" */Info.plist
```

### Entitlements 安全检查

```bash
# 检查 entitlements 文件
grep -rn "com.apple.security" --include="*.entitlements"

# App Sandbox 禁用 (macOS)
grep "com.apple.security.app-sandbox.*false" --include="*.entitlements"

# Keychain 共享组
grep "keychain-access-groups" --include="*.entitlements"

# App Groups
grep "com.apple.security.application-groups" --include="*.entitlements"

# Associated Domains (Universal Links)
grep "com.apple.developer.associated-domains" --include="*.entitlements"
```

---

## iOS 审计清单

```
URL Scheme 安全:
- [ ] 搜索 func application(_:open:options:) / onOpenURL
- [ ] 检查 URL host/path/参数 是否有白名单验证
- [ ] 检查 sourceApplication 是否验证
- [ ] 敏感操作 (支付/账户) 是否需要用户确认

Universal Links:
- [ ] 检查 apple-app-site-association 配置
- [ ] 验证 webpageURL 处理是否有域名/路径白名单
- [ ] 检查 "paths" 是否限制具体路径

ATS (传输安全):
- [ ] 检查 NSAllowsArbitraryLoads 是否为 true
- [ ] 检查 NSExceptionDomains 的例外配置
- [ ] 验证最低 TLS 版本 >= 1.2

WebView 安全:
- [ ] 搜索 evaluateJavaScript / loadHTMLString
- [ ] 检查用户输入是否进入 JavaScript/HTML
- [ ] 验证 WKScriptMessageHandler 白名单
- [ ] 检查导航策略 (decidePolicyFor)

Keychain 安全:
- [ ] 搜索 kSecAttrAccessible 设置
- [ ] 检查是否使用 kSecAttrAccessibleAlways (已废弃)
- [ ] 验证敏感数据使用 WhenUnlockedThisDeviceOnly

数据存储:
- [ ] 搜索 UserDefaults 存储敏感数据
- [ ] 搜索 NSLog/print/os_log 打印敏感信息
- [ ] 检查 plist 文件是否存储密码/token
- [ ] 验证文件保护级别 (NSFileProtection)

剪贴板安全:
- [ ] 搜索 UIPasteboard.general 写入操作
- [ ] 检查敏感数据是否写入系统剪贴板
- [ ] 验证密码字段是否禁用复制

截图保护:
- [ ] 搜索 applicationDidEnterBackground
- [ ] 检查是否在后台时遮盖敏感 UI

生物识别:
- [ ] 搜索 LAContext / evaluatePolicy
- [ ] 检查是否仅依赖客户端验证结果
- [ ] 验证 Keychain 绑定生物识别

证书固定:
- [ ] 搜索 URLAuthenticationChallenge
- [ ] 检查是否使用 DisabledTrustEvaluator
- [ ] 验证证书/公钥固定实现

SQL 注入:
- [ ] 搜索 sqlite3_exec + 字符串拼接
- [ ] 搜索 NSPredicate(format:) + 字符串插值
- [ ] 验证参数化查询使用

反序列化:
- [ ] 搜索 NSKeyedUnarchiver.unarchiveObject (已废弃)
- [ ] 搜索 JSONDecoder/PropertyListDecoder 解码不受信任数据
- [ ] 验证解码后的字段校验

越狱检测:
- [ ] 检查是否有越狱检测逻辑
- [ ] 验证检测维度 (文件/写入/URL Scheme/动态库)
- [ ] 检查检测结果的处理 (仅提示 vs 限制功能)

Swift 特定:
- [ ] 搜索 try! / as! / force unwrap
- [ ] 搜索字符串插值用于 SQL/URL/Predicate
- [ ] 搜索 UnsafeRawPointer / UnsafeMutablePointer
- [ ] 搜索 @objc dynamic 方法暴露
- [ ] 检查闭包 capture list ([weak self])

配置审计:
- [ ] 审计 Info.plist 安全配置
- [ ] 审计 Entitlements 权限范围
- [ ] 检查第三方 SDK 权限和数据收集
```

---

## 审计正则

```regex
# ATS 禁用
NSAllowsArbitraryLoads|NSExceptionAllowsInsecureHTTPLoads|NSAllowsLocalNetworking

# Keychain 不安全访问级别
kSecAttrAccessibleAlways|kSecAttrAccessibleAlwaysThisDeviceOnly

# WebView 注入
evaluateJavaScript|loadHTMLString|WKUserScript|WKScriptMessageHandler|WKUserContentController

# 明文存储敏感数据
UserDefaults.*(password|token|secret|apiKey|creditCard|ssn)

# TLS/证书绕过
DisabledTrustEvaluator|ServerTrustPolicy\.disableEvaluation|urlSession.*didReceive.*challenge.*useCredential

# 日志泄露
NSLog\(.*password|NSLog\(.*token|print\(.*password|print\(.*secret|os_log.*public.*(token|password|key)

# URL Scheme 无验证
func application.*open.*url.*options.*->.*Bool

# 强制解包
try!|as!|\.first!|\.last!|\[.*\]!

# 反序列化
NSKeyedUnarchiver\.unarchiveObject|NSCoding|unarchivedObject.*ofClass.*NSObject

# 剪贴板操作
UIPasteboard\.general\.(string|setItems|setValue|url)

# 后台截图
applicationDidEnterBackground|sceneDidEnterBackground|scenePhase.*background

# 不安全随机数
arc4random\b(?!_uniform)|srand\(|srand48|drand48|rand\(\)

# Entitlements 过宽
com\.apple\.security\.app-sandbox.*false

# SQL 注入
sqlite3_exec.*\\(|"SELECT.*\\(.*\\)"|NSPredicate\(format:.*\\\\(

# 证书固定缺失
URLAuthenticationChallenge|ServerTrust

# Unsafe Pointer
UnsafeRawPointer|UnsafeMutablePointer|UnsafeBufferPointer|withUnsafeBytes

# 动态调度/方法注入
NSClassFromString|NSSelectorFromString|perform\(#selector|value\(forKey:.*user

# 生物识别
LAContext|evaluatePolicy|deviceOwnerAuthentication

# 越狱检测
fileExists.*Cydia|canOpenURL.*cydia|MobileSubstrate|/bin/bash

# 文件路径遍历
appendingPathComponent.*user|contentsOfFile.*user|Data\(contentsOf.*user

# SSRF
URL\(string:.*user|URLSession.*dataTask.*user|AF\.request.*user

# 硬编码凭据
(password|passwd|secret|token|apikey|api_key)\s*[:=]\s*["'][^"']+["']

# Extension 数据泄露
UserDefaults.*suiteName|containerURL.*forSecurityApplicationGroupIdentifier
```

---

## 审计工具

```bash
# SwiftLint - Swift 代码检查 (可配置安全规则)
brew install swiftlint
swiftlint lint --path ./Sources

# SwiftLint 安全相关规则配置 (.swiftlint.yml)
cat > .swiftlint.yml << 'EOF'
opt_in_rules:
  - force_unwrapping          # 禁止 !
  - force_try                 # 禁止 try!
  - force_cast                # 禁止 as!
  - implicitly_unwrapped_optional  # 禁止 ImplicitlyUnwrappedOptional

custom_rules:
  nslog_usage:
    name: "NSLog Usage"
    regex: "NSLog\\("
    message: "Use os_log with private level instead of NSLog"
    severity: warning
  userdefaults_sensitive:
    name: "UserDefaults Sensitive Data"
    regex: "UserDefaults.*(password|token|secret|key)"
    message: "Do not store sensitive data in UserDefaults, use Keychain"
    severity: error
EOF

# MobSF - 移动安全框架 (支持 iOS/Android)
# https://github.com/MobSF/Mobile-Security-Framework-MobSF
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# class-dump - Objective-C 类导出 (检查 @objc 暴露)
class-dump -H MyApp.app/MyApp -o headers/

# Xcode Analyzer - 内置静态分析
xcodebuild analyze -project MyApp.xcodeproj -scheme MyApp

# otool - 检查二进制安全特性
otool -hv MyApp           # 检查 PIE (Position Independent Executable)
otool -l MyApp | grep -A2 LC_ENCRYPTION_INFO  # 检查加密
otool -l MyApp | grep -A2 __RESTRICT  # 检查 __RESTRICT 段

# codesign - 验证签名
codesign -dvvv MyApp.app

# security - Keychain 调试
security dump-keychain -d login.keychain  # macOS 开发时检查 Keychain 内容

# Frida (渗透测试用)
# frida -U -f com.myapp.bundle -l bypass.js
# 用于验证越狱检测、SSL Pinning 等防护的有效性
```

---

## 授权漏洞检测 (Authorization Gap)

> **核心问题**: iOS app 的授权检查通常在服务端, 但客户端也需要防护
> **解决方案**: 验证客户端是否正确传递和校验授权信息

### 方法论

```
❌ 旧思路 (仅关注服务端):
   假设所有授权由服务端处理, 忽略客户端逻辑

✅ 新思路 (客户端 + 服务端):
   1. 客户端: 验证 Token 传递、请求签名、防重放
   2. 服务端: 验证授权逻辑完整性
   3. 通信: 验证请求不可被篡改
```

### iOS 客户端授权检测

```bash
# 步骤1: 找到所有 API 请求
grep -rn "URLRequest\|AF\.request\|Moya" --include="*.swift"

# 步骤2: 检查 Token 传递方式
grep -rn "Authorization\|Bearer\|X-Token\|accessToken" --include="*.swift"

# 步骤3: 检查是否有请求签名
grep -rn "HMAC\|signature\|nonce\|timestamp" --include="*.swift"
```

### 漏洞模式

```swift
// ❌ 漏洞: Token 存储在 UserDefaults, 可被轻易提取
let token = UserDefaults.standard.string(forKey: "auth_token")!
var request = URLRequest(url: url)
request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

// ❌ 漏洞: 客户端权限判断可被绕过
if currentUser.role == "admin" {
    showAdminPanel()  // 仅客户端判断, Hook 即可绕过
}

// ✓ 安全: Token 从 Keychain 获取 + 服务端验证
let token = KeychainHelper.getValue(for: "auth_token")
var request = URLRequest(url: url)
request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
// 服务端验证 Token 有效性和权限
```

---

## CSRF / Deep Link CSRF (CWE-352)

### 危险模式

```swift
// ❌ URL Scheme 触发的 CSRF
// 攻击者网页包含: <a href="myapp://transfer?to=attacker&amount=1000">
func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
    if url.host == "transfer" {
        // 自动执行转账, 无用户确认 = Deep Link CSRF!
        performTransfer(url.queryItems)
    }
    return true
}
```

### 安全配置

```swift
// ✓ 安全: 敏感操作要求用户确认 + 防 CSRF Token
func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
    if url.host == "transfer" {
        // 1. 验证来源
        guard let source = options[.sourceApplication] as? String,
              trustedApps.contains(source) else {
            return false
        }

        // 2. 验证防伪 Token
        guard let csrfToken = url.queryItems?["csrf"],
              CSRFManager.validate(token: csrfToken) else {
            return false
        }

        // 3. 显示确认对话框
        showTransferConfirmation(url.queryItems) { confirmed in
            if confirmed {
                self.performTransfer(url.queryItems)
            }
        }
    }
    return true
}
```

---

## 最小 PoC 示例

```bash
# URL Scheme 劫持
# 在 Safari 中打开:
open "myapp://transfer?to=attacker&amount=1000"

# Universal Link 测试
open "https://www.myapp.com/deeplink?action=delete&id=123"

# 剪贴板嗅探测试 (在另一个 app 中)
# 复制敏感数据后, 检查其他 app 是否可读取 UIPasteboard.general.string

# ATS 绕过测试
# 使用 mitmproxy 或 Charles Proxy 拦截 HTTP 流量
mitmproxy -p 8080

# Keychain dump (越狱设备)
# keychain-dumper (需越狱)

# Frida SSL Pinning 绕过测试
frida -U -f com.myapp.bundle -l ssl_pinning_bypass.js --no-pause

# 二进制安全检查
otool -hv MyApp.app/MyApp | grep PIE    # 检查 ASLR
otool -l MyApp.app/MyApp | grep -A2 ENCRYPT  # 检查加密
```

---

## 审计正则速查

```regex
# ATS 禁用: NSAllowsArbitraryLoads\s*(=|:)\s*true|NSExceptionAllowsInsecureHTTPLoads
# Keychain 不安全: kSecAttrAccessibleAlways|kSecAttrAccessibleAlwaysThisDeviceOnly
# WebView JS 注入: evaluateJavaScript\(|WKUserScript\(|WKScriptMessageHandler|javaScriptEnabled\s*=\s*true
# 明文存储: UserDefaults\.(set|standard).*[Pp]assword|UserDefaults.*[Tt]oken|UserDefaults.*[Ss]ecret
# TLS 绕过: ServerTrustPolicy\.disableEvaluation|didReceive.*challenge.*\.useCredential|trustAllCerts
# 日志泄露: NSLog\(.*[Pp]assword|NSLog\(.*[Tt]oken|print\(.*[Pp]assword|print\(.*[Ss]ecret|os_log.*[Tt]oken
# URL Scheme 无验证: func application.*open.*url.*options.*->.*Bool(?!.*guard|.*allowedActions)
# 强制解包: try!|as!(?!\s*Any)|\.first!|\.last!
# 反序列化: NSKeyedUnarchiver\.unarchiveObject|NSCoding|unarchiveTopLevelObjectWithData
# 剪贴板泄露: UIPasteboard\.general\.(string|setItems|setValue)
# 后台截图: applicationDidEnterBackground|sceneDidEnterBackground(?!.*blur|.*cover|.*placeholder)
# 不安全随机: arc4random\b(?!_uniform)|srand\(|rand\(\)(?!.*SecRandom)
# SQL 注入: sqlite3_exec\(.*\\(|"SELECT.*\\(|"INSERT.*\\(|"DELETE.*\\(
# 证书固定缺失: URLAuthenticationChallenge(?!.*pinnedCertificates|.*TrustKit|.*SecTrustEvaluate)
# 文件保护缺失: FileManager\.default\.(createFile|write)(?!.*FileProtection)
# Entitlements 过宽: com\.apple\.security\.app-sandbox.*false
# Cookie 泄露: HTTPCookieStorage\.shared|WKWebsiteDataStore.*httpCookieStore
# 硬编码凭据: (password|secret|api[_-]?key|token)\s*[:=]\s*["'][^"']{8,}["']
```

> 执行方式：对每条正则，Grep 搜索目标目录全部 `.swift` 和 `.plist` 文件。匹配结果逐一分析。零匹配 = 该类型安全。

---

## 参考资源

- [OWASP Mobile Security Testing Guide (MSTG)](https://mas.owasp.org/MASTG/)
- [OWASP Mobile Application Security Verification Standard (MASVS)](https://mas.owasp.org/MASVS/)
- [Apple - Secure Coding Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/)
- [Apple - App Transport Security](https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity)
- [Apple - Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
- [MobSF - Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [Frida - Dynamic Instrumentation](https://frida.re/)
