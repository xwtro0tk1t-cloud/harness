# Flutter Security Audit Guide

> Flutter 跨平台安全审计模块
> 适用于: Flutter 3.x+, Dart 3.x+, Android/iOS 双平台, Platform Channels, WebView 插件, 状态管理

## 核心危险面概述

Flutter 跨平台架构带来独特安全挑战：Platform Channel 是 Dart ↔ Native 的安全边界，WebView 插件引入 JS 交互风险，Deep Link 跨平台路由需要统一验证，本地存储默认明文，网络安全依赖平台配置。共享代码库掩盖了平台差异——同一应用在 Android 上可能因 `network_security_config` 缺失而允许明文流量，在 iOS 上因 ATS 而安全。审计必须同时检查 Dart 层、Android 端 (`android/app/`) 和 iOS 端 (`ios/Runner/`)。

---

## Platform Channel 安全 (CRITICAL)

Platform Channel 是 Dart 与 Native 代码的唯一通信桥梁，也是最关键的安全边界。

### MethodChannel 参数注入 (Dart → Native)

```dart
// ❌ 危险: Dart 端传递未验证的用户输入到 Native 层
class PaymentService {
  static const _channel = MethodChannel('com.app/payment');
  Future<void> processPayment(String userId, double amount) async {
    await _channel.invokeMethod('processPayment', {
      'userId': userId,     // ❌ 可能包含注入 payload
      'amount': amount,     // ❌ 未校验范围 (负数? 溢出?)
    });
  }
}
```

```kotlin
// ❌ 危险: Kotlin 端未验证 Channel 参数
override fun onMethodCall(call: MethodCall, result: Result) {
    val userId = call.argument<String>("userId")!!  // ❌ 强制解包
    val amount = call.argument<Double>("amount")!!
    db.execSQL("UPDATE accounts SET balance = balance - $amount WHERE id = '$userId'") // ❌ SQL拼接
}
```

```swift
// ❌ 危险: Swift 端未验证 Channel 参数
let args = call.arguments as! [String: Any]  // ❌ 强制转换
let userId = args["userId"] as! String        // ❌ 无验证
PaymentManager.shared.charge(user: userId, amount: args["amount"] as! Double) // ❌
```

```dart
// ✓ 安全: Dart 端验证后再传递
Future<void> processPayment(String userId, double amount) async {
  if (!RegExp(r'^[a-zA-Z0-9]{8,32}$').hasMatch(userId)) {
    throw ArgumentError('Invalid userId format');
  }
  if (amount <= 0 || amount > 100000) throw ArgumentError('Amount out of range');
  await _channel.invokeMethod('processPayment', {'userId': userId, 'amount': amount});
}
```

```kotlin
// ✓ 安全: Kotlin 端也做防御性验证 (不信任 Dart 层)
val userId = call.argument<String>("userId")
if (userId == null || !userId.matches(Regex("^[a-zA-Z0-9]{8,32}$"))) {
    result.error("INVALID_INPUT", "Invalid userId", null); return
}
// ✓ 参数化查询
db.execSQL("UPDATE accounts SET balance = balance - ? WHERE id = ?", arrayOf(amount, userId))
```

### EventChannel 数据泄露

```dart
// ❌ 危险: 敏感 token 通过 EventChannel 传递
EventChannel('com.app/userEvents').receiveBroadcastStream().listen((event) {
  final token = event['accessToken'];  // ❌ 敏感数据
  print('Received token: $token');      // ❌ 日志泄露
});

// ✓ 安全: 过滤敏感字段
EventChannel('com.app/userEvents').receiveBroadcastStream().listen((event) {
  final sanitized = Map<String, dynamic>.from(event)
    ..remove('accessToken')..remove('refreshToken');
  _handleEvent(sanitized);
});
```

### 类型安全 (Native → Dart)

```dart
// ❌ 危险: dynamic 类型导致类型混淆
final result = await _channel.invokeMethod('getData');
final isAdmin = result['isAdmin'];  // ❌ dynamic, 可能被注入 true
if (isAdmin == true) showAdminPanel();

// ✓ 安全: 严格类型检查 + 不从 native 获取授权决策
final result = await _channel.invokeMethod<Map>('getData');
if (result == null) throw StateError('Null response');
final balance = result['balance'];
if (balance is! num || balance < 0) throw FormatException('Invalid balance');
final isAdmin = await _authService.checkAdminRole();  // ✓ 服务端校验
```

---

## Deep Link / 路由安全

### URL 参数注入 + 开放重定向

```dart
// ❌ 危险: go_router 未验证参数 + 开放重定向
final router = GoRouter(routes: [
  GoRoute(
    path: '/user/:userId',
    builder: (context, state) {
      final userId = state.pathParameters['userId']!;  // ❌ 未验证
      return UserProfilePage(userId: userId);
    },
  ),
  GoRoute(
    path: '/redirect',
    builder: (context, state) {
      launchUrl(Uri.parse(state.uri.queryParameters['url']!));  // ❌ 开放重定向
      return const SizedBox();
    },
  ),
]);

// ✓ 安全: 参数验证 + 重定向白名单 + 路由守卫
final router = GoRouter(
  redirect: (context, state) {
    if (!authNotifier.isAuthenticated) return '/login';
    if (state.matchedLocation.startsWith('/admin') && !authNotifier.isAdmin) {
      return '/unauthorized';
    }
    return null;
  },
  routes: [
    GoRoute(
      path: '/user/:userId',
      builder: (context, state) {
        final userId = state.pathParameters['userId']!;
        if (!RegExp(r'^[0-9]{1,10}$').hasMatch(userId)) return const NotFoundPage();
        return UserProfilePage(userId: userId);
      },
    ),
    GoRoute(
      path: '/redirect',
      redirect: (context, state) {
        final uri = Uri.tryParse(state.uri.queryParameters['url'] ?? '');
        if (uri == null || !_allowedHosts.contains(uri.host)) return '/home';
        return null;
      },
    ),
  ],
);
```

### Android App Links + iOS Universal Links

```xml
<!-- android/app/src/main/AndroidManifest.xml -->
<!-- ❌ 危险: scheme deep link (任何 app 可注册相同 scheme) -->
<intent-filter>
    <data android:scheme="myapp" />  <!-- ❌ 可被劫持 -->
</intent-filter>

<!-- ✓ 安全: App Links (需域名验证) -->
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="https" android:host="app.example.com" android:pathPrefix="/open" />
</intent-filter>
```

```json
// ios/Runner/Runner.entitlements - ✓ Universal Links
{ "com.apple.developer.associated-domains": ["applinks:app.example.com"] }
```

---

## WebView 安全 (webview_flutter / flutter_inappwebview)

### JavascriptChannel 消息处理

```dart
// ❌ 危险: JS 可伪造任意操作指令 + 暴露 token
JavascriptChannel(
  name: 'NativeBridge',
  onMessageReceived: (message) {
    final data = jsonDecode(message.message);
    if (data['action'] == 'makePayment') {
      _processPayment(data['amount'], data['to']);  // ❌ 无验证
    }
    if (data['action'] == 'getToken') {
      _controller.runJavascript('window.receiveToken("${_authService.accessToken}")'); // ❌
    }
  },
)

// ✓ 安全: 白名单操作 + 不暴露 token
JavascriptChannel(
  name: 'NativeBridge',
  onMessageReceived: (message) {
    final data = jsonDecode(message.message);
    const allowedActions = {'getTheme', 'shareContent', 'logEvent'};
    final action = data['action'] as String?;
    if (action == null || !allowedActions.contains(action)) return;
    _handleSafeAction(action, data);  // ✓ 永远不传递 token/credential
  },
)
```

### navigationDelegate + InAppWebView 高危配置

```dart
// ❌ 危险: 无 URL 过滤 + 过度宽松配置
WebView(initialUrl: 'https://example.com', javascriptMode: JavascriptMode.unrestricted)

InAppWebView(initialSettings: InAppWebViewSettings(
  allowFileAccess: true,                    // ❌ file:// 协议
  allowFileAccessFromFileURLs: true,        // ❌ file:// 读 file://
  allowUniversalAccessFromFileURLs: true,   // ❌ file:// 跨域
  allowContentAccess: true,                 // ❌ content:// 协议
))

// ✓ 安全: URL 白名单 + 最小权限
WebView(
  navigationDelegate: (request) {
    final uri = Uri.parse(request.url);
    if (uri.scheme != 'https' || !_trustedHosts.contains(uri.host)) {
      return NavigationDecision.prevent;
    }
    return NavigationDecision.navigate;
  },
)

InAppWebView(initialSettings: InAppWebViewSettings(
  allowFileAccess: false, allowFileAccessFromFileURLs: false,
  allowUniversalAccessFromFileURLs: false, allowContentAccess: false,
  useShouldOverrideUrlLoading: true,
))
```

---

## 本地存储安全

### SharedPreferences (明文!) vs flutter_secure_storage

```dart
// ❌ 危险: SharedPreferences 明文存储敏感数据
final prefs = await SharedPreferences.getInstance();
await prefs.setString('access_token', token);     // ❌ 明文 token
await prefs.setString('user_password', password);  // ❌ 明文密码
await prefs.setBool('is_admin', true);             // ❌ 客户端授权决策

// ✓ 安全: flutter_secure_storage (Android Keystore / iOS Keychain)
const _secureStorage = FlutterSecureStorage(
  aOptions: AndroidOptions(encryptedSharedPreferences: true),
  iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
);
await _secureStorage.write(key: 'access_token', value: token);  // ✓ 加密存储
await prefs.setBool('dark_mode', true);  // ✓ SharedPreferences 仅用于非敏感偏好
```

### sqflite SQL 注入

```dart
// ❌ 危险: rawQuery 字符串拼接
db.rawQuery("SELECT * FROM users WHERE name LIKE '%$keyword%'");  // ❌ SQL 注入
db.rawInsert("INSERT INTO users (name, email) VALUES ('$name', '$email')"); // ❌

// ✓ 安全: 参数化查询
db.rawQuery("SELECT * FROM users WHERE name LIKE ?", ['%$keyword%']);  // ✓
db.insert('users', {'name': name, 'email': email});  // ✓ ORM 方法
```

### Hive 未加密 + path_provider 目录

```dart
// ❌ 危险: Hive 未加密存储敏感数据
var box = await Hive.openBox('secrets');
box.put('jwt_token', myToken);  // ❌ 明文

// ✓ 安全: 加密 Hive Box
final key = await _secureStorage.read(key: 'hive_key') ??
    base64Encode(Hive.generateSecureKey());
await _secureStorage.write(key: 'hive_key', value: key);
var box = await Hive.openBox('secrets',
  encryptionCipher: HiveAesCipher(base64Decode(key)));  // ✓ AES 加密

// ❌ 危险: 外部存储 (Android 其他应用可读)
final dir = await getExternalStorageDirectory();  // ❌
File('${dir!.path}/user_data.json').writeAsString(jsonEncode(sensitiveData));

// ✓ 安全: 应用内部目录
final dir = await getApplicationDocumentsDirectory();  // ✓ 沙箱内
final supportDir = await getApplicationSupportDirectory();  // ✓ 不被 iTunes 备份
```

---

## 网络安全

### badCertificateCallback + 证书固定

```dart
// ❌ 危险: 禁用 SSL 证书验证
HttpClient()..badCertificateCallback = (cert, host, port) => true;  // ❌ MITM

final dio = Dio();
(dio.httpClientAdapter as IOHttpClientAdapter).createHttpClient = () {
  final client = HttpClient();
  client.badCertificateCallback = (cert, host, port) => true;  // ❌
  return client;
};

// ✓ 安全: 证书固定
(dio.httpClientAdapter as IOHttpClientAdapter).createHttpClient = () {
  final context = SecurityContext();
  context.setTrustedCertificatesBytes(pinnedCertBytes);  // ✓ 固定证书
  return HttpClient(context: context);
};
```

### SSRF 风险

```dart
// ❌ 危险: 用户输入直接构造请求 URL
return dio.get(userUrl);  // ❌ SSRF: http://169.254.169.254/latest/meta-data/

// ✓ 安全: URL 白名单验证
final uri = Uri.tryParse(userUrl);
if (uri == null || uri.scheme != 'https') throw ArgumentError('HTTPS only');
if (!_allowedApiHosts.contains(uri.host)) throw ArgumentError('Host not allowed');
final addr = InternetAddress.tryParse(uri.host);
if (addr != null && (addr.isLoopback || addr.isLinkLocal)) throw ArgumentError('Blocked');
```

### 平台网络安全配置

```xml
<!-- android/app/src/main/res/xml/network_security_config.xml -->
<!-- ❌ --> <base-config cleartextTrafficPermitted="true" />
<!-- ✓ --> <base-config cleartextTrafficPermitted="false">
              <trust-anchors><certificates src="system" /></trust-anchors>
           </base-config>
```

```xml
<!-- ios/Runner/Info.plist -->
<!-- ❌ 全局禁用 ATS -->
<key>NSAppTransportSecurity</key>
<dict><key>NSAllowsArbitraryLoads</key><true/></dict>

<!-- ✓ 仅对特定域名例外 -->
<key>NSAppTransportSecurity</key>
<dict>
  <key>NSAllowsArbitraryLoads</key><false/>
  <key>NSExceptionDomains</key>
  <dict>
    <key>legacy-api.example.com</key>
    <dict>
      <key>NSTemporaryExceptionAllowsInsecureHTTPLoads</key><true/>
      <key>NSTemporaryExceptionMinimumTLSVersion</key><string>TLSv1.2</string>
    </dict>
  </dict>
</dict>
```

---

## 状态管理安全

```dart
// ❌ 危险: 全局暴露 token + toString 泄露
class AuthState extends ChangeNotifier {
  String? accessToken;    // ❌ 内存明文, 可被其他 widget 读取
  String? refreshToken;
  void login(String token, String refresh) {
    accessToken = token; refreshToken = refresh;
    notifyListeners();    // ❌ 通知所有监听者
  }
  @override
  String toString() => 'AuthState(token=$accessToken)';  // ❌ 泄露
}

// ✓ 安全: 最小化暴露, token 存 secure storage
class AuthState extends ChangeNotifier {
  bool _isAuthenticated = false;
  String? _userId;
  bool get isAuthenticated => _isAuthenticated;
  // ✓ 不暴露 token getter

  Future<void> login(String token, String refresh) async {
    await _secureStorage.write(key: 'access_token', value: token);
    _isAuthenticated = true;
    _userId = _extractUserId(token);
    notifyListeners();
  }
  @override
  String toString() => 'AuthState(authenticated=$_isAuthenticated)';  // ✓
}

// ❌ 危险: Bloc 日志泄露
void onTransition(Transition<AuthEvent, AuthState> transition) {
  print('Transition: $transition');  // ❌ toString 含 token
}

// ✓ 安全: 仅 debug 模式 + 不含敏感信息
assert(() { log('Auth transition: ${transition.event.runtimeType}'); return true; }());
```

---

## 代码与构建安全

```bash
# ❌ 危险: release 构建未启用混淆
flutter build apk --release

# ✓ 安全: 混淆 + 分离调试信息
flutter build apk --release --obfuscate --split-debug-info=build/debug-info/
```

```dart
// ❌ 危险: 硬编码 API 密钥
static const apiKey = 'sk_live_abc123def456';  // ❌

// ✓ 安全: 编译时注入 (flutter build apk --dart-define=API_KEY=$API_KEY)
static const apiKey = String.fromEnvironment('API_KEY');

// ✓ release 模式检查
if (kReleaseMode) return;  // 生产环境禁用调试功能
```

```groovy
// android/app/build.gradle
// ❌ minifyEnabled false / shrinkResources false
// ✓ minifyEnabled true + shrinkResources true + proguardFiles
```

---

## 第三方插件安全

```yaml
# ❌ 危险: 废弃插件 + git 依赖 (无版本锁定)
dependencies:
  abandoned_plugin: ^1.0.0                                    # ❌ 2+ 年未更新
  sketchy_plugin:
    git: { url: https://github.com/unknown/sketchy.git }      # ❌ 可被篡改
  local_plugin: { path: ../local_plugin }                     # ❌ 不应出现在生产

# ✓ 安全: 受信任、活跃维护的插件
  flutter_secure_storage: ^9.0.0    # ✓
  dio: ^5.4.0                       # ✓
```

```xml
<!-- 权限审查: 移除插件引入的不必要权限 -->
<uses-permission android:name="android.permission.READ_PHONE_STATE"
    tools:node="remove" />  <!-- ✓ 显式移除 -->
```

---

## 跨平台安全配置检查清单

| 检查项 | Android 端 | iOS 端 | Flutter/Dart 层 |
|--------|-----------|--------|-----------------|
| **网络安全** | `network_security_config` 禁止明文 | ATS 不全局禁用 | `badCertificateCallback` 不返回 `true` |
| **证书固定** | `<pin-set>` | ATS pinning | `SecurityContext` / dio 拦截器 |
| **安全存储** | `EncryptedSharedPreferences` | Keychain | `flutter_secure_storage` |
| **数据库加密** | SQLCipher | SQLCipher | Hive `HiveAesCipher` / sqflite_sqlcipher |
| **备份保护** | `allowBackup="false"` | 排除 Keychain 项 | 敏感数据不存 Documents |
| **调试保护** | `debuggable="false"` | 无 `get-task-allow` | `kReleaseMode` + `--obfuscate` |
| **权限最小化** | `AndroidManifest.xml` | `Info.plist` 权限键 | `pubspec.yaml` 插件权限 |
| **代码混淆** | ProGuard/R8 | Swift 编译优化 | `--obfuscate --split-debug-info` |
| **Deep Link** | `autoVerify="true"` App Links | Universal Links | 路由参数验证 + 守卫 |
| **WebView** | `setAllowFileAccess(false)` | WKWebView 默认安全 | `navigationDelegate` URL 过滤 |
| **日志清理** | 移除 `Log.d/v` | 移除 `NSLog` | 移除 `print()` 敏感内容 |
| **截屏保护** | `FLAG_SECURE` | `UIApplicationDelegate` 遮罩 | `WidgetsBindingObserver` |

---

## 审计正则速查

```regex
# === Platform Channel ===
MethodChannel\s*\(
EventChannel\s*\(
BasicMessageChannel\s*\(
invokeMethod\s*(<|\()
call\.argument<.*>\(                     # Kotlin 端参数获取
call\.arguments\s+as                     # Swift 端参数转换
\.invokeMethod\(.*\$                     # 字符串拼接方法名

# === Deep Link / 路由 ===
GoRoute\s*\(
pathParameters\[|queryParameters\[
state\.uri\.queryParameters
launchUrl\(.*\$|launchUrl\(Uri\.parse\(  # 开放重定向
auto_route|AutoRoute|onGenerateRoute

# === WebView ===
WebView\s*\(|InAppWebView\s*\(
JavascriptChannel\s*\(|addJavaScriptHandler
runJavascript\(|evaluateJavascript\(
javascriptMode:\s*JavascriptMode\.unrestricted
allowFileAccess:\s*true
allowFileAccessFromFileURLs:\s*true
allowUniversalAccessFromFileURLs:\s*true

# === 本地存储 ===
SharedPreferences\.getInstance
\.setString\(.*(?i)(token|password|secret|key|credential|session)
rawQuery\(.*\$|rawQuery\(.*\+           # sqflite SQL 注入
rawInsert\(.*\$|rawInsert\(.*\+
Hive\.openBox\((?!.*encryptionCipher)   # 未加密 Hive
getExternalStorageDirectory

# === 网络安全 ===
badCertificateCallback.*=>\s*true       # 证书验证绕过
cleartextTrafficPermitted.*true         # Android 明文流量
NSAllowsArbitraryLoads.*true            # iOS ATS 禁用
http://(?!localhost|127\.0\.0\.1|10\.)   # 非本地 HTTP

# === 硬编码密钥 ===
(?i)(api[_-]?key|secret[_-]?key|password|token)\s*[:=]\s*['"][^'"]{8,}
sk_live_|pk_live_|sk_test_
AKIA[0-9A-Z]{16}                        # AWS Access Key
-----BEGIN (RSA |EC )?PRIVATE KEY-----

# === 日志泄露 ===
print\(.*(?i)(token|password|secret|key|credential)
debugPrint\(.*(?i)(token|password|secret)
developer\.log\(.*(?i)(token|password)

# === 构建安全 ===
kDebugMode|kReleaseMode
minifyEnabled\s+false
android:debuggable\s*=\s*"true"
android:allowBackup\s*=\s*"true"

# === 状态管理 ===
ChangeNotifier.*(?i)(token|secret|password)
StateNotifier.*(?i)(token|secret|password)
\.state\.(token|secret|password)
```

---

## 快速审计检查清单

```markdown
[ ] 搜索所有 MethodChannel/EventChannel，验证双端参数校验
[ ] 搜索 Deep Link 路由 (GoRoute/AutoRoute)，验证参数白名单
[ ] 检查是否存在开放重定向 (launchUrl + 用户输入)
[ ] 搜索 WebView 配置 (JavascriptChannel, allowFileAccess)
[ ] 检查 navigationDelegate URL 过滤
[ ] 搜索 SharedPreferences 中的敏感数据
[ ] 检查 flutter_secure_storage 使用
[ ] 搜索 sqflite rawQuery/rawInsert 拼接 (SQL 注入)
[ ] 检查 Hive Box 加密
[ ] 搜索 badCertificateCallback => true
[ ] 检查 network_security_config.xml + Info.plist ATS
[ ] 搜索硬编码 API 密钥
[ ] 检查 --obfuscate 和 minifyEnabled
[ ] 搜索 print()/debugPrint() 敏感信息
[ ] 检查 pubspec.yaml 废弃/不受信任插件
[ ] 检查权限最小化 (AndroidManifest + Info.plist)
[ ] 搜索状态管理中暴露的 token/secret
[ ] 检查 android:allowBackup + getExternalStorageDirectory
[ ] 验证 App Links (autoVerify) + Universal Links
```

---

## 最小 PoC / 审计命令

```bash
# Platform Channel 定义
grep -rn "MethodChannel\|EventChannel\|BasicMessageChannel" lib/ android/ ios/

# SharedPreferences 敏感数据
grep -rn "setString.*token\|setString.*password\|setString.*secret" lib/

# SQL 注入风险
grep -rn "rawQuery\|rawInsert\|rawUpdate\|rawDelete" lib/ | grep -v "?"

# WebView 危险配置
grep -rn "allowFileAccess.*true\|JavascriptMode.unrestricted" lib/

# 证书验证绕过
grep -rn "badCertificateCallback" lib/

# 硬编码密钥
grep -rEn "(api_key|secret_key|password|token)\s*[:=]\s*['\"][^'\"]{8,}" lib/

# 日志泄露
grep -rEin "print\(.*token|print\(.*password|debugPrint\(.*secret" lib/

# 平台配置
cat android/app/src/main/res/xml/network_security_config.xml 2>/dev/null
grep -A 5 "NSAppTransportSecurity" ios/Runner/Info.plist

# 反编译检查 (Dart 符号未混淆时)
strings app-release.apk | grep -E "package:|lib/" | head -20
```

---

## 参考资源

- [Flutter Security Best Practices](https://docs.flutter.dev/security)
- [OWASP Mobile Security Testing Guide (MASTG)](https://mas.owasp.org/MASTG/)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [Flutter Platform Channels](https://docs.flutter.dev/platform-integration/platform-channels)
- [flutter_secure_storage](https://pub.dev/packages/flutter_secure_storage)
- [Android Network Security Configuration](https://developer.android.com/privacy-and-security/security-config)
- [iOS App Transport Security](https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity)
- [Dart Code Obfuscation](https://docs.flutter.dev/deployment/obfuscate)
