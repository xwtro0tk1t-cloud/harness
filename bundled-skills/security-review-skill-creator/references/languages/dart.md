# Dart/Flutter Security Audit

> Dart/Flutter 代码安全审计模块 | **双轨并行完整覆盖**
> 适用于: Dart, Flutter, dart:io, dart:ffi, shelf, dio, http, sqflite, go_router, auto_route, webview_flutter, flutter_inappwebview

---

## 审计方法论

### 双轨并行框架

```
                  Dart/Flutter 代码安全审计
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
         ▼                 ▼                 ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  轨道A (50%)    │ │  轨道B (40%)    │ │  补充 (10%)     │
│  控制建模法     │ │  数据流分析法   │ │  配置+依赖审计  │
│                 │ │                 │ │                 │
│ 缺失类漏洞:     │ │ 注入类漏洞:     │ │ • 硬编码凭据    │
│ • 认证缺失      │ │ • SQL注入       │ │ • 不安全配置    │
│ • 授权缺失      │ │ • 命令注入      │ │ • CVE依赖       │
│ • IDOR          │ │ • SSRF          │ │ • 平台配置      │
│ • 明文存储      │ │ • XSS(WebView)  │ │ • 混淆配置      │
│ • 平台通道滥用  │ │ • 路径遍历      │ │                 │
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
# HTTP 路由 (shelf / shelf_router)
grep -rn "router\.\(get\|post\|put\|delete\|patch\)" --include="*.dart"

# go_router / auto_route 路由定义
grep -rn "GoRoute\|@RoutePage\|AutoRoute(" --include="*.dart"

# REST API 调用 (数据修改)
grep -rn "\.post(\|\.put(\|\.delete(\|\.patch(" --include="*.dart"

# Platform Channel 通信
grep -rn "MethodChannel\|EventChannel\|BasicMessageChannel" --include="*.dart"

# 文件操作
grep -rn "File(\|Directory(\|\.writeAsString\|\.readAsString\|\.writeAsBytes" --include="*.dart"

# 数据库操作
grep -rn "rawQuery\|rawInsert\|rawUpdate\|rawDelete\|execute(" --include="*.dart"

# 进程执行
grep -rn "Process\.run\|Process\.start\|Process\.runSync" --include="*.dart"

# 本地存储
grep -rn "SharedPreferences\|FlutterSecureStorage\|Hive\.\|Isar\." --include="*.dart"

# WebView 操作
grep -rn "WebViewController\|InAppWebView\|loadUrl\|runJavaScript" --include="*.dart"

# Deep Link 处理
grep -rn "onGenerateRoute\|uni_links\|go_router\|getInitialLink\|linkStream" --include="*.dart"

# 资金/支付操作
grep -rn "payment\|purchase\|InAppPurchase\|Stripe\|balance" --include="*.dart"
```

### 1.2 输出模板

```markdown
| # | 端点/函数 | 类型 | 敏感类型 | 位置 | 风险等级 |
|---|-----------|------|----------|------|----------|
| 1 | MethodChannel('payment') | Platform Channel | 资金操作 | payment_channel.dart:23 | 严重 |
| 2 | /api/user/delete | HTTP DELETE | 数据修改 | user_service.dart:67 | 高 |
| 3 | WebViewController.loadUrl() | WebView | 页面加载 | web_page.dart:45 | 高 |
```

---

## A2. 安全控制建模

### 2.1 Dart/Flutter 安全控制实现方式

| 控制类型 | Flutter 实现 | Dart Server (shelf) | 通用实现 |
|----------|-------------|---------------------|----------|
| **认证控制** | Firebase Auth, token 拦截器 | shelf middleware | JWT / OAuth |
| **授权控制** | 自定义 Guard, Navigator guard | shelf middleware | RBAC 中间件 |
| **资源所有权** | API 层 userId 比对 | handler 中比对 | `user.id == resource.ownerId` |
| **输入验证** | Form validators, TextFormField | 自定义验证 | 正则 + 白名单 |
| **本地存储保护** | flutter_secure_storage | 加密文件 | Keychain / Keystore |
| **网络安全** | Certificate Pinning | TLS 配置 | SecurityContext |

### 2.2 控制矩阵模板

```yaml
敏感操作: MethodChannel('payment').invokeMethod('charge')
位置: payment_service.dart:34
类型: 资金操作

应有控制:
  认证控制: { 要求: 必须登录, 验证: token 非空且未过期 }
  授权控制: { 要求: 已绑定支付方式 }
  输入验证: { 要求: 金额合法 (>0, 精度限制) }
  平台通道验证: { 要求: native 侧二次验证参数 }
```

### 2.3 验证命令

```bash
# 检查 dio 拦截器 (认证)
grep -rn "interceptors\.\(add\|addAll\)" --include="*.dart"

# 检查路由 Guard
grep -rn "redirect\|canPop\|GoRouterRedirect\|AutoRouteGuard" --include="*.dart"

# 检查 Platform Channel 参数验证
grep -A 20 "setMethodCallHandler" --include="*.dart" | grep "call\.arguments\|call\.method"
```

### 2.4 常见缺失模式 → 漏洞映射

| 缺失控制 | 漏洞类型 | CWE | Dart/Flutter 检测方法 |
|----------|----------|-----|----------------------|
| 无 Auth 拦截器 | 认证缺失 | CWE-306 | 检查 dio interceptors / http headers |
| 无路由 Guard | 授权缺失 | CWE-862 | 检查 go_router redirect / auto_route guard |
| 无 userId 比对 | IDOR | CWE-639 | 检查 API 请求参数 |
| SharedPreferences 明文 | 敏感数据泄露 | CWE-312 | 搜索 SharedPreferences 存储内容 |
| 无 Certificate Pinning | 中间人攻击 | CWE-295 | 检查 SecurityContext / dio adapter |
| Deep Link 无验证 | 注入攻击 | CWE-20 | 检查 onGenerateRoute 参数验证 |

---

# 轨道B: 数据流分析法 (注入类漏洞)

> **核心公式**: Source → [无净化] → Sink = 注入类漏洞

## B1. Dart/Flutter Source (用户可控输入)

```dart
// Deep Link 参数 (go_router)
state.pathParameters['id'];          // Source!
state.uri.queryParameters['q'];      // Source!
// uni_links
getInitialLink();                    // Source! (首次启动 deep link)
linkStream.listen((link) { ... });   // Source! (运行时 deep link)

// Platform Channel 接收
call.arguments;                      // Source! (来自 native)

// HTTP 响应
response.body;                       // Source! (http 包)
response.data;                       // Source! (dio 包)

// WebView JavaScript 通道
message.message;                     // Source! (JavascriptChannel)

// 用户输入
TextEditingController().text;        // Source!

// 剪贴板
Clipboard.getData(Clipboard.kTextPlain);  // Source!

// 文件选取
FilePicker.platform.pickFiles();     // Source! (path + bytes)

// 推送通知 payload
FirebaseMessaging.onMessage → message.data;  // Source!

// QR Code / NFC
BarcodeScanner.scan() → rawContent;  // Source!
NfcManager → tag.data;              // Source!

// 本地存储 (root 设备可修改)
SharedPreferences.getString('key');  // Source!
Hive.openBox('box').get('key');      // Source!
```

## B2. Dart/Flutter Sink (危险操作)

| Sink 类型 | 漏洞 | CWE | 危险函数 |
|-----------|------|-----|----------|
| Platform Channel 调用 | Native 代码注入 | CWE-94 | `MethodChannel.invokeMethod(userMethod, userData)` |
| HTTP 请求 | SSRF | CWE-918 | `http.get(Uri.parse(userUrl))`, `dio.get(userUrl)` |
| WebView 加载 | XSS / 钓鱼 | CWE-79 | `controller.loadRequest(Uri.parse(userUrl))` |
| WebView JS执行 | XSS | CWE-79 | `controller.runJavaScript(userScript)` |
| 文件操作 | 路径遍历 | CWE-22 | `File(userPath).readAsString()`, `File(userPath).writeAsString()` |
| SQL (sqflite) | SQL 注入 | CWE-89 | `db.rawQuery("SELECT * FROM t WHERE id = $id")` |
| 进程执行 | 命令注入 | CWE-78 | `Process.run(userCmd, userArgs)` |
| HTML 渲染 | XSS | CWE-79 | `Html(data: userHtml)` (flutter_html) |
| 动态反射 | 访问控制绕过 | CWE-470 | `dart:mirrors` reflect |
| 日志输出 | 敏感数据泄露 | CWE-532 | `print(password)`, `debugPrint(token)` |
| JSON 反序列化 | 类型混淆 | CWE-502 | `jsonDecode(untrustedInput)` |
| URL Launcher | 钓鱼 / Scheme 滥用 | CWE-601 | `launchUrl(Uri.parse(userUrl))` |
| Dart FFI | 内存安全 | CWE-787 | `Pointer<Uint8>.allocate()`, `ptr.ref` |
| 不安全随机 | 可预测值 | CWE-338 | `Random()` (非 `Random.secure()`) |

## B3. Sink 检测命令

```bash
# Platform Channel 调用
grep -rn "invokeMethod\|invokeMapMethod\|invokeListMethod" --include="*.dart"

# HTTP 请求 (SSRF)
grep -rn "http\.\(get\|post\|put\|delete\|patch\)(\|dio\.\(get\|post\|put\|delete\)(\|Uri\.parse(" --include="*.dart"

# WebView (XSS)
grep -rn "loadRequest\|loadUrl\|loadHtmlString\|runJavaScript\|evaluateJavascript" --include="*.dart"

# 文件操作 (路径遍历)
grep -rn "File(\|Directory(\|\.writeAsString\|\.readAsString\|\.writeAsBytes" --include="*.dart"

# SQL 注入 (sqflite)
grep -rn "rawQuery\|rawInsert\|rawUpdate\|rawDelete\|execute(" --include="*.dart"

# 命令注入
grep -rn "Process\.run\|Process\.start\|Process\.runSync" --include="*.dart"

# Dart FFI
grep -rn "Pointer<\|DynamicLibrary\|allocate(\|ffi\." --include="*.dart"
```

---

## 识别特征

```dart
// Dart/Flutter 项目识别
import 'package:flutter/material.dart';
import 'dart:io';

// 文件结构
├── pubspec.yaml          // 依赖配置
├── lib/
│   ├── main.dart
│   ├── src/
│   │   ├── models/
│   │   ├── services/
│   │   ├── screens/      // (or pages/ or views/)
│   │   ├── widgets/
│   │   └── providers/    // (or blocs/ or controllers/)
├── android/
│   └── app/src/main/AndroidManifest.xml
├── ios/
│   └── Runner/Info.plist
└── test/
```

---

## Dart/Flutter 特定漏洞

### 1. Platform Channel 安全

```dart
// ❌ 危险: 未验证参数，直接操作文件
channel.setMethodCallHandler((call) async {
  final data = call.arguments as String;
  await File(data).readAsString();  // 路径遍历!
});

// ❌ 危险: 用户数据直接传入 native
await channel.invokeMethod('execute', controller.text);  // native 侧可能有注入

// ✓ 安全: 严格验证 method 和参数类型
channel.setMethodCallHandler((call) async {
  switch (call.method) {
    case 'processData':
      final args = call.arguments;
      if (args is! Map<String, dynamic>) throw PlatformException(code: 'INVALID');
      final id = args['id'];
      if (id is! int || id < 0) throw PlatformException(code: 'INVALID_ID');
      return await _repository.getById(id);
    default:
      throw MissingPluginException();
  }
});

// 搜索模式
MethodChannel\(|EventChannel\(|BasicMessageChannel\(
setMethodCallHandler|invokeMethod
```

### 2. SQL 注入 (sqflite)

```dart
// ❌ 危险: 字符串插值 / 拼接
db.rawQuery("SELECT * FROM users WHERE id = $id");  // SQL注入!
db.rawQuery("SELECT * FROM users WHERE name = '" + name + "'");  // SQL注入!
db.execute("UPDATE users SET role = 'admin' WHERE id = ${userId}");  // SQL注入!

// ✓ 安全: 参数化查询
db.rawQuery('SELECT * FROM users WHERE id = ?', [id]);
db.query('users', where: 'id = ?', whereArgs: [id]);
db.insert('users', {'name': name, 'email': email});

// 搜索模式
rawQuery\(|rawInsert\(|rawUpdate\(|rawDelete\(|execute\(.*\$
```

### 3. SSRF (HTTP 请求)

```dart
// ❌ 危险: 用户可控 URL
final response = await http.get(Uri.parse(userUrl));  // SSRF!
final response = await dio.get(controller.text);  // SSRF!
// 本地存储也可被篡改
http.get(Uri.parse('http://${prefs.getString("api_host")}/api'));

// ✓ 安全: 白名单 + 内网地址过滤
const allowedHosts = {'api.example.com', 'cdn.example.com'};
final uri = Uri.parse(userUrl);
if (!allowedHosts.contains(uri.host)) throw ArgumentError('Host not allowed');
final addresses = await InternetAddress.lookup(uri.host);
for (final addr in addresses) {
  if (addr.address.startsWith('10.') || addr.address.startsWith('192.168.') ||
      addr.address.startsWith('127.') || addr.address == '::1') {
    throw ArgumentError('Internal addresses not allowed');
  }
}

// 搜索模式
http\.(get|post|put|delete|patch)\(|dio\.(get|post|put|delete)\(|Uri\.parse\(
```

### 4. WebView XSS

```dart
// ❌ 危险: 加载用户可控 URL / HTML / JS
controller.loadRequest(Uri.parse(userUrl));  // XSS / 钓鱼!
controller.runJavaScript(message.message);  // XSS!
controller.loadHtmlString('<body>${userContent}</body>');  // XSS!

// ❌ 危险: InAppWebView 危险设置
InAppWebView(initialSettings: InAppWebViewSettings(
  allowFileAccessFromFileURLs: true,  // 文件读取!
  allowUniversalAccessFromFileURLs: true,  // 跨域!
))

// ✓ 安全: URL 白名单 + 导航拦截 + 禁用不必要 JS
final controller = WebViewController()
  ..setNavigationDelegate(NavigationDelegate(
    onNavigationRequest: (request) {
      final uri = Uri.parse(request.url);
      if (!allowedDomains.contains(uri.host)) return NavigationDecision.prevent;
      return NavigationDecision.navigate;
    },
  ))
  ..setJavaScriptMode(JavaScriptMode.disabled);

// 搜索模式
WebViewController|InAppWebView|loadUrl\(|loadRequest\(|loadHtmlString\(
runJavaScript\(|evaluateJavascript\(|JavascriptChannel
allowFileAccessFromFileURLs|allowUniversalAccessFromFileURLs
```

### 5. 路径遍历

```dart
// ❌ 危险: 用户文件名直接拼接
File('/data/uploads/$fileName').readAsString();
// fileName = "../../etc/passwd" → 读取系统文件!

// ❌ 危险: path.join 不防路径遍历 (同 Go filepath.Join)
p.join('/uploads', '../../etc/passwd')  // = '/etc/passwd'

// ✓ 安全: 验证规范化路径
String safeJoin(String baseDir, String userPath) {
  final absBase = p.canonicalize(baseDir);
  final target = p.canonicalize(p.join(absBase, userPath));
  if (!target.startsWith(absBase + p.separator)) {
    throw ArgumentError('Path traversal detected');
  }
  return target;
}

// 搜索模式
File\(.*\+|File\(.*\$|Directory\(
```

### 6. 命令注入

```dart
// ❌ 危险: 用户输入作为命令参数 / shell 模式
Process.run('ping', ['-c', '1', userHost]);  // 命令注入!
Process.run('sh', ['-c', userCmd], runInShell: true);  // RCE!

// ✓ 安全: 固定命令 + 白名单 + 不用 runInShell
const allowed = {'google.com', 'example.com'};
if (!allowed.contains(host)) throw ArgumentError('Host not allowed');
Process.run('/usr/bin/ping', ['-c', '1', host]);

// 搜索模式
Process\.(run|start|runSync)\(
runInShell:\s*true
```

### 7. Deep Link 注入

```dart
// ❌ 危险: Deep Link 参数无验证
GoRoute(path: '/product/:id', builder: (ctx, state) {
  db.rawQuery("SELECT * FROM products WHERE id = ${state.pathParameters['id']}");  // SQL注入!
})

// ❌ 危险: URL 参数加载 WebView / 任意导航
final url = state.uri.queryParameters['url'];
WebViewPage(url: url);  // XSS!
Navigator.pushNamed(context, uri.queryParameters['redirect']!);  // 任意导航!

// ✓ 安全: 类型转换 + 白名单
final id = int.tryParse(state.pathParameters['id']!);
if (id == null || id < 0) return ErrorPage();

const allowedRoutes = {'/home', '/profile', '/settings'};
if (allowedRoutes.contains(target)) Navigator.pushNamed(context, target);

// 搜索模式
onGenerateRoute|uni_links|go_router|auto_route
getInitialLink|linkStream|pathParameters|queryParameters
```

### 8. 明文存储 (SharedPreferences)

```dart
// ❌ 危险: SharedPreferences 存储敏感数据 (Android 明文 XML)
prefs.setString('auth_token', jwtToken);  // 明文!
prefs.setString('password', password);  // 明文!

// ❌ 危险: Hive 默认不加密
Hive.openBox('secrets').then((box) => box.put('token', token));  // 明文!

// ✓ 安全: flutter_secure_storage (Android: KeyStore, iOS: Keychain)
final storage = FlutterSecureStorage();
await storage.write(key: 'auth_token', value: jwtToken);

// ✓ 安全: Hive 加密
Hive.openBox('secrets', encryptionCipher: HiveAesCipher(key));

// 搜索模式
SharedPreferences|\.setString\(.*token|\.setString\(.*password
Hive\.openBox\((?!.*encryptionCipher)
```

### 9. 不安全 TLS 配置

```dart
// ❌ 危险: 接受所有证书
client.badCertificateCallback = (cert, host, port) => true;  // 中间人攻击!

// ❌ 危险: dio 禁用验证
(dio.httpClientAdapter as IOHttpClientAdapter).createHttpClient = () {
  final client = HttpClient();
  client.badCertificateCallback = (cert, host, port) => true;  // 危险!
  return client;
};

// ✓ 安全: Certificate Pinning
client.badCertificateCallback = (cert, host, port) {
  return sha256.convert(cert.der).toString() == expectedFingerprint;
};

// ✓ 安全: SecurityContext 指定信任证书
final context = SecurityContext()..setTrustedCertificatesBytes(certBytes);
final client = HttpClient(context: context);

// 搜索模式
badCertificateCallback.*true|SecurityContext.*allowLegacy
```

### 10. 不安全随机数

```dart
// ❌ 危险: Random() 用于安全场景
final token = List.generate(32, (_) => Random().nextInt(256));  // 可预测!
final r = Random(DateTime.now().millisecondsSinceEpoch);  // 种子可猜测!

// ✓ 安全: Random.secure()
final token = List.generate(32, (_) => Random.secure().nextInt(256));

// 搜索模式
Random\(\)|Random\((?!\.secure)
```

### 11. Dart FFI 内存安全

```dart
// ❌ 危险: 未释放 / 越界 / Use-After-Free
final ptr = calloc<Uint8>(1024);
// 忘记 calloc.free(ptr) → 内存泄漏!
ptr[2000] = 0xFF;  // 越界写入!
calloc.free(ptr); ptr[0] = 0xFF;  // UAF!

// ❌ 危险: 用户输入决定分配大小
calloc<Uint8>(int.parse(userInput));  // 可能为负或极大!

// ✓ 安全: 边界检查 + try/finally 确保释放
if (size <= 0 || size > maxAllowedSize) throw ArgumentError('Invalid size');
final ptr = calloc<Uint8>(size);
try {
  for (var i = 0; i < size; i++) ptr[i] = data[i];
} finally {
  calloc.free(ptr);
}

// 搜索模式
Pointer<|ffi\.|allocate\(|DynamicLibrary|calloc<|malloc<
```

### 12. null safety 绕过

```dart
// ❌ 危险: 滥用 ! 操作符 → 运行时崩溃
final user = await getUser(id);  // User?
print(user!.name);  // null → crash!

// ❌ 危险: late 未初始化
late final String token;  // 条件赋值可能不执行 → LateInitializationError!

// ❌ 危险: as 强制转换不可信数据
final name = jsonDecode(input)['name'] as String;  // TypeError!

// ✓ 安全: 防御性检查 + is 类型提升
if (user == null) return ErrorPage();
final name = data['name'];
if (name is! String) throw FormatException('Invalid');

// 搜索模式
\w+!\.|as\s+\w+[^?]|late\s+(final\s+)?(?!override)\w+
```

### 13. Isolate 通信安全

```dart
// ❌ 危险: Isolate 返回数据未验证后直接用于 SQL
receivePort.listen((msg) {
  db.rawQuery("SELECT * FROM t WHERE data = '$msg'");  // SQL注入!
});

// ✓ 安全: 验证类型 + 参数化查询
receivePort.listen((msg) {
  if (msg is! Map<String, dynamic>) return;
  final id = msg['id'];
  if (id is! int || id < 0) return;
  db.query('table', where: 'id = ?', whereArgs: [id]);
});

// 搜索模式
SendPort|ReceivePort|Isolate\.spawn|Isolate\.run
```

### 14. 日志泄露

```dart
// ❌ 危险: 打印敏感数据
print('User token: $token');
debugPrint('Password: $password');
// dio LogInterceptor 记录请求/响应体
dio.interceptors.add(LogInterceptor(requestBody: true, responseBody: true));

// ✓ 安全: 仅 debug 模式 + 脱敏
if (kDebugMode) print('Debug: $data');
// 生产环境不添加 LogInterceptor

// 搜索模式
print\(.*password|print\(.*token|debugPrint\(.*secret
LogInterceptor\(.*requestBody:\s*true
```

### 15. JSON 反序列化安全

```dart
// ❌ 危险: 未验证结构 + 信任客户端权限字段
final data = jsonDecode(input) as Map<String, dynamic>;
final isAdmin = data['isAdmin'] as bool;  // 用户可注入 isAdmin: true!
final count = data['count'] as int;  // 类型不匹配则崩溃

// ✓ 安全: 严格类型检查 + json_serializable
if (data is! Map<String, dynamic>) throw FormatException('Expected object');
final amount = data['amount'];
if (amount is! num || amount <= 0) throw FormatException('Invalid');

// ✓ 安全: 生成类型安全的解析 (不含权限字段)
@JsonSerializable()
class UserRequest {
  final String name;
  final String email;
  factory UserRequest.fromJson(Map<String, dynamic> json) => _$UserRequestFromJson(json);
}

// 搜索模式
jsonDecode\(|json\.decode\(|as\s+(Map|List|String|int|double|bool)
```

### 16. 插件安全审计

```dart
// ❌ 危险信号: git 依赖无版本锁定 / any 约束 / 过度权限
dependencies:
  suspicious_plugin:
    git: { url: https://github.com/unknown/plugin.git }  // 无版本锁定!

// ✓ 检查清单
// 1. pub.dev verified publisher 标记
// 2. 锁定版本号 (不用 any/git)
// 3. 审查 AndroidManifest.xml 和 Info.plist 权限变化
// 4. flutter pub outdated 检查更新

// 搜索模式
grep -rn "git:\|any$" pubspec.yaml
```

### 17. 代码混淆配置

```bash
# ❌ 危险: Release 未开启混淆 (攻击者可反编译)
flutter build apk

# ✓ 安全: 混淆 + 调试信息分离
flutter build apk --obfuscate --split-debug-info=build/debug-info
flutter build ipa --obfuscate --split-debug-info=build/debug-info

# 搜索模式
grep -rn "obfuscate\|split-debug-info" Makefile .github/ .gitlab-ci.yml
```

### 18. 平台网络安全配置

```xml
<!-- ❌ Android: 允许明文流量 -->
<application android:usesCleartextTraffic="true">

<!-- ✓ Android: 禁止明文 + Network Security Config -->
<application android:usesCleartextTraffic="false"
    android:networkSecurityConfig="@xml/network_security_config">

<!-- ❌ iOS: ATS 完全禁用 -->
<key>NSAllowsArbitraryLoads</key><true/>

<!-- ✓ iOS: 仅允许必要例外 -->
<key>NSAllowsArbitraryLoads</key><false/>
<key>NSExceptionDomains</key>
<dict><key>legacy-api.example.com</key><dict>
  <key>NSExceptionMinimumTLSVersion</key><string>TLSv1.2</string>
</dict></dict>
```

```bash
grep -rn "usesCleartextTraffic\|NSAllowsArbitraryLoads" android/ ios/
```

### 19. 硬编码凭据

```dart
// ❌ 危险: 代码/assets 中硬编码
const apiKey = 'sk-1234567890abcdef';
const dbPassword = 'SuperSecret123!';
// assets/config.json 含 API keys → 编译进 APK 可提取

// ✓ 安全: 编译时注入 / 服务器获取
final apiKey = const String.fromEnvironment('API_KEY');
// flutter build apk --dart-define=API_KEY=sk-xxx

// 搜索模式
(password|secret|api[_-]?key|token|credential)\s*[:=]\s*['"][^'"]{8,}['"]
(AIzaSy|sk-|pk_live|sk_live|ghp_|gho_)\w+
```

### 20. URL Launcher 滥用

```dart
// ❌ 危险: 用户可控 URL 直接启动
launchUrl(Uri.parse(userUrl));
// userUrl = "tel:+123" → 自动拨号; "sms:+123?body=x" → 发送短信

// ✓ 安全: scheme + host 白名单
final uri = Uri.parse(userUrl);
if (uri.scheme != 'https') throw ArgumentError('Only HTTPS');
if (!allowedHosts.contains(uri.host)) throw ArgumentError('Domain not allowed');
await launchUrl(uri, mode: LaunchMode.externalApplication);

// 搜索模式
launchUrl\(|launch\(|canLaunchUrl
```

---

## Dart/Flutter 审计清单

```
Platform Channel (CWE-94):
- [ ] 搜索 MethodChannel / EventChannel / BasicMessageChannel
- [ ] 检查 setMethodCallHandler 参数验证
- [ ] 审计对应的 Android/iOS native 代码

SQL 注入 (CWE-89):
- [ ] 搜索 rawQuery / rawInsert / rawUpdate / rawDelete / execute
- [ ] 验证使用参数化查询 (whereArgs)

SSRF (CWE-918):
- [ ] 搜索 http.get / dio.get / Uri.parse
- [ ] 验证 host 白名单 + 内网地址过滤

WebView XSS (CWE-79):
- [ ] 搜索 WebViewController / InAppWebView
- [ ] 检查 loadUrl / loadHtmlString / runJavaScript 数据来源
- [ ] 检查 allowFileAccessFromFileURLs 设置

路径遍历 (CWE-22):
- [ ] 搜索 File() / Directory() 中用户输入
- [ ] 验证路径规范化检查

命令注入 (CWE-78):
- [ ] 搜索 Process.run / Process.start
- [ ] 检查 runInShell: true

Deep Link (CWE-20):
- [ ] 搜索 go_router / auto_route / uni_links
- [ ] 检查 URL 参数验证 + redirect 白名单

明文存储 (CWE-312):
- [ ] 搜索 SharedPreferences 存储敏感数据
- [ ] 验证使用 flutter_secure_storage

TLS 配置 (CWE-295):
- [ ] 搜索 badCertificateCallback
- [ ] 检查 usesCleartextTraffic / NSAllowsArbitraryLoads

弱随机 (CWE-338):
- [ ] 搜索 Random() (非 Random.secure())

Dart FFI (CWE-787):
- [ ] 搜索 Pointer< / DynamicLibrary / allocate
- [ ] 检查内存分配释放配对 + 边界检查

日志泄露 (CWE-532):
- [ ] 搜索 print / debugPrint / log 含敏感数据
- [ ] 检查 LogInterceptor 配置

硬编码凭据 (CWE-798):
- [ ] 搜索硬编码 API key / password / token / secret

代码保护:
- [ ] 检查 --obfuscate / --split-debug-info
```

---

## 审计正则

```regex
# Platform Channel
MethodChannel\(|EventChannel\(|BasicMessageChannel\(
setMethodCallHandler|invokeMethod|invokeMapMethod

# SQL 注入 (sqflite)
rawQuery\(|rawInsert\(|rawUpdate\(|rawDelete\(|execute\(.*\$

# HTTP 请求 (SSRF)
http\.(get|post|put|delete|patch)\(|dio\.(get|post|put|delete)\(|Uri\.parse\(

# WebView (XSS)
WebViewController|InAppWebView|loadUrl\(|loadRequest\(|loadHtmlString\(
runJavaScript\(|evaluateJavascript\(|JavascriptChannel
allowFileAccessFromFileURLs|allowUniversalAccessFromFileURLs

# 文件操作 (路径遍历)
File\(.*\+|File\(.*\$|Directory\(
\.readAsString\(|\.writeAsString\(|\.readAsBytes\(|\.writeAsBytes\(

# 进程执行 (命令注入)
Process\.(run|start|runSync)\(
runInShell:\s*true

# 明文存储
SharedPreferences|getSharedPreferences
\.setString\(.*token|\.setString\(.*password|\.setString\(.*key
Hive\.openBox\((?!.*encryptionCipher)

# 硬编码凭据
(password|secret|api[_-]?key|token|credential)\s*[:=]\s*['"][^'"]{8,}['"]
(AIzaSy|sk-|pk_live|sk_live|ghp_|gho_)\w+

# 不安全随机
Random\(\)|Random\((?!\.secure)

# 日志泄露
print\(.*password|print\(.*token|debugPrint\(.*secret
LogInterceptor\(.*requestBody:\s*true

# Dart FFI
Pointer<|ffi\.|allocate\(|DynamicLibrary
calloc<|malloc<|\.ref\b

# Deep Link
onGenerateRoute|uni_links|go_router|auto_route
getInitialLink|linkStream|pathParameters|queryParameters

# 剪贴板
Clipboard\.(getData|setData)

# 不安全 TLS
badCertificateCallback.*true|SecurityContext.*allowLegacy
usesCleartextTraffic.*true|NSAllowsArbitraryLoads.*true

# null safety 滥用
\w+!\.\w+|late\s+(final\s+)?\w+\s+\w+;

# URL Launcher
launchUrl\(|launch\(|canLaunchUrl

# 反射 (dart:mirrors)
import\s+['"]dart:mirrors['"]|reflect\(|MirrorSystem

# Isolate 通信
SendPort|ReceivePort|Isolate\.spawn|Isolate\.run
```
