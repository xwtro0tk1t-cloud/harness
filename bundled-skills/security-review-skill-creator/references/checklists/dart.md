# Dart/Flutter 安全审计语义提示 (Semantic Hints)

> 本文件为覆盖率矩阵 (`coverage_matrix.md`) 的补充。
> **仅对未覆盖的维度按需加载对应 `## D{N}` 段落**，无需全量加载。
> LLM 自行决定搜索策略（Grep/Read/LSP/代码推理均可）。

## D1: 注入

**关键问题**:
1. SQL (sqflite): 是否使用 `rawQuery()` / `rawInsert()` 拼接用户输入？（安全: `query()` + `whereArgs` / 危险: `"SELECT * FROM t WHERE id = $id"`）
2. WebView: `runJavaScript(userInput)` 或 `loadUrl(userUrl)` 是否存在？
3. Platform Channel: `invokeMethod` 的参数是否来自不受信任的来源？
4. Process: `Process.run('sh', ['-c', userInput])` 命令注入？
5. HTML 渲染: `flutter_html` 或 `flutter_widget_from_html` 是否渲染用户 HTML？

**易漏场景**:
- `db.rawQuery("SELECT * FROM users WHERE name = '$name'")` 在 Repository 层
- `webViewController.runJavaScript("setData('$userData')")` JS 注入
- `Process.run('grep', ['-r', userInput, '/data'])` 命令参数注入

**判定规则**:
- `rawQuery` + 字符串拼接/插值 = **Critical (SQL 注入)**
- sqflite `query()` + `whereArgs: [param]` = **安全**
- `runJavaScript(userInput)` = **High (XSS)**
- `Process.run` + 用户输入参数 = **Critical (命令注入)**

## D2: 认证

**关键问题**:
1. 生物认证: `local_auth` 的 `authenticate()` 返回值是否可被绕过？是否仅用于 UI 解锁而非真正的密钥保护？
2. Token 存储: `flutter_secure_storage` (KeyStore/Keychain) 还是 `SharedPreferences` (明文)？
3. 自动登录: token 过期处理？refresh token 存储位置？
4. Firebase Auth: `currentUser` 是否及时刷新？token 验证是否在服务端？
5. 证书固定: dio/http 是否配置 certificate pinning？

**易漏场景**:
- `SharedPreferences.setString('token', jwt)` 明文存储
- `local_auth` 返回 true 后直接导航，不绑定加密密钥
- 仅前端检查 `FirebaseAuth.currentUser != null`，不验证 token 有效性

**判定规则**:
- SharedPreferences 存储 token = **High (不安全存储)**
- `local_auth` 无 CryptoObject 绑定 = **Medium (生物认证可绕过)**
- 仅前端 auth check 无后端验证 = **High**
- `flutter_secure_storage` + 正确配置 = **安全**

## D3: 授权 / 路由

**关键问题**:
1. 路由守卫: go_router `redirect` / auto_route `AutoRouteGuard` 是否保护敏感页面？
2. Deep Link: URL 参数是否验证？`myapp://transfer?to=xxx&amount=999` 是否可触发敏感操作？
3. Platform Channel: native 侧方法调用是否验证 Dart 端传来的权限/角色？
4. API 授权: 请求头是否正确携带 auth token？401 处理？

**易漏场景**:
- go_router 无 `redirect` 保护的 `/admin` 路由
- Deep link `myapp://pay?amount=$amount` 无二次确认
- Navigator.pushNamed('/settings') 无 auth check

**判定规则**:
- 敏感路由无 guard/redirect = **High (未授权访问)**
- Deep link 触发支付/删除无确认 = **Critical**
- Platform Channel 无 native 层权限验证 = **Medium**

## D4: 数据存储

**关键问题**:
1. SharedPreferences: 敏感数据（token, 密码, PII）是否明文？
2. sqflite / Hive / Isar: 数据库是否加密？（sqflite_sqlcipher, Hive encryptionCipher）
3. 文件存储: `getApplicationDocumentsDirectory` (私有) vs `getExternalStorageDirectory` (Android 公开)
4. 日志: `print()` / `debugPrint()` / `log()` 是否打印敏感信息？（release 模式仍可通过 logcat 看到 print）
5. 剪贴板: `Clipboard.setData(ClipboardData(text: password))` 泄露风险

**易漏场景**:
- `SharedPreferences.setString('user_data', jsonEncode(userProfile))` 含 PII
- `print('Auth token: $token')` 在 release build 泄露
- `File('${(await getExternalStorageDirectory())!.path}/cache.json')` Android 外部存储

**判定规则**:
- SharedPreferences 存储敏感数据 = **High**
- 外部存储写入用户数据 = **High**
- print/debugPrint 输出 token = **Medium (release 可读)**
- flutter_secure_storage + 加密 DB = **安全**

## D5: WebView 安全

**关键问题**:
1. JS 通道: `JavascriptChannel` handler 是否验证消息内容？是否返回敏感数据？
2. URL 加载: `loadUrl(userUrl)` 是否验证 scheme/domain 白名单？
3. Navigation: `navigationDelegate` 是否过滤导航请求？
4. Cookie: WebView 是否共享 app session cookie？
5. JS 执行: `runJavaScript(userScript)` 是否使用用户输入？

**易漏场景**:
- `JavascriptChannel(name: 'Auth', onMessageReceived: (msg) { ... })` 返回 token
- `webViewController.loadRequest(Uri.parse(deepLinkUrl))` 加载外部 URL
- 无 `navigationDelegate` → WebView 可导航到任意 URL

**判定规则**:
- JavascriptChannel 返回 token/session = **Critical**
- loadUrl 无 URL 白名单 = **Medium**
- runJavaScript + 用户输入 = **High (XSS)**

## D6: 网络安全

**关键问题**:
1. TLS: `HttpClient.badCertificateCallback` 是否返回 true？（信任所有证书）
2. 明文流量: Android `network_security_config` / iOS `ATS` 是否允许 cleartext？
3. 证书固定: dio / http_client 是否配置 pin？
4. SSRF: `Uri.parse(userInput)` 用于 HTTP 请求？
5. 请求日志: dio `LogInterceptor` 是否在 release 打印 body？

**易漏场景**:
- `httpClient.badCertificateCallback = (cert, host, port) => true` 信任所有
- dio `LogInterceptor(requestBody: true, responseBody: true)` release 可见
- `http.get(Uri.parse(userProvidedUrl))` SSRF

**判定规则**:
- `badCertificateCallback => true` = **Critical (MitM)**
- 全局允许明文流量 = **High**
- URL 用户可控 + 无白名单 = **High (SSRF)**

## D7: 加密

**关键问题**:
1. 密钥硬编码: 加密密钥是否在 Dart 源码中？（反编译可提取）
2. 弱随机: `Random()` vs `Random.secure()` 用于安全场景？
3. 弱算法: MD5/SHA1 用于密码？
4. flutter_secure_storage: 底层是否正确使用 AndroidKeyStore / iOS Keychain？

**判定规则**:
- Dart 源码硬编码密钥 = **High（Dart 可反编译）**
- `Random()` (非 secure) 用于 token/nonce = **High**
- MD5 密码哈希 = **High**
- `Random.secure()` + flutter_secure_storage = **安全**

## D8: Platform Channel

**关键问题**:
1. 类型安全: Dart `dynamic` 传给 native，native 是否校验类型？
2. 参数验证: native 端 `MethodCallHandler` 是否验证参数范围和格式？
3. 返回值: native 返回的敏感数据（token, 密钥）是否在 Dart 侧暴露给不受信任代码？
4. 错误处理: native 异常是否泄露堆栈/路径到 Dart 侧？

**判定规则**:
- native 端无参数验证 + 执行敏感操作 = **High**
- Platform Channel 传递未验证数据到文件/SQL/命令 = **Critical (二次注入)**
- native 异常堆栈泄露到前端 = **Low (信息泄露)**

## D9: 第三方依赖

**关键问题**:
1. pubspec.yaml: 依赖是否有已知 CVE？（`dart pub outdated`）
2. 插件 native 代码: 第三方插件的 Android/iOS 原生代码是否安全？
3. 废弃插件: 是否使用不再维护的插件？
4. 权限: 第三方插件是否在 AndroidManifest / Info.plist 声明多余权限？

**判定规则**:
- 已知 CVE 且可利用 = **按 CVE 等级**
- 废弃插件 + 无替代 = **Medium**
- 插件请求多余权限 = **Low**

## D10: 构建与配置

**关键问题**:
1. 混淆: release build 是否使用 `--obfuscate --split-debug-info`？
2. Debug 模式: `kDebugMode` / `kReleaseMode` 检查是否正确？
3. Source map: `--split-debug-info` 输出的 symbols 文件是否泄露？
4. Android 配置: `debuggable`, `allowBackup`, ProGuard/R8
5. iOS 配置: ATS, entitlements, minimum deployment target

**判定规则**:
- release 无 `--obfuscate` = **Medium (易逆向)**
- debug 代码在 release 执行 = **Medium**
- symbols 文件公开 = **High (完整逆向)**
- `debuggable=true` 在 release = **Critical**
