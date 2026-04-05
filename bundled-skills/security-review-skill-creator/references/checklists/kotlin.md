# Kotlin/Android 安全审计语义提示 (Semantic Hints)

> 本文件为覆盖率矩阵 (`coverage_matrix.md`) 的补充。
> **仅对未覆盖的维度按需加载对应 `## D{N}` 段落**，无需全量加载。
> LLM 自行决定搜索策略（Grep/Read/LSP/代码推理均可）。

## D1: 注入

**关键问题**:
1. SQL: 是否使用 `rawQuery()` / `execSQL()` 拼接用户输入？（安全: Room DAO `@Query("SELECT * FROM t WHERE id = :id")` / 危险: `"SELECT * FROM t WHERE id = $id"`）
2. Room: `@RawQuery` 是否接受动态构建的 `SupportSQLiteQuery`？
3. ContentProvider: `query()` 的 `selection` / `projection` 参数是否直接转发用户输入？
4. WebView: `loadUrl("javascript:" + userInput)` 或 `evaluateJavascript(userInput)` 是否存在？
5. Intent URI: `Intent.parseUri()` / `Uri.parse()` 是否解析不受信任的 URI？
6. Log 注入: `Log.d(TAG, userInput)` 是否可能泄露敏感数据或注入恶意日志行？

**易漏场景**:
- `db.rawQuery("SELECT * FROM users WHERE name = '$name'", null)` 在 DAO 层
- `contentResolver.query(uri, projection, "user_id = $id", null, null)` selection 拼接
- `webView.loadUrl("javascript:handleData('$userInput')")` JS 注入
- `@RawQuery fun custom(query: SupportSQLiteQuery)` 暴露原始查询

**判定规则**:
- `rawQuery` / `execSQL` + 字符串拼接/模板 + 用户输入 = **Critical (SQL 注入)**
- Room `@Query` 使用 `:param` 参数 = **安全**
- ContentProvider `selection` 拼接 + 外部调用 = **High**
- `evaluateJavascript(userInput)` = **High (XSS)**

## D2: 认证

**关键问题**:
1. BiometricPrompt: `setNegativeBtnText` 是否绕过生物认证？认证回调是否真正保护敏感操作？
2. Token 存储: 访问令牌是否存储在 SharedPreferences（明文）还是 EncryptedSharedPreferences / AndroidKeyStore？
3. 自动登录: token 过期策略？refresh token 泄露后的影响？
4. WebView 登录: 是否通过 WebView 执行 OAuth，JS Bridge 是否泄露 token？
5. 证书固定: OkHttp `CertificatePinner` 是否正确配置？是否可被用户安装的 CA 证书绕过？

**易漏场景**:
- BiometricPrompt 回调中仅检查 `result != null`，不验证 CryptoObject
- Token 存储在 `getSharedPreferences("auth", MODE_PRIVATE)` 中，root 可读
- WebView OAuth flow 通过 `@JavascriptInterface` 暴露 token 给页面 JS

**判定规则**:
- 明文 SharedPreferences 存储 token/密码 = **High (不安全存储)**
- BiometricPrompt 无 CryptoObject 绑定 = **Medium (生物认证可绕过)**
- 证书固定缺失 + 处理敏感数据 = **Medium**
- OkHttp `CertificatePinner` 正确配置 = **安全**

## D3: 授权 / 组件导出

**关键问题**:
1. 组件导出: `AndroidManifest.xml` 中 Activity/Service/Receiver/Provider 是否合理设置 `exported`？
2. Intent 权限: 导出组件是否通过 `android:permission` 保护？
3. ContentProvider 权限: `readPermission` / `writePermission` / `path-permission` 是否配置？
4. PendingIntent: 是否使用 `FLAG_IMMUTABLE`？implicit Intent + `FLAG_MUTABLE` = 劫持风险
5. 深层组件: 非导出组件是否可通过导出组件间接访问（Intent 重定向）？

**易漏场景**:
- `<activity android:name=".DeepLinkActivity">` 有 `<intent-filter>` 但缺少 exported 声明（API < 31 默认 true）
- `PendingIntent.getActivity(ctx, 0, Intent(), FLAG_MUTABLE)` implicit + mutable
- 导出 Activity 接收 Intent extra 中的 `Intent` 对象并 `startActivity(it)` → 重定向攻击
- ContentProvider `android:exported="true"` 无 permission 保护

**判定规则**:
- 导出组件 + 无 permission + 处理敏感操作 = **High (未授权访问)**
- Intent 重定向（exported → intent extra → startActivity）= **Critical**
- PendingIntent FLAG_MUTABLE + implicit Intent = **High (PendingIntent 劫持)**
- ContentProvider exported + 无 permission + 含敏感数据 = **Critical**

## D4: 数据存储

**关键问题**:
1. SharedPreferences: 敏感数据（token, 密码, PII）是否明文存储？
2. SQLite / Room: 数据库是否加密（SQLCipher）？敏感列是否加密？
3. External Storage: 是否在 `/sdcard/` 写入敏感数据？（任何 app 可读）
4. 日志: `Log.d()` / `Log.i()` 是否打印敏感信息？（Android 4.0+ logcat 需同 UID，但 root 可读）
5. Clipboard: 敏感数据是否复制到剪贴板？（其他 app 可读取）
6. Backup: `android:allowBackup="true"` 是否暴露敏感数据？

**易漏场景**:
- `prefs.edit().putString("jwt_token", token).apply()` 明文存储
- `Log.d("Auth", "Token: $accessToken")` 泄露到 logcat
- `File(Environment.getExternalStorageDirectory(), "cache.json").writeText(userData)` 外部存储
- `clipboardManager.setPrimaryClip(ClipData.newPlainText("password", pwd))` 剪贴板泄露

**判定规则**:
- 明文 SharedPreferences 存储敏感数据 = **High**
- External storage 存储用户数据 = **High**
- Log 输出 token/password = **Medium (信息泄露)**
- `android:allowBackup="true"` + 明文数据 = **Medium**
- EncryptedSharedPreferences + AndroidKeyStore = **安全**

## D5: WebView 安全

**关键问题**:
1. JavaScript: `setJavaScriptEnabled(true)` 后是否加载不受信任的 URL？
2. JS Bridge: `addJavascriptInterface` 暴露了哪些方法？`@JavascriptInterface` 标注的方法是否返回敏感数据？
3. File Access: `setAllowFileAccessFromFileURLs(true)` 是否开启？（SOP 绕过）
4. URL 验证: `shouldOverrideUrlLoading` 是否验证 URL scheme 和域名？
5. SSL 错误: `onReceivedSslError` 是否直接 `handler.proceed()`？（中间人攻击）
6. Cookie: WebView cookie 是否包含 session token？是否设置 HttpOnly/Secure？

**易漏场景**:
- `@JavascriptInterface fun getToken(): String = prefs.getString("token", "")!!` 暴露 token
- `onReceivedSslError` → `handler.proceed()` 忽略证书错误
- `webView.loadUrl(intent.getStringExtra("url")!!)` 加载外部 URL
- `setAllowFileAccessFromFileURLs(true)` + `loadUrl("file:///...")` 读取本地文件

**判定规则**:
- JS enabled + `addJavascriptInterface` + 加载外部 URL = **Critical (JS Bridge 劫持)**
- `@JavascriptInterface` 返回 token/session = **Critical (凭据泄露)**
- `onReceivedSslError` → `proceed()` = **High (MitM)**
- `setAllowFileAccessFromFileURLs(true)` = **High (SOP 绕过)**
- JS disabled 或仅加载 app 内置 HTML = **安全**

## D6: 网络安全

**关键问题**:
1. 明文流量: `android:usesCleartextTraffic="true"` 或 `network_security_config.xml` 允许 cleartext？
2. TLS: 自定义 `TrustManager` 是否接受所有证书？`HostnameVerifier` 是否为 `ALLOW_ALL`？
3. 证书固定: 是否使用 OkHttp `CertificatePinner` 或 `network_security_config.xml` pin？
4. 请求拦截: OkHttp `Interceptor` 是否在日志中打印请求/响应 body（含敏感数据）？
5. SSRF: 用户输入是否直接用于 URL 构造？

**易漏场景**:
- `<base-config cleartextTrafficPermitted="true"/>` 在 network_security_config
- 自定义 `X509TrustManager.checkServerTrusted` 为空实现
- `HttpLoggingInterceptor(Level.BODY)` 在 release build 打印完整请求
- `OkHttpClient().newCall(Request.Builder().url(userInput).build())` SSRF

**判定规则**:
- 全局允许明文流量 + 传输敏感数据 = **High**
- 空 TrustManager / ALLOW_ALL HostnameVerifier = **Critical (MitM)**
- 生产 build 含 BODY 级别日志 = **Medium (信息泄露)**
- URL 用户可控 + 无白名单 = **High (SSRF)**

## D7: 加密

**关键问题**:
1. 密钥硬编码: 加密密钥是否写死在代码中？应使用 AndroidKeyStore。
2. 弱算法: MD5/SHA1 是否用于密码或签名？ECB 模式？
3. 弱随机: `java.util.Random` 是否用于安全场景？（应用 `SecureRandom`）
4. IV 复用: AES-CBC/GCM 的 IV 是否固定或可预测？
5. AndroidKeyStore: `setUserAuthenticationRequired` 是否合理设置？

**判定规则**:
- 硬编码密钥 = **High**
- MD5/SHA1 用于密码哈希 = **High**
- `java.util.Random` 用于 token/nonce = **High**
- ECB 模式 = **Medium**
- AndroidKeyStore + 正确参数 = **安全**

## D8: IPC / Intent 安全

**关键问题**:
1. Intent 数据验证: 从 Intent extra 提取的数据是否验证类型和范围？
2. 隐式广播: `sendBroadcast(intent)` 是否应改为 `LocalBroadcastManager` 或 explicit broadcast？
3. Service 绑定: `bindService` 是否验证调用者 UID/包名？
4. deep link: `intent.data` URI 的 host/path/query 是否验证？
5. 文件共享: `FileProvider` 路径配置是否过宽？

**判定规则**:
- 隐式广播含敏感数据 = **High (广播窃听)**
- 未验证的 Intent extra 直接用于敏感操作 = **High**
- deep link URI 无验证 = **Medium (URL 注入)**
- FileProvider paths 包含根目录 = **Critical (任意文件访问)**

## D9: 第三方依赖

**关键问题**:
1. Gradle 依赖: 是否有已知 CVE 的库版本？（使用 dependency-check-gradle）
2. SDK: 第三方 SDK 是否请求过多权限？是否有已知后门？
3. ProGuard/R8: 混淆配置是否保留了敏感类名？

**判定规则**:
- 已知 CVE 且可利用 = **按 CVE 等级**
- 第三方 SDK 请求 INTERNET + READ_EXTERNAL_STORAGE + 后台服务 = **Medium (数据收集风险)**

## D10: 配置与调试

**关键问题**:
1. `android:debuggable="true"` 是否在 release build？
2. `android:allowBackup="true"` 是否合理？
3. StrictMode 是否在 release build 中禁用？
4. `BuildConfig.DEBUG` 相关的调试代码是否有条件编译？
5. ProGuard/R8 是否启用？mapping 文件是否泄露？

**判定规则**:
- `debuggable=true` 在 release = **Critical (可 attach debugger)**
- `allowBackup=true` + 敏感数据 = **Medium**
- 调试端点在 release 暴露 = **High**
