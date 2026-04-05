# Android SDK Security Audit Guide

> Android SDK 安全审计模块
> 适用于: Android SDK (API 21+), Kotlin/Java, Jetpack, WebView, IPC 机制

## 核心危险面概述

Android 四大组件 + WebView + IPC 机制构成独特的攻击面：Intent 劫持/重定向、ContentProvider 注入/遍历、WebView JS Bridge 劫持、Broadcast 窃听/伪造、Service 未授权访问、Binder IPC 攻击、不安全的数据存储、网络通信中间人攻击等。

---

## 组件导出漏洞 (Exported Components)

### Activity 导出

```xml
<!-- ❌ 危险: 隐式导出 (有 intent-filter 时 API < 31 默认 exported=true) -->
<activity android:name=".PaymentActivity">
    <intent-filter>
        <action android:name="com.app.PAY" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>

<!-- ❌ 危险: 显式导出无权限保护 -->
<activity android:name=".AdminActivity"
    android:exported="true" />

<!-- ✓ 安全: 显式关闭导出 -->
<activity android:name=".PaymentActivity"
    android:exported="false" />

<!-- ✓ 安全: 导出但有自定义权限保护 -->
<activity android:name=".AdminActivity"
    android:exported="true"
    android:permission="com.app.permission.ADMIN" />
```

### Service 导出

```xml
<!-- ❌ 危险: 后台 Service 无保护导出 -->
<service android:name=".SyncService"
    android:exported="true" />

<!-- ❌ 危险: 绑定 Service 无权限 -->
<service android:name=".PaymentService">
    <intent-filter>
        <action android:name="com.app.BIND_PAYMENT" />
    </intent-filter>
</service>

<!-- ✓ 安全: signature 级别权限保护 -->
<permission android:name="com.app.permission.BIND_SERVICE"
    android:protectionLevel="signature" />

<service android:name=".PaymentService"
    android:exported="true"
    android:permission="com.app.permission.BIND_SERVICE" />
```

### BroadcastReceiver 导出

```xml
<!-- ❌ 危险: 广播接收器无保护导出 -->
<receiver android:name=".OrderReceiver"
    android:exported="true">
    <intent-filter>
        <action android:name="com.app.ORDER_COMPLETED" />
    </intent-filter>
</receiver>

<!-- ✓ 安全: 使用权限保护 -->
<receiver android:name=".OrderReceiver"
    android:exported="true"
    android:permission="com.app.permission.ORDER_NOTIFY">
    <intent-filter>
        <action android:name="com.app.ORDER_COMPLETED" />
    </intent-filter>
</receiver>
```

```kotlin
// ❌ 危险: 动态注册无权限保护
registerReceiver(orderReceiver, IntentFilter("com.app.ORDER_COMPLETED"))

// ✓ 安全: 动态注册使用权限或 RECEIVER_NOT_EXPORTED (API 33+)
registerReceiver(
    orderReceiver,
    IntentFilter("com.app.ORDER_COMPLETED"),
    "com.app.permission.ORDER_NOTIFY",
    null
)
// API 33+ 更安全
registerReceiver(
    orderReceiver,
    IntentFilter("com.app.ORDER_COMPLETED"),
    Context.RECEIVER_NOT_EXPORTED
)
```

### ContentProvider 导出

```xml
<!-- ❌ 危险: Provider 无保护导出 -->
<provider android:name=".UserProvider"
    android:authorities="com.app.provider.users"
    android:exported="true" />

<!-- ✓ 安全: 读写权限分离保护 -->
<provider android:name=".UserProvider"
    android:authorities="com.app.provider.users"
    android:exported="true"
    android:readPermission="com.app.permission.READ_USERS"
    android:writePermission="com.app.permission.WRITE_USERS" />

<!-- ✓ 安全: 路径级别权限控制 -->
<provider android:name=".UserProvider"
    android:authorities="com.app.provider.users"
    android:exported="true">
    <path-permission
        android:pathPrefix="/public"
        android:readPermission="com.app.permission.READ_PUBLIC" />
    <path-permission
        android:pathPrefix="/admin"
        android:readPermission="com.app.permission.READ_ADMIN"
        android:writePermission="com.app.permission.WRITE_ADMIN" />
</provider>
```

### API 31+ 行为变更

```xml
<!-- Android 12 (API 31+) 强制要求显式声明 exported -->
<!-- ❌ 编译错误: 有 intent-filter 但未声明 exported -->
<activity android:name=".MainActivity">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
    </intent-filter>
</activity>

<!-- ✓ 正确: 显式声明 -->
<activity android:name=".MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
    </intent-filter>
</activity>
```

---

## Intent 安全

### Intent 重定向漏洞

```kotlin
// ❌ Critical: Intent 重定向 - 从 extra 中取出 Intent 并启动
class RedirectActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val redirect = intent.getParcelableExtra<Intent>("next_intent")
        redirect?.let { startActivity(it) }  // ❌ 攻击者可启动任意非导出组件
    }
}

// 攻击: 恶意应用构造嵌套 Intent，访问受保护组件
val maliciousInner = Intent().apply {
    setClassName("com.victim", "com.victim.InternalActivity")
}
val outer = Intent().apply {
    setClassName("com.victim", "com.victim.RedirectActivity")
    putExtra("next_intent", maliciousInner)
}
startActivity(outer)

// ✓ 安全: 验证 Intent 目标包名
class RedirectActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val redirect = intent.getParcelableExtra<Intent>("next_intent")
        redirect?.let {
            // 确保目标组件属于本应用
            if (it.component?.packageName == packageName) {
                startActivity(it)
            }
        }
    }
}
```

### PendingIntent 劫持

```kotlin
// ❌ Critical: 可变 PendingIntent + 隐式 Intent
val intent = Intent("com.app.ACTION_NOTIFY")  // 隐式 Intent
val pendingIntent = PendingIntent.getBroadcast(
    context, 0, intent,
    PendingIntent.FLAG_MUTABLE  // ❌ 可被劫持修改
)

// ❌ 危险: 空 Intent + FLAG_MUTABLE
val pendingIntent = PendingIntent.getActivity(
    context, 0, Intent(),  // ❌ 空 Intent 可被完全替换
    PendingIntent.FLAG_MUTABLE
)

// ✓ 安全: 显式 Intent + FLAG_IMMUTABLE
val intent = Intent(context, NotificationReceiver::class.java)
val pendingIntent = PendingIntent.getBroadcast(
    context, 0, intent,
    PendingIntent.FLAG_IMMUTABLE  // ✓ 不可修改
)

// 如果必须 FLAG_MUTABLE (如 inline reply)，确保使用显式 Intent
val intent = Intent(context, ReplyReceiver::class.java).apply {
    action = "com.app.REPLY"
}
val pendingIntent = PendingIntent.getBroadcast(
    context, 0, intent,
    PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
)
```

### Deep Link / App Link 安全

```xml
<!-- ❌ 危险: Deep Link 未验证可被任意应用注册 -->
<activity android:name=".DeepLinkActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="myapp" android:host="pay" />
    </intent-filter>
</activity>

<!-- ✓ 安全: App Link 使用 https + autoVerify -->
<activity android:name=".DeepLinkActivity"
    android:exported="true">
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" android:host="example.com"
            android:pathPrefix="/pay" />
    </intent-filter>
</activity>
```

```kotlin
// ❌ 危险: Deep Link 参数未校验直接使用
class DeepLinkActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val uri = intent.data
        val userId = uri?.getQueryParameter("user_id")
        loadUserData(userId!!)  // ❌ 未验证来源和参数
    }
}

// ✓ 安全: 验证 Deep Link 来源和参数
class DeepLinkActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val uri = intent.data ?: return finish()

        // 验证 scheme 和 host
        if (uri.scheme != "https" || uri.host != "example.com") {
            finish()
            return
        }

        // 验证并清洗参数
        val userId = uri.getQueryParameter("user_id")
        if (userId.isNullOrBlank() || !userId.matches(Regex("^[0-9]+$"))) {
            finish()
            return
        }

        loadUserData(userId)
    }
}
```

### Implicit vs Explicit Intent

```kotlin
// ❌ 危险: 隐式 Intent 发送敏感数据 - 可被其他应用拦截
val intent = Intent("com.app.SEND_TOKEN")
intent.putExtra("auth_token", token)
sendBroadcast(intent)  // ❌ 任何应用都能接收

// ✓ 安全: 使用显式 Intent 或 LocalBroadcastManager
val intent = Intent(context, TokenReceiver::class.java)
intent.putExtra("auth_token", token)
sendBroadcast(intent, "com.app.permission.RECEIVE_TOKEN")  // ✓ 带权限

// ✓ 更安全: 使用 LocalBroadcastManager (应用内广播)
LocalBroadcastManager.getInstance(context)
    .sendBroadcast(Intent("TOKEN_UPDATE").putExtra("token", token))
```

---

## ContentProvider 安全

### SQL 注入

```kotlin
// ❌ Critical: selection 参数拼接导致 SQL 注入
class UserProvider : ContentProvider() {
    override fun query(
        uri: Uri, projection: Array<String>?,
        selection: String?, selectionArgs: Array<String>?,
        sortOrder: String?
    ): Cursor? {
        val db = dbHelper.readableDatabase
        // ❌ 直接使用 selection，可注入 SQL
        return db.rawQuery(
            "SELECT * FROM users WHERE $selection",
            null
        )
    }
}
// 攻击: content://com.app.provider/users?selection=1=1--

// ❌ 危险: projection 参数可注入
override fun query(uri: Uri, projection: Array<String>?, ...): Cursor? {
    // projection 来自调用方，可包含子查询
    return db.query("users", projection, selection, selectionArgs, null, null, sortOrder)
    // 攻击: projection = arrayOf("* FROM sqlite_master--")
}

// ✓ 安全: 参数化查询 + 白名单
class UserProvider : ContentProvider() {
    private val VALID_COLUMNS = setOf("id", "name", "email")

    override fun query(
        uri: Uri, projection: Array<String>?,
        selection: String?, selectionArgs: Array<String>?,
        sortOrder: String?
    ): Cursor? {
        // 验证 projection
        val safeProjection = projection?.filter { it in VALID_COLUMNS }?.toTypedArray()

        val qb = SQLiteQueryBuilder().apply {
            tables = "users"
            // 设置 projection map 防止注入
            projectionMap = VALID_COLUMNS.associateWith { it }
            isStrict = true  // ✓ 启用严格模式
        }

        return qb.query(
            dbHelper.readableDatabase,
            safeProjection, selection, selectionArgs,
            null, null, sortOrder
        )
    }
}
```

### Path Traversal via openFile()

```kotlin
// ❌ Critical: openFile 路径遍历
class FileProvider : ContentProvider() {
    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor? {
        val file = File("/data/data/com.app/files/" + uri.lastPathSegment)
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
        // 攻击: content://com.app.files/..%2F..%2F..%2Fetc%2Fpasswd
    }
}

// ✓ 安全: 规范化路径 + 验证
class FileProvider : ContentProvider() {
    private val BASE_DIR = File("/data/data/com.app/files/")

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor? {
        val fileName = uri.lastPathSegment ?: throw FileNotFoundException("No file specified")

        // 拒绝路径遍历字符
        if (fileName.contains("..") || fileName.contains("/") || fileName.contains("\\")) {
            throw SecurityException("Invalid file path")
        }

        val file = File(BASE_DIR, fileName)

        // 验证规范化路径在基础目录下
        if (!file.canonicalPath.startsWith(BASE_DIR.canonicalPath)) {
            throw SecurityException("Path traversal detected")
        }

        if (!file.exists()) throw FileNotFoundException(fileName)

        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
    }
}
```

### 临时 URI 权限

```kotlin
// ❌ 危险: 过度授权
val intent = Intent(Intent.ACTION_SEND).apply {
    data = Uri.parse("content://com.app.provider/users")
    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or
             Intent.FLAG_GRANT_WRITE_URI_PERMISSION)  // ❌ 不需要写权限
    addFlags(Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)  // ❌ 持久化权限
}

// ✓ 安全: 最小权限 + 指定目标包
val intent = Intent(Intent.ACTION_SEND).apply {
    data = Uri.parse("content://com.app.provider/users/123")  // ✓ 仅特定记录
    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)  // ✓ 仅读权限
    setPackage("com.trusted.app")  // ✓ 指定目标
}
```

---

## WebView 安全

### JavaScript Bridge 攻击

```kotlin
// ❌ Critical: JavaScript 与 Native 桥接 - 危险用法
class VulnerableActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = WebView(this)

        webView.settings.javaScriptEnabled = true
        webView.addJavascriptInterface(JsBridge(), "NativeBridge")  // ❌

        // 加载不受信任的 URL
        val url = intent.getStringExtra("url")
        webView.loadUrl(url!!)  // ❌ 用户控制的 URL 可执行 JS 调用 Native
    }

    inner class JsBridge {
        @JavascriptInterface
        fun getToken(): String {
            return getAuthToken()  // ❌ 暴露敏感数据给 JS
        }

        @JavascriptInterface
        fun executeCommand(cmd: String) {
            Runtime.getRuntime().exec(cmd)  // ❌ Critical: 远程代码执行
        }
    }
}

// ✓ 安全: 严格控制 JS Bridge
class SecureWebActivity : AppCompatActivity() {
    private val ALLOWED_HOSTS = setOf("www.example.com", "m.example.com")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = WebView(this)

        webView.settings.javaScriptEnabled = true

        // 仅暴露安全方法
        webView.addJavascriptInterface(SafeJsBridge(), "AppBridge")

        // 验证 URL
        val url = intent.getStringExtra("url") ?: return
        val uri = Uri.parse(url)
        if (uri.scheme == "https" && uri.host in ALLOWED_HOSTS) {
            webView.loadUrl(url)  // ✓
        }
    }

    inner class SafeJsBridge {
        @JavascriptInterface
        fun getAppVersion(): String {
            return BuildConfig.VERSION_NAME  // ✓ 仅暴露非敏感信息
        }

        @JavascriptInterface
        fun logEvent(eventName: String) {
            // ✓ 验证输入
            if (eventName.matches(Regex("^[a-zA-Z_]{1,50}$"))) {
                analytics.logEvent(eventName)
            }
        }
    }
}
```

### WebView 文件访问

```kotlin
// ❌ Critical: 启用危险的文件访问设置
webView.settings.apply {
    allowFileAccess = true  // ❌ 允许 file:// 协议
    allowFileAccessFromFileURLs = true  // ❌ Critical: file:// 可读取其他文件
    allowUniversalAccessFromFileURLs = true  // ❌ Critical: file:// 可跨域访问
    allowContentAccess = true  // ❌ 允许 content:// 协议
}

// ✓ 安全: 禁用文件访问
webView.settings.apply {
    allowFileAccess = false  // ✓ 禁用 file://
    allowFileAccessFromFileURLs = false  // ✓
    allowUniversalAccessFromFileURLs = false  // ✓
    allowContentAccess = false  // ✓
}
```

### WebView SSL 错误处理

```kotlin
// ❌ Critical: 忽略 SSL 错误
webView.webViewClient = object : WebViewClient() {
    override fun onReceivedSslError(
        view: WebView?, handler: SslErrorHandler?, error: SslError?
    ) {
        handler?.proceed()  // ❌ 接受无效证书，允许中间人攻击
    }
}

// ✓ 安全: 拒绝 SSL 错误
webView.webViewClient = object : WebViewClient() {
    override fun onReceivedSslError(
        view: WebView?, handler: SslErrorHandler?, error: SslError?
    ) {
        handler?.cancel()  // ✓ 拒绝无效证书
        // 可选: 提示用户并记录日志
        Log.w("WebView", "SSL error: ${error?.primaryError}")
    }
}
```

### URL 加载控制

```kotlin
// ❌ 危险: 未过滤 URL scheme
webView.webViewClient = object : WebViewClient() {
    override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
        view?.loadUrl(request?.url.toString())  // ❌ 可能加载 file:// javascript: 等
        return true
    }
}

// ✓ 安全: 白名单 URL scheme 和域名
webView.webViewClient = object : WebViewClient() {
    override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
        val url = request?.url ?: return true
        return when {
            url.scheme !in listOf("http", "https") -> true  // ✓ 阻止非 HTTP(S)
            url.host !in ALLOWED_HOSTS -> {
                // 外部浏览器打开
                startActivity(Intent(Intent.ACTION_VIEW, url))
                true
            }
            else -> false  // 允许 WebView 加载
        }
    }
}
```

### WebView Cookie 安全

```kotlin
// ❌ 危险: WebView Cookie 泄露到第三方域
CookieManager.getInstance().apply {
    setAcceptCookie(true)
    setAcceptThirdPartyCookies(webView, true)  // ❌ 接受第三方 Cookie
}

// ✓ 安全: 限制 Cookie
CookieManager.getInstance().apply {
    setAcceptCookie(true)
    setAcceptThirdPartyCookies(webView, false)  // ✓ 拒绝第三方 Cookie
}

// 退出时清除
CookieManager.getInstance().removeAllCookies(null)
```

---

## 数据存储安全

### SharedPreferences

```kotlin
// ❌ Critical: 全局可读写 (已废弃但仍有旧代码使用)
val prefs = getSharedPreferences("config", Context.MODE_WORLD_READABLE)  // ❌
prefs.edit().putString("auth_token", token).apply()  // ❌ 明文存储 token

// ❌ 危险: MODE_PRIVATE 但明文存储敏感数据
val prefs = getSharedPreferences("user", Context.MODE_PRIVATE)
prefs.edit().putString("password", password).apply()  // ❌ 明文密码

// ✓ 安全: 使用 EncryptedSharedPreferences
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val securePrefs = EncryptedSharedPreferences.create(
    context,
    "secure_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

securePrefs.edit().putString("auth_token", token).apply()  // ✓ 加密存储
```

### SQLite / Room 数据库

```kotlin
// ❌ 危险: 未加密的数据库存储敏感信息
@Database(entities = [User::class], version = 1)
abstract class AppDatabase : RoomDatabase() {
    // 数据库文件可被 root 用户或备份读取
}

val db = Room.databaseBuilder(context, AppDatabase::class.java, "app.db")
    .build()  // ❌ 未加密

// ✓ 安全: 使用 SQLCipher 加密
val passphrase = SQLCipherUtils.getPassphrase(context)
val factory = SupportFactory(passphrase)

val db = Room.databaseBuilder(context, AppDatabase::class.java, "app.db")
    .openHelperFactory(factory)  // ✓ SQLCipher 加密
    .build()
```

### External Storage

```kotlin
// ❌ Critical: 敏感数据写入外部存储 (其他应用可读)
val file = File(Environment.getExternalStorageDirectory(), "user_data.json")
file.writeText(userDataJson)  // ❌ 全局可读

// ❌ 危险: 从外部存储读取未验证的数据
val data = File(getExternalFilesDir(null), "config.json").readText()
val config = Gson().fromJson(data, Config::class.java)  // ❌ 可能被篡改

// ✓ 安全: 使用内部存储
val file = File(context.filesDir, "user_data.json")
file.writeText(userDataJson)  // ✓ 仅本应用可访问

// ✓ 安全: 使用 EncryptedFile
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val encryptedFile = EncryptedFile.Builder(
    context,
    File(context.filesDir, "secret.txt"),
    masterKey,
    EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
).build()

encryptedFile.openFileOutput().use { output ->
    output.write(sensitiveData.toByteArray())  // ✓ 加密写入
}
```

### AndroidKeyStore

```kotlin
// ❌ 危险: 硬编码密钥
val secretKey = SecretKeySpec("MySecretKey12345".toByteArray(), "AES")  // ❌

// ✓ 安全: 使用 AndroidKeyStore
val keyGenerator = KeyGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
)
keyGenerator.init(
    KeyGenParameterSpec.Builder("my_key",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setUserAuthenticationRequired(true)  // ✓ 需要用户认证
        .setUserAuthenticationValidityDurationSeconds(300)
        .build()
)
val key = keyGenerator.generateKey()  // ✓ 硬件安全模块存储
```

### Backup 安全

```xml
<!-- ❌ 危险: 允许完整备份 (含敏感数据) -->
<application android:allowBackup="true">
    <!-- adb backup 可提取应用所有数据 -->
</application>

<!-- ✓ 安全: 禁用备份或精确控制 -->
<application android:allowBackup="false" />

<!-- ✓ 或使用 backup rules 精确控制 (API 31+) -->
<application
    android:dataExtractionRules="@xml/data_extraction_rules"
    android:fullBackupContent="@xml/backup_rules">
</application>
```

```xml
<!-- res/xml/backup_rules.xml -->
<full-backup-content>
    <exclude domain="sharedpref" path="secure_prefs.xml" />
    <exclude domain="database" path="secret.db" />
    <exclude domain="file" path="tokens/" />
</full-backup-content>

<!-- res/xml/data_extraction_rules.xml (API 31+) -->
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="sharedpref" path="secure_prefs.xml" />
    </cloud-backup>
    <device-transfer>
        <exclude domain="database" path="secret.db" />
    </device-transfer>
</data-extraction-rules>
```

### FileProvider 配置

```xml
<!-- ❌ 危险: 暴露过多路径 -->
<paths>
    <root-path name="root" path="" />  <!-- ❌ Critical: 暴露整个文件系统 -->
    <external-path name="external" path="" />  <!-- ❌ 暴露整个外部存储 -->
</paths>

<!-- ✓ 安全: 最小化暴露路径 -->
<paths>
    <files-path name="images" path="shared_images/" />  <!-- ✓ 仅特定子目录 -->
    <cache-path name="cache" path="shared_cache/" />     <!-- ✓ 仅缓存子目录 -->
</paths>
```

---

## 网络安全配置

### Network Security Config

```xml
<!-- res/xml/network_security_config.xml -->

<!-- ❌ 危险: 允许明文流量 -->
<network-security-config>
    <base-config cleartextTrafficPermitted="true" />  <!-- ❌ 允许 HTTP -->
</network-security-config>

<!-- ❌ 危险: 信任用户安装的 CA 证书 -->
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="user" />  <!-- ❌ 信任用户证书 -->
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>

<!-- ✓ 安全: 严格网络安全配置 -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">  <!-- ✓ 禁止明文 -->
        <trust-anchors>
            <certificates src="system" />  <!-- ✓ 仅信任系统 CA -->
        </trust-anchors>
    </base-config>

    <!-- 仅 debug 构建允许用户 CA (用于抓包调试) -->
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

### Certificate Pinning

```xml
<!-- ✓ 安全: 证书固定 -->
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2025-12-31">
            <pin digest="SHA-256">base64_encoded_hash_1=</pin>
            <pin digest="SHA-256">base64_encoded_hash_backup=</pin>  <!-- 备份 pin -->
        </pin-set>
    </domain-config>
</network-security-config>
```

```kotlin
// OkHttp Certificate Pinning
val client = OkHttpClient.Builder()
    .certificatePinner(
        CertificatePinner.Builder()
            .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .add("api.example.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
            .build()
    )
    .build()
```

### Custom TrustManager 陷阱

```kotlin
// ❌ Critical: 禁用 SSL 验证的自定义 TrustManager
val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
})

val sslContext = SSLContext.getInstance("TLS")
sslContext.init(null, trustAllCerts, SecureRandom())  // ❌ 中间人攻击

// ❌ Critical: 禁用主机名验证
val hostnameVerifier = HostnameVerifier { _, _ -> true }  // ❌

// ✓ 安全: 使用默认 TrustManager, 通过 network_security_config.xml 配置
// 不要自定义 TrustManager 除非有非常充分的理由
```

### OkHttp/Retrofit Interceptor 安全

```kotlin
// ❌ 危险: Interceptor 日志泄露敏感信息
val loggingInterceptor = HttpLoggingInterceptor().apply {
    level = HttpLoggingInterceptor.Level.BODY  // ❌ 生产环境日志含请求/响应体
}

// ❌ 危险: Interceptor 中硬编码凭证
class AuthInterceptor : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request().newBuilder()
            .addHeader("Authorization", "Bearer hardcoded_token_here")  // ❌
            .build()
        return chain.proceed(request)
    }
}

// ✓ 安全: 条件日志 + 安全凭证管理
val loggingInterceptor = HttpLoggingInterceptor().apply {
    level = if (BuildConfig.DEBUG) {
        HttpLoggingInterceptor.Level.BODY
    } else {
        HttpLoggingInterceptor.Level.NONE  // ✓ 生产禁用
    }
}

class AuthInterceptor(private val tokenProvider: TokenProvider) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val token = tokenProvider.getToken()  // ✓ 从安全存储获取
        val request = chain.request().newBuilder()
            .addHeader("Authorization", "Bearer $token")
            .build()
        return chain.proceed(request)
    }
}
```

---

## 进程间通信 (IPC) 安全

### Binder 攻击

```kotlin
// ❌ 危险: AIDL Service 无调用者验证
class PaymentService : Service() {
    private val binder = object : IPaymentService.Stub() {
        override fun processPayment(amount: Double): Boolean {
            return doPayment(amount)  // ❌ 未验证调用者身份
        }
    }

    override fun onBind(intent: Intent): IBinder = binder
}

// ✓ 安全: 验证调用者
class PaymentService : Service() {
    private val binder = object : IPaymentService.Stub() {
        override fun processPayment(amount: Double): Boolean {
            // 验证调用者 UID
            val callingUid = Binder.getCallingUid()
            val callingPackage = packageManager.getNameForUid(callingUid)

            if (callingPackage != "com.trusted.app") {
                throw SecurityException("Unauthorized caller: $callingPackage")
            }

            // 验证签名
            val callingPid = Binder.getCallingPid()
            if (!verifyCallerSignature(callingUid)) {
                throw SecurityException("Signature verification failed")
            }

            // 使用 clearCallingIdentity 恢复自身身份执行操作
            val token = Binder.clearCallingIdentity()
            try {
                return doPayment(amount)
            } finally {
                Binder.restoreCallingIdentity(token)
            }
        }
    }
}
```

### Messenger IPC

```kotlin
// ❌ 危险: 未验证消息来源
class MessengerService : Service() {
    private val handler = object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(msg: Message) {
            when (msg.what) {
                MSG_EXECUTE -> {
                    val command = msg.data.getString("cmd")
                    executeCommand(command!!)  // ❌ 未验证来源
                }
            }
        }
    }
    private val messenger = Messenger(handler)
    override fun onBind(intent: Intent): IBinder = messenger.binder
}

// ✓ 安全: 验证消息来源 + 输入验证
class MessengerService : Service() {
    override fun onBind(intent: Intent): IBinder {
        // 检查绑定者权限
        val callingUid = Binder.getCallingUid()
        if (!isAuthorizedCaller(callingUid)) {
            throw SecurityException("Unauthorized")
        }
        return messenger.binder
    }
}
```

---

## AndroidManifest.xml 审计检查清单

| 配置项 | 危险值 | 安全值 | 影响 |
|--------|--------|--------|------|
| `android:debuggable` | `true` | `false` / 不设置 | 允许调试器附加，内存读取 |
| `android:allowBackup` | `true` | `false` | adb backup 可提取应用数据 |
| `android:usesCleartextTraffic` | `true` | `false` | 允许 HTTP 明文流量 |
| `android:exported` (有intent-filter) | 未设置 (API<31) | `false` 或加权限 | 组件可被外部调用 |
| `android:permission` (组件) | 未设置 | 设置 signature 权限 | 组件无访问控制 |
| `android:networkSecurityConfig` | 未设置 | 引用安全配置文件 | 无证书固定/明文控制 |
| `android:taskAffinity` | 默认值 | 空字符串 `""` | Task 劫持攻击 |
| `android:launchMode` | `singleTask` | 按需设置 | 结合 taskAffinity 可被劫持 |
| `android:grantUriPermissions` | `true` | `false` + path-permission | Provider URI 过度授权 |
| `<uses-permission>` | 过多权限 | 最小必要权限 | 攻击面扩大 |
| `<queries>` (API 30+) | 未设置 | 声明需要的包 | 包可见性 |
| `tools:node="remove"` on provider | 未设置 | 移除不需要的 provider | 减少攻击面 |

---

## 权限与 API 安全

```kotlin
// ❌ 危险: 请求过多权限
// AndroidManifest.xml
// <uses-permission android:name="android.permission.READ_CONTACTS" />
// <uses-permission android:name="android.permission.CAMERA" />
// <uses-permission android:name="android.permission.READ_SMS" />
// <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
// 应用仅需定位功能却请求了短信和联系人权限

// ❌ 危险: 运行时权限检查后未处理拒绝情况
if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
    != PackageManager.PERMISSION_GRANTED) {
    requestPermissions(arrayOf(Manifest.permission.CAMERA), 100)
}
// 然后直接使用相机，未等待回调  ❌

// ✓ 安全: 最小权限 + 正确处理回调
override fun onRequestPermissionsResult(
    requestCode: Int, permissions: Array<String>, grantResults: IntArray
) {
    if (requestCode == 100 && grantResults.isNotEmpty()
        && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
        openCamera()  // ✓ 仅在授权后使用
    } else {
        showPermissionDeniedMessage()  // ✓ 优雅降级
    }
}
```

---

## 加密安全

```kotlin
// ❌ Critical: 不安全的加密实践
val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")  // ❌ ECB 模式不安全
val cipher = Cipher.getInstance("DES/CBC/PKCS5Padding")   // ❌ DES 已过时
val md = MessageDigest.getInstance("MD5")                  // ❌ MD5 已破解
val md = MessageDigest.getInstance("SHA-1")                // ❌ SHA-1 已不安全

// ❌ 危险: 固定 IV
val iv = IvParameterSpec("1234567890123456".toByteArray())  // ❌ 固定 IV

// ❌ 危险: 不安全的随机数
val random = java.util.Random()  // ❌ 可预测
val seed = System.currentTimeMillis()  // ❌ 可预测种子

// ✓ 安全: 现代加密实践
val cipher = Cipher.getInstance("AES/GCM/NoPadding")  // ✓ GCM 模式
val md = MessageDigest.getInstance("SHA-256")           // ✓

// ✓ 安全: 随机 IV
val iv = ByteArray(12)
SecureRandom().nextBytes(iv)  // ✓ 安全随机数
val ivSpec = GCMParameterSpec(128, iv)
```

---

## 日志安全

```kotlin
// ❌ 危险: 日志泄露敏感信息
Log.d("Auth", "User token: $authToken")        // ❌ token 泄露
Log.i("Payment", "Card: $cardNumber")           // ❌ 银行卡号泄露
Log.e("Login", "Password: $password")           // ❌ 密码泄露
println("Debug: session=$sessionId")            // ❌ System.out 也会进 logcat
e.printStackTrace()                              // ❌ 堆栈信息泄露

// ✓ 安全: 条件日志 + 脱敏
if (BuildConfig.DEBUG) {
    Log.d("Auth", "Auth flow completed")  // ✓ 仅 debug 版本
}

// ✓ 使用 Timber 等库控制日志级别
// Release 构建中移除 debug 日志
class ReleaseTree : Timber.Tree() {
    override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
        if (priority >= Log.WARN) {
            // 仅上报 WARN 及以上到监控系统
            crashReporter.log(priority, tag, message)
        }
    }
}
```

---

## 审计正则速查

```regex
# === 组件导出 ===
android:exported\s*=\s*"true"
<(activity|service|receiver|provider)[^>]*(?!android:permission).*android:exported="true"

# === Intent 安全 ===
getParcelableExtra.*Intent|getParcelable\(.*Intent
startActivity\(.*getParcelableExtra|startService\(.*getParcelableExtra
FLAG_MUTABLE
PendingIntent\.(getActivity|getBroadcast|getService).*FLAG_MUTABLE

# === ContentProvider 注入 ===
rawQuery\(.*\$|rawQuery\(.*\+
db\.(query|delete|update)\((?!.*selectionArgs)
openFile\(.*uri\.(getPath|getLastPathSegment)

# === WebView ===
setJavaScriptEnabled\s*\(\s*true\s*\)
addJavascriptInterface
setAllowFileAccess\s*\(\s*true\s*\)
setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)
setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)
onReceivedSslError.*proceed
loadUrl\(.*\$|loadUrl\(.*getStringExtra|loadUrl\(.*intent

# === 数据存储 ===
MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE
getSharedPreferences.*putString.*(token|password|secret|key|credential)
getExternalStorageDirectory|getExternalFilesDir
SecretKeySpec\s*\(.*".*"

# === 网络安全 ===
cleartextTrafficPermitted\s*=\s*"true"
TrustManager|X509TrustManager.*checkServerTrusted\s*\{?\s*\}
HostnameVerifier.*true|ALLOW_ALL_HOSTNAME_VERIFIER
\.setSslSocketFactory\(|\.setHostnameVerifier\(

# === 加密 ===
AES/ECB|DES/|Blowfish|RC4
getInstance\s*\(\s*"MD5"|getInstance\s*\(\s*"SHA-1"
java\.util\.Random\s*\(
IvParameterSpec\s*\(.*".*"

# === Manifest ===
android:debuggable\s*=\s*"true"
android:allowBackup\s*=\s*"true"
android:usesCleartextTraffic\s*=\s*"true"
<root-path\s+name=
android:taskAffinity\s*=

# === 日志 ===
Log\.(d|v|i|e|w)\s*\(.*(?i)(token|password|secret|key|card|ssn|credential)
printStackTrace\(\)
System\.(out|err)\.print

# === PendingIntent ===
PendingIntent\.get(Activity|Broadcast|Service)\(.*Intent\(\)
PendingIntent\.get(Activity|Broadcast|Service)\(.*Intent\("[^"]*"\)(?!.*setComponent)

# === Binder IPC ===
Binder\.getCallingUid|Binder\.getCallingPid
# 反向: 搜索 AIDL Service 中缺少 getCallingUid 验证的实现
```

---

## 快速审计检查清单

```markdown
[ ] 检查 targetSdkVersion 和 minSdkVersion (影响安全默认值)
[ ] 搜索所有 android:exported="true" 组件，验证权限保护
[ ] 搜索 Intent 重定向 (getParcelableExtra + startActivity)
[ ] 检查 PendingIntent (FLAG_MUTABLE + 隐式 Intent)
[ ] 搜索 Deep Link 参数验证
[ ] 检查 ContentProvider SQL 注入 (rawQuery, selection 拼接)
[ ] 检查 ContentProvider openFile() 路径遍历
[ ] 搜索 WebView JavaScript 启用 + addJavascriptInterface
[ ] 检查 WebView 文件访问设置
[ ] 检查 WebView SSL 错误处理
[ ] 搜索 SharedPreferences 明文存储敏感数据
[ ] 检查 External Storage 使用
[ ] 搜索硬编码密钥和弱加密算法
[ ] 检查 android:allowBackup 设置
[ ] 检查 network_security_config.xml (明文流量/证书固定)
[ ] 搜索自定义 TrustManager (SSL 绕过)
[ ] 检查 Binder Service 调用者验证
[ ] 搜索 Log 语句中的敏感信息
[ ] 检查 android:debuggable 设置
[ ] 检查 FileProvider paths 配置
[ ] 检查 root 检测和防篡改机制
[ ] 审查 ProGuard/R8 混淆配置
```

---

## 最小 PoC 示例

```bash
# 查找导出组件
aapt dump xmltree app.apk AndroidManifest.xml | grep -E "exported|permission"

# 启动导出 Activity
adb shell am start -n com.app/.InternalActivity

# 发送广播
adb shell am broadcast -a com.app.ACTION_SENSITIVE -e "data" "malicious"

# 查询 ContentProvider
adb shell content query --uri content://com.app.provider/users

# 路径遍历测试 ContentProvider
adb shell content read --uri "content://com.app.provider/files/..%2F..%2Fetc%2Fpasswd"

# 检查备份
adb backup -f backup.ab com.app
java -jar abe.jar unpack backup.ab backup.tar

# 检查日志泄露
adb logcat | grep -iE "token|password|secret|key"

# Drozer 自动化审计 (如已安装)
dz> run app.package.attacksurface com.app
dz> run app.activity.info -a com.app
dz> run app.provider.finduri com.app
dz> run scanner.provider.injection -a com.app
dz> run scanner.provider.traversal -a com.app
```

---

## 参考资源

- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [Android Network Security Configuration](https://developer.android.com/privacy-and-security/security-config)
- [OWASP Mobile Security Testing Guide (MASTG)](https://mas.owasp.org/MASTG/)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [Android Developers - Security Tips](https://developer.android.com/privacy-and-security/security-tips)
- [Android Intent Redirection Vulnerabilities](https://blog.oversecured.com/Android-Access-to-app-protected-components/)
- [Drozer - Android Security Assessment Framework](https://github.com/WithSecureLabs/drozer)
