# Kotlin/Android Security Audit

> Kotlin/Android 代码安全审计模块 | **双轨并行完整覆盖**
> 适用于: Kotlin, Android SDK, Jetpack Compose, Retrofit, OkHttp, Room, Ktor

---

## 审计方法论

### 双轨并行框架

```
                  Kotlin/Android 代码安全审计
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
         ▼                 ▼                 ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  轨道A (50%)    │ │  轨道B (40%)    │ │  补充 (10%)     │
│  控制建模法     │ │  数据流分析法   │ │  配置+依赖审计  │
│                 │ │                 │ │                 │
│ 缺失类漏洞:     │ │ 注入类漏洞:     │ │ • 硬编码凭据    │
│ • 组件导出未防护│ │ • SQL注入       │ │ • 不安全配置    │
│ • 认证缺失      │ │ • 命令注入      │ │ • CVE依赖       │
│ • 授权缺失      │ │ • WebView XSS   │ │ • Manifest配置  │
│ • PendingIntent │ │ • Intent注入    │ │                 │
│ • Backup泄露    │ │ • 路径遍历      │ │                 │
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
# AndroidManifest.xml 组件导出
grep -rn 'android:exported="true"' --include="*.xml"

# 含 intent-filter 的组件 (隐式导出)
grep -rn '<intent-filter>' --include="*.xml"

# Activity 启动
grep -rn "startActivity\|startActivityForResult\|startService\|sendBroadcast" --include="*.kt"

# ContentProvider 操作
grep -rn "ContentResolver\|contentResolver\|query(\|insert(\|update(\|delete(" --include="*.kt"

# 文件操作
grep -rn "openFileOutput\|FileOutputStream\|FileInputStream\|File(" --include="*.kt"

# 命令执行
grep -rn "Runtime\.getRuntime\|ProcessBuilder" --include="*.kt"

# 网络请求
grep -rn "OkHttpClient\|Retrofit\|HttpURLConnection\|URL(" --include="*.kt"

# WebView 加载
grep -rn "loadUrl\|loadData\|evaluateJavascript\|addJavascriptInterface" --include="*.kt"

# 数据库操作
grep -rn "rawQuery\|execSQL\|@Query\|@Insert\|@Update\|@Delete" --include="*.kt"

# 加密操作
grep -rn "Cipher\|SecretKeySpec\|MessageDigest\|KeyStore" --include="*.kt"

# SharedPreferences 敏感存储
grep -rn "getSharedPreferences\|edit()\|putString" --include="*.kt"

# PendingIntent 构造
grep -rn "PendingIntent\.\(getActivity\|getBroadcast\|getService\)" --include="*.kt"

# 动态加载
grep -rn "DexClassLoader\|PathClassLoader\|Class\.forName" --include="*.kt"
```

### 1.2 输出模板

```markdown
## Android 敏感操作清单

| # | 组件/函数 | 类型 | 敏感类型 | 位置 | 风险等级 |
|---|-----------|------|----------|------|----------|
| 1 | DeepLinkActivity | Activity(exported) | 外部可达 | AndroidManifest.xml:23 | 高 |
| 2 | rawQuery() | 数据库 | SQL执行 | UserDao.kt:45 | 高 |
| 3 | loadUrl(url) | WebView | 动态加载 | WebFragment.kt:32 | 严重 |
| 4 | PendingIntent.getActivity | PendingIntent | 隐式Intent | NotifyService.kt:56 | 高 |
```

---

## A2. 安全控制建模

### 2.1 Android 安全控制实现方式

| 控制类型 | 实现方式 | 配置位置 |
|----------|----------|----------|
| **组件访问控制** | android:exported, permission, signature | AndroidManifest.xml |
| **认证控制** | BiometricPrompt, AccountManager, Firebase Auth | Activity/Fragment |
| **授权控制** | 自定义 Permission, signature-level protection | Manifest + Runtime |
| **输入验证** | Intent extra 校验, Uri scheme 白名单 | Activity/Receiver |
| **数据保护** | EncryptedSharedPreferences, Jetpack Security | 存储层 |
| **网络安全** | network_security_config, CertificatePinner | res/xml + OkHttp |
| **WebView 安全** | WebSettings 限制, WebViewClient 覆写 | WebView 初始化 |

### 2.2 控制矩阵模板 (Android)

```yaml
敏感操作: DeepLinkActivity (exported)
位置: AndroidManifest.xml:23, DeepLinkActivity.kt
类型: 外部可达组件

应有控制:
  组件访问控制:
    要求: 限制调用方
    实现: android:permission="signature" 或 exported="false"
    验证: 检查 Manifest 中 exported 和 permission 属性

  输入验证:
    要求: 校验 Intent data / extras
    实现: scheme/host 白名单, 参数校验
    验证: 检查 onCreate 中 intent.data 处理

  授权控制:
    要求: 敏感操作需二次确认
    实现: 用户确认对话框, 生物识别
```

---

## A3. 控制存在性验证

### 3.1 Android 组件验证清单

```markdown
## 控制验证: [组件名称]

| 控制项 | 应有 | 代码实现 | 结果 |
|--------|------|----------|------|
| 组件导出限制 | 必须 | exported="false" / permission | ✅/❌ |
| Intent 输入校验 | 必须 | scheme/host 白名单 | ✅/❌ |
| 认证保护 | 视情况 | BiometricPrompt | ✅/❌ |
| 数据加密存储 | 必须 | EncryptedSharedPreferences | ✅/❌ |
| 网络安全配置 | 必须 | network_security_config | ✅/❌ |

### 验证命令
```bash
# 检查所有导出组件
grep -B 2 -A 5 'android:exported="true"' AndroidManifest.xml

# 检查 intent-filter (隐式导出)
grep -B 5 '<intent-filter>' AndroidManifest.xml | grep -E "activity|service|receiver|provider"

# 检查权限保护
grep -A 3 'android:exported="true"' AndroidManifest.xml | grep "android:permission"

# 检查 network_security_config
grep -rn "networkSecurityConfig" --include="*.xml"
```
```

### 3.2 常见缺失模式 → 漏洞映射

| 缺失控制 | 漏洞类型 | CWE | Android 检测方法 |
|----------|----------|-----|-------------------|
| 无 exported 限制 | 组件劫持 | CWE-926 | 检查 Manifest exported + intent-filter |
| 无 Intent 校验 | Intent 注入 | CWE-940 | 检查 getIntent() 后的校验逻辑 |
| 无 PendingIntent flag | PendingIntent 劫持 | CWE-927 | 检查 FLAG_IMMUTABLE 使用 |
| 无 allowBackup=false | 数据泄露 | CWE-530 | 检查 Manifest backup 配置 |
| 无 network_security_config | 中间人攻击 | CWE-295 | 检查 TLS 配置 |
| 无 WebView 限制 | XSS/文件泄露 | CWE-79 | 检查 WebSettings 配置 |

---

# 轨道B: 数据流分析法 (注入类漏洞)

> **核心公式**: Source → [无净化] → Sink = 注入类漏洞
> **工具**: Android Lint, MobSF 静态扫描

## B1. Kotlin/Android Source (用户可控输入)

```kotlin
// Intent extras (其他应用传入)
intent.getStringExtra("key")
intent.getIntExtra("key", 0)
intent.getBooleanExtra("key", false)
intent.getParcelableExtra<Parcelable>("key")
intent.data                     // Uri
intent.action                   // action string

// Deep link / Uri 参数
intent.data?.getQueryParameter("param")
Uri.parse(urlString)
intent.data?.host
intent.data?.path

// ContentProvider 查询结果
contentResolver.query(uri, projection, selection, selectionArgs, sortOrder)

// WebView JavaScript 回调
@JavascriptInterface
fun onData(data: String) { ... }

// 网络响应 (Retrofit / OkHttp)
response.body()?.string()
retrofitService.getData()       // 远程返回值

// Clipboard
val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
clipboard.primaryClip?.getItemAt(0)?.text

// 外部存储文件
Environment.getExternalStorageDirectory()
File(context.getExternalFilesDir(null), filename)

// NFC / Bluetooth 数据
NfcAdapter.getDefaultAdapter(this)
tag.id                          // NFC tag data
BluetoothSocket.inputStream     // BT data

// EditText 用户输入
editText.text.toString()

// SharedPreferences (可能被其他应用写入 MODE_WORLD_READABLE)
getSharedPreferences("prefs", MODE_WORLD_READABLE)

// Notification extras
remoteInput.getCharSequence(KEY)
```

## B2. Kotlin/Android Sink (危险操作)

| Sink 类型 | 漏洞 | CWE | 危险函数 |
|-----------|------|-----|----------|
| SQL 执行 | SQL 注入 | CWE-89 | `rawQuery(sql)`, `execSQL(sql)`, `db.query()` + 字符串拼接 |
| 命令执行 | RCE | CWE-78 | `Runtime.getRuntime().exec(cmd)`, `ProcessBuilder(cmd)` |
| WebView 加载 | XSS | CWE-79 | `loadUrl(url)`, `loadData(html)`, `evaluateJavascript(js)` |
| Intent 构造 | Intent 注入 | CWE-940 | `Intent(action)`, `startActivity(intent)` + 用户数据 |
| 文件操作 | 路径遍历 | CWE-22 | `openFileOutput(name)`, `FileOutputStream(path)`, `File(path)` |
| 网络请求 | SSRF | CWE-918 | `URL(userUrl)`, `OkHttpClient`, `HttpURLConnection` |
| 动态加载 | 代码注入 | CWE-94 | `DexClassLoader`, `PathClassLoader`, `Class.forName(name)` |
| 反序列化 | 反序列化 | CWE-502 | `ObjectInputStream`, `Parcelable`, `Serializable` |
| 日志输出 | 信息泄露 | CWE-532 | `Log.d(tag, msg)`, `Log.i(tag, msg)`, `Log.v(tag, msg)` |
| 数据库写入 | 数据篡改 | CWE-915 | `ContentValues`, `Room @Insert`, `ContentProvider.insert()` |
| Reflection | 访问控制绕过 | CWE-470 | `Method.invoke()`, `Field.set()`, `Class.getDeclaredMethod()` |
| 剪贴板写入 | 信息泄露 | CWE-200 | `ClipboardManager.setPrimaryClip()` |
| SharedPreferences | 明文存储 | CWE-312 | `edit().putString("password", pwd)` |

## B3. Android Lint 规则及 Sink 检测

### 识别特征

```kotlin
// Kotlin/Android 项目识别
// build.gradle.kts
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// 文件结构
├── app/
│   ├── build.gradle.kts
│   ├── src/main/
│   │   ├── AndroidManifest.xml
│   │   ├── java/com/example/app/
│   │   │   ├── MainActivity.kt
│   │   │   ├── ui/
│   │   │   ├── data/
│   │   │   ├── domain/
│   │   │   └── di/
│   │   └── res/
│   │       ├── xml/network_security_config.xml
│   │       └── layout/
│   └── src/test/
├── build.gradle.kts
└── settings.gradle.kts
```

---

## Android 特定漏洞

### 1. 组件导出漏洞 (CWE-926)

```kotlin
// ❌ 危险: Activity 导出且无权限保护
// AndroidManifest.xml
<activity
    android:name=".AdminActivity"
    android:exported="true">  // 任何应用都可以启动!
    <intent-filter>
        <action android:name="com.example.ADMIN" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>

// ❌ 危险: Service 导出
<service
    android:name=".DataSyncService"
    android:exported="true" />  // 其他应用可启动/绑定!

// ❌ 危险: BroadcastReceiver 导出
<receiver
    android:name=".PaymentReceiver"
    android:exported="true" />  // 可被伪造广播触发!

// ❌ 危险: ContentProvider 导出且无权限
<provider
    android:name=".UserProvider"
    android:exported="true"
    android:authorities="com.example.provider" />  // 数据可被任意读取!

// ✓ 安全: 限制导出 + 权限保护
<activity
    android:name=".AdminActivity"
    android:exported="false" />

// ✓ 安全: 需要签名级别权限
<activity
    android:name=".AdminActivity"
    android:exported="true"
    android:permission="com.example.permission.ADMIN">
    <intent-filter>
        <action android:name="com.example.ADMIN" />
    </intent-filter>
</activity>

<permission
    android:name="com.example.permission.ADMIN"
    android:protectionLevel="signature" />

// 搜索模式
android:exported="true"|<intent-filter>
```

### 2. WebView 安全 (CWE-79)

```kotlin
// ❌ 危险: JavaScript 启用 + addJavascriptInterface + 文件访问
class VulnerableWebActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = WebView(this)

        webView.settings.javaScriptEnabled = true               // JS 开启
        webView.settings.allowFileAccess = true                  // 文件访问
        webView.settings.allowUniversalAccessFromFileURLs = true // file:// 跨域
        webView.addJavascriptInterface(JsBridge(), "Android")    // JS 接口

        // 加载用户控制的 URL
        val url = intent.getStringExtra("url")
        webView.loadUrl(url!!)  // XSS + 文件窃取!
    }

    inner class JsBridge {
        @JavascriptInterface
        fun getToken(): String {
            return getSharedPreferences("auth", MODE_PRIVATE)
                .getString("token", "")!!  // 泄露 token!
        }
    }
}

// ✓ 安全: 最小权限 WebView 配置
class SafeWebActivity : AppCompatActivity() {
    private val allowedHosts = setOf("example.com", "cdn.example.com")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = WebView(this)

        webView.settings.javaScriptEnabled = true  // 仅在必要时启用
        webView.settings.allowFileAccess = false
        webView.settings.allowContentAccess = false
        webView.settings.allowUniversalAccessFromFileURLs = false
        webView.settings.allowFileAccessFromFileURLs = false

        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(
                view: WebView, request: WebResourceRequest
            ): Boolean {
                val host = request.url.host
                if (host !in allowedHosts) {
                    return true  // 阻止非白名单域名
                }
                return false
            }
        }

        val url = intent.getStringExtra("url")
        if (url != null && Uri.parse(url).host in allowedHosts) {
            webView.loadUrl(url)
        }
    }
}

// 搜索模式
setJavaScriptEnabled\(true\)|addJavascriptInterface|@JavascriptInterface
allowFileAccess|allowUniversalAccessFromFileURLs|allowFileAccessFromFileURLs
```

### 3. Intent 重定向 (CWE-940)

```kotlin
// ❌ 危险: 从不可信 Intent 中提取 Intent 并转发
class RedirectActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 攻击者控制 "next_intent" extra
        val nextIntent = intent.getParcelableExtra<Intent>("next_intent")
        startActivity(nextIntent!!)  // 可以启动任意 Activity, 包括非导出的!
    }
}

// 攻击示例:
// val maliciousIntent = Intent()
// maliciousIntent.setComponent(ComponentName("com.victim", "com.victim.InternalActivity"))
// val wrapperIntent = Intent("com.victim.REDIRECT")
// wrapperIntent.putExtra("next_intent", maliciousIntent)
// startActivity(wrapperIntent)

// ✓ 安全: 校验目标 Intent
class SafeRedirectActivity : AppCompatActivity() {
    private val allowedActivities = setOf(
        "com.example.SettingsActivity",
        "com.example.ProfileActivity"
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val nextIntent = intent.getParcelableExtra<Intent>("next_intent")
        if (nextIntent != null) {
            val targetComponent = nextIntent.component?.className
            if (targetComponent in allowedActivities) {
                // 重新构造 Intent, 不直接转发
                val safeIntent = Intent(this, Class.forName(targetComponent!!))
                startActivity(safeIntent)
            }
        }
    }
}

// 搜索模式
getParcelableExtra.*Intent|intent\.setComponent.*getParcelableExtra
startActivity.*getParcelableExtra|startService.*getParcelableExtra
```

### 4. PendingIntent 劫持 (CWE-927)

```kotlin
// ❌ 危险: Mutable PendingIntent + 隐式 Intent
fun createNotification() {
    val intent = Intent("com.example.ACTION_VIEW")  // 隐式 Intent!
    val pendingIntent = PendingIntent.getActivity(
        context, 0, intent,
        PendingIntent.FLAG_MUTABLE  // 可被修改!
    )
    // 恶意应用可以注册 intent-filter 拦截,
    // 并修改 PendingIntent 的内容
    val notification = NotificationCompat.Builder(context, "channel")
        .setContentIntent(pendingIntent)
        .build()
}

// ✓ 安全: Immutable PendingIntent + 显式 Intent
fun createSafeNotification() {
    val intent = Intent(context, TargetActivity::class.java)  // 显式 Intent
    intent.setPackage(context.packageName)  // 限制包名
    val pendingIntent = PendingIntent.getActivity(
        context, 0, intent,
        PendingIntent.FLAG_IMMUTABLE  // 不可修改!
    )
    val notification = NotificationCompat.Builder(context, "channel")
        .setContentIntent(pendingIntent)
        .build()
}

// 搜索模式
PendingIntent\.(getActivity|getBroadcast|getService).*FLAG_MUTABLE
Intent\([^)]*"[^"]*"[^)]*\).*PendingIntent  // 隐式Intent + PendingIntent
```

### 5. ContentProvider 注入 (CWE-89 / CWE-22)

```kotlin
// ❌ 危险: SQL 注入 via projection
class VulnerableProvider : ContentProvider() {
    override fun query(
        uri: Uri, projection: Array<String>?,
        selection: String?, selectionArgs: Array<String>?,
        sortOrder: String?
    ): Cursor? {
        val db = dbHelper.readableDatabase
        // projection 直接拼入 SQL, 攻击者可注入: ["* FROM sqlite_master--"]
        return db.query("users", projection, selection, selectionArgs, null, null, sortOrder)
    }

    // ❌ 危险: 路径遍历 via openFile
    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor? {
        val file = File(context!!.filesDir, uri.lastPathSegment!!)
        // uri.lastPathSegment = "../../shared_prefs/secrets.xml"
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
    }
}

// ✓ 安全: 参数化查询 + 路径校验
class SafeProvider : ContentProvider() {
    private val validColumns = setOf("id", "name", "email")

    override fun query(
        uri: Uri, projection: Array<String>?,
        selection: String?, selectionArgs: Array<String>?,
        sortOrder: String?
    ): Cursor? {
        // 白名单校验 projection
        val safeProjection = projection?.filter { it in validColumns }?.toTypedArray()
        val db = dbHelper.readableDatabase
        return db.query("users", safeProjection, selection, selectionArgs, null, null, null)
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor? {
        val fileName = uri.lastPathSegment ?: return null
        // 路径遍历防护
        if (fileName.contains("..") || fileName.contains("/")) {
            throw SecurityException("Invalid file name")
        }
        val file = File(context!!.filesDir, fileName)
        val canonicalBase = context!!.filesDir.canonicalPath
        if (!file.canonicalPath.startsWith(canonicalBase)) {
            throw SecurityException("Path traversal detected")
        }
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
    }
}

// 搜索模式
openFile.*uri\.path|ParcelFileDescriptor\.open.*getPath|uri\.lastPathSegment
db\.query\(.*projection|rawQuery\(.*\+|execSQL\(.*\+
```

### 6. Broadcast 劫持 (CWE-925)

```kotlin
// ❌ 危险: 发送隐式广播 (任何应用都可接收)
val intent = Intent("com.example.USER_LOGIN")
intent.putExtra("token", authToken)
sendBroadcast(intent)  // token 泄露给所有注册了此 action 的应用!

// ❌ 危险: 有序广播可被高优先级接收者拦截
sendOrderedBroadcast(intent, null)  // 可被拦截和修改!

// ✓ 安全: 使用 LocalBroadcastManager 或显式广播
// 方式1: LocalBroadcastManager (仅应用内)
LocalBroadcastManager.getInstance(this).sendBroadcast(intent)

// 方式2: 指定接收者包名
intent.setPackage("com.example.myapp")
sendBroadcast(intent)

// 方式3: 带权限的广播
sendBroadcast(intent, "com.example.permission.RECEIVE_LOGIN")

// 搜索模式
sendBroadcast\(|sendOrderedBroadcast\(|sendStickyBroadcast\(
```

### 7. Clipboard 泄露 (CWE-200)

```kotlin
// ❌ 危险: 将敏感信息复制到剪贴板
fun copyPassword(password: String) {
    val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
    val clip = ClipData.newPlainText("password", password)
    clipboard.setPrimaryClip(clip)  // 所有应用都可读取剪贴板!
}

// ✓ 安全: 避免复制敏感数据, 或设置过期
fun safeCopy(text: String) {
    val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
    val clip = ClipData.newPlainText("data", text)
    // Android 13+ 可标记为敏感内容
    clip.description.extras = PersistableBundle().apply {
        putBoolean("android.content.extra.IS_SENSITIVE", true)
    }
    clipboard.setPrimaryClip(clip)
}

// 搜索模式
ClipboardManager|setPrimaryClip.*password|setPrimaryClip.*token|setPrimaryClip.*secret
```

### 8. Backup 泄露 (CWE-530)

```xml
<!-- ❌ 危险: 允许备份, 敏感数据可被 adb backup 提取 -->
<application
    android:allowBackup="true"
    android:fullBackupContent="true">
    <!-- 所有 SharedPreferences, 数据库, 文件都会被备份 -->
</application>

<!-- ✓ 安全: 禁止备份或精确控制 -->
<application
    android:allowBackup="false"
    android:fullBackupContent="false">
</application>

<!-- ✓ 安全: 精确控制备份内容 (Android 12+) -->
<application
    android:allowBackup="true"
    android:fullBackupContent="@xml/backup_rules"
    android:dataExtractionRules="@xml/data_extraction_rules">
</application>

<!-- res/xml/backup_rules.xml -->
<full-backup-content>
    <exclude domain="sharedpref" path="secret_prefs.xml"/>
    <exclude domain="database" path="credentials.db"/>
</full-backup-content>
```

```bash
# 搜索模式
android:allowBackup="true"
```

### 9. Tapjacking (CWE-1021)

```kotlin
// ❌ 危险: 未防护 Tapjacking (覆盖攻击)
class PaymentActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_payment)
        // 恶意应用可以在此 Activity 上覆盖透明窗口,
        // 诱导用户点击隐藏按钮
    }
}

// ✓ 安全: 过滤被遮挡时的触摸事件
class SafePaymentActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_payment)
        // 方式1: 在布局 XML 中设置
        // android:filterTouchesWhenObscured="true"

        // 方式2: 代码中设置
        val payButton = findViewById<Button>(R.id.pay_button)
        payButton.filterTouchesWhenObscured = true
    }

    // 方式3: 检测覆盖
    override fun onFilterTouchEventForSecurity(event: MotionEvent): Boolean {
        if (event.flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED != 0) {
            return false  // 拒绝被遮挡时的触摸
        }
        return super.onFilterTouchEventForSecurity(event)
    }
}

// 搜索模式
filterTouchesWhenObscured|FLAG_WINDOW_IS_OBSCURED
```

### 10. Fragment 注入 (CWE-470) — Legacy

```kotlin
// ❌ 危险: PreferenceActivity 的 Fragment 注入 (API < 19)
class VulnerableSettingsActivity : PreferenceActivity() {
    // 攻击者可通过 Intent extra ":android:show_fragment" 注入任意 Fragment
    // 可访问应用内部的 Fragment, 绕过权限检查
}

// ✓ 安全: 覆写 isValidFragment
class SafeSettingsActivity : PreferenceActivity() {
    override fun isValidFragment(fragmentName: String?): Boolean {
        return fragmentName == SettingsFragment::class.java.name ||
               fragmentName == AboutFragment::class.java.name
    }
}

// 搜索模式
PreferenceActivity|isValidFragment|:android:show_fragment
```

---

## Kotlin 特定漏洞

### 11. SQL 注入 (CWE-89)

```kotlin
// ❌ 危险: 字符串拼接构造 SQL
fun searchUser(name: String): Cursor {
    val db = helper.readableDatabase
    return db.rawQuery("SELECT * FROM users WHERE name = '$name'", null)  // SQLi!
}

// ❌ 危险: execSQL 拼接
fun deleteUser(id: String) {
    val db = helper.writableDatabase
    db.execSQL("DELETE FROM users WHERE id = $id")  // SQLi!
}

// ❌ 危险: Room @Query 字符串拼接 (虽然 Room 通常安全)
// 注意: Room 的 @Query 注解本身是参数化的, 但 @RawQuery 可能不安全
@Dao
interface UserDao {
    @RawQuery
    fun search(query: SupportSQLiteQuery): List<User>
}
// 调用处:
val query = SimpleSQLiteQuery("SELECT * FROM users WHERE name = '$userInput'")
dao.search(query)  // SQLi!

// ✓ 安全: 参数化查询
fun searchUserSafe(name: String): Cursor {
    val db = helper.readableDatabase
    return db.rawQuery("SELECT * FROM users WHERE name = ?", arrayOf(name))
}

// ✓ 安全: Room @Query 参数绑定
@Dao
interface UserDao {
    @Query("SELECT * FROM users WHERE name = :name")
    fun findByName(name: String): List<User>
}

// 搜索模式
rawQuery\(.*\$|rawQuery\(.*\+|execSQL\(.*\$|execSQL\(.*\+
SimpleSQLiteQuery\(.*\$|SimpleSQLiteQuery\(.*\+
```

### 12. 命令执行 (CWE-78)

```kotlin
// ❌ 危险: 用户输入拼接到命令
fun ping(host: String): String {
    val process = Runtime.getRuntime().exec("ping -c 1 $host")  // RCE!
    // host = "google.com; cat /data/data/com.example/shared_prefs/secrets.xml"
    return process.inputStream.bufferedReader().readText()
}

// ❌ 危险: ProcessBuilder 接受用户输入
fun runCommand(cmd: String) {
    val process = ProcessBuilder("sh", "-c", cmd).start()  // RCE!
}

// ✓ 安全: 白名单 + 参数分离
fun safePing(host: String): String? {
    val allowedPattern = Regex("^[a-zA-Z0-9.-]+$")
    if (!allowedPattern.matches(host)) return null

    // 参数分离, 不通过 shell
    val process = ProcessBuilder("ping", "-c", "1", host).start()
    return process.inputStream.bufferedReader().readText()
}

// 搜索模式
Runtime\.getRuntime\(\)\.exec|ProcessBuilder
```

### 13. 不安全 TLS 配置 (CWE-295)

```kotlin
// ❌ 危险: 信任所有证书
val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
})

val sslContext = SSLContext.getInstance("TLS")
sslContext.init(null, trustAllCerts, SecureRandom())
val client = OkHttpClient.Builder()
    .sslSocketFactory(sslContext.socketFactory, trustAllCerts[0] as X509TrustManager)
    .hostnameVerifier { _, _ -> true }  // 忽略主机名验证!
    .build()

// ❌ 危险: 明文流量
// AndroidManifest.xml
<application android:usesCleartextTraffic="true">

// ✓ 安全: network_security_config
// res/xml/network_security_config.xml
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>

// ✓ 安全: OkHttp Certificate Pinning
val client = OkHttpClient.Builder()
    .certificatePinner(
        CertificatePinner.Builder()
            .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .build()
    )
    .build()

// 搜索模式
ALLOW_ALL_HOSTNAME_VERIFIER|trustAllCerts|setHostnameVerifier|X509TrustManager
usesCleartextTraffic="true"|cleartextTrafficPermitted="true"
```

### 14. 硬编码凭据 (CWE-798)

```kotlin
// ❌ 危险: 硬编码 API 密钥
object ApiConfig {
    const val API_KEY = "sk-live-1234567890abcdef"  // 泄露!
    const val SECRET = "my_super_secret_password"    // 泄露!
    const val DB_PASSWORD = "admin123"               // 泄露!
}

// ❌ 危险: 硬编码在 BuildConfig 中 (可反编译)
// build.gradle.kts
buildConfigField("String", "API_KEY", "\"sk-live-1234567890\"")

// ✓ 安全: 使用 Android Keystore
val keyStore = KeyStore.getInstance("AndroidKeyStore")
keyStore.load(null)

// ✓ 安全: 使用 EncryptedSharedPreferences
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val prefs = EncryptedSharedPreferences.create(
    context, "secret_prefs", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

// 搜索模式
(password|secret|api_key|token|apikey)\s*=\s*["'][^"']+["']
const val.*(KEY|SECRET|PASSWORD|TOKEN)\s*=
buildConfigField.*API_KEY|buildConfigField.*SECRET
```

### 15. 不安全随机数 (CWE-338)

```kotlin
// ❌ 危险: java.util.Random 用于安全场景
import java.util.Random

fun generateToken(): String {
    val random = Random()  // 可预测!
    return (1..32).map { random.nextInt(36).toString(36) }.joinToString("")
}

// ❌ 危险: Math.random()
val otp = (Math.random() * 999999).toInt()  // 可预测!

// ❌ 危险: Kotlin Random (底层是 java.util.Random)
import kotlin.random.Random
val token = Random.nextInt()  // 可预测!

// ✓ 安全: SecureRandom
import java.security.SecureRandom

fun generateSecureToken(): String {
    val random = SecureRandom()
    val bytes = ByteArray(32)
    random.nextBytes(bytes)
    return bytes.joinToString("") { "%02x".format(it) }
}

// 搜索模式
java\.util\.Random\b|Math\.random\(\)|kotlin\.random\.Random\b
```

### 16. 明文存储 (CWE-312)

```kotlin
// ❌ 危险: SharedPreferences 明文存储敏感数据
val prefs = getSharedPreferences("user_data", MODE_PRIVATE)
prefs.edit()
    .putString("password", userPassword)      // 明文密码!
    .putString("credit_card", cardNumber)      // 明文卡号!
    .putString("token", authToken)             // 明文 token!
    .apply()

// ❌ 危险: MODE_WORLD_READABLE (已废弃但仍存在于旧代码)
val prefs = getSharedPreferences("config", MODE_WORLD_READABLE)  // 其他应用可读!

// ❌ 危险: 数据库明文存储
val db = helper.writableDatabase
val values = ContentValues().apply {
    put("username", user)
    put("password", password)  // 明文!
}
db.insert("users", null, values)

// ✓ 安全: EncryptedSharedPreferences
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val encryptedPrefs = EncryptedSharedPreferences.create(
    context, "secure_prefs", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
encryptedPrefs.edit().putString("token", authToken).apply()

// ✓ 安全: SQLCipher 加密数据库
val db = SQLiteDatabase.openOrCreateDatabase(dbPath, password, null)

// 搜索模式
getSharedPreferences|MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE
putString.*password|putString.*token|putString.*secret
```

### 17. SSRF (CWE-918)

```kotlin
// ❌ 危险: 用户可控 URL
fun fetchUrl(userUrl: String): String {
    val url = URL(userUrl)  // SSRF!
    val conn = url.openConnection() as HttpURLConnection
    return conn.inputStream.bufferedReader().readText()
}

// ❌ 危险: OkHttp 请求用户 URL
fun fetch(userUrl: String): String {
    val client = OkHttpClient()
    val request = Request.Builder().url(userUrl).build()  // SSRF!
    return client.newCall(request).execute().body?.string() ?: ""
}

// ✓ 安全: URL 白名单 + 协议限制
fun safeFetch(userUrl: String): String? {
    val parsed = Uri.parse(userUrl)
    val allowedHosts = setOf("api.example.com", "cdn.example.com")
    val allowedSchemes = setOf("https")

    if (parsed.scheme !in allowedSchemes) return null
    if (parsed.host !in allowedHosts) return null

    // 额外: DNS 重绑定防护 - 解析后检查 IP
    val addr = InetAddress.getByName(parsed.host)
    if (addr.isLoopbackAddress || addr.isSiteLocalAddress || addr.isLinkLocalAddress) {
        return null  // 禁止内网地址
    }

    val client = OkHttpClient()
    val request = Request.Builder().url(userUrl).build()
    return client.newCall(request).execute().body?.string()
}

// 搜索模式
URL\(.*\$|URL\(.*\+|Request\.Builder\(\)\.url\(.*\$
HttpURLConnection|OkHttpClient.*url\(
```

### 18. 路径遍历 (CWE-22)

```kotlin
// ❌ 危险: 用户控制文件名
fun readFile(fileName: String): String {
    val file = File(context.filesDir, fileName)
    // fileName = "../../shared_prefs/secrets.xml"
    return file.readText()  // 路径遍历!
}

// ❌ 危险: 从 Intent 获取文件路径
fun openDocument() {
    val path = intent.getStringExtra("file_path")
    val file = File(path!!)  // 攻击者可指定任意路径
    val content = file.readText()
}

// ✓ 安全: 规范化路径 + 基目录校验
fun safeReadFile(fileName: String): String? {
    if (fileName.contains("..") || fileName.contains(File.separator)) {
        return null
    }
    val baseDir = context.filesDir
    val file = File(baseDir, fileName)
    val canonicalBase = baseDir.canonicalPath
    val canonicalFile = file.canonicalPath

    if (!canonicalFile.startsWith(canonicalBase + File.separator)) {
        return null  // 路径遍历检测
    }
    return file.readText()
}

// 搜索模式
File\(.*intent\.|File\(.*getStringExtra|File\(.*getExtra
openFileInput\(.*\$|FileInputStream\(.*\$
```

---

## Kotlin 特定安全模式

### 19. Coroutine 安全

```kotlin
// ❌ 危险: 异常吞没 — 子协程异常不传播
val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
scope.launch {
    // 异常被吞没, 安全检查可能静默失败
    val result = validateToken(token)  // 抛异常但不被注意到
}

// ❌ 危险: Scope 泄漏 — GlobalScope 无生命周期管理
GlobalScope.launch {
    val sensitiveData = fetchSensitiveData()
    // Activity 已销毁, 但协程仍在运行, 可能导致内存泄漏
    updateUI(sensitiveData)
}

// ❌ 危险: Job 取消不当 — 资源未释放
suspend fun processPayment() {
    val file = File("temp.dat")
    file.createNewFile()
    delay(1000)  // 如果此处被取消, 下面的清理不会执行
    file.delete()
}

// ✓ 安全: 结构化并发 + 异常处理
class SafeViewModel : ViewModel() {
    fun processData() {
        viewModelScope.launch {  // 绑定到 ViewModel 生命周期
            try {
                val result = withContext(Dispatchers.IO) {
                    validateToken(token)
                }
                handleResult(result)
            } catch (e: CancellationException) {
                throw e  // 不要吞没 CancellationException!
            } catch (e: Exception) {
                handleError(e)
            }
        }
    }
}

// ✓ 安全: 使用 finally 或 NonCancellable 确保清理
suspend fun safeProcessPayment() {
    val file = File("temp.dat")
    try {
        file.createNewFile()
        delay(1000)
    } finally {
        withContext(NonCancellable) {
            file.delete()  // 即使被取消也会执行
        }
    }
}

// 搜索模式
GlobalScope\.launch|GlobalScope\.async
SupervisorJob|CoroutineExceptionHandler
```

### 20. Null 安全绕过

```kotlin
// ❌ 危险: !! 操作符导致崩溃 (DoS)
fun processIntent(intent: Intent) {
    val userId = intent.getStringExtra("user_id")!!  // NPE 崩溃!
    val data = intent.data!!.toString()  // NPE 崩溃!
}

// ❌ 危险: Java 互操作的 Platform Type (T!)
// Java 方法返回 @Nullable 但未标注
val result: String = javaObject.getData()  // 可能是 null, 运行时 NPE!

// ❌ 危险: lateinit 未初始化
class MyActivity : AppCompatActivity() {
    lateinit var authManager: AuthManager
    fun checkAuth() {
        authManager.validate()  // UninitializedPropertyAccessException 崩溃!
    }
}

// ✓ 安全: 安全调用 + 默认值
fun safeProcessIntent(intent: Intent) {
    val userId = intent.getStringExtra("user_id") ?: run {
        Log.w(TAG, "Missing user_id")
        return
    }
    val data = intent.data?.toString() ?: return
}

// ✓ 安全: lateinit 检查
fun safeCheckAuth() {
    if (::authManager.isInitialized) {
        authManager.validate()
    }
}

// 搜索模式
\!\!|lateinit var|as [A-Z]  // !! 操作符, lateinit, 不安全 cast
```

### 21. Sealed Class 不完整 when 表达式

```kotlin
// ❌ 危险: when 表达式缺少分支 (权限检查)
sealed class UserRole {
    object Admin : UserRole()
    object User : UserRole()
    object Guest : UserRole()
    object SuperAdmin : UserRole()  // 后来新增的角色
}

fun checkPermission(role: UserRole): Boolean {
    return when (role) {
        is UserRole.Admin -> true
        is UserRole.User -> false
        is UserRole.Guest -> false
        // SuperAdmin 被遗忘! Kotlin 编译器只在 when 作为表达式时警告
        else -> false  // 如果用 else 兜底, SuperAdmin 被当作无权限!
    }
}

// ✓ 安全: 穷举所有分支, 不使用 else
fun safeCheckPermission(role: UserRole): Boolean {
    return when (role) {
        is UserRole.Admin -> true
        is UserRole.SuperAdmin -> true
        is UserRole.User -> false
        is UserRole.Guest -> false
        // 编译器强制覆盖所有分支 (作为表达式时)
    }
}

// 搜索模式
sealed class|when\s*\(.*\)\s*\{.*else
```

### 22. Inline/Value Class 序列化问题

```kotlin
// ❌ 危险: Value class 序列化可能暴露内部结构
@JvmInline
value class UserId(val id: String)

@JvmInline
value class Password(val value: String)  // 序列化时可能泄露!

// Kotlin Serialization 中 value class 的处理
@Serializable
data class LoginRequest(
    val username: String,
    val password: Password  // JSON: {"username":"...", "password":"actual_password"}
)

// ✓ 安全: 自定义序列化器, 避免敏感 value class 直接序列化
@Serializable(with = PasswordSerializer::class)
@JvmInline
value class Password(val value: String)

object PasswordSerializer : KSerializer<Password> {
    override val descriptor = PrimitiveSerialDescriptor("Password", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: Password) {
        encoder.encodeString("***")  // 不序列化真实值
    }
    override fun deserialize(decoder: Decoder): Password {
        return Password(decoder.decodeString())
    }
}

// 搜索模式
@JvmInline|value class.*(Password|Secret|Token|Key)
```

### 23. Companion Object 线程安全

```kotlin
// ❌ 危险: companion object 中的非线程安全初始化
class ApiClient {
    companion object {
        private var instance: ApiClient? = null

        fun getInstance(): ApiClient {
            if (instance == null) {     // 竞态条件!
                instance = ApiClient()  // 多线程可能创建多个实例
            }
            return instance!!
        }
    }
}

// ❌ 危险: companion object 可变状态
class SessionManager {
    companion object {
        var currentToken: String = ""   // 多线程读写不安全!
        var isLoggedIn: Boolean = false // 竞态条件!
    }
}

// ✓ 安全: 使用 lazy 或 Double-Check Locking
class SafeApiClient private constructor() {
    companion object {
        // 方式1: lazy (线程安全, 推荐)
        val instance: SafeApiClient by lazy { SafeApiClient() }

        // 方式2: @Volatile + synchronized
        @Volatile
        private var _instance: SafeApiClient? = null

        fun getInstance(): SafeApiClient {
            return _instance ?: synchronized(this) {
                _instance ?: SafeApiClient().also { _instance = it }
            }
        }
    }
}

// ✓ 安全: 使用 AtomicReference 或 StateFlow
class SafeSessionManager {
    companion object {
        private val _token = AtomicReference<String>("")
        val currentToken: String get() = _token.get()

        fun updateToken(newToken: String) {
            _token.set(newToken)
        }
    }
}

// 搜索模式
companion object|@Volatile|synchronized\(
```

---

## 日志泄露 (CWE-532)

```kotlin
// ❌ 危险: 日志中记录敏感数据
Log.d(TAG, "User login: password=$password")
Log.i(TAG, "Auth token: $authToken")
Log.v(TAG, "Credit card: $cardNumber")
Log.w(TAG, "Request: ${request.headers}")  // 可能包含 Authorization header

// ❌ 危险: 异常堆栈中的敏感数据
try {
    authenticate(username, password)
} catch (e: Exception) {
    Log.e(TAG, "Auth failed", e)  // 堆栈可能包含敏感参数
}

// ✓ 安全: 生产环境禁用调试日志 + 脱敏
object SecureLog {
    private val isDebug = BuildConfig.DEBUG

    fun d(tag: String, msg: String) {
        if (isDebug) Log.d(tag, msg)
    }

    fun sanitize(value: String): String {
        if (value.length <= 4) return "***"
        return "${value.take(2)}***${value.takeLast(2)}"
    }
}

// ✓ 安全: ProGuard/R8 移除日志
// proguard-rules.pro
// -assumenosideeffects class android.util.Log {
//     public static int v(...);
//     public static int d(...);
//     public static int i(...);
// }

// 搜索模式
Log\.(d|i|v|w|e)\(.*[Pp]assword|Log\.(d|i|v|w|e)\(.*[Tt]oken
Log\.(d|i|v|w|e)\(.*[Ss]ecret|Log\.(d|i|v|w|e)\(.*[Cc]redit
```

---

## 动态加载 (CWE-94)

```kotlin
// ❌ 危险: 从外部存储加载 DEX
val dexPath = Environment.getExternalStorageDirectory().absolutePath + "/plugin.dex"
val classLoader = DexClassLoader(
    dexPath, context.cacheDir.absolutePath, null, context.classLoader
)  // 攻击者可替换 external storage 上的 plugin.dex!

// ❌ 危险: 反射加载用户指定的类
val className = intent.getStringExtra("class_name")
val clazz = Class.forName(className)  // 可加载任意类!
val method = clazz.getDeclaredMethod("execute")
method.invoke(clazz.newInstance())

// ✓ 安全: 仅从应用内部目录加载 + 完整性校验
fun safeLoadDex(dexName: String): ClassLoader? {
    val allowedDexes = setOf("module_a.dex", "module_b.dex")
    if (dexName !in allowedDexes) return null

    val dexPath = File(context.filesDir, dexName)
    if (!dexPath.exists()) return null

    // 校验文件哈希
    val expectedHash = getExpectedHash(dexName)
    val actualHash = calculateSHA256(dexPath)
    if (actualHash != expectedHash) return null

    return DexClassLoader(
        dexPath.absolutePath, context.cacheDir.absolutePath,
        null, context.classLoader
    )
}

// 搜索模式
DexClassLoader|PathClassLoader|Class\.forName|InMemoryDexClassLoader
Method\.invoke|Field\.set|getDeclaredMethod|getDeclaredField
```

---

## 反序列化 (CWE-502)

```kotlin
// ❌ 危险: ObjectInputStream 反序列化不可信数据
fun deserialize(data: ByteArray): Any {
    val bais = ByteArrayInputStream(data)
    val ois = ObjectInputStream(bais)
    return ois.readObject()  // 反序列化攻击!
}

// ❌ 危险: 从 Intent 中获取 Serializable/Parcelable (低版本)
val payload = intent.getSerializableExtra("data")  // 可被伪造!
// Android 13 之前, getParcelableExtra 不做类型检查
val parcel = intent.getParcelableExtra<UserData>("user")

// ✓ 安全: 使用类型安全的序列化
// 方式1: Kotlin Serialization
@Serializable
data class UserData(val id: Int, val name: String)

val json = Json.decodeFromString<UserData>(jsonString)

// 方式2: Android 13+ 类型安全 API
val parcel = intent.getParcelableExtra("user", UserData::class.java)

// 方式3: 如果必须使用 ObjectInputStream, 使用白名单
class SafeObjectInputStream(inputStream: InputStream) : ObjectInputStream(inputStream) {
    private val allowedClasses = setOf("com.example.model.UserData")

    override fun resolveClass(desc: ObjectStreamClass): Class<*> {
        if (desc.name !in allowedClasses) {
            throw InvalidClassException("Unauthorized class: ${desc.name}")
        }
        return super.resolveClass(desc)
    }
}

// 搜索模式
ObjectInputStream|readObject\(\)|getSerializableExtra|getParcelableExtra
```

---

## 授权漏洞检测 (Authorization Gap)

> **核心问题**: 授权漏洞是"代码缺失", grep 无法检测"应该有但没有"的代码
> **解决方案**: 授权矩阵方法 - 从"应该是什么"出发, 而非"存在什么"

### 方法论

```
❌ 旧思路 (被动检测):
   搜索 permission 属性 → 检查是否存在
   问题: exported 组件可能看似有 intent-filter 但缺少 permission

✅ 新思路 (主动建模):
   1. 枚举所有导出组件 / 敏感操作
   2. 定义应有的权限级别
   3. 对比实际配置, 检测缺失或不一致
```

### 检测命令

```bash
# 步骤1: 找到所有导出组件
grep -rn 'android:exported="true"' --include="*.xml"
grep -B 3 '<intent-filter>' --include="*.xml"

# 步骤2: 检查权限保护
grep -A 5 'android:exported="true"' --include="*.xml" | grep "android:permission"

# 步骤3: 检查代码中的权限验证
grep -rn "checkCallingPermission\|enforceCallingPermission\|checkSelfPermission" --include="*.kt"

# 步骤4: 检查 Intent 输入校验
grep -rn "intent\.get\|getIntent()\." --include="*.kt" -A 5 | grep -E "require|check|validate|verify"
```

### 授权一致性检测

```bash
#!/bin/bash
# check_android_auth.sh

echo "=== Android 组件导出安全检测 ==="

# 检查 AndroidManifest.xml
MANIFEST=$(find . -name "AndroidManifest.xml" -path "*/main/*" | head -1)

if [ -z "$MANIFEST" ]; then
    echo "未找到 AndroidManifest.xml"
    exit 1
fi

echo ""
echo "--- 导出组件检查 ---"
# 检查 exported=true 但无 permission 的组件
grep -n 'android:exported="true"' "$MANIFEST" | while read line; do
    linenum=$(echo "$line" | cut -d: -f1)
    # 检查附近是否有 permission 属性
    has_perm=$(sed -n "$((linenum-2)),$((linenum+5))p" "$MANIFEST" | grep -c "android:permission")
    if [ "$has_perm" -eq 0 ]; then
        echo "  ⚠️  行 $linenum: 导出组件无 permission 保护"
        echo "      $line"
    fi
done

echo ""
echo "--- allowBackup 检查 ---"
grep -n 'android:allowBackup="true"' "$MANIFEST" && echo "  ⚠️  allowBackup 已启用" || echo "  ✅  allowBackup 已禁用或未设置"

echo ""
echo "--- 明文流量检查 ---"
grep -n 'usesCleartextTraffic="true"' "$MANIFEST" && echo "  ⚠️  明文流量已允许" || echo "  ✅  明文流量已禁用或未设置"

echo ""
echo "--- debuggable 检查 ---"
grep -n 'android:debuggable="true"' "$MANIFEST" && echo "  ⚠️  应用可调试" || echo "  ✅  应用不可调试"
```

---

## Kotlin/Android 审计清单

```
组件导出 (CWE-926):
- [ ] 搜索 android:exported="true" 和 <intent-filter>
- [ ] 检查导出组件是否有 android:permission 保护
- [ ] 检查 permission 的 protectionLevel (signature vs dangerous)
- [ ] 验证导出的 ContentProvider 的 readPermission/writePermission

WebView 安全 (CWE-79):
- [ ] 搜索 setJavaScriptEnabled(true)
- [ ] 搜索 addJavascriptInterface / @JavascriptInterface
- [ ] 检查 allowFileAccess / allowUniversalAccessFromFileURLs
- [ ] 验证 shouldOverrideUrlLoading 中的 URL 校验
- [ ] 检查 loadUrl / loadData 的输入来源

Intent 安全 (CWE-940):
- [ ] 搜索 getParcelableExtra<Intent> (Intent 重定向)
- [ ] 检查接收 Intent 后的输入校验
- [ ] 验证 PendingIntent 使用 FLAG_IMMUTABLE
- [ ] 检查隐式 Intent 是否可被劫持

SQL 注入 (CWE-89):
- [ ] 搜索 rawQuery / execSQL + 字符串拼接
- [ ] 搜索 SimpleSQLiteQuery + 变量拼接
- [ ] 检查 ContentProvider 的 query/selection/projection
- [ ] 验证 Room @RawQuery 使用安全

命令执行 (CWE-78):
- [ ] 搜索 Runtime.getRuntime().exec
- [ ] 搜索 ProcessBuilder
- [ ] 检查用户输入是否进入命令参数

路径遍历 (CWE-22):
- [ ] 搜索 File() + 用户输入
- [ ] 检查 ContentProvider.openFile 路径校验
- [ ] 验证文件名中的 ".." 检测

TLS/网络 (CWE-295):
- [ ] 搜索 trustAllCerts / ALLOW_ALL_HOSTNAME_VERIFIER
- [ ] 检查 network_security_config.xml
- [ ] 搜索 usesCleartextTraffic="true"
- [ ] 验证 Certificate Pinning 配置

数据存储 (CWE-312):
- [ ] 搜索 SharedPreferences 中的敏感数据存储
- [ ] 检查 MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE
- [ ] 验证使用 EncryptedSharedPreferences
- [ ] 检查数据库明文密码存储

硬编码凭据 (CWE-798):
- [ ] 搜索 const val 包含 KEY/SECRET/PASSWORD/TOKEN
- [ ] 检查 BuildConfig 中的敏感字段
- [ ] 搜索 build.gradle.kts 中的 buildConfigField

日志泄露 (CWE-532):
- [ ] 搜索 Log.d/i/v/w/e 中的敏感数据
- [ ] 检查 ProGuard/R8 是否配置移除日志
- [ ] 验证 release 构建的日志级别

弱随机 (CWE-338):
- [ ] 搜索 java.util.Random / Math.random() / kotlin.random.Random
- [ ] 验证安全场景使用 SecureRandom

Kotlin 特定:
- [ ] 搜索 !! 操作符 (NPE 崩溃风险)
- [ ] 搜索 GlobalScope.launch (生命周期泄漏)
- [ ] 检查 sealed class when 表达式完整性
- [ ] 检查 companion object 线程安全
- [ ] 搜索 lateinit var 未初始化使用

Backup 与调试:
- [ ] 检查 android:allowBackup
- [ ] 检查 android:debuggable
- [ ] 检查 StrictMode 配置
```

---

## 审计正则速查

```regex
# Android 组件导出
android:exported="true"|<intent-filter>

# WebView JS 注入
setJavaScriptEnabled\(true\)|addJavascriptInterface|@JavascriptInterface

# 明文存储
getSharedPreferences|MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE

# SQL 注入
rawQuery\(.*\$|rawQuery\(.*\+|execSQL\(.*\$|execSQL\(.*\+
SimpleSQLiteQuery\(.*\$|SimpleSQLiteQuery\(.*\+

# 命令执行
Runtime\.getRuntime\(\)\.exec|ProcessBuilder

# 不安全 TLS
ALLOW_ALL_HOSTNAME_VERIFIER|trustAllCerts|setHostnameVerifier|X509TrustManager
usesCleartextTraffic="true"

# 硬编码凭据
(password|secret|api_key|token|apikey)\s*=\s*["'][^"']+["']
const val.*(KEY|SECRET|PASSWORD|TOKEN)\s*=

# 日志泄露
Log\.(d|i|v|w|e)\(.*[Pp]assword|Log\.(d|i|v|w|e)\(.*[Tt]oken
Log\.(d|i|v|w|e)\(.*[Ss]ecret|Log\.(d|i|v|w|e)\(.*[Cc]redit

# 动态加载
DexClassLoader|PathClassLoader|Class\.forName|InMemoryDexClassLoader

# PendingIntent
PendingIntent\.(getActivity|getBroadcast|getService).*FLAG_MUTABLE

# 不安全随机
java\.util\.Random\b|Math\.random\(\)|kotlin\.random\.Random\b

# Intent 重定向
getParcelableExtra.*Intent|intent\.setComponent.*getParcelableExtra

# ContentProvider 路径遍历
openFile.*uri\.path|ParcelFileDescriptor\.open.*getPath|uri\.lastPathSegment

# Clipboard 泄露
ClipboardManager|setPrimaryClip.*password|setPrimaryClip.*token

# Backup 泄露
android:allowBackup="true"

# 反序列化
ObjectInputStream|readObject\(\)|getSerializableExtra|getParcelableExtra

# Kotlin !! 操作符 (DoS)
\!\!

# Coroutine 泄漏
GlobalScope\.launch|GlobalScope\.async

# Debuggable
android:debuggable="true"

# Reflection
Method\.invoke|Field\.set|getDeclaredMethod|setAccessible\(true\)
```

---

## 审计工具

```bash
# MobSF - 移动安全框架 (静态 + 动态分析)
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
# 上传 APK 进行自动化扫描

# Android Lint - 内置安全检查
./gradlew lint
./gradlew lintDebug

# lint.xml 自定义安全规则
cat > lint.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<lint>
    <issue id="SetJavaScriptEnabled" severity="error" />
    <issue id="ExportedActivity" severity="error" />
    <issue id="AllowBackup" severity="warning" />
    <issue id="HardcodedDebugMode" severity="error" />
    <issue id="TrustAllX509TrustManager" severity="error" />
    <issue id="UnprotectedSMSBroadcastReceiver" severity="error" />
</lint>
EOF

# Semgrep - Kotlin/Android 规则
semgrep --config "p/kotlin" --config "p/android" .

# QARK - Quick Android Review Kit
pip install qark
qark --apk path/to/app.apk

# Jadx - APK 反编译审计
jadx -d output_dir app.apk
# 然后对反编译代码进行 grep 审计

# Drozer - 动态分析
drozer console connect
# run app.package.attacksurface com.example.app
# run app.activity.info -a com.example.app
# run app.provider.query content://com.example.provider/users

# apktool - 资源文件审计
apktool d app.apk -o app_decoded
grep -rn 'android:exported="true"' app_decoded/AndroidManifest.xml
grep -rn 'android:allowBackup' app_decoded/AndroidManifest.xml
```

---

## 最小 PoC 示例

```bash
# 组件劫持 (adb)
adb shell am start -n com.victim/.AdminActivity

# ContentProvider 数据泄露 (adb)
adb shell content query --uri content://com.victim.provider/users

# Intent 注入 (adb)
adb shell am start -n com.victim/.DeepLinkActivity -d "evil://attack?param=../../etc/passwd"

# Broadcast 伪造 (adb)
adb shell am broadcast -a com.victim.USER_LOGIN --es token "stolen_token"

# Backup 提取 (adb)
adb backup -f backup.ab com.victim
# 使用 android-backup-extractor 解压
java -jar abe.jar unpack backup.ab backup.tar

# WebView XSS (deep link)
adb shell am start -n com.victim/.WebViewActivity --es url "javascript:alert(document.cookie)"

# SQL 注入 (ContentProvider)
adb shell content query --uri "content://com.victim.provider/users" --projection "* FROM sqlite_master--"
```

---

## 参考资源

- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [Android Security Checklist](https://developer.android.com/privacy-and-security/security-tips)
- [MobSF GitHub](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [MASTG - Mobile Application Security Testing Guide](https://mas.owasp.org/MASTG/)
