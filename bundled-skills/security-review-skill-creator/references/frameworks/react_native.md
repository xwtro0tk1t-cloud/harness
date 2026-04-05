# React Native Security Audit Guide

> React Native 安全审计模块
> 适用于: React Native 0.68+, Hermes/JSC, Expo, React Navigation, CodePush/EAS Update

## 核心危险面概述

React Native 的 JS Bridge 架构使得攻击面跨越 JS 层和 Native 层：JS Bundle 可被提取和逆向（Hermes bytecode 可反编译）、Bridge 通信可被调试工具拦截（Flipper/Chrome DevTools）、Native Module 暴露本地系统能力、AsyncStorage 默认明文存储、Deep Link 路由缺乏验证、OTA 更新（CodePush/EAS Update）引入供应链风险、WebView postMessage 通信可被劫持、npm 依赖链攻击等。

---

## JS Bridge 安全 (CRITICAL)

### Old Architecture (Bridge)

JS 和 Native 之间通过异步 JSON 序列化桥接通信，所有数据在 Bridge 上明文传输。

```javascript
// ❌ 危险: 通过 Bridge 传递敏感数据（Bridge 消息可被 Flipper 拦截）
import { NativeModules } from 'react-native';

const { PaymentModule } = NativeModules;
// Bridge 消息: {"module":"PaymentModule","method":"pay","args":["4111111111111111","123","12/26"]}
PaymentModule.pay(cardNumber, cvv, expiry);
```

```java
// ❌ 危险: Native Module 未验证 Bridge 调用来源
@ReactMethod
public void pay(String cardNumber, String cvv, String expiry) {
    // 直接处理支付，无调用来源验证
    processPayment(cardNumber, cvv, expiry);
}
```

```javascript
// ✓ 安全: 敏感操作在 Native 层完成，JS 层仅传递引用/token
import { NativeModules } from 'react-native';

const { PaymentModule } = NativeModules;
// 仅传递 token 引用，实际卡号在 Native 层安全输入组件中获取
const paymentToken = await PaymentModule.initiateSecurePayment(transactionId);
```

### New Architecture (TurboModules / JSI)

TurboModules 通过 JSI 直接持有 C++ host object 引用，不再经过 JSON 序列化桥。

```typescript
// ❌ 危险: TurboModule Spec 暴露过宽的接口
// NativePaymentModule.ts
import type { TurboModule } from 'react-native';
import { TurboModuleRegistry } from 'react-native';

export interface Spec extends TurboModule {
  executeSQL(query: string): Promise<string>;    // ❌ 暴露原始 SQL 执行
  readFile(path: string): Promise<string>;       // ❌ 任意文件读取
  runCommand(cmd: string): Promise<string>;      // ❌ 命令执行
}

export default TurboModuleRegistry.getEnforcing<Spec>('PaymentModule');
```

```typescript
// ✓ 安全: TurboModule 接口最小化，利用 Codegen 类型约束
export interface Spec extends TurboModule {
  getPaymentStatus(transactionId: string): Promise<PaymentStatus>;
  initiateSecurePayment(amount: number, currency: string): Promise<string>;
}
```

### Bridge 调试拦截风险

```javascript
// ❌ 危险: 调试模式下 Bridge 消息可通过 Flipper / Chrome DevTools 完整捕获
// 攻击者可看到: NativeModules.AuthModule.login("admin", "P@ssw0rd!")
// 生产包中必须确保调试功能关闭

// ✓ 检查: 确保 release 构建禁用调试桥
if (!__DEV__) {
  // release 模式下 Bridge 消息不可通过 Chrome DevTools 拦截
  // 但 Frida 等工具仍可 hook JSI 调用
}
```

---

## Native Module 安全

### 自定义 Native Module 暴露面

```java
// ❌ 危险: @ReactMethod 暴露危险系统能力，无权限检查
public class FileModule extends ReactContextBaseJavaModule {

    @ReactMethod
    public void readFile(String path, Promise promise) {
        // ❌ 任意文件读取，path 来自 JS 层（不可信）
        try {
            String content = new String(Files.readAllBytes(Paths.get(path)));
            promise.resolve(content);
        } catch (Exception e) {
            promise.reject("ERROR", e);
        }
    }

    @ReactMethod
    public void executeCommand(String cmd, Promise promise) {
        // ❌ CRITICAL: 命令注入
        Runtime.getRuntime().exec(cmd);
    }
}
```

```swift
// ❌ 危险: iOS Native Module 暴露 Keychain 全量读取
@objc(KeychainModule)
class KeychainModule: NSObject {

    @objc func readItem(_ key: String,
                        resolver resolve: @escaping RCTPromiseResolveBlock,
                        rejecter reject: @escaping RCTPromiseRejectBlock) {
        // ❌ JS 层可读取任意 Keychain 条目
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,    // 不受限的 key
            kSecReturnData as String: true
        ]
        // ...
    }
}
```

```java
// ✓ 安全: 参数白名单验证 + 路径限制 + 权限检查
public class FileModule extends ReactContextBaseJavaModule {

    private static final Set<String> ALLOWED_DIRS = Set.of("cache", "documents");

    @ReactMethod
    public void readFile(String relativePath, Promise promise) {
        // 1. 路径规范化，防止目录遍历
        String normalized = Paths.get(relativePath).normalize().toString();
        if (normalized.contains("..") || normalized.startsWith("/")) {
            promise.reject("INVALID_PATH", "Path traversal detected");
            return;
        }

        // 2. 白名单目录检查
        String dir = normalized.split("/")[0];
        if (!ALLOWED_DIRS.contains(dir)) {
            promise.reject("FORBIDDEN", "Access denied for directory: " + dir);
            return;
        }

        // 3. 在沙箱目录下解析
        File file = new File(getReactApplicationContext().getFilesDir(), normalized);
        // ... 读取文件
    }
}
```

### JS 弱类型参数风险

```javascript
// ❌ 危险: JS 端传递的参数类型不可控
NativeModules.UserModule.updateProfile({
  userId: "1; DROP TABLE users;--",  // 字符串注入
  age: "not_a_number",               // 类型不匹配
  role: "admin",                     // 越权字段
});
```

```java
// ✓ 安全: Native 端严格验证类型和内容
@ReactMethod
public void updateProfile(ReadableMap profile, Promise promise) {
    // 类型验证
    if (!profile.hasKey("userId") || profile.getType("userId") != ReadableType.Number) {
        promise.reject("INVALID_PARAM", "userId must be a number");
        return;
    }

    int userId = profile.getInt("userId");

    // 白名单字段过滤
    Set<String> allowedFields = Set.of("userId", "displayName", "age");
    ReadableMapKeySetIterator it = profile.keySetIterator();
    while (it.hasNextKey()) {
        if (!allowedFields.contains(it.nextKey())) {
            promise.reject("FORBIDDEN_FIELD", "Unauthorized field in profile");
            return;
        }
    }
    // ... parameterized query
}
```

---

## Bundle 安全 / 逆向

### Hermes Bytecode vs JavaScriptCore

```bash
# ❌ 风险: Hermes bytecode (.hbc) 可被反编译
# 从 APK 中提取 bundle:
unzip app-release.apk -d extracted/
ls extracted/assets/index.android.bundle   # Hermes bytecode

# 使用 hbcdump 反编译:
hbcdump extracted/assets/index.android.bundle -dump-bytecode > decompiled.txt

# 使用 hermes-dec 获取可读 JS:
hermes-dec extracted/assets/index.android.bundle -o output.js

# iOS IPA 中同理:
unzip App.ipa -d extracted_ipa/
ls extracted_ipa/Payload/App.app/main.jsbundle
```

```javascript
// ❌ 危险: JS Bundle 中硬编码敏感信息（即使 Hermes 编译也可提取）
const API_KEY = "sk-live-a1b2c3d4e5f6g7h8i9j0";
const FIREBASE_CONFIG = {
  apiKey: "AIzaSyB-XXXXXXXXXXXXXXXXXXXXXX",
  authDomain: "myapp.firebaseapp.com",
  projectId: "myapp-prod",
};
const ADMIN_CREDENTIALS = { user: "admin", pass: "SuperSecret123" };
```

```javascript
// ✓ 安全: 敏感配置从 Native 层或远程获取
import { NativeModules, Platform } from 'react-native';
import Config from 'react-native-config'; // 环境变量（仍在 bundle 中，仅适合非密钥配置）

// 密钥从 Native Keychain/Keystore 获取
const apiKey = await NativeModules.SecureConfig.getApiKey();

// 或运行时从安全后端获取
const config = await fetchSecureConfig(authToken);
```

### Source Map 泄露

```javascript
// ❌ 危险: Metro bundler 配置未关闭 source map
// metro.config.js
module.exports = {
  // 默认在 release 也可能生成 source map
  transformer: {
    // ...
  },
};

// ✓ 安全: Release 构建不生成/不打包 source map
// metro.config.js
module.exports = {
  transformer: {
    // ...
  },
};
// build 命令: react-native bundle --sourcemap-output /dev/null
// 或在 CI 中确保 .map 文件不进入产物
```

---

## Deep Link / Navigation 安全

### React Navigation Deep Link 配置

```javascript
// ❌ 危险: Deep link 配置暴露敏感路由，无验证
const linking = {
  prefixes: ['myapp://', 'https://myapp.com'],
  config: {
    screens: {
      Payment: 'payment/:amount/:to',      // ❌ myapp://payment/10000/attacker
      Admin: 'admin',                       // ❌ myapp://admin
      ResetPassword: 'reset/:token',        // ❌ myapp://reset/guessed-token
      UserProfile: 'user/:id',              // ❌ myapp://user/other-user-id
    },
  },
};

function App() {
  return (
    <NavigationContainer linking={linking}>
      {/* ... */}
    </NavigationContainer>
  );
}
```

```javascript
// ✓ 安全: 敏感路由不通过 deep link 暴露 + 路由守卫
const linking = {
  prefixes: ['https://myapp.com'],  // ✓ 仅 HTTPS Universal Links
  config: {
    screens: {
      Home: '',
      Product: 'product/:id',      // ✓ 只暴露公开内容
      // Payment, Admin 不在 deep link 配置中
    },
  },
};

// ✓ 路由守卫: 在 Navigation state 变化时验证
function App() {
  const onStateChange = (state) => {
    const currentRoute = navigationRef.getCurrentRoute();
    if (PROTECTED_ROUTES.includes(currentRoute.name) && !isAuthenticated()) {
      navigationRef.navigate('Login');
    }
  };

  return (
    <NavigationContainer
      ref={navigationRef}
      linking={linking}
      onStateChange={onStateChange}
    >
      {/* ... */}
    </NavigationContainer>
  );
}
```

### URL 参数注入

```javascript
// ❌ 危险: Deep link 参数未验证直接使用
import { Linking } from 'react-native';

Linking.addEventListener('url', ({ url }) => {
  const parsed = new URL(url);
  const userId = parsed.searchParams.get('userId');
  // ❌ 直接用于 API 请求，可能导致 IDOR
  fetch(`https://api.myapp.com/users/${userId}/profile`);
});

// ✓ 安全: 参数验证 + 仅使用当前认证用户上下文
Linking.addEventListener('url', ({ url }) => {
  const parsed = new URL(url);
  const productId = parsed.searchParams.get('id');

  // 验证格式
  if (!/^[a-zA-Z0-9-]{1,36}$/.test(productId)) {
    console.warn('Invalid deep link parameter');
    return;
  }

  // 使用认证 token，后端验证权限
  navigation.navigate('Product', { id: productId });
});
```

### Android App Links + iOS Universal Links

```xml
<!-- ✓ Android: android/app/src/main/AndroidManifest.xml -->
<!-- 使用 App Links (autoVerify) 防止其他 app 劫持 -->
<activity android:name=".MainActivity">
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https"
              android:host="myapp.com"
              android:pathPrefix="/app" />
    </intent-filter>
</activity>
<!-- ❌ 避免: 仅用自定义 scheme（任何 app 可注册） -->
<!-- <data android:scheme="myapp" /> -->
```

---

## 本地存储安全

### AsyncStorage (明文存储)

```javascript
// ❌ 危险: AsyncStorage 明文存储敏感数据
import AsyncStorage from '@react-native-async-storage/async-storage';

// 数据以明文存储在:
// Android: /data/data/com.myapp/databases/RKStorage (SQLite)
// iOS: ~/Library/Application Support/RCTAsyncLocalStorage/
await AsyncStorage.setItem('authToken', 'eyJhbGciOiJIUzI1NiIs...');
await AsyncStorage.setItem('userCredentials', JSON.stringify({
  email: 'user@example.com',
  password: 'plaintext_password',  // ❌ CRITICAL
}));
await AsyncStorage.setItem('creditCard', '4111111111111111');
```

### 安全存储替代方案

```javascript
// ✓ 安全: 使用 react-native-keychain（基于 Android Keystore / iOS Keychain）
import * as Keychain from 'react-native-keychain';

// 存储
await Keychain.setGenericPassword('authToken', tokenValue, {
  accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  securityLevel: Keychain.SECURITY_LEVEL.SECURE_HARDWARE, // Android: TEE/StrongBox
});

// 读取（需要设备认证）
const credentials = await Keychain.getGenericPassword({
  authenticationPrompt: {
    title: '身份验证',
    description: '请验证身份以访问安全数据',
  },
});

// ✓ 安全: Expo SecureStore
import * as SecureStore from 'expo-secure-store';

await SecureStore.setItemAsync('token', tokenValue, {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  requireAuthentication: true,
  authenticationPrompt: '请验证身份',
});
```

### react-native-mmkv 加密

```javascript
// ❌ 危险: MMKV 未启用加密
import { MMKV } from 'react-native-mmkv';
const storage = new MMKV();
storage.set('user.token', sensitiveToken);  // 明文存储

// ✓ 安全: MMKV 启用加密，密钥从 Keychain 获取
import { MMKV } from 'react-native-mmkv';
import * as Keychain from 'react-native-keychain';

const encryptionKey = await getOrCreateEncryptionKey(); // 从 Keychain 读取
const storage = new MMKV({
  id: 'secure-storage',
  encryptionKey: encryptionKey,
});
```

### SQLite 注入

```javascript
// ❌ 危险: SQL 拼接注入
import SQLite from 'react-native-sqlite-storage';

const db = await SQLite.openDatabase({ name: 'app.db' });
const userInput = route.params.searchTerm;
// ❌ SQL 注入: searchTerm = "'; DROP TABLE users; --"
db.executeSql(`SELECT * FROM products WHERE name = '${userInput}'`);

// ✓ 安全: 参数化查询
db.executeSql('SELECT * FROM products WHERE name = ?', [userInput]);
```

---

## 网络安全

### 基本请求安全

```javascript
// ❌ 危险: 硬编码 URL + 无超时 + 无错误处理
fetch('http://api.myapp.com/data', {  // ❌ HTTP 明文
  headers: {
    'Authorization': 'Bearer ' + hardcodedToken,  // ❌ 硬编码
  },
});

// ✓ 安全: HTTPS + 动态 token + 超时 + 错误处理
const controller = new AbortController();
const timeoutId = setTimeout(() => controller.abort(), 10000);

try {
  const token = await SecureStore.getItemAsync('authToken');
  const response = await fetch('https://api.myapp.com/data', {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    signal: controller.signal,
  });

  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const data = await response.json();
} catch (error) {
  if (error.name === 'AbortError') {
    // 超时处理
  }
} finally {
  clearTimeout(timeoutId);
}
```

### 证书固定 (Certificate Pinning)

```javascript
// ✓ 使用 react-native-ssl-pinning
import { fetch as pinnedFetch } from 'react-native-ssl-pinning';

const response = await pinnedFetch('https://api.myapp.com/data', {
  method: 'GET',
  sslPinning: {
    certs: ['api_myapp_com'],  // .cer 文件名（放在 assets 中）
  },
  headers: {
    Authorization: `Bearer ${token}`,
  },
});
```

```xml
<!-- ✓ Android: android/app/src/main/res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- ❌ 危险: 允许明文流量 -->
    <!-- <base-config cleartextTrafficPermitted="true" /> -->

    <!-- ✓ 安全: 禁止明文 + 证书固定 -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>

    <domain-config>
        <domain includeSubdomains="true">api.myapp.com</domain>
        <pin-set expiration="2027-01-01">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

### SSRF 风险

```javascript
// ❌ 危险: 用户输入直接作为 URL（SSRF）
const imageUrl = route.params.imageUrl;
const response = await fetch(imageUrl);  // ❌ 可能访问内网

// ✓ 安全: URL 白名单验证
const ALLOWED_HOSTS = ['cdn.myapp.com', 'images.myapp.com'];

function validateUrl(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') return false;
    if (!ALLOWED_HOSTS.includes(parsed.hostname)) return false;
    // 检查私有 IP
    if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(parsed.hostname)) return false;
    return true;
  } catch {
    return false;
  }
}
```

---

## WebView 安全 (react-native-webview)

### postMessage / onMessage 通信

```javascript
// ❌ 危险: WebView 消息无来源验证，直接执行
import { WebView } from 'react-native-webview';

<WebView
  source={{ uri: userProvidedUrl }}  // ❌ 不可信的 URL
  onMessage={(event) => {
    const data = JSON.parse(event.nativeEvent.data);
    // ❌ 直接执行 WebView 传来的操作
    if (data.action === 'navigate') {
      navigation.navigate(data.screen, data.params);  // ❌ 任意路由导航
    }
    if (data.action === 'setToken') {
      SecureStore.setItemAsync('token', data.token);  // ❌ 覆盖 token
    }
  }}
/>
```

```javascript
// ✓ 安全: URL 白名单 + 来源验证 + 操作白名单
const ALLOWED_ORIGINS = ['https://webview.myapp.com'];
const ALLOWED_ACTIONS = ['trackEvent', 'updateTheme'];

<WebView
  source={{ uri: 'https://webview.myapp.com/page' }}  // ✓ 固定可信 URL
  originWhitelist={['https://webview.myapp.com']}
  onMessage={(event) => {
    // 验证来源 URL
    const sourceUrl = event.nativeEvent.url;
    if (!ALLOWED_ORIGINS.some(origin => sourceUrl.startsWith(origin))) {
      console.warn('Rejected message from untrusted origin:', sourceUrl);
      return;
    }

    let data;
    try {
      data = JSON.parse(event.nativeEvent.data);
    } catch {
      return;  // 格式错误的消息
    }

    // 操作白名单
    if (!ALLOWED_ACTIONS.includes(data.action)) {
      console.warn('Rejected unknown action:', data.action);
      return;
    }

    handleSafeAction(data);
  }}
  javaScriptEnabled={true}
  domStorageEnabled={false}         // ✓ 按需开启
  allowFileAccess={false}           // ✓ 禁止文件访问
  allowUniversalAccessFromFileURLs={false}  // ✓ 必须 false
  mixedContentMode="never"          // ✓ 禁止混合内容
  sharedCookiesEnabled={false}      // ✓ 不共享 cookie
/>
```

### injectedJavaScript 风险

```javascript
// ❌ 危险: 注入脚本中拼接不可信数据
const userId = route.params.userId;  // 来自 deep link
<WebView
  source={{ uri: 'https://webview.myapp.com' }}
  injectedJavaScript={`
    document.getElementById('user').value = '${userId}';
  `}  // ❌ XSS: userId = "'; alert(document.cookie); //'"
/>

// ✓ 安全: 通过 postMessage 传递数据，避免拼接
<WebView
  source={{ uri: 'https://webview.myapp.com' }}
  injectedJavaScript={`
    window.addEventListener('message', (e) => {
      if (e.origin === 'https://webview.myapp.com') {
        const data = JSON.parse(e.data);
        if (data.type === 'setUser') {
          document.getElementById('user').value =
            DOMPurify.sanitize(data.userId);
        }
      }
    });
    true;
  `}
  onLoadEnd={() => {
    webViewRef.current?.postMessage(JSON.stringify({
      type: 'setUser',
      userId: sanitizedUserId,
    }));
  }}
/>
```

---

## OTA 更新安全 (CodePush / EAS Update)

### 中间人攻击与代码签名

```javascript
// ❌ 危险: CodePush 未启用代码签名，可能接受篡改的更新
import codePush from 'react-native-code-push';

const App = codePush({
  checkFrequency: codePush.CheckFrequency.ON_APP_RESUME,
  installMode: codePush.InstallMode.IMMEDIATE,
  // ❌ 未配置 code signing public key
})(RootComponent);
```

```javascript
// ✓ 安全: 启用代码签名验证
// iOS: Info.plist 中配置 CodePushPublicKey
// Android: MainActivity 中配置 CodePush.setPublicKey()

// ✓ EAS Update 使用代码签名
// eas.json
{
  "cli": { "version": ">= 3.0.0" },
  "build": {
    "production": {
      "channel": "production"
    }
  },
  "submit": {},
  "updates": {
    "codeSigningCertificate": "./code-signing/certificate.pem",
    "codeSigningMetadata": {
      "keyid": "main",
      "alg": "rsa-v1_5-sha256"
    }
  }
}
```

### 回滚攻击与恶意更新

```javascript
// ❌ 危险: 无版本校验，可能回滚到旧版有漏洞的代码
codePush.sync({
  installMode: codePush.InstallMode.IMMEDIATE,
  // ❌ 没有最低版本限制
});

// ✓ 安全: 检查最低版本 + 更新完整性
codePush.sync({
  installMode: codePush.InstallMode.ON_NEXT_RESTART,
  minimumBackgroundDuration: 60,
  mandatoryInstallMode: codePush.InstallMode.IMMEDIATE,
}, (status) => {
  // 监控更新状态
  if (status === codePush.SyncStatus.UPDATE_INSTALLED) {
    logUpdateEvent('update_installed');
  }
});

// ✓ 敏感逻辑不应通过 OTA 可更新 — 放在 Native 层
// 支付逻辑、加密操作、认证核心逻辑 → Native Module
// UI 展示、非敏感业务逻辑 → JS（可 OTA 更新）
```

### 供应链风险检查

```bash
# ✓ 检查 CodePush 部署密钥是否硬编码在代码中
# 应通过环境变量或 CI/CD 注入
grep -r "deployment-key" android/ ios/ src/ --include="*.java" --include="*.swift" --include="*.js" --include="*.ts"

# ✓ 检查 EAS Update 配置
# 确保 production channel 启用了代码签名
```

---

## 调试与发布安全

### __DEV__ Flag 检查

```javascript
// ❌ 危险: 生产代码中残留调试功能
if (__DEV__) {
  // 这段在 release 中会被移除...
}

// ❌ 但这种写法不会被移除:
const isDebug = __DEV__;
// ... 100 行后 ...
if (isDebug) {
  enableDebugMenu();  // ❌ 可能通过变量传播保留
}

// ❌ 危险: 自定义调试入口未保护
const DEBUG_ENABLED = AsyncStorage.getItem('debug_mode');
if (DEBUG_ENABLED) {
  showDebugPanel();  // ❌ 用户可手动设置 AsyncStorage 开启
}
```

```javascript
// ✓ 安全: 直接使用 __DEV__ 常量，确保死代码消除有效
if (__DEV__) {
  require('./devtools').setup();  // ✓ release 中 metro 会完全移除
}

// ✓ 确保 console.log 在 release 中被清理
// babel.config.js
module.exports = {
  presets: ['module:metro-react-native-babel-preset'],
  env: {
    production: {
      plugins: ['transform-remove-console'],  // ✓ 移除所有 console.*
    },
  },
};
```

### Flipper / 调试工具

```java
// ❌ 危险: Release 构建中启用了 Flipper
// android/app/src/main/java/com/myapp/MainApplication.java
// Flipper 默认仅在 debug 中初始化，但需确认:

// ✓ 安全: 确保 Flipper 仅在 debug variant 中存在
// android/app/src/debug/java/com/myapp/ReactNativeFlipper.java  → 只在 debug
// android/app/src/release/java/com/myapp/ReactNativeFlipper.java → 空实现
```

### Hermes 与代码保护

```groovy
// android/app/build.gradle
// ✓ 确保 release 启用 Hermes（字节码比明文 JS 稍难逆向）
project.ext.react = [
    enableHermes: true,  // ✓ 启用 Hermes
]

// ✓ 启用 ProGuard/R8 混淆 Native 层
android {
    buildTypes {
        release {
            minifyEnabled true  // ✓ 启用代码混淆
            shrinkResources true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'),
                          'proguard-rules.pro'
        }
    }
}
```

---

## 第三方依赖安全

### npm 依赖审计

```bash
# ✓ 检查已知漏洞
npm audit
npm audit --production  # 仅生产依赖

# ✓ 使用 audit fix（注意 major 升级可能有破坏性变更）
npm audit fix
npm audit fix --force  # ⚠️ 谨慎: 可能引入破坏性变更

# ✓ 检查废弃包
npx depcheck
npm outdated
```

### Native 依赖审计

```bash
# ✓ iOS CocoaPods 依赖检查
cd ios/
pod outdated
# 检查 Podfile.lock 中的版本

# ✓ Android Gradle 依赖检查
cd android/
./gradlew dependencies
./gradlew dependencyCheckAnalyze  # OWASP Dependency Check plugin
```

### Autolinking 暴露风险

```javascript
// ❌ 风险: react-native.config.js 未限制 autolinking
// 安装的 npm 包如果包含 native 代码，会自动链接到项目中
// 恶意 npm 包可能通过 autolinking 注入 Native Module

// ✓ 安全: 审查并限制 autolinking
// react-native.config.js
module.exports = {
  dependencies: {
    'suspicious-package': {
      platforms: {
        ios: null,      // ✓ 禁止 iOS autolinking
        android: null,  // ✓ 禁止 Android autolinking
      },
    },
  },
};

// ✓ 定期检查已 autolink 的 native 模块
// npx react-native config  → 列出所有 autolinked 依赖
```

### 第三方 SDK 权限审查

```xml
<!-- ❌ 危险: 第三方 SDK 通过 manifest merge 注入权限 -->
<!-- 检查合并后的 AndroidManifest.xml -->
<!-- android/app/build/intermediates/merged_manifest/release/ -->

<!-- ✓ 安全: 在主 manifest 中移除不需要的权限 -->
<uses-permission android:name="android.permission.READ_CONTACTS"
    tools:node="remove" />
<uses-permission android:name="android.permission.CAMERA"
    tools:node="remove" />
```

---

## 跨平台安全配置检查清单

| 检查项 | Android 端 | iOS 端 | JS 层 |
|--------|-----------|--------|-------|
| **Bundle 保护** | ProGuard/R8 + Hermes | Hermes + Bitcode | 不在 bundle 中存敏感数据 |
| **安全存储** | Android Keystore | iOS Keychain | react-native-keychain / Expo SecureStore |
| **网络安全** | network_security_config | ATS (Info.plist) | HTTPS only + cert pinning |
| **Deep Link** | App Links (autoVerify) | Universal Links | 路由守卫 + 参数验证 |
| **调试禁用** | debuggable=false | 无 Get-Task-Allow | __DEV__ === false |
| **日志清理** | ProGuard 移除 Log.* | OS_LOG 级别控制 | transform-remove-console |
| **代码签名** | APK/AAB signing | Xcode code signing | CodePush/EAS code signing |
| **权限最小化** | AndroidManifest 审计 | Info.plist 审计 | 运行时按需申请 |
| **后台安全** | FLAG_SECURE | UIApplicationDelegate 截屏保护 | AppState listener |
| **Clipboard** | 清除敏感数据 | UIPasteboardName | Clipboard.setString('') |
| **WebView** | 禁用 file:// | WKWebView (非 UIWebView) | originWhitelist + allowFileAccess=false |
| **OTA 更新** | CodePush code signing | CodePush code signing | 敏感逻辑不走 OTA |

---

## 审计正则速查

```python
# === JS Bridge / Native Module 暴露 ===
r'@ReactMethod'                                    # Java/Kotlin: 暴露给 JS 的方法
r'RCT_EXPORT_METHOD'                               # ObjC: 暴露给 JS 的方法
r'RCT_EXTERN_METHOD'                               # ObjC: 外部暴露方法
r'TurboModuleRegistry\.(get|getEnforcing)'         # TurboModule 注册
r'NativeModules\.\w+'                              # JS 端调用 Native Module
r'requireNativeComponent'                          # 原生 UI 组件注册

# === 存储安全 ===
r'AsyncStorage\.(setItem|getItem|multiSet)'        # 明文存储检查
r'(password|token|secret|key|credential).*AsyncStorage'  # 敏感数据 + AsyncStorage
r'MMKV\(\s*\)'                                     # MMKV 无加密初始化
r'openDatabase\('                                  # SQLite 数据库使用
r'executeSql\s*\(\s*`'                             # SQLite 模板字符串（可能注入）
r'executeSql\s*\(\s*[\'"][^?]*\$\{'                # SQLite 字符串插值注入

# === 网络安全 ===
r'http://'                                         # 明文 HTTP
r'fetch\s*\(\s*[`\'"]http://'                      # fetch 明文请求
r'cleartextTrafficPermitted\s*=\s*"true"'          # Android 允许明文
r'NSAllowsArbitraryLoads.*true'                    # iOS 禁用 ATS
r'SSL_PINNING|sslPinning'                          # 证书固定配置
r'rejectUnauthorized\s*:\s*false'                  # TLS 验证禁用

# === Deep Link ===
r'Linking\.(getInitialURL|addEventListener)'       # Deep link 入口
r'prefixes\s*:\s*\['                               # React Navigation deep link 配置
r'myapp://'                                        # 自定义 scheme（优先用 Universal Links）
r'android:scheme='                                 # Android scheme 声明

# === WebView ===
r'<WebView'                                        # WebView 使用
r'injectedJavaScript\s*=\s*\{?\s*`'               # JS 注入（检查拼接）
r'onMessage\s*='                                   # WebView 消息处理
r'allowFileAccess\s*=\s*\{?\s*true'                # 文件访问开启
r'allowUniversalAccessFromFileURLs\s*=\s*\{?\s*true'  # 跨域文件访问
r'originWhitelist\s*=\s*\{\s*\[\s*[\'\"]\*'        # 通配符 origin（危险）
r'mixedContentMode\s*=\s*[\'"]always'              # 混合内容允许

# === OTA / CodePush ===
r'codePush\.sync\('                                # CodePush 更新调用
r'CodePush\.setPublicKey'                          # 代码签名公钥（应存在）
r'deployment-key'                                  # CodePush 部署密钥（不应硬编码）
r'expo-updates'                                    # Expo Update 使用

# === 调试安全 ===
r'__DEV__'                                         # 开发模式检查
r'console\.(log|warn|error|debug|info)\('          # 日志输出（release 应移除）
r'debuggable\s*=\s*true'                           # Android debuggable
r'Flipper'                                         # Flipper 调试工具引用
r'ReactNativeFlipper'                              # Flipper 初始化

# === 敏感数据 ===
r'(api[_-]?key|secret|password|token)\s*[:=]\s*[\'"`]' # 硬编码密钥
r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'          # 私钥文件
r'AKIA[0-9A-Z]{16}'                                # AWS Access Key
r'AIzaSy[0-9A-Za-z_-]{33}'                         # Firebase/Google API Key
r'sk[-_](live|test)[-_][0-9a-zA-Z]+'               # Stripe Secret Key
r'source[Mm]ap'                                    # Source map 配置

# === 第三方依赖 ===
r'react-native-webview'                            # WebView 依赖（需审查配置）
r'react-native-code-push'                          # CodePush（需审查签名）
r'react-native-ssl-pinning'                        # SSL Pinning（应存在）
r'react-native-keychain'                           # 安全存储（应使用）
r'@react-native-async-storage'                     # AsyncStorage（不应存敏感数据）
```

---

## 附录: 常见安全配置参考

### Android: android/app/build.gradle

```groovy
android {
    defaultConfig {
        // ✓ 最低 SDK 版本（API 24+ 支持更多安全特性）
        minSdkVersion 24
    }
    buildTypes {
        release {
            debuggable false          // ✓ 禁用调试
            minifyEnabled true        // ✓ 代码混淆
            shrinkResources true      // ✓ 资源压缩
        }
    }
}
```

### iOS: Info.plist 安全配置

```xml
<!-- ✓ App Transport Security -->
<key>NSAppTransportSecurity</key>
<dict>
    <!-- 不设置 NSAllowsArbitraryLoads 或设为 false -->
    <key>NSAllowsArbitraryLoads</key>
    <false/>
</dict>

<!-- ✓ 禁止第三方键盘 (如处理敏感输入) -->
<key>UIApplicationSupportsSecureRestorableState</key>
<true/>
```

### package.json 安全脚本

```json
{
  "scripts": {
    "security:audit": "npm audit --production",
    "security:outdated": "npm outdated",
    "security:depcheck": "npx depcheck",
    "security:secrets": "npx secretlint '**/*'",
    "postinstall": "npx react-native-config && echo 'Run npm audit after install'"
  }
}
```
