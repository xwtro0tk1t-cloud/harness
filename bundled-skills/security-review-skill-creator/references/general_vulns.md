# 通用漏洞模式库

生成 security-review-skill 时参考的漏洞模式。

## OWASP Top 10

### A01 - 越权 (Broken Access Control)

**横向越权 (IDOR)**
```python
# 危险：未校验资源归属
order = Order.query.get(order_id)

# 安全：校验 user_id
order = Order.query.filter_by(id=order_id, user_id=current_user.id).first()
```

**纵向越权**
```python
# 危险：只检查登录，不检查角色
@login_required
def admin_action(): ...

# 安全：检查角色
@require_role('admin')
def admin_action(): ...
```

### A02 - 加密失败

- 弱哈希：MD5/SHA1 用于密码
- 硬编码密钥：`SECRET_KEY = "xxx"`
- 弱随机：`random.random()` 用于安全场景

### A03 - 注入

**SQL 注入**
```python
# 危险
cursor.execute(f"SELECT * FROM users WHERE id = {uid}")

# 安全
cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))
```

**命令注入**
```python
# 危险
os.system(f"ping {host}")

# 安全
subprocess.run(["ping", host], shell=False)
```

**SSTI**
```python
# 危险
Template(user_input).render()

# 安全
template.render(name=user_input)
```

### A04 - 业务逻辑漏洞

**价格篡改**
```python
# 危险：信任客户端价格
total = sum(item['price'] for item in request.json['items'])

# 安全：服务端计算
total = sum(Product.query.get(item['id']).price * item['quantity'] for item in items)
```

**状态机跳跃**
```python
# 危险：直接改状态
order.status = 'shipped'

# 安全：验证当前状态
if order.status != 'paid':
    abort(400)
order.status = 'shipped'
```

**竞态条件**
```python
# 危险：check-then-act
if user.balance >= amount:
    user.balance -= amount

# 安全：原子操作
db.execute("UPDATE users SET balance = balance - ? WHERE id = ? AND balance >= ?", (amount, user_id, amount))
```

### A05 - 配置错误

- `DEBUG = True` 在生产环境
- 默认凭证
- 详细错误信息暴露

### A07 - 认证失败

- 可预测 session ID
- 缺少 session 超时
- JWT 无过期时间

**OAuth**
- 缺少 PKCE（移动端/SPA）
- 缺少 state 参数
- redirect_uri 未验证

### A08 - 反序列化

```python
# 危险
pickle.loads(user_data)
yaml.load(user_input)

# 安全
json.loads(user_data)
yaml.safe_load(user_input)
```

### A10 - SSRF

```python
# 危险
requests.get(user_url)

# 安全：域名白名单
if urlparse(user_url).netloc not in ALLOWED_DOMAINS:
    abort(400)
```

## 其他常见漏洞

### XSS
```javascript
// 危险
element.innerHTML = userInput

// 安全
element.textContent = userInput
```

### 路径遍历
```python
# 危险
open(f"/uploads/{filename}")

# 安全
filename = secure_filename(filename)
path = os.path.realpath(os.path.join("/uploads", filename))
if not path.startswith("/uploads/"):
    abort(400)
```

### 文件上传
- 无扩展名验证
- 只检查 Content-Type（可伪造）
- 允许可执行扩展名

## 语言特定

| 语言 | 重点检查 |
|-----|---------|
| Python | eval/exec, pickle, os.system, SSTI |
| Java | ObjectInputStream, Runtime.exec, JNDI, SpEL |
| Go | sql 拼接, text/template, 并发竞态 |
| JavaScript | eval, innerHTML, child_process, 原型污染 |
