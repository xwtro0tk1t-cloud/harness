# 密钥管理与供应链安全检查

## 密钥泄露检测

### 检测正则

在所有容器配置文件中搜索：

```bash
# 硬编码密钥值（高置信）
Grep("(password|passwd|secret|token|api_key|apikey|access_key|private_key)\\s*[:=]\\s*['\"][^${}][^'\"]{8,}", -i=true)

# AWS 密钥
Grep("AKIA[0-9A-Z]{16}")
Grep("aws_secret_access_key\\s*=", -i=true)

# 私钥文件
Grep("BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY")
Grep("COPY.*\\.(pem|key|p12|pfx|jks)", glob="*Dockerfile*")

# SSH 密钥
Grep("COPY.*id_rsa|COPY.*id_ed25519", glob="*Dockerfile*")

# JWT/Generic Secrets
Grep("eyJ[A-Za-z0-9-_]+\\.eyJ")  # JWT token
Grep("ghp_[A-Za-z0-9]{36}")       # GitHub PAT
Grep("sk-[A-Za-z0-9]{48}")        # OpenAI key
```

### Build-time 密钥泄露

**多阶段构建中的密钥传递**：

```dockerfile
# ❌ ARG 密钥泄露到 image history
FROM builder AS build
ARG GITHUB_TOKEN=ghp_xxxxx
RUN git clone https://${GITHUB_TOKEN}@github.com/org/repo

FROM runtime
# GITHUB_TOKEN 虽然不在 final stage 代码中
# 但 builder stage 的 ARG 仍可通过 docker history 查看！

# ✅ 安全: 使用 BuildKit secrets
FROM builder AS build
RUN --mount=type=secret,id=github_token \
    export GITHUB_TOKEN=$(cat /run/secrets/github_token) && \
    git clone https://${GITHUB_TOKEN}@github.com/org/repo

FROM runtime
# secret 不保留在任何 image 层中
```

**检查方法**：
1. 找到所有 `ARG` 指令中包含密钥相关名称的
2. 检查这些 ARG 是否在 `RUN` 中使用
3. 如果使用了，检查是否有安全替代（BuildKit secrets / multi-stage 隔离）

### 运行时密钥注入

| 方法 | 安全性 | 说明 |
|------|--------|------|
| `docker run -e SECRET=val` | 低 | 可通过 `docker inspect` 查看 |
| `env_file: .env` | 中 | .env 不提交到 git 即可 |
| `docker secret` | 高 | Swarm mode，挂载到 `/run/secrets/` |
| K8s Secret + Volume | 中高 | 需确保不以环境变量暴露 |
| External Secrets Operator | 高 | 从 Vault/AWS SM 动态获取 |

---

## 供应链安全

### Base Image CVE

**检测思路**：
1. 提取所有 `FROM` 指令的 image:tag
2. 检查是否使用已知有严重 CVE 的版本
3. 检查 image 是否过旧（>6 个月未更新）

**常见高危 base image**：
- `alpine:3.16` 及以下（已 EOL）
- `node:14` / `node:16`（已 EOL）
- `python:3.7` / `python:3.8`（已 EOL 或即将 EOL）
- `java:8` 无补丁版本
- 任何 `ubuntu:18.04`（已 EOL）

### 不可信来源

```dockerfile
# ❌ HIGH: 从不可信源下载
RUN curl -fsSL https://random-site.com/tool.tar.gz | tar xz
RUN wget https://github.com/someone/tool/releases/download/v1.0/tool -O /usr/local/bin/tool
RUN pip install --index-url https://pypi.example.com/simple some-package

# ✅ 安全: 校验哈希
RUN curl -fsSL https://github.com/org/tool/releases/v1.0/tool.tar.gz -o tool.tar.gz && \
    echo "sha256_hash  tool.tar.gz" | sha256sum -c && \
    tar xzf tool.tar.gz

# ✅ 安全: 使用包管理器（有签名验证）
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# ✅ 安全: 使用内部 PyPI mirror
RUN pip install --index-url https://{{INTERNAL_REGISTRY}}/api/pypi/pypi-remote/simple some-package
```

### CI/CD 容器构建

检查 CI/CD 文件中的容器构建步骤：

```yaml
# ❌ HIGH: CI 中使用 --privileged 构建
- name: Build
  run: docker build --privileged -t myapp .

# ❌ MEDIUM: 未锁定 builder image
- name: Build
  image: docker:latest    # 应 pin 版本

# ✅ 安全: 使用 BuildKit + 固定版本
- name: Build
  image: docker:24.0.7
  run: |
    DOCKER_BUILDKIT=1 docker build \
      --no-cache \
      --pull \
      -t {{INTERNAL_REGISTRY}}/docker-local/myapp:$CI_COMMIT_SHA .
```

### Image 签名与验证

```yaml
# 推荐: 使用 Cosign 签名验证
# K8s admission controller 或 CI 步骤中
cosign verify --key cosign.pub {{INTERNAL_REGISTRY}}/docker-local/myapp:1.2.3
```

---

## 综合审查矩阵

| 检查项 | Dockerfile | Compose | K8s | CI/CD |
|--------|-----------|---------|-----|-------|
| 密钥硬编码 | ENV/ARG/COPY | environment | Secret/ConfigMap | 环境变量 |
| Base image 来源 | FROM | image | image | builder image |
| 版本锁定 | tag/digest | tag/digest | tag/digest | tag/digest |
| 远程下载验证 | RUN curl/wget | — | initContainer | run steps |
| 构建缓存泄露 | multi-stage | — | — | BuildKit cache |
