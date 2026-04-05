# Dockerfile 深度安全检查

## Base Image 安全

### 来源合规检查

```dockerfile
# ❌ 危险：直接拉 Docker Hub
FROM python:3.11-slim
FROM node:18-alpine
FROM ubuntu:22.04

# ✅ 安全：使用内部 JFrog mirror
FROM {{INTERNAL_REGISTRY}}/docker-local/python:3.11-slim
FROM {{INTERNAL_REGISTRY}}/docker-remote/library/node:18-alpine

# ✅ 最佳：使用 digest 锁定
FROM {{INTERNAL_REGISTRY}}/docker-local/python@sha256:abc123...
```

**判定规则**：
- `FROM` 不以 `{{INTERNAL_REGISTRY}}/` 开头 → HIGH（必须迁移到内部 registry）
- 使用 `:latest` tag → MEDIUM（版本不确定性）
- 使用 full image（ubuntu/debian）但可用 slim/alpine → LOW（攻击面过大）

### Minimal Image 选择

| Base Image | 大小 | 攻击面 | 推荐度 |
|-----------|------|--------|--------|
| distroless | ~2MB | 极小（无 shell） | 最佳 |
| alpine | ~5MB | 小 | 推荐 |
| slim | ~50MB | 中等 | 可接受 |
| full（ubuntu/debian） | ~100MB+ | 大 | 不推荐 |

## 用户权限

```dockerfile
# ❌ 危险：无 USER 指令（默认 root）
FROM python:3.11-slim
COPY . /app
CMD ["python", "app.py"]

# ❌ 危险：显式 USER root
FROM python:3.11-slim
USER root
COPY . /app
CMD ["python", "app.py"]

# ✅ 安全：创建并切换到非 root 用户
FROM python:3.11-slim
RUN groupadd -r app && useradd -r -g app -d /app -s /sbin/nologin app
COPY --chown=app:app . /app
USER app
CMD ["python", "app.py"]

# ✅ Alpine 版本
FROM python:3.11-alpine
RUN addgroup -S app && adduser -S app -G app
COPY --chown=app:app . /app
USER app
CMD ["python", "app.py"]
```

**Multi-stage 例外**：build stage 可以用 root（安装编译依赖），但 final stage 必须非 root。

```dockerfile
# ✅ Multi-stage: build 用 root, final 用 app
FROM python:3.11-slim AS builder
# root is OK here for installing build deps
RUN pip install --prefix=/install -r requirements.txt

FROM python:3.11-slim
RUN groupadd -r app && useradd -r -g app app
COPY --from=builder /install /usr/local
COPY --chown=app:app . /app
USER app
CMD ["python", "app.py"]
```

## 密钥泄露

### 危险模式

```dockerfile
# ❌ CRITICAL: 复制 .env
COPY .env /app/.env
ADD .env /app/

# ❌ CRITICAL: 硬编码密钥
ENV DB_PASSWORD=MyS3cretPass!
ENV API_KEY=sk-1234567890abcdef
ARG AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE

# ❌ CRITICAL: 复制私钥
COPY deploy_key /root/.ssh/id_rsa
ADD server.key /etc/ssl/private/

# ❌ HIGH: ARG 传密钥（保留在 image history 中）
ARG GITHUB_TOKEN
RUN git clone https://${GITHUB_TOKEN}@github.com/org/repo.git
# docker history 可看到 GITHUB_TOKEN 值！
```

### 安全模式

```dockerfile
# ✅ 运行时环境变量注入（不在 image 中）
ENV DB_PASSWORD=""
# 启动时: docker run -e DB_PASSWORD=xxx

# ✅ Docker BuildKit secrets（不留在 image 层中）
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=github_token \
    GITHUB_TOKEN=$(cat /run/secrets/github_token) && \
    git clone https://${GITHUB_TOKEN}@github.com/org/repo.git

# ✅ Multi-stage 隔离（secret 只在 build stage）
FROM builder AS build
ARG NPM_TOKEN
RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > .npmrc && \
    npm ci && \
    rm .npmrc

FROM node:18-alpine
# NPM_TOKEN 不在 final image 中
COPY --from=build /app/node_modules ./node_modules
```

## .dockerignore 检查

必须存在且至少包含：

```
.git
.env
.env.*
*.key
*.pem
id_rsa*
node_modules
__pycache__
*.pyc
.DS_Store
docker-compose*.yml
```

缺少 `.dockerignore` → MEDIUM
存在但缺少 `.env` 或 `.git` → HIGH

## 构建安全

### Pipe to Shell

```dockerfile
# ❌ HIGH: 未经验证的远程脚本
RUN curl -fsSL https://get.docker.com | sh
RUN wget -O- https://example.com/install.sh | bash

# ✅ 安全: 下载后校验再执行
RUN curl -fsSL https://get.docker.com -o install.sh && \
    echo "expected_sha256  install.sh" | sha256sum -c && \
    sh install.sh && \
    rm install.sh
```

### 层清理

```dockerfile
# ❌ 每层留下缓存
RUN apt-get update
RUN apt-get install -y curl
RUN apt-get install -y python3

# ✅ 合并 + 清理
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl python3 && \
    rm -rf /var/lib/apt/lists/*

# ✅ Alpine
RUN apk add --no-cache curl python3
```

### HEALTHCHECK

```dockerfile
# ✅ 有健康检查
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# ✅ 无 curl 的替代方案
HEALTHCHECK --interval=30s --timeout=10s \
    CMD ["/app/healthcheck"]
```
