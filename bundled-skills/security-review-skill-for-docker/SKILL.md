---
name: security-review-skill-for-docker
description: 审计 Docker/容器部署安全。检测 Dockerfile、docker-compose.yml、Kubernetes manifests 中的安全问题：特权容器、root 运行、敏感挂载、资源无限制、密钥泄露、Base Image 不合规、网络暴露等。当审计容器配置、Docker 安全、K8s 部署安全、或检查基础设施安全时使用。支持 Dockerfile、docker-compose.yml、Kubernetes YAML、Helm charts。
---

# Docker / Container Security Review

## 适用范围

本 skill 审计以下文件类型的安全配置：
- **Dockerfile** / **Dockerfile.***（多阶段构建）
- **docker-compose.yml** / **docker-compose.*.yml**
- **Kubernetes manifests**（Deployment, Pod, Service, Ingress, RBAC, NetworkPolicy）
- **Helm charts**（templates/ 下的 YAML）
- **.dockerignore**
- **CI/CD 中的容器相关步骤**

## 审计模式

触发 skill 后，根据用户 prompt 判断模式：

### 全量模式
扫描项目中所有容器相关文件。

### PR/分支模式
```bash
git diff --name-only <base>...<target>
```
只审计变更的 Dockerfile / compose / K8s YAML 文件，但需 Read 完整文件理解上下文。

### 最近变更模式
```bash
git log --since="7 days ago" --name-only --pretty=format: | sort -u
```
筛选容器相关文件变更。

---

## 审计方法论

### Step 1: 侦察 — 发现所有容器配置文件

```bash
# 发现 Dockerfile
Glob("**/Dockerfile*")

# 发现 docker-compose
Glob("**/docker-compose*.yml")
Glob("**/docker-compose*.yaml")

# 发现 K8s manifests
Glob("**/k8s/**/*.yml")
Glob("**/k8s/**/*.yaml")
Glob("**/deploy/**/*.yml")
Glob("**/manifests/**/*.yml")
Glob("**/helm/**/*.yaml")
Glob("**/.k8s/**/*.yaml")

# 发现 .dockerignore
Glob("**/.dockerignore")

# CI/CD 中的容器步骤
Glob("**/.github/workflows/*.yml")
Glob("**/.gitlab-ci.yml")
Glob("**/Jenkinsfile*")
```

### Step 2: 正则扫描（必须执行）

对发现的所有文件，逐一执行以下正则检查：

#### Dockerfile 正则
```bash
# D1: Base Image 合规
Grep("^FROM ", glob="*Dockerfile*")                    # 所有 FROM 指令
Grep("FROM.*:latest", glob="*Dockerfile*")              # 禁止 :latest
Grep("FROM.*docker\\.io|FROM.*dockerhub", glob="*Dockerfile*")  # 禁止 Docker Hub 直拉
Grep("^FROM (?!jfrog\\.cmex\\.corp)", glob="*Dockerfile*")      # 必须用内部 registry

# D2: 权限控制
Grep("USER root", glob="*Dockerfile*")                  # 禁止 root 用户
Grep("--privileged", glob="*Dockerfile*")               # 禁止特权模式
Grep("chmod 777|chmod -R 777", glob="*Dockerfile*")     # 过宽文件权限
Grep("sudo ", glob="*Dockerfile*")                      # 容器内不应有 sudo

# D3: 密钥泄露
Grep("COPY.*\\.env|ADD.*\\.env", glob="*Dockerfile*")   # 禁止复制 .env
Grep("ARG.*PASSWORD|ARG.*SECRET|ARG.*TOKEN|ARG.*KEY", glob="*Dockerfile*", -i=true)  # ARG 传密钥
Grep("ENV.*PASSWORD|ENV.*SECRET|ENV.*TOKEN|ENV.*API_KEY", glob="*Dockerfile*", -i=true)  # ENV 硬编码
Grep("COPY.*\\.pem|COPY.*\\.key|COPY.*id_rsa", glob="*Dockerfile*")  # 复制私钥

# D4: 网络/SSH
Grep("EXPOSE 22|sshd|openssh", glob="*Dockerfile*")     # 禁止 SSH
Grep("EXPOSE.*0\\.0\\.0\\.0", glob="*Dockerfile*")      # 不安全绑定

# D5: 最佳实践
Grep("^ADD ", glob="*Dockerfile*")                       # ADD 改用 COPY
Grep("apt-get install(?!.*--no-install-recommends)", glob="*Dockerfile*")  # 缺少 --no-install-recommends
Grep("apk add(?!.*--no-cache)", glob="*Dockerfile*")     # 缺少 --no-cache
Grep("curl.*\\| ?bash|curl.*\\| ?sh|wget.*\\| ?sh", glob="*Dockerfile*")  # pipe to shell
```

#### docker-compose 正则
```bash
# D6: 特权和安全
Grep("privileged: true", glob="*docker-compose*")        # 特权容器
Grep("network_mode: host", glob="*docker-compose*")      # 主机网络
Grep("pid: host", glob="*docker-compose*")               # 主机 PID
Grep("ipc: host", glob="*docker-compose*")               # 主机 IPC
Grep("cap_add:", glob="*docker-compose*")                 # 能力添加（需逐一审查）

# D7: 资源限制
Grep("deploy:", glob="*docker-compose*")                  # 检查是否设了 resources.limits
Grep("mem_limit|memory:", glob="*docker-compose*")        # 内存限制

# D8: 敏感挂载
Grep("docker\\.sock", glob="*docker-compose*")            # Docker socket 挂载
Grep("/etc:/|/var:/|/root:/|/home:/", glob="*docker-compose*")  # 宿主机敏感路径
Grep("volumes:.*:rw", glob="*docker-compose*")            # 可写挂载（检查必要性）

# D9: 密钥
Grep("PASSWORD|SECRET|TOKEN|API_KEY", glob="*docker-compose*", -i=true)  # 明文密钥
```

#### Kubernetes 正则
```bash
# D10: Pod 安全
Grep("privileged: true", glob="**/*.{yml,yaml}")         # 特权容器
Grep("allowPrivilegeEscalation: true", glob="**/*.{yml,yaml}")
Grep("runAsUser: 0|runAsNonRoot: false", glob="**/*.{yml,yaml}")  # root 运行
Grep("hostNetwork: true|hostPID: true|hostIPC: true", glob="**/*.{yml,yaml}")
Grep("hostPath:", glob="**/*.{yml,yaml}")                 # 宿主机路径挂载

# D11: RBAC
Grep("cluster-admin|system:masters", glob="**/*.{yml,yaml}")  # 过宽权限
Grep("resources:.*\\*|verbs:.*\\*", glob="**/*.{yml,yaml}")   # 通配符权限

# D12: 资源限制
Grep("resources:", glob="**/*.{yml,yaml}")                # 检查 limits 存在
Grep("limits:", glob="**/*.{yml,yaml}")                   # CPU/memory limits

# D13: Secrets
Grep("kind: Secret", glob="**/*.{yml,yaml}")              # 明文 Secret（应用 sealed-secrets/external-secrets）
Grep("stringData:", glob="**/*.{yml,yaml}")               # 明文数据
```

### Step 3: 逐文件深度审计

对每个发现的文件，Read 完整内容后按以下检查清单审计：

#### Dockerfile 审计清单

| # | 检查项 | 严重性 | 判定标准 |
|---|--------|--------|---------|
<!-- Replace {{INTERNAL_REGISTRY}} with your organization's internal Docker/package registry URL -->
| F1 | Base Image 来源 | HIGH | FROM 必须以 `{{INTERNAL_REGISTRY}}/docker-local/` 开头 |
| F2 | Image Tag 固定 | MEDIUM | 禁止 `:latest`，必须 pin 到具体版本或 sha256 digest |
| F3 | Minimal Image | LOW | 优先 alpine/distroless/slim，非必要不用 ubuntu/debian full |
| F4 | 非 Root 用户 | HIGH | 最终 stage 必须有 `USER <非root>`；中间 build stage 可以 root |
| F5 | 无 COPY .env | CRITICAL | 禁止 `COPY .env` / `ADD .env` / `COPY *.env` |
| F6 | 无硬编码密钥 | CRITICAL | ENV/ARG 不含密码/token/secret 的实际值（占位符可以） |
| F7 | 无私钥复制 | CRITICAL | 禁止 COPY .pem/.key/id_rsa 到 final stage |
| F8 | 无 SSH | HIGH | 禁止安装/启动 sshd |
| F9 | COPY 优于 ADD | LOW | ADD 只应用于解压 tar，其他场景用 COPY |
| F10 | Multi-stage build | LOW | 有编译步骤时应使用 multi-stage，final stage 不含编译工具 |
| F11 | HEALTHCHECK | LOW | 建议有 HEALTHCHECK 指令 |
| F12 | 层清理 | LOW | `apt-get` 后有 `rm -rf /var/lib/apt/lists/*`；`apk add --no-cache` |
| F13 | 无 pipe to shell | HIGH | 禁止 `curl|bash` / `wget|sh` |
| F14 | .dockerignore 存在 | MEDIUM | 项目根目录必须有 .dockerignore，排除 .git/.env/node_modules/*.key |
| F15 | Build secrets 不泄露 | HIGH | Multi-stage 中 build stage 的 ARG/密钥不能出现在 final stage 的层中 |

#### docker-compose 审计清单

| # | 检查项 | 严重性 | 判定标准 |
|---|--------|--------|---------|
| C1 | 无 privileged | CRITICAL | 禁止 `privileged: true`（除非有书面批准） |
| C2 | 最小 cap_add | HIGH | 只允许: NET_BIND_SERVICE, NET_RAW（如需网络诊断）。SYS_ADMIN/ALL 禁止 |
| C3 | 资源限制 | HIGH | 每个 service 必须有 `deploy.resources.limits.memory` 和 `cpus` |
| C4 | 无 host 网络 | HIGH | 禁止 `network_mode: host`（除 monitoring agent） |
| C5 | Docker socket 审查 | HIGH | `/var/run/docker.sock` 挂载必须注释说明原因，确认无替代方案 |
| C6 | 无宿主机敏感路径 | CRITICAL | 禁止挂载 `/etc`、`/var`、`/root`、`/home` |
| C7 | 环境变量无明文密钥 | HIGH | `environment:` 中密钥必须引用变量 `${VAR}` 或 `.env`，不能明文写入 |
| C8 | 端口暴露最小化 | MEDIUM | 仅暴露必要端口；内部服务不绑定到 `0.0.0.0`（用 `127.0.0.1:port:port`） |
| C9 | restart 策略 | LOW | 使用 `unless-stopped` 或 `on-failure`，避免 `always`（防崩溃循环） |
| C10 | read_only | LOW | 建议 `read_only: true` + `tmpfs` 挂载运行时目录 |

#### Kubernetes 审计清单

| # | 检查项 | 严重性 | 判定标准 |
|---|--------|--------|---------|
| K1 | securityContext | HIGH | Pod 必须有 `securityContext.runAsNonRoot: true` |
| K2 | allowPrivilegeEscalation | HIGH | 必须 `false` |
| K3 | readOnlyRootFilesystem | MEDIUM | 建议 `true`，用 emptyDir 做运行时写入 |
| K4 | 资源 limits | HIGH | 必须设 `resources.limits.cpu` 和 `memory` |
| K5 | 资源 requests | MEDIUM | 必须设 `resources.requests`（调度保障） |
| K6 | 无 hostPath | HIGH | 禁止 `hostPath` 挂载（用 PVC 替代） |
| K7 | 无 hostNetwork/PID/IPC | HIGH | 禁止 `hostNetwork`/`hostPID`/`hostIPC` |
| K8 | ServiceAccount | MEDIUM | `automountServiceAccountToken: false`（除非需要 API 访问） |
| K9 | RBAC 最小化 | HIGH | 禁止绑定 `cluster-admin`；使用最小权限 Role |
| K10 | Secret 管理 | HIGH | 禁止 kind: Secret + stringData 明文；用 sealed-secrets/external-secrets |
| K11 | NetworkPolicy | MEDIUM | 建议有 NetworkPolicy 限制 Pod 间通信 |
| K12 | Ingress 安全 | MEDIUM | 检查 TLS 配置、Host/Path 限制 |
| K13 | Image 来源 | HIGH | 同 F1，`image:` 必须用内部 registry |
| K14 | Image tag | MEDIUM | 同 F2，禁止 `:latest` |

### Step 4: 跨文件一致性检查

检查 Dockerfile 和 compose/K8s 之间的一致性：

1. **Dockerfile 设了 USER 但 compose 用 `user: root` 覆盖** → CRITICAL
2. **Dockerfile EXPOSE 的端口和 compose ports 不匹配** → INFO（可能是有意为之）
3. **Multi-stage build 的 final stage image 是否和 compose/K8s 的 image 匹配**
4. **.dockerignore 是否排除了 .env，但 compose 中又 COPY 了** → 交叉检查

### Step 5: 攻防验证

对每个发现的问题，验证：
- **攻击方**：该配置是否真的可被利用？（例如：`privileged: true` 在隔离网络中风险降低但仍不推荐）
- **防御方**：是否有其他层的防护？（例如：K8s PodSecurityPolicy/PodSecurityAdmission 可能已限制 privileged）

### Step 6: 覆盖评估

| # | 维度 | 已覆盖? |
|---|------|---------|
| D1 | Base Image 合规（来源 + 版本） | [ ] |
| D2 | 权限控制（root/privileged/capabilities） | [ ] |
| D3 | 资源限制（memory/cpu） | [ ] |
| D4 | 网络安全（host network/端口暴露/SSH） | [ ] |
| D5 | 密钥管理（.env/硬编码/build args） | [ ] |
| D6 | 文件安全（.dockerignore/敏感挂载/volume） | [ ] |
| D7 | Dockerfile 最佳实践（multi-stage/COPY/HEALTHCHECK） | [ ] |
| D8 | K8s 安全上下文（securityContext/RBAC/SA） | [ ] |
| D9 | 供应链（image CVE/pipe-to-shell/untrusted sources） | [ ] |

D1-D6 必须全部覆盖，D7-D9 建议覆盖。

---

## 误报过滤

### Kill Switch 条件

| 场景 | 判定 |
|------|------|
| `USER root` 在 multi-stage 的 **非 final stage** | 安全（build stage 可以 root） |
| `ADD` 用于 `.tar.gz` 文件 | 安全（ADD 的合法用途） |
| `cap_add: NET_RAW` 用于网络诊断容器 | 降级为 LOW |
| `docker.sock` 挂载有注释说明且服务有访问控制 | 降级为 MEDIUM |
| `privileged: true` 在标注为 CI runner / 一次性 job 的容器 | 降级为 MEDIUM（仍需报告） |
| `hostPath` 用于 DaemonSet 的日志收集 | 降级为 LOW |
| `cluster-admin` 绑定到 CI/CD ServiceAccount 且有命名空间限制 | 降级为 MEDIUM |
| compose 中 `environment:` 的值是 `${VAR}` 引用（非明文） | 安全 |
| ARG 用于 build 阶段且 final stage 不继承 | 安全 |

### 常见误报模式

1. **Base image 为 `FROM python:3.11-slim`**：Docker Hub 官方镜像。在内部 registry 未 mirror 的情况下，标记为 MEDIUM（建议迁移）而非 CRITICAL
2. **`EXPOSE 8080`**：EXPOSE 只是声明，不等于端口对外开放，需结合 compose/K8s 检查实际暴露
3. **`ENV APP_SECRET=changeme`**：如果是占位符/默认值且有文档说明需替换，降级为 LOW

---

## 公司特定规则

### 内部 Registry 规范

| 规则 | 要求 |
|------|------|
| Base Image 来源 | `{{INTERNAL_REGISTRY}}/docker-local/` 或 `{{INTERNAL_REGISTRY}}/docker-remote/`（mirror） |
| 禁止来源 | 直接 `docker.io/`、`ghcr.io/`、`quay.io/`（需通过内部 mirror） |
| Tag 格式 | 必须 pin 到版本号（如 `python:3.11-slim`），最佳实践是 digest（`@sha256:...`） |

### 允许的 cap_add 白名单

| Capability | 允许场景 | 审查要求 |
|-----------|---------|---------|
| NET_BIND_SERVICE | 绑定低端口 | LOW |
| NET_RAW | 网络诊断/安全测试 | 需注释说明 |
| SYS_PTRACE | 调试容器（仅 dev） | 禁止进入生产 |
| 其他任何 | — | 默认禁止，需安全团队审批 |

---

## 审计路由表

| 审计目标 | 读取文件 |
|---------|---------|
| Dockerfile 安全 | checks/dockerfile-security.md |
| docker-compose 安全 | checks/compose-k8s-security.md |
| Kubernetes 部署安全 | checks/compose-k8s-security.md |
| 密钥和供应链 | checks/secrets-supply-chain.md |
| 全量审计 | 依次读取所有 checks/ |

已知问题对照：Read known-issues/common-vulnerabilities.md

---

## 输出格式

以 JSON 数组输出所有发现，放在 ```json ... ``` 代码块中：

```json
[
  {
    "title": "容器以 root 用户运行",
    "severity": "HIGH",
    "file": "Dockerfile",
    "line": 1,
    "description": "Dockerfile 缺少 USER 指令，容器默认以 root 运行。攻击者突破应用后直接获得 root 权限，可逃逸到宿主机。",
    "recommendation": "在最终 stage 添加非 root 用户：\nRUN addgroup -S app && adduser -S app -G app\nUSER app",
    "cwe_id": "CWE-250"
  }
]
```

每个 finding 字段：
- `title`：中文简述
- `severity`：CRITICAL / HIGH / MEDIUM / LOW
- `file`：文件路径
- `line`：行号
- `description`：漏洞原理和利用方式
- `recommendation`：修复建议（含代码示例）
- `cwe_id`：CWE 编号

**重要**：最后一条消息必须是完整的 findings JSON，不要在 JSON 之后输出其他内容。
