# docker-compose & Kubernetes 部署安全检查

## docker-compose 安全

### 特权与能力控制

```yaml
# ❌ CRITICAL: 特权容器
services:
  app:
    privileged: true  # 完全绕过所有隔离，等于 root on host

# ❌ HIGH: 过宽能力
services:
  app:
    cap_add:
      - SYS_ADMIN      # 几乎等于 privileged
      - ALL             # 所有能力

# ✅ 安全: 最小能力 + 移除默认
services:
  app:
    cap_drop:
      - ALL             # 先移除所有
    cap_add:
      - NET_BIND_SERVICE  # 仅添加需要的
    security_opt:
      - no-new-privileges:true
```

**cap_add 白名单审查表**：

| Capability | 风险 | 允许条件 |
|-----------|------|---------|
| NET_BIND_SERVICE | LOW | 需要绑定 <1024 端口 |
| NET_RAW | MEDIUM | 网络诊断/安全扫描工具 |
| NET_ADMIN | HIGH | 网络配置修改（需说明） |
| SYS_PTRACE | HIGH | 仅 dev/debug 环境 |
| SYS_ADMIN | CRITICAL | 禁止（等于 privileged） |
| ALL | CRITICAL | 禁止 |

### 资源限制

```yaml
# ❌ HIGH: 无资源限制（单容器可耗尽宿主机资源）
services:
  app:
    image: myapp:latest

# ✅ 安全: 明确资源限制
services:
  app:
    image: myapp:1.2.3
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
```

**判定规则**：
- 没有 `deploy.resources.limits` → HIGH
- 有 limits 但没有 `memory` → HIGH（OOM 风险）
- 有 limits 但没有 `cpus` → MEDIUM

### 网络安全

```yaml
# ❌ HIGH: 主机网络（容器共享宿主机网络栈）
services:
  app:
    network_mode: host

# ❌ HIGH: 暴露宿主机 PID/IPC
services:
  app:
    pid: host
    ipc: host

# ❌ MEDIUM: 不必要的端口暴露到所有接口
services:
  redis:
    ports:
      - "6379:6379"         # 绑定 0.0.0.0

# ✅ 安全: 仅本地绑定
services:
  redis:
    ports:
      - "127.0.0.1:6379:6379"

# ✅ 安全: 内部服务不暴露端口（通过 Docker 网络互通）
services:
  redis:
    expose:
      - "6379"              # 仅容器间可见
```

### Volume 挂载审查

```yaml
# ❌ CRITICAL: 挂载宿主机敏感路径
volumes:
  - /etc:/host-etc
  - /var:/host-var
  - /root:/root
  - /:/host-root          # 最危险：整个文件系统

# ❌ HIGH: Docker socket（需审查必要性）
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
  # 谁需要？为什么？有无替代方案？
  # 允许条件：CI runner、容器编排工具，且必须注释说明

# ✅ 安全: 命名 volume（隔离存储）
volumes:
  - app-data:/app/data
  - redis-data:/data

# ✅ 安全: 只读挂载
volumes:
  - ./config:/app/config:ro
```

**Docker socket 挂载审查清单**：
1. 该服务为什么需要访问 Docker API？
2. 是否有注释说明原因？
3. 能否用更窄的 API 替代（如 Docker API proxy/限流）？
4. 服务本身是否以非 root 运行？（root + docker.sock = 宿主机 root）

### 环境变量密钥

```yaml
# ❌ HIGH: 明文密钥
services:
  app:
    environment:
      - DB_PASSWORD=MySecretPassword123
      - API_KEY=sk-1234567890

# ✅ 安全: 引用 .env 文件（不提交到 git）
services:
  app:
    env_file: .env

# ✅ 安全: 引用环境变量
services:
  app:
    environment:
      - DB_PASSWORD=${DB_PASSWORD}
      - API_KEY=${API_KEY:-}

# ✅ 最佳: Docker secrets
services:
  app:
    secrets:
      - db_password
secrets:
  db_password:
    external: true
```

---

## Kubernetes 安全

### Pod SecurityContext

```yaml
# ❌ 危险: 无 securityContext
spec:
  containers:
    - name: app
      image: myapp:latest

# ✅ 安全: 完整的 securityContext
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
  containers:
    - name: app
      image: {{INTERNAL_REGISTRY}}/docker-local/myapp:1.2.3
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      volumeMounts:
        - name: tmp
          mountPath: /tmp
  volumes:
    - name: tmp
      emptyDir: {}
```

### 资源限制

```yaml
# ❌ HIGH: 无资源限制
containers:
  - name: app
    image: myapp

# ✅ 安全: 明确 requests + limits
containers:
  - name: app
    image: myapp
    resources:
      requests:
        cpu: 100m
        memory: 128Mi
      limits:
        cpu: 500m
        memory: 512Mi
```

### RBAC 最小化

```yaml
# ❌ CRITICAL: cluster-admin 绑定
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: app-admin
roleRef:
  kind: ClusterRole
  name: cluster-admin       # 上帝权限
subjects:
  - kind: ServiceAccount
    name: app-sa

# ❌ HIGH: 通配符权限
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]

# ✅ 安全: 最小权限
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: production
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get"]
```

### ServiceAccount

```yaml
# ❌ MEDIUM: 自动挂载 SA token（不需要时应关闭）
spec:
  serviceAccountName: default
  # automountServiceAccountToken 默认 true

# ✅ 安全: 关闭自动挂载
spec:
  serviceAccountName: app-sa
  automountServiceAccountToken: false
```

### Secret 管理

```yaml
# ❌ HIGH: 明文 Secret 提交到 git
apiVersion: v1
kind: Secret
metadata:
  name: db-secret
type: Opaque
stringData:
  password: MySecretPassword   # base64 不是加密！

# ✅ 安全: 使用 sealed-secrets
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: db-secret
spec:
  encryptedData:
    password: AgByz...encrypted...

# ✅ 安全: 使用 external-secrets
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
spec:
  secretStoreRef:
    name: vault
  data:
    - secretKey: password
      remoteRef:
        key: secret/db
        property: password
```

### NetworkPolicy

```yaml
# ✅ 推荐: 默认拒绝 + 显式允许
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app-ingress
spec:
  podSelector:
    matchLabels:
      app: myapp
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
      ports:
        - port: 8080
```

### Ingress 安全

```yaml
# 检查项:
# 1. TLS 是否配置
# 2. Host 是否限制（非通配符）
# 3. Path 是否最小化

# ❌ MEDIUM: 无 TLS
apiVersion: networking.k8s.io/v1
kind: Ingress
spec:
  rules:
    - host: "*.example.com"   # 通配符域名
      http:
        paths:
          - path: /
            backend: ...

# ✅ 安全: 有 TLS + 限定 host + 限定 path
spec:
  tls:
    - hosts:
        - api.example.com
      secretName: api-tls
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /api
            pathType: Prefix
            backend: ...
```
