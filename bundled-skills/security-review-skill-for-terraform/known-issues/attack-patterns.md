# Terraform / IaC 攻击模式参考

## 攻击模式速查表

| 攻击类型 | 手法 | 检查点 |
|---------|------|--------|
| State 文件窃取 | 本地 State 泄露 / S3 公开 / Git 误提交 | backend 配置 + .gitignore |
| 凭据提取 | 从 State 中提取密码/密钥/证书 | State 加密 + Secrets Manager |
| Provider 劫持 | 恶意 Provider 镜像 / 未锁定版本 | .terraform.lock.hcl + 版本约束 |
| Module 后门 | 第三方模块含隐藏资源（如额外 IAM user） | 模块源码审查 + 版本锁定 |
| 网络暴露 | 0.0.0.0/0 + 敏感端口 | SG/Firewall 规则审计 |
| IAM 提权 | 通配符权限 → 创建管理员用户 | IAM 策略最小权限 |
| 数据泄露 | S3 公开 / RDS 公开 / 日志中含敏感数据 | 存储安全 + 公开访问阻止 |
| CI/CD 接管 | Terraform apply 权限过大 / PR 触发 apply | CI 权限隔离 + Plan-only PR |
| Drift 利用 | 手动修改安全配置，Terraform 不感知 | Drift 检测 + 定期 plan |

## 跨维度关联风险

| 组合 | 维度1 | + 维度2 | = 复合攻击 | 严重性 |
|------|-------|---------|-----------|--------|
| State+凭据 | State 文件无加密/公开 | + State 含 DB 密码/IAM key | = 一次泄露获取全部凭据 | CRITICAL |
| SG+DB公开 | 0.0.0.0/0 入站 | + RDS publicly_accessible | = 数据库直接暴露互联网 | CRITICAL |
| IAM+Lambda | Lambda 执行角色过大 | + Lambda 可被外部触发 | = 通过 Lambda 执行管理员操作 | CRITICAL |
| Module+IAM | 未审查的第三方模块 | + 模块创建了额外 IAM user | = 供应链后门 + 持久化访问 | CRITICAL |
| 无日志+SG | CloudTrail 未启用 | + SG 被手动修改 | = 安全变更无审计追踪 | HIGH |
| 无加密+公开 | S3 无加密 | + 公开访问未阻止 | = 明文数据可被任何人下载 | CRITICAL |

**审计时**：发现一个维度的问题后，立即检查关联维度。

## 真实攻击案例

### 1. Capital One S3 数据泄露 (2019)
- **原因**：WAF 配置不当 + IAM Role 权限过大 + S3 无额外访问控制
- **教训**：IAM 最小权限 + S3 访问策略 + VPC 端点限制
- **Terraform 检查**：IAM Role 策略 + S3 bucket policy + VPC endpoint policy

### 2. Uber S3 密钥泄露 (2016)
- **原因**：开发者将 AWS Access Key 硬编码在 GitHub repo
- **教训**：绝不硬编码凭据 + 使用 AssumeRole + 密钥轮换
- **Terraform 检查**：Provider block 无硬编码 + tfvars 不含凭据 + .gitignore

### 3. Tesla Kubernetes Dashboard 暴露 (2018)
- **原因**：K8s Dashboard 无认证 + 公开暴露 → 挖矿
- **教训**：K8s API Server 私有化 + RBAC + 网络策略
- **Terraform 检查**：EKS endpoint_public_access + SG 规则

### 4. Codecov Supply Chain Attack (2021)
- **原因**：CI/CD 脚本被篡改，窃取环境变量中的凭据
- **教训**：CI 中的 Terraform 凭据应使用 OIDC + 短期 token
- **Terraform 检查**：CI pipeline 凭据提供方式

## 绕过技巧

1. **SG 规则拆分**：多条规则各开少量端口，组合后等于全开 → 需检查同一 SG 的所有规则
2. **IPv6 绕过**：只检查 `0.0.0.0/0` 但忽略 `::/0` → 两个都要检查
3. **条件资源**：`count = var.enable_xxx ? 1 : 0`，变量默认值可能开启危险资源 → 检查变量默认值
4. **间接模块引用**：模块 A 引用模块 B，后门在模块 B 中 → 递归检查模块依赖
5. **data source 信任**：`data.terraform_remote_state` 假设其他环境 State 可信 → 检查跨环境信任
6. **lifecycle ignore**：`lifecycle { ignore_changes = [tags, policy] }` 可能导致手动的不安全变更被 Terraform 忽略
7. **Provisioner 后门**：`provisioner "local-exec"` 可执行任意命令 → 检查所有 provisioner block
