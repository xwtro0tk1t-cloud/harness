# Compute & Container Security Checks

> 技术栈：Terraform HCL | 维度：EC2 / ECS / EKS / Lambda / ECR

## 模块背景

计算资源安全覆盖实例配置、容器特权、IAM 角色绑定、user_data 脚本安全。

## 容器特权 (CRITICAL)

**检查项**：
- [ ] ECS task definition 中 `privileged = true`
- [ ] `user = "0"` 或 `user = "root"`
- [ ] `readonlyRootFilesystem = false` 或缺失
- [ ] K8s pod spec 中 `allowPrivilegeEscalation = true`
- [ ] K8s `hostNetwork = true`, `hostPID = true`, `hostIPC = true`
- [ ] K8s `hostPath` volume mount（特别是 `/`, `/etc`, `/var/run/docker.sock`）

**代码模式**：
```hcl
# 危险：ECS 特权容器
resource "aws_ecs_task_definition" "bad" {
  container_definitions = jsonencode([{
    privileged = true
    user       = "root"
  }])
}

# 安全
resource "aws_ecs_task_definition" "secure" {
  container_definitions = jsonencode([{
    privileged             = false
    readonlyRootFilesystem = true
    user                   = "1000"
    linuxParameters = {
      capabilities = { drop = ["ALL"] }
    }
  }])
}
```

## EKS 集群安全 (HIGH)

**检查项**：
- [ ] `endpoint_public_access = true` + `public_access_cidrs = ["0.0.0.0/0"]`（API Server 公开）
- [ ] `endpoint_private_access = true`（是否启用私有访问）
- [ ] 节点组 IAM 角色权限是否过大
- [ ] 是否启用了 Pod Security Standards / Policy
- [ ] Secrets encryption 是否配置（KMS key）
- [ ] 日志类型是否启用（`enabled_cluster_log_types`：api/audit/authenticator）
- [ ] EKS Add-ons 是否使用 IRSA（IAM Roles for Service Accounts）
- [ ] 节点组是否使用 Bottlerocket 或 AL2023 AMI（安全增强）

**代码模式**：
```hcl
# 安全：EKS 私有集群
resource "aws_eks_cluster" "secure" {
  vpc_config {
    endpoint_private_access = true
    endpoint_public_access  = false  # 或限制 CIDR
    public_access_cidrs     = ["10.0.0.0/8"]
  }

  encryption_config {
    provider { key_arn = aws_kms_key.eks.arn }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator"]
}
```

## EC2 实例安全 (HIGH)

**检查项**：
- [ ] `user_data` 是否包含明文凭据/密码
- [ ] `user_data` 脚本是否从不可信 URL 下载并执行（`curl | bash`）
- [ ] `iam_instance_profile` 权限是否过大
- [ ] `metadata_options` 是否限制了 IMDSv2（`http_tokens = "required"`）
- [ ] `associate_public_ip_address` 是否对非公开实例启用
- [ ] `root_block_device.encrypted` 是否为 `true`

**代码模式**：
```hcl
# 危险：user_data 含密钥 + IMDSv1
resource "aws_instance" "bad" {
  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD="secret123"
    curl http://setup.example.com/install.sh | bash
  EOF
}

# 安全：IMDSv2 + 无硬编码
resource "aws_instance" "secure" {
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"  # 强制 IMDSv2
  }
  user_data = templatefile("${path.module}/init.sh.tpl", {
    db_password_arn = aws_secretsmanager_secret.db.arn
  })
}
```

## Lambda 安全 (MEDIUM)

**检查项**：
- [ ] 环境变量是否包含明文凭据
- [ ] IAM 执行角色权限是否最小化
- [ ] VPC 配置是否合理（是否需要私有网络访问）
- [ ] 是否配置了 reserved_concurrent_executions（防止 DDoS 费用爆炸）
- [ ] Runtime 是否过旧

## ECR 容器镜像安全 (MEDIUM)

**检查项**：
- [ ] `aws_ecr_repository` 是否启用 `image_scanning_configuration { scan_on_push = true }`
- [ ] 是否配置了 `aws_ecr_lifecycle_policy`（清理旧镜像）
- [ ] `image_tag_mutability` 是否为 `IMMUTABLE`（防止标签覆盖）
- [ ] 是否启用了 KMS 加密（`encryption_configuration`）

## 资源限制 (LOW)

**检查项**：
- [ ] Auto Scaling Group 是否有 max_size 上限
- [ ] Lambda 是否有并发限制（`reserved_concurrent_executions`）
- [ ] ECS Service 是否有 desired_count 上限
- [ ] 是否设置了 AWS Budget alarm（`aws_budgets_budget`）
