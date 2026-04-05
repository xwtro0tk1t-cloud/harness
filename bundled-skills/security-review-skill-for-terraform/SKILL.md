---
name: security-review-skill-for-terraform
description: 审计 Terraform / IaC 代码安全（AWS 基础设施）。检测硬编码凭据、过宽 Security Group(0.0.0.0/0)、IAM 权限过大(Action/Resource *)、S3 公开访问、RDS 未加密/公开、State 文件泄露、ECS/EKS 容器特权、CloudTrail/VPC FlowLog 缺失、不安全 Provider/Module 引用等。当审计 Terraform 代码、IaC 安全评审、AWS 云基础设施配置检查、GitOps 安全审计时使用。支持 HCL(.tf)、Terraform JSON、tfvars、Terragrunt(HCL) 代码。
---

# Terraform / AWS IaC Security Review

## 技术栈背景

Terraform (HCL) 基础设施即代码安全审计，**聚焦 AWS Provider**。

**审计范围**：
- `.tf` 文件（HCL 资源定义）
- `.tfvars` / `terraform.tfvars`（变量值文件）
- `backend.tf` / `provider.tf`（后端和 Provider 配置）
- `modules/`（自定义和第三方模块）
- `terragrunt.hcl`（如使用 Terragrunt）
- `.terraform.lock.hcl`（Provider 锁定文件）
- CI/CD pipeline 中的 Terraform 步骤

**关键审计维度**：
- D1: 凭据与密钥管理
- D2: 网络安全（Security Group / NSG / Firewall）
- D3: IAM 与访问控制
- D4: 加密（静态 + 传输）
- D5: 公开访问与暴露面
- D6: State 文件安全
- D7: Provider 与 Module 供应链
- D8: 容器与计算资源安全
- D9: 日志、监控与合规
- D10: Terraform 运行时安全

## 审计模式

触发 skill 后，**首先**用 AskUserQuestion 询问用户审计模式：

**问题**: "选择审计模式"
**选项**:
1. **全量审计** — 扫描指定目录/模块的全部 .tf 文件
2. **PR/分支审计** — 只扫描 Terraform 变更（`git diff` 中的 .tf/.tfvars 文件）
3. **最近变更审计** — 扫描最近 N 天/N 个 commit 的 .tf 变更

如果用户 prompt 中已明确指定模式，跳过询问。

### PR/分支模式

**Step 0: 确定 diff 范围**
```bash
git diff --name-only <base>...<target> -- '*.tf' '*.tfvars' 'terragrunt.hcl'
```

**Step 0.1: 范围分析**
1. 将改动 .tf 文件按模块/目录分类
2. 对每个改动文件：Read 完整文件 + 识别新增/修改的 resource block
3. 检查相关 variable/output/data source 引用链

---

## 审计方法

**核心原则**：宁可漏过也不误报。所有发现必须基于实际代码。IaC 审计特点：**配置即代码**——缺失安全配置本身就是漏洞。

### Step 1: 侦察阶段

1. **识别 Provider**：`required_providers` block → AWS（主要）/ Kubernetes / Helm
2. **识别 Backend**：`backend` block → S3（推荐）/ Consul / Local
3. **资源清单**：列出所有 `resource` 和 `data` 类型，构建攻击面
4. **模块依赖**：`module` block 的 source 属性 → 本地/Registry/Git
5. **变量流**：`variable` → `locals` → `resource` 属性的数据流

### Step 2: 正则扫描（必须执行）

根据下方"审计正则速查"逐条 Grep。IaC 正则扫描是核心检测手段——Terraform 安全问题大多是**配置模式匹配**。

### Step 3: 双轨审计

**Sink-driven（找危险配置）**：
- 过宽 CIDR（0.0.0.0/0）、通配符 IAM 权限（`*`）、公开存储桶
- 硬编码凭据、明文密码、未加密资源

**Control-driven（找缺失的安全控制）**：
- 存储资源无加密？计算资源无 IAM role？日志未启用？
- **缺失即脆弱**：应有的安全属性未设置 → 漏洞

### Step 4: 数据流分析

IaC 数据流 = **变量传播**：
```
variable "db_password" → local.config → resource.aws_db_instance.password
                       → tfvars 文件中是否明文？
                       → State 文件中是否存储？
```

追踪：
1. `variable` 定义是否标记 `sensitive = true`
2. 变量值来源：tfvars / 环境变量 / Vault / SSM
3. 变量是否传入不安全的属性（如 `user_data` 脚本）

### Step 5: 跨模块分析

- 子模块 output 是否暴露敏感值？
- 父模块是否信任子模块输出用于安全决策？
- `terraform_remote_state` 读取是否暴露其他环境的敏感数据？

### Step 6: 攻防对抗验证

**攻击方**：如果获得对此基础设施的只读/读写权限，能做什么？
**防御方**：是否有 WAF/SecurityGroup/NACL/IAM boundary 阻止？

### Step 7: 覆盖评估
- [ ] 凭据与密钥（硬编码/明文/State泄露）
- [ ] 网络安全（SG/NACL/防火墙规则）
- [ ] IAM 权限（最小权限/通配符/跨账户）
- [ ] 加密（存储/传输/密钥管理）
- [ ] 公开访问（S3/RDS/端点）
- [ ] State 文件（远程后端/加密/访问控制）
- [ ] Module 供应链（来源/版本/完整性）
- [ ] 容器/计算（特权/root/资源限制）
- [ ] 日志监控（CloudTrail/VPC FlowLog/审计）
- [ ] 运行时安全（Provider 认证/CI 权限）

### 误报识别
- `0.0.0.0/0` 在 **egress** 规则中通常是合理的（出站全放行）
- `description` 字段中包含密码样例字符串不是凭据泄露
- `terraform.tfvars.example` 中的占位值不是真实凭据
- `data.aws_iam_policy_document` 中 `actions = ["s3:GetObject"]` + `resources = ["*"]` 对只读 S3 可能是合理的
- `count = 0` 或 `for_each = {}` 的资源不会实际创建
- `dynamic` block 中的 `content` 可能有条件控制

## 优先检查

| 优先级 | 目标 | 原因 |
|--------|------|------|
| P0 | 硬编码凭据/密钥 | 直接泄露即可攻陷 |
| P0 | `0.0.0.0/0` ingress + 敏感端口 | 互联网直接暴露 |
| P0 | IAM `*:*` 权限 | 等同管理员，极度危险 |
| P1 | S3 公开访问 | 数据泄露 |
| P1 | 数据库/存储未加密 | 合规 + 数据保护 |
| P1 | State 文件无加密/无远程后端 | State 含所有密钥 |
| P2 | 模块来源未锁版本 | 供应链攻击 |
| P2 | 日志/监控缺失 | 无法检测攻击 |
| P2 | 容器特权/root | 容器逃逸 |

## 通用漏洞检查

### D1: 凭据与密钥管理

**硬编码凭据**：
```hcl
# 危险：明文密码
resource "aws_db_instance" "main" {
  password = "MyS3cretP@ss!"  # 硬编码
}

resource "aws_iam_access_key" "user" {
  user = aws_iam_user.example.name
  # access_key/secret_key 会存入 State
}

# 安全：引用 Secrets Manager
resource "aws_db_instance" "main" {
  password = data.aws_secretsmanager_secret_version.db.secret_string
}

# 安全：标记 sensitive
variable "db_password" {
  type      = string
  sensitive = true
}
```

**State 文件中的密钥**：
```hcl
# 危险：本地 State（含所有资源属性，包括密码）
terraform {
  backend "local" {}  # State 文件存在本地磁盘
}

# 安全：远程 State + 加密
terraform {
  backend "s3" {
    bucket         = "my-tf-state"
    key            = "prod/terraform.tfstate"
    encrypt        = true
    dynamodb_table = "tf-locks"
  }
}
```

### D2: 网络安全

**过宽 Security Group**：
```hcl
# 危险：全开入站
resource "aws_security_group_rule" "bad" {
  type        = "ingress"
  from_port   = 0
  to_port     = 65535
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}

# 危险：SSH/RDP 对公网开放
resource "aws_security_group_rule" "ssh_open" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]  # SSH 对全互联网开放
}

# 安全：限制到 VPN/堡垒机 IP
resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]  # 仅内网
}
```

**VPC Endpoint 缺失**：
```hcl
# 危险：S3 流量走公网（可被拦截）
# 无 aws_vpc_endpoint for s3

# 安全：VPC Endpoint 限制 S3 访问
resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.main.id
  service_name = "com.amazonaws.ap-southeast-1.s3"
  route_table_ids = [aws_route_table.private.id]
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:*"
      Resource  = ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
    }]
  })
}
```

### D3: IAM 与访问控制

**过宽 IAM 策略**：
```hcl
# 危险：管理员权限
resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"           # 全部操作
      Resource = "*"           # 全部资源
    }]
  })
}

# 危险：通配符 Action
resource "aws_iam_policy" "too_wide" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"       # S3 全部操作
      Resource = "*"
    }]
  })
}

# 安全：最小权限
resource "aws_iam_policy" "minimal" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/*"
      ]
    }]
  })
}
```

**AssumeRole 信任过宽**：
```hcl
# 危险：任何 AWS 账户可 AssumeRole
resource "aws_iam_role" "bad" {
  assume_role_policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }  # 任何人
      Action    = "sts:AssumeRole"
    }]
  })
}
```

### D4: 加密

**存储未加密**：
```hcl
# 危险：S3 无服务端加密
resource "aws_s3_bucket" "data" {
  bucket = "sensitive-data"
  # 缺少 server_side_encryption_configuration
}

# 危险：RDS 未加密
resource "aws_db_instance" "main" {
  storage_encrypted = false  # 或缺失此属性
}

# 危险：EBS 未加密
resource "aws_ebs_volume" "data" {
  encrypted = false
}

# 安全
resource "aws_s3_bucket_server_side_encryption_configuration" "enc" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
```

### D5: 公开访问与暴露面

**S3 公开**：
```hcl
# 危险：S3 公开读
resource "aws_s3_bucket_acl" "public" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}

# 危险：S3 公开访问未阻止
resource "aws_s3_bucket_public_access_block" "bad" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# 安全
resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

**数据库公开**：
```hcl
# 危险
resource "aws_db_instance" "public_db" {
  publicly_accessible = true
}

# 危险：ElastiCache 无加密
resource "aws_elasticache_replication_group" "bad" {
  at_rest_encryption_enabled = false
  transit_encryption_enabled = false
}

# 危险：EKS API Server 公开
resource "aws_eks_cluster" "public" {
  vpc_config {
    endpoint_public_access  = true
    public_access_cidrs     = ["0.0.0.0/0"]
  }
}
```

### D6: 配置与部署

**Provider 版本未锁定**：
```hcl
# 危险：无版本约束
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      # 缺少 version 约束
    }
  }
}

# 安全
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
```

**调试/开发模式**：
```hcl
# 危险：输出敏感值
output "db_password" {
  value = aws_db_instance.main.password
  # 缺少 sensitive = true
}
```

### D9: 业务逻辑（资源配置）

**资源无备份/版本化**：
```hcl
# 危险：S3 无版本化（数据可被覆盖/删除）
resource "aws_s3_bucket_versioning" "none" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Disabled"
  }
}

# 危险：RDS 无备份
resource "aws_db_instance" "no_backup" {
  backup_retention_period = 0
}
```

**无删除保护**：
```hcl
# 危险：生产数据库可被 terraform destroy 直接删除
resource "aws_db_instance" "prod" {
  deletion_protection = false  # 或缺失
}
```

## 深度漏洞模式

### HCL 深度 Sink/Source

**危险 Sink（安全敏感属性）**：
| 类别 | Resource.Attribute | 风险 |
|------|-------------------|------|
| 凭据 | `*.password`, `*.secret_key`, `*.access_key`, `*.token` | 硬编码凭据 |
| 网络 | `*.cidr_blocks`, `*.source_ranges`, `*.ip_range_filter` | 过宽网络 |
| IAM | `*.policy` (JSON), `*.actions`, `*.principal` | 权限过大 |
| 加密 | `*.encrypted`, `*.kms_key_id`, `*.sse_algorithm` | 未加密 |
| 公开 | `*.publicly_accessible`, `*.acl`, `*.public_access` | 公开暴露 |
| 计算 | `*.privileged`, `*.user_data`, `*.root_block_device` | 容器/实例安全 |
| 日志 | `*.logging`, `*.access_logs`, `*.trail` | 监控缺失 |

**Source（配置值来源）**：
- `variable` 定义 → 检查是否 `sensitive = true`
- `terraform.tfvars` / `*.auto.tfvars` → 检查是否含明文凭据
- `data` source → 检查是否从不可信源读取
- `locals` → 检查是否拼接生成不安全配置
- `templatefile()` / `user_data` → 检查内嵌脚本安全

### 审计正则速查（Step 2 必须执行）

以下正则在 Step 2 **必须逐条执行** Grep：

#### HCL 正则（`*.tf` + `*.tfvars` 文件）

| # | 类型 | 正则 | 说明 |
|---|------|------|------|
| T1 | 硬编码凭据 | `(?:password\|secret\|token\|api_key\|access_key)\s*=\s*"[^"]{8,}"` | 明文凭据赋值 |
| T2 | 硬编码凭据 | `(?:AKIA\|ABIA\|ACCA\|ASIA)[A-Z0-9]{16}` | AWS Access Key ID |
| T3 | 硬编码凭据 | `(?:BEGIN\s+(?:RSA\|DSA\|EC\|OPENSSH)\s+PRIVATE\s+KEY)` | 私钥文件内容 |
| T4 | 过宽网络 | `(?:cidr_blocks\|source_ranges\|ip_range_filter)\s*=\s*\[?"?0\.0\.0\.0/0` | 全开入站 CIDR |
| T5 | 过宽网络 | `(?:cidr_blocks\|source_ranges)\s*=\s*\[?"::/0` | IPv6 全开 |
| T6 | 敏感端口 | `(?:from_port\|to_port)\s*=\s*(?:22\|3389\|3306\|5432\|6379\|27017\|9200)` | SSH/RDP/DB 端口 |
| T7 | IAM 通配符 | `"Action"\s*:\s*(?:"\*"\|\["\*"\])` | IAM 全部操作 |
| T8 | IAM 通配符 | `"Resource"\s*:\s*(?:"\*"\|\["\*"\])` | IAM 全部资源 |
| T9 | IAM 通配符 | `actions\s*=\s*\["\*"\]` | data.aws_iam_policy_document 通配 |
| T10 | IAM Principal | `"Principal"\s*:\s*(?:"\*"\|\{"AWS"\s*:\s*"\*"\})` | 任何人可访问 |
| T11 | S3 公开 | `acl\s*=\s*"(?:public-read\|public-read-write\|authenticated-read)"` | S3 公开 ACL |
| T12 | S3 公开 | `block_public_acls\s*=\s*false` | 未阻止公开访问 |
| T13 | 未加密 | `(?:storage_encrypted\|encrypted)\s*=\s*false` | 存储未加密 |
| T14 | 未加密 | `(?:at_rest_encryption_enabled\|encryption_at_rest)\s*=\s*false` | 静态加密关闭 |
| T15 | 公开DB | `publicly_accessible\s*=\s*true` | 数据库公开 |
| T16 | 版本缺失 | `source\s*=\s*"[^"]+"\s*$` + 同一 block 无 `version` | Provider/Module 无版本 |
| T17 | 特权容器 | `privileged\s*=\s*true` | 容器特权模式 |
| T18 | Root 容器 | `user\s*=\s*"?(?:0\|root)"?` | 容器 root 用户 |
| T19 | 无删除保护 | `deletion_protection\s*=\s*false` | 无删除保护 |
| T20 | 敏感输出 | `output\s+"[^"]*(?:password\|secret\|key\|token)[^"]*"` + 无 `sensitive = true` | 输出敏感值未标记 |
| T21 | 本地后端 | `backend\s+"local"` | 本地 State（不安全） |
| T22 | State 未加密 | `encrypt\s*=\s*false` | 远程 State 未加密 |
| T23 | 无备份 | `backup_retention_period\s*=\s*0` | RDS 无备份 |
| T24 | 日志关闭 | `(?:logging\|access_logs?\|enable_logging)\s*=\s*false` | 日志/审计关闭 |
| T25 | TLS 版本 | `(?:minimum_tls_version\|tls_version)\s*=\s*"(?:TLS1_0\|TLSv1\|TLSv1\.0\|1\.0)"` | 过旧 TLS |
| T26 | Sensitive 缺失 | `variable\s+"[^"]*(?:password\|secret\|token\|key)[^"]*"\s*\{` + 无 `sensitive\s*=\s*true` | 敏感变量未标记 |
| T27 | User Data | `user_data\s*=\s*` | 检查 EC2 user_data 内容 |
| T28 | 模块来源 | `source\s*=\s*"(?:git::\|github\.com\|bitbucket\.org)` | Git 远程模块（检查版本锁定） |
| T29 | SSM 明文 | `type\s*=\s*"String"` (aws_ssm_parameter) | SSM Parameter 应使用 SecureString |
| T30 | GuardDuty | 检查 `aws_guardduty_detector` 是否存在 | 威胁检测未启用 |
| T31 | WAF 缺失 | 检查公网 ALB 是否关联 `aws_wafv2_web_acl_association` | 无 WAF 防护 |
| T32 | CloudFront HTTP | `viewer_protocol_policy\s*=\s*"allow-all"` | CloudFront 允许 HTTP |
| T33 | API GW 无认证 | `authorization\s*=\s*"NONE"` | API Gateway 无认证 |
| T34 | ECR 扫描 | 检查 `aws_ecr_repository` 是否有 `image_scanning_configuration` | 容器镜像无扫描 |

> 执行方式：对每条正则，Grep 搜索目标目录全部 `.tf` / `.tfvars` 文件。匹配结果逐一分析。零匹配 = 该类型安全。

### 框架威胁面

#### Terraform 核心威胁面

| 威胁 | 检查点 |
|------|--------|
| **State 文件泄露** | State 含所有资源属性（包括密码、密钥）。检查 backend 配置、State 文件权限 |
| **Provider 认证** | Provider 凭据如何提供？硬编码/环境变量/AssumeRole？ |
| **Plan/Apply 权限** | CI/CD 中 terraform apply 的权限是否过大？ |
| **Module 供应链** | 第三方模块是否可信？版本是否锁定？ |
| **Drift 检测** | 手动变更是否会被覆盖或遗漏？ |
| **Import 安全** | `terraform import` 是否引入了不安全的既有资源？ |

#### AWS 特定威胁面

| 威胁 | 资源类型 | 检查属性 |
|------|---------|---------|
| S3 数据泄露 | `aws_s3_bucket` | `acl`, `public_access_block`, `policy` |
| RDS 暴露 | `aws_db_instance` | `publicly_accessible`, `storage_encrypted` |
| SG 过宽 | `aws_security_group_rule` | `cidr_blocks` + `from_port` |
| IAM 提权 | `aws_iam_policy` | `Action: *`, `Resource: *` |
| Lambda 权限 | `aws_lambda_function` | `role`, `environment.variables` |
| ECS 特权 | `aws_ecs_task_definition` | `privileged`, `user` |
| CloudTrail 缺失 | `aws_cloudtrail` | 资源是否存在 |

#### AWS 高级服务威胁面

| 威胁 | 资源类型 | 检查属性 |
|------|---------|---------|
| Secrets 明文 | `aws_ssm_parameter` | `type = "SecureString"` + `key_id` |
| WAF 缺失 | `aws_wafv2_web_acl` | 是否关联到公网 ALB/API Gateway/CloudFront |
| CloudFront 不安全 | `aws_cloudfront_distribution` | `viewer_protocol_policy`, `minimum_protocol_version` |
| API Gateway 公开 | `aws_api_gateway_rest_api` | 认证方式、throttling、WAF 关联 |
| Route53 DNSSEC | `aws_route53_zone` | DNSSEC 签名是否启用 |
| SNS/SQS 未加密 | `aws_sns_topic` / `aws_sqs_queue` | `kms_master_key_id` |
| GuardDuty 未启用 | `aws_guardduty_detector` | 资源是否存在 |
| Security Hub 未启用 | `aws_securityhub_account` | 资源是否存在 |
| Config 未启用 | `aws_config_configuration_recorder` | 资源是否存在 |
| SCP 缺失 | `aws_organizations_policy` | Service Control Policy 限制危险操作 |

#### Kubernetes (EKS) 威胁面

| 威胁 | 检查点 |
|------|--------|
| 特权容器 | `privileged = true`, `allow_privilege_escalation = true` |
| HostPath 挂载 | `host_path` volume mount |
| 默认 SA | `automount_service_account_token = true` |
| 公开 API Server | `endpoint_public_access = true` + `public_access_cidrs = ["0.0.0.0/0"]` |
| 过宽 RBAC | `cluster-admin` binding |

## 误报过滤增强

**Kill Switch 条件**（命中任一 → 非漏洞）：
1. **Egress 规则 0.0.0.0/0**：出站全放行是常见且合理的做法 → 仅当 `type = "ingress"` 时报告
2. **count = 0 / for_each = {}**：资源不会实际创建 → 跳过
3. **example/template 文件**：`*.example`, `*.template`, `*.sample` → 跳过
4. **注释中的值**：`# password = "old_value"` → 非生效配置
5. **条件加密**：`encrypted = var.enable_encryption`（变量控制）→ 检查变量默认值
6. **data source 的 IAM policy**：`data.aws_iam_policy_document` 中只读操作 + `*` 资源可能合理 → 需结合上下文判断
7. **Dev/Staging 环境**：路径含 `dev/`, `staging/`, `sandbox/` → 降低严重性但仍报告

**需要二次确认的模式**：
- `cidr_blocks = var.allowed_cidr` → 需检查变量默认值和实际 tfvars
- `kms_key_id = ""` 或缺失 → 某些资源默认使用 AWS managed key，需确认
- `lifecycle { prevent_destroy = false }` → 需确认是否是生产资源

## 污点分析指南

### IaC 变量追踪

```
Source: variable 定义 / tfvars / 环境变量 / data source
Propagation: locals 计算 / module 参数传递 / templatefile()
Sink: resource 安全敏感属性（见上方 Sink 表）
```

**追踪规则**：
1. `variable` 含 `password/secret/token/key` → 标记为敏感数据流
2. 追踪该变量在 `locals` / `resource` / `module` 中的所有引用
3. 检查最终 sink：是否明文存储？是否输出？是否传入 user_data？
4. 检查 State：该值是否会出现在 State 文件中？（几乎所有 resource 属性都会）

## 审计路由

根据审计目标，**必须**先 Read 对应检查文件再开始审计：

| 代码路径模式 | 加载 checks/ |
|-------------|-------------|
| `**/sg*.tf`, `**/security*.tf`, `**/network*.tf`, `**/firewall*.tf` | network-security.md |
| `**/iam*.tf`, `**/role*.tf`, `**/policy*.tf` | iam-access-control.md |
| `**/s3*.tf`, `**/rds*.tf`, `**/storage*.tf`, `**/db*.tf` | data-storage-security.md |
| `**/ecs*.tf`, `**/eks*.tf`, `**/k8s*.tf`, `**/lambda*.tf` | compute-container-security.md |
| `backend.tf`, `provider.tf`, `versions.tf`, `modules/` | state-provider-module.md |
| `**/cloudtrail*.tf`, `**/logging*.tf`, `**/monitoring*.tf` | logging-compliance.md |

| 审计目标 | 读取文件 |
|---------|---------|
| 网络安全 / SG / 防火墙 | checks/network-security.md |
| IAM / 权限 / 角色 | checks/iam-access-control.md |
| 数据存储 / S3 / RDS / 加密 | checks/data-storage-security.md |
| 容器 / ECS / EKS / K8s | checks/compute-container-security.md |
| State / Provider / Module | checks/state-provider-module.md |
| 日志 / 监控 / 合规 | checks/logging-compliance.md |
| 全量审计 | 按优先级依次读取所有 checks/ |

已知问题对照：审计完成后 Read `known-issues/attack-patterns.md` 对照攻击模式。

## 输出格式

```json
{
  "scan_mode": "full | pr | recent_changes",
  "diff_scope": {
    "base": "main",
    "target": "feature-branch",
    "changed_files": ["modules/network/main.tf"],
    "related_files": ["modules/network/variables.tf"]
  },
  "findings": [
    {
      "severity": "CRITICAL/HIGH/MEDIUM/LOW",
      "type": "漏洞类型",
      "location": "file:line",
      "in_diff": true,
      "resource": "aws_security_group_rule.ssh_open",
      "description": "SSH 端口(22)对 0.0.0.0/0 开放",
      "current_config": "cidr_blocks = [\"0.0.0.0/0\"]",
      "expected_config": "cidr_blocks = [\"10.0.0.0/8\"]",
      "attack_scenario": "攻击者可从互联网暴力破解 SSH",
      "defense_analysis": "未发现其他网络层防护（WAF/NACL）",
      "remediation": "限制 CIDR 到 VPN/堡垒机 IP 段",
      "cwe": "CWE-284"
    }
  ]
}
```
