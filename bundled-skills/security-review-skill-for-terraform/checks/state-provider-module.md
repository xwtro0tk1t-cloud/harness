# State / Provider / Module Security Checks

> 技术栈：Terraform HCL | 维度：State 文件 / Provider 认证 / Module 供应链

## 模块背景

Terraform State 文件包含所有资源的完整属性（含密码、密钥），是最高价值攻击目标。Provider 和 Module 的供应链安全决定了整个 IaC 的可信度。

## State 文件安全 (CRITICAL)

**背景**：State 文件（terraform.tfstate）以明文 JSON 存储所有资源属性，包括 `aws_db_instance.password`、`aws_iam_access_key.secret`、`tls_private_key.private_key_pem` 等。

**检查项**：
- [ ] 是否使用远程 backend（而非 `backend "local"`）
- [ ] 远程 backend 是否加密（`encrypt = true`）
- [ ] S3 backend 是否配置了 `dynamodb_table`（状态锁）
- [ ] State 存储桶是否有 `public_access_block`（不可公开）
- [ ] State 存储桶是否启用了版本化（误操作可回滚）
- [ ] State 存储桶的 IAM 策略是否限制了访问主体
- [ ] `.terraform/` 目录是否在 `.gitignore` 中
- [ ] `terraform.tfstate` / `terraform.tfstate.backup` 是否在 `.gitignore` 中
- [ ] 是否有 `terraform_remote_state` data source 暴露其他环境的数据

**代码模式**：
```hcl
# 安全的 S3 backend
terraform {
  backend "s3" {
    bucket         = "company-tf-state"
    key            = "prod/infra.tfstate"
    region         = "ap-southeast-1"
    encrypt        = true                 # 必须
    dynamodb_table = "tf-state-lock"      # 必须（防并发）
    kms_key_id     = "arn:aws:kms:..."    # 推荐（CMK 加密）
  }
}
```

**攻击场景**：
1. State 文件泄露（Git/S3 公开）→ 获取所有密码、密钥、ARN → 完全控制基础设施
2. State 无锁 → 并发 apply 导致资源状态不一致

## Provider 认证安全 (CRITICAL)

**检查项**：
- [ ] Provider block 中是否硬编码了 `access_key` / `secret_key` / `token`
- [ ] 是否使用 `assume_role` 或环境变量提供凭据
- [ ] CI/CD 中 Provider 凭据是否通过 OIDC/Workload Identity（而非长期密钥）

**代码模式**：
```hcl
# 危险：硬编码凭据
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# 安全：AssumeRole
provider "aws" {
  assume_role {
    role_arn = "arn:aws:iam::123456789012:role/TerraformRole"
  }
}

# 安全：环境变量（不出现在代码中）
# export AWS_ACCESS_KEY_ID=...
# export AWS_SECRET_ACCESS_KEY=...
provider "aws" {
  region = "ap-southeast-1"
}
```

## Module 供应链安全 (HIGH)

**检查项**：
- [ ] `module.source` 是否来自可信来源（Terraform Registry / 内部 Git）
- [ ] 是否锁定了版本（`version = "x.y.z"` 或 Git `ref`）
- [ ] Git 模块是否指定了 commit hash 或 tag（而非 branch）
- [ ] `.terraform.lock.hcl` 是否提交到 Git（Provider 完整性校验）
- [ ] 第三方模块内容是否已审查（可能包含后门资源）

**代码模式**：
```hcl
# 危险：未锁定版本
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  # 无 version → 每次 init 可能拉取不同版本
}

# 危险：Git branch（可被修改）
module "custom" {
  source = "git::https://github.com/org/module.git?ref=main"
}

# 安全：锁定版本
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"  # 固定版本
}

# 安全：Git commit hash
module "custom" {
  source = "git::https://github.com/org/module.git?ref=abc123def456"
}
```

## Provider 版本锁定 (MEDIUM)

**检查项**：
- [ ] `required_providers` 是否指定了 `version` 约束
- [ ] `required_version` 是否限制了 Terraform CLI 版本
- [ ] `.terraform.lock.hcl` 是否存在且提交到 VCS

## Sensitive 变量标记 (MEDIUM)

**检查项**：
- [ ] 含 `password/secret/token/key` 的 `variable` 是否标记 `sensitive = true`
- [ ] `output` 是否暴露了敏感值（无 `sensitive = true`）
- [ ] `locals` 中是否有敏感值被 `terraform console` 暴露的风险
