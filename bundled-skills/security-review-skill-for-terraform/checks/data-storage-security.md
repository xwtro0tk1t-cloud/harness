# Data Storage Security Checks

> 技术栈：Terraform HCL | 维度：S3 / RDS / DynamoDB / EBS / ElastiCache / 加密

## 模块背景

存储安全覆盖加密、公开访问、备份、版本化。云存储桶公开是最常见的数据泄露原因。

## S3 公开访问 (CRITICAL)

**检查项**：
- [ ] `aws_s3_bucket_acl` 是否为 `public-read` / `public-read-write`
- [ ] `aws_s3_bucket_public_access_block` 四个属性是否全部 `true`
- [ ] `aws_s3_bucket_policy` 中 `Principal = "*"` 是否存在
- [ ] 账户级别 `aws_s3_account_public_access_block` 是否配置
- [ ] S3 Bucket 是否通过 VPC Endpoint 访问（限制公网路径）

**代码模式**：
```hcl
# 完整的 S3 安全配置
resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true   # 必须
  block_public_policy     = true   # 必须
  ignore_public_acls      = true   # 必须
  restrict_public_buckets = true   # 必须
}

resource "aws_s3_bucket_server_side_encryption_configuration" "enc" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "ver" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration { status = "Enabled" }
}
```

## 存储加密 (HIGH)

**检查项**：
- [ ] `aws_s3_bucket` → 是否有 `server_side_encryption_configuration`
- [ ] `aws_db_instance` → `storage_encrypted = true`
- [ ] `aws_ebs_volume` → `encrypted = true`
- [ ] `aws_dynamodb_table` → `server_side_encryption { enabled = true }`
- [ ] `aws_sqs_queue` → `kms_master_key_id` 是否设置
- [ ] `aws_sns_topic` → `kms_master_key_id` 是否设置
- [ ] `aws_elasticache_replication_group` → `at_rest_encryption_enabled`, `transit_encryption_enabled`
- [ ] `aws_secretsmanager_secret` → 是否存在（优先于 SSM Parameter Store 存储密钥）
- [ ] `aws_ssm_parameter` → `type = "SecureString"`（非 "String"）
- [ ] KMS 密钥是否有轮换策略（`enable_key_rotation = true`）
- [ ] `aws_ebs_encryption_by_default` → 是否启用账户级 EBS 默认加密

## 数据库安全 (HIGH)

**检查项**：
- [ ] `publicly_accessible = true`（RDS/Aurora 公开暴露）
- [ ] `backup_retention_period > 0`（备份启用）
- [ ] `deletion_protection = true`（生产环境必须）
- [ ] `iam_database_authentication_enabled = true`（IAM 认证）
- [ ] `performance_insights_enabled` + `kms_key_id` 设置
- [ ] `storage_encrypted = true`
- [ ] `multi_az = true`（高可用）
- [ ] `skip_final_snapshot = false`（删除前备份）
- [ ] 数据库引擎版本是否过旧

## 版本化与生命周期 (MEDIUM)

**检查项**：
- [ ] S3 版本化是否启用（防止数据覆盖/删除）
- [ ] S3 生命周期规则是否有 MFA Delete
- [ ] DynamoDB 是否启用 Point-in-time Recovery
- [ ] RDS 是否有自动备份
