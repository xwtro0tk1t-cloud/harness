# Terraform / AWS IaC 高频漏洞案例

> 来源：CIS AWS Foundations Benchmark v3.0、AWS 安全最佳实践、真实事故

## AWS 高频漏洞（CIS Benchmark）

| # | 类别 | 漏洞 | CIS 编号 | Terraform 检查点 |
|---|------|------|---------|-----------------|
| 1 | S3 | 桶公开读/写 | 2.1.1 | `aws_s3_bucket_public_access_block` 四项 `true` |
| 2 | S3 | 无服务端加密 | 2.1.2 | `server_side_encryption_configuration` 存在 |
| 3 | S3 | 无版本化 | 2.1.3 | `aws_s3_bucket_versioning` status = Enabled |
| 4 | IAM | 根账户有 Access Key | 1.4 | 不应创建 `aws_iam_access_key` for root |
| 5 | IAM | 策略 Action/Resource `*` | 1.16 | `aws_iam_policy` JSON 检查 |
| 6 | SG | SSH 0.0.0.0/0 | 5.2 | `aws_security_group_rule` ingress 22 |
| 7 | SG | RDP 0.0.0.0/0 | 5.3 | `aws_security_group_rule` ingress 3389 |
| 8 | CloudTrail | 未启用 | 3.1 | `aws_cloudtrail` 资源存在 |
| 9 | CloudTrail | 无日志加密 | 3.7 | `kms_key_id` 设置 |
| 10 | RDS | 公开访问 | - | `publicly_accessible = false` |
| 11 | RDS | 未加密 | - | `storage_encrypted = true` |
| 12 | EBS | 默认未加密 | 2.2.1 | `aws_ebs_encryption_by_default` enabled |
| 13 | VPC | 无 Flow Logs | 3.9 | `aws_flow_log` 存在 |
| 14 | EKS | 公开 API Server | - | `endpoint_public_access = false` |
| 15 | EC2 | IMDSv1 启用 | - | `http_tokens = "required"` |

## AWS 高级服务安全

| # | 类别 | 漏洞 | Terraform 检查点 |
|---|------|------|-----------------|
| 16 | SSM | Parameter Store 明文存储 | `aws_ssm_parameter` type = `SecureString` |
| 17 | Secrets Manager | 密钥无自动轮换 | `aws_secretsmanager_secret_rotation` 存在 |
| 18 | WAF | 公网 ALB 无 WAF | `aws_wafv2_web_acl_association` 关联到 ALB |
| 19 | CloudFront | 允许 HTTP | `viewer_protocol_policy = "redirect-to-https"` |
| 20 | CloudFront | 旧 TLS 版本 | `minimum_protocol_version = "TLSv1.2_2021"` |
| 21 | API Gateway | 无认证 | `authorization` 非 `NONE` |
| 22 | API Gateway | 无 throttling | `aws_api_gateway_method_settings` 存在 |
| 23 | GuardDuty | 未启用 | `aws_guardduty_detector` 存在 |
| 24 | Security Hub | 未启用 | `aws_securityhub_account` 存在 |
| 25 | Config | 未启用 | `aws_config_configuration_recorder` 存在 |
| 26 | ECR | 镜像无扫描 | `image_scanning_configuration { scan_on_push = true }` |
| 27 | ECR | 标签可变 | `image_tag_mutability = "IMMUTABLE"` |
| 28 | SNS/SQS | 未加密 | `kms_master_key_id` 设置 |
| 29 | ElastiCache | 无传输加密 | `transit_encryption_enabled = true` |
| 30 | DynamoDB | 无 PITR | `point_in_time_recovery { enabled = true }` |

## AWS IAM 提权路径（高频攻击链）

| 攻击路径 | 所需权限 | 效果 |
|---------|---------|------|
| 策略版本提权 | `iam:CreatePolicyVersion` | 创建新版本覆盖为管理员权限 |
| 角色策略注入 | `iam:PutRolePolicy` | 给角色内联管理员策略 |
| Lambda 提权 | `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | 创建以高权限角色运行的 Lambda |
| EC2 提权 | `iam:PassRole` + `ec2:RunInstances` | 启动绑定管理员角色的 EC2 |
| CloudFormation 提权 | `iam:PassRole` + `cloudformation:CreateStack` | 通过 CFN 创建高权限资源 |

## Terraform 运行时高频漏洞

| # | 类别 | 漏洞 | 检查点 |
|---|------|------|--------|
| 1 | State | 本地存储 | `backend "local"` → 改用 S3 |
| 2 | State | 未加密 | `encrypt = false` 或缺失 |
| 3 | State | 无锁定 | `dynamodb_table` 缺失 |
| 4 | State | S3 桶无 public_access_block | State 桶可被公开访问 |
| 5 | Provider | 硬编码凭据 | `access_key/secret_key` 在 `.tf` 中 |
| 6 | Provider | 版本未锁 | 无 `version` 约束 |
| 7 | Module | 未审查来源 | 第三方 Git 模块无版本锁 |
| 8 | Output | 泄露敏感值 | `output` 无 `sensitive = true` |
| 9 | Variable | 未标记敏感 | `variable` 含密码无 `sensitive` |
| 10 | Provisioner | 不安全执行 | `local-exec` / `remote-exec` 含敏感数据 |
| 11 | CI/CD | 权限过大 | Terraform apply 使用管理员角色 |
| 12 | CI/CD | 无 OIDC | CI 使用长期 Access Key 而非 OIDC federation |
