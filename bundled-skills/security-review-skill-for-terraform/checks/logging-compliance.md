# Logging, Monitoring & Compliance Checks

> 技术栈：Terraform HCL | 维度：CloudTrail / VPC Flow Logs / 审计日志 / 合规

## 模块背景

安全监控是防御的最后一道防线。IaC 审计需确保日志和监控基础设施已正确配置。缺失日志 = 攻击无法被检测。

## CloudTrail / 审计日志缺失 (HIGH)

**检查项**：
- [ ] 是否存在 `aws_cloudtrail` 资源（全局审计日志）
- [ ] CloudTrail 是否启用 `is_multi_region_trail = true`
- [ ] CloudTrail 是否配置了 `kms_key_id`（日志加密）
- [ ] CloudTrail 是否启用 `enable_log_file_validation = true`（防篡改）
- [ ] CloudTrail S3 bucket 是否安全（不公开、加密、版本化）
- [ ] GuardDuty 是否启用（`aws_guardduty_detector`）
- [ ] Security Hub 是否启用（`aws_securityhub_account`）
- [ ] AWS Config 是否启用（`aws_config_configuration_recorder`）

**代码模式**：
```hcl
# 安全的 CloudTrail 配置
resource "aws_cloudtrail" "main" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.trail.arn
  include_global_service_events = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}
```

## VPC Flow Logs 缺失 (HIGH)

**检查项**：
- [ ] 每个 VPC 是否有 `aws_flow_log` 资源
- [ ] Flow Log 目标是否为 CloudWatch Logs 或 S3
- [ ] `traffic_type` 是否为 `ALL`（而非仅 `REJECT`）

**代码模式**：
```hcl
resource "aws_flow_log" "vpc" {
  vpc_id               = aws_vpc.main.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow.arn
  iam_role_arn         = aws_iam_role.flow.arn
}
```

## 服务级日志 (MEDIUM)

**检查项**：
- [ ] ALB/NLB 是否启用 `access_logs`
- [ ] S3 是否启用 `logging`（访问日志）
- [ ] RDS 是否启用 `enabled_cloudwatch_logs_exports`
- [ ] EKS 是否启用 `enabled_cluster_log_types`（api/audit/authenticator）
- [ ] Lambda 是否有 CloudWatch Logs 权限
- [ ] API Gateway 是否启用 access logging
- [ ] WAF 是否启用 logging

## 监控告警 (MEDIUM)

**检查项**：
- [ ] 是否有 CloudWatch Alarm 或 GCP Monitoring Alert
- [ ] 关键安全事件是否有告警（如 root 登录、IAM 变更、SG 变更）
- [ ] 是否配置了 SNS Topic 通知目标
- [ ] GuardDuty / Security Hub 是否启用
- [ ] AWS Config 是否启用（配置合规检查）

## 合规基线 (LOW)

**检查项**：
- [ ] 资源是否有标签策略（`tags` 包含 `Environment`, `Owner`, `Team`）
- [ ] 是否有 `aws_config_config_rule` 定义合规规则
- [ ] 是否有 SCP (Service Control Policy) 限制危险操作
- [ ] 是否启用了 AWS Organizations 的 AI opt-out policy（如适用）
