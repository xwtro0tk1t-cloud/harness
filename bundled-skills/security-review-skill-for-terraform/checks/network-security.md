# Network Security Checks

> 技术栈：Terraform HCL | 维度：Security Group / NACL / 防火墙 / VPC

## 模块背景

云网络安全是 IaC 审计的核心。过宽的入站规则是云环境被攻陷的最常见原因之一。

## 过宽入站规则 (CRITICAL)

**检查项**：
- [ ] 所有 `ingress` 规则中 `cidr_blocks` 是否包含 `0.0.0.0/0` 或 `::/0`
- [ ] 对 0.0.0.0/0 开放的端口是否为敏感端口（22/SSH, 3389/RDP, 3306/MySQL, 5432/PostgreSQL, 6379/Redis, 27017/MongoDB, 9200/ES）
- [ ] 是否存在 `protocol = "-1"` (全协议) + `0.0.0.0/0` 的组合
- [ ] `from_port = 0, to_port = 65535` 全端口开放

**AWS 资源检查**：
```hcl
# 检查 aws_security_group 内联规则
resource "aws_security_group" "..." {
  ingress { cidr_blocks = ["0.0.0.0/0"] }  # 内联
}

# 检查 aws_security_group_rule
resource "aws_security_group_rule" "..." {
  type        = "ingress"
  cidr_blocks = ["0.0.0.0/0"]
}

# 检查 aws_vpc_security_group_ingress_rule (新版)
resource "aws_vpc_security_group_ingress_rule" "..." {
  cidr_ipv4 = "0.0.0.0/0"
}
```

**AWS VPC Endpoint 检查**：
```hcl
# 检查 S3/DynamoDB 是否通过 VPC Endpoint 访问（而非公网）
resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.main.id
  service_name = "com.amazonaws.${var.region}.s3"
}
```

**攻击场景**：
SSH 对公网开放 → Botnet 暴力破解 → 获取实例访问 → 横向移动到 VPC 内其他资源

## NACL / 网络防火墙 (HIGH)

**检查项**：
- [ ] `aws_network_acl_rule` 入站规则是否过宽
- [ ] NACL 是否优先级设置正确（编号越小优先级越高）
- [ ] VPC 是否有 Flow Logs 启用

## VPC 配置 (MEDIUM)

**检查项**：
- [ ] 是否使用默认 VPC（`default = true`）
- [ ] 子网是否正确区分 public/private
- [ ] NAT Gateway 是否用于 private 子网出站
- [ ] VPC Peering / Transit Gateway 是否限制了路由范围
- [ ] DNS 解析是否启用（`enable_dns_hostnames`, `enable_dns_support`）

## 负载均衡器 & WAF (MEDIUM)

**检查项**：
- [ ] ALB/NLB/CLB 是否配置了 HTTPS listener
- [ ] SSL Policy 是否使用 TLS 1.2+（`ELBSecurityPolicy-TLS13-1-2-2021-06` 或更新）
- [ ] 是否启用了 access logs
- [ ] 公网 ALB 是否关联 `aws_wafv2_web_acl_association`
- [ ] 是否存在 HTTP → HTTPS 重定向
- [ ] CloudFront `viewer_protocol_policy` 是否为 `redirect-to-https`
- [ ] CloudFront `minimum_protocol_version` 是否为 `TLSv1.2_2021`
- [ ] API Gateway 是否配置了 throttling（`aws_api_gateway_method_settings`）
- [ ] API Gateway 是否有认证（`authorization` 非 `NONE`）
