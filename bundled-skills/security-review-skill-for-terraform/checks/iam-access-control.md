# IAM & Access Control Checks

> 技术栈：Terraform HCL | 维度：IAM Policy / Role / User / 跨账户

## 模块背景

IAM 权限过大是云安全事故的头号根因。Terraform 中的 IAM 策略通常以 JSON 嵌入 HCL，需要同时审计 HCL 结构和 JSON policy 内容。

## IAM 权限过大 (CRITICAL)

**检查项**：
- [ ] 是否存在 `Action = "*"` + `Resource = "*"` 的策略（等同管理员）
- [ ] 是否存在 `Action = "service:*"` 通配符（如 `s3:*`, `ec2:*`, `iam:*`）
- [ ] `Resource = "*"` 是否可以缩窄到具体 ARN
- [ ] `iam:PassRole` 是否限制了可传递的角色
- [ ] `iam:CreatePolicyVersion` / `iam:AttachUserPolicy` 等提权 Action 是否存在
- [ ] `sts:AssumeRole` 的信任策略 `Principal` 是否为 `*`

**高危 IAM Action（提权路径）**：
```
iam:CreatePolicyVersion     → 创建新策略版本覆盖权限
iam:SetDefaultPolicyVersion → 切换到过宽版本
iam:AttachUserPolicy        → 给自己附加管理员策略
iam:AttachRolePolicy        → 给角色附加管理员策略
iam:PutRolePolicy           → 内联策略注入
iam:CreateUser              → 创建新管理员用户
iam:CreateLoginProfile      → 为无控制台用户创建登录
iam:UpdateLoginProfile      → 重置其他用户密码
iam:PassRole                → 将高权限角色传递给 Lambda/EC2
lambda:CreateFunction       → 创建以高权限角色运行的 Lambda
lambda:InvokeFunction       → 触发高权限 Lambda
ec2:RunInstances            → 以高权限角色启动 EC2
```

**代码模式**：
```hcl
# 危险：开发者图方便给 Lambda 全部权限
resource "aws_iam_role_policy_attachment" "lambda_admin" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# 安全：最小权限
resource "aws_iam_role_policy" "lambda_minimal" {
  role = aws_iam_role.lambda.name
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["dynamodb:GetItem", "dynamodb:PutItem"]
      Resource = aws_dynamodb_table.main.arn
    }]
  })
}
```

## 跨账户信任 (HIGH)

**检查项**：
- [ ] `assume_role_policy` 中 `Principal.AWS` 是否指定了具体账户 ID
- [ ] 外部账户 ID 是否通过 `Condition` 限制了 `ExternalId`
- [ ] 是否有非预期的跨账户信任关系
- [ ] Service Principal 是否是预期的服务

## IAM User 与 Access Key (HIGH)

**检查项**：
- [ ] 是否创建了 `aws_iam_user`（应优先使用 Role/SSO）
- [ ] 是否创建了 `aws_iam_access_key`（长期凭据，高风险）
- [ ] Access Key 的 `pgp_key` 是否设置（加密输出）
- [ ] 是否有 IAM User 直接附加策略（应使用 Group）

## AWS Organizations & SCP (HIGH)

**检查项**：
- [ ] 是否使用 `aws_organizations_policy` 定义 SCP 限制危险操作
- [ ] SCP 是否禁止 `iam:CreateUser`、`iam:CreateAccessKey`（生产账户）
- [ ] SCP 是否禁止关闭 CloudTrail、GuardDuty、Security Hub
- [ ] SCP 是否限制特定 Region（防止在非预期区域创建资源）
- [ ] 是否有 `aws_organizations_policy_attachment` 绑定到 OU

## Permission Boundary (MEDIUM)

**检查项**：
- [ ] 高权限角色是否设置了 `permissions_boundary`
- [ ] Boundary 策略是否有效限制了权限范围
