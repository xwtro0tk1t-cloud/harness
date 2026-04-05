# Security Grader

评估生成的 security-review-skill 的检测效果。

## 评估方法

用已知漏洞的测试代码运行 skill，对比检测结果和 ground truth。

## 输入

- **ground_truth**: 测试代码中的已知漏洞
- **skill_output**: skill 的检测结果

## 评估指标

### 核心指标

| 指标 | 计算 | 说明 |
|-----|------|------|
| **检出率 (Recall)** | TP / (TP + FN) | 真实漏洞被检出的比例 |
| **精确率 (Precision)** | TP / (TP + FP) | 报告中真实漏洞的比例 |
| **定位准确** | - | 行号是否准确（允许 ±3 行） |

### 分类

| 分类 | 说明 |
|-----|------|
| **True Positive (TP)** | 正确检出的真实漏洞 |
| **False Positive (FP)** | 误报（安全代码被标记为漏洞） |
| **False Negative (FN)** | 漏检（真实漏洞未被检出） |

## 评估流程

1. **准备测试用例**
```json
{
  "test_file": "test_vuln.py",
  "vulnerabilities": [
    {"type": "sql_injection", "line": 15}
  ],
  "safe_code": [
    {"line": 30, "reason": "使用参数化查询"}
  ]
}
```

2. **运行 skill**
```
让 skill 审计 test_vuln.py
```

3. **对比结果**
- 每个 ground truth 漏洞是否被检出？
- 每个 skill 报告是否对应真实漏洞？
- 定位是否准确？

4. **输出评估报告**
```json
{
  "recall": 0.9,
  "precision": 0.8,
  "improvements": [
    "漏检 IDOR，需补充越权检测规则",
    "Jinja2 误报 XSS，需加框架保护识别"
  ]
}
```

## 改进建议

根据评估结果：

| 问题 | 改进方向 |
|-----|---------|
| **漏检 (FN 高)** | 补充检测模式，加强危险函数识别 |
| **误报 (FP 高)** | 添加框架保护识别，加强上下文分析 |
| **定位不准** | 改进代码模式描述 |
