# Skill Recommendation Guide

Find the best Skill for your scenario. The `harness guide` command reads this file + scans installed Skills to provide recommendations.

---

## 1. Security & Compliance

| Scenario | Recommended Skill | Notes |
|----------|------------------|-------|
| Project-wide security audit | `security-review-skill-creator` → generate a project-specific audit Skill | Generate first, then audit with the generated Skill |
| Docker/container security audit | `security-review-skill-for-docker` | Covers Dockerfile / docker-compose / K8s security checks |
| Terraform/IaC security audit | `security-review-skill-for-terraform` | Covers compute/storage/network/IAM/logging compliance |
| SCA vulnerability denoising | `sca-ai-denoise` | Grades SCA scan results by P0-P3 severity, filters noise |
| Supply chain poisoning detection | `supply-chain-audit` | 8-language coverage, detects dependency poisoning/typosquatting |
| Third-party Skill security audit | `skills-audit` | Audits installed Skills for malicious behavior |
| Web vulnerability deep analysis | `web-vuln-analyzer` ⚠️ | Requires Docker environment + API keys |
| Android vulnerability analysis | `android-vuln-analyzer` ⚠️ | Requires apktool/jadx/frida toolchain |

## 2. Development Workflow

| Scenario | Recommended Skill | Notes |
|----------|------------------|-------|
| New feature development (full flow) | `superpowers` | brainstorming → writing-plans → TDD → code-review → verification |
| Task planning & progress tracking | `planning-with-files` | /plan command + 4 hooks for continuous injection |
| Bug debugging | `superpowers` (systematic-debugging) | 4 stages: root cause investigation → pattern analysis → hypothesis testing → fix |
| Code review | `superpowers` (requesting-code-review) | Dispatches a reviewer subagent for AI Code Review |
| Create custom workflow Skills | `skill-creator` | Codify recurring workflows into Skills |
| Capture lessons learned | `claudeception` | Auto-extract reusable Skills from debugging experience |

## 3. Frontend & Design

| Scenario | Recommended Skill | Notes |
|----------|------------------|-------|
| High-quality frontend UI development | `frontend-design` | React/Vue/CSS component generation |
| Visual design (posters/charts) | `canvas-design` | PNG/PDF poster and chart generation |

## 4. Project Management

| Scenario | Recommended Skill | Notes |
|----------|------------------|-------|
| Project initialization / full guardrails | `harness` | 8-step one-click four-layer guardrail setup |
| Project health check | `harness-audit` | Check CLAUDE.md/docs/hooks/skill completeness |
| Pre-commit quality gate | `harness-quality-gate` | Tests + lint + security review + doc sync |

---

## Decision Tree

```
What do you want to do?
│
├─ 🔒 Security-related
│   ├─ Audit project code security → Have a project-specific security-review skill?
│   │   ├─ Yes → Use that Skill directly
│   │   └─ No → security-review-skill-creator to generate one first
│   ├─ Audit Docker/containers → security-review-skill-for-docker
│   ├─ Audit Terraform → security-review-skill-for-terraform
│   ├─ Too many SCA vulnerabilities, need denoising → sca-ai-denoise
│   ├─ Suspect dependency poisoning → supply-chain-audit
│   ├─ Audit third-party Skill security → skills-audit
│   ├─ Web penetration testing → web-vuln-analyzer ⚠️
│   └─ Android reverse engineering → android-vuln-analyzer ⚠️
│
├─ 🚀 Development workflow
│   ├─ Start a new feature → superpowers (brainstorming → TDD)
│   ├─ Need a task plan → planning-with-files (/plan)
│   ├─ Debug a bug → superpowers (systematic-debugging)
│   ├─ Code review → superpowers (requesting-code-review)
│   ├─ Pre-commit checks → harness-quality-gate
│   └─ Codify a workflow → skill-creator
│
├─ 🎨 Frontend/Design
│   ├─ UI component development → frontend-design
│   └─ Visual design → canvas-design
│
└─ 🛠 Meta operations
    ├─ Initialize project → harness
    ├─ Check guardrail health → harness-audit
    ├─ Capture experience → claudeception
    └─ Create new Skill → skill-creator
```

---

## Status Labels

| Label | Meaning |
|-------|---------|
| ✅ | Installed, ready to use |
| ❌ | Not installed, needs installation |
| ⚠️ | Installed but requires configuration (Docker/toolchain/API keys) |
| 🔧 | Basic features available, advanced features need configuration |

> The `harness guide` command automatically scans `~/.claude/skills/` and labels each Skill's actual installation status.
