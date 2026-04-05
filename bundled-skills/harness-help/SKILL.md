# Harness Help — Command Index & Scenario Quick Reference

---
description: Triggered when the user says "harness help", "harness commands", "harness usage", "what commands are available", or "show harness commands". Displays the Harness command index, installed Skill inventory, and high-frequency scenario entry points.
---

## Behavior

1. Display Harness command index
2. Scan `~/.claude/skills/` to list installed Skills by category
3. Show high-frequency scenario → command/Skill quick entry points

---

## Command Index

```
Harness Command System:

  harness              — Project initialization (full 8-step workflow)
  harness help         — This help page (command index + scenario quick ref)
  harness audit        — Project health check (verify CLAUDE.md/docs/hooks/skill completeness)
  harness quality gate — Pre-commit quality gate (tests + lint + security review + doc sync)
  harness guide        — Skill recommendation (match the best Skill for your scenario)
```

## Installed Skills Inventory

Scan `~/.claude/skills/` directory, display by category:

```
🔧 Infrastructure (behavior control + planning + knowledge extraction):
  [status] superpowers          — brainstorming/TDD/debugging/code-review/verification
  [status] planning-with-files  — /plan task planning + 4 hooks for continuous injection
  [status] claudeception        — lessons learned → auto-generate Skills

🏭 Skill Factories (generate new Skills):
  [status] skill-creator                  — codify workflows into Skills
  [status] security-review-skill-creator  — generate security audit rules for a project

🔒 Security:
  [status] security-review-skill-for-docker    — Docker/container security
  [status] security-review-skill-for-terraform — Terraform/IaC security
  [status] sca-ai-denoise                      — SCA vulnerability denoising
  [status] supply-chain-audit                  — supply chain poisoning detection
  [status] skills-audit                        — third-party Skill audit
  [status] web-vuln-analyzer                   — web vulnerability analysis
  [status] android-vuln-analyzer               — Android vulnerability analysis
  [status] security-review-skill-for-*         — project-specific security audit

🎨 Development Aids:
  [status] frontend-design  — frontend UI generation
  [status] canvas-design    — visual design

📝 Project Skills (.claude/skills/):
  [list project-level Skills]
```

Status labels: ✅ Installed | ❌ Not installed | ⚠️ Needs configuration

## High-Frequency Scenarios

| Scenario | Action |
|----------|--------|
| Initialize a new project | Say "harness" |
| Start a new feature | Say "/plan" → use superpowers brainstorming |
| Debug a bug | superpowers auto-injects systematic-debugging |
| Security audit | "Generate a security audit skill for this project" → security-review-skill-creator |
| SCA denoising | "Analyze these SCA vulnerabilities" → sca-ai-denoise |
| Supply chain audit | "Check dependency security" → supply-chain-audit |
| Docker security review | "Review Docker configuration" → security-review-skill-for-docker |
| Pre-commit check | Say "quality gate" → harness-quality-gate |
| Check project health | Say "harness audit" |
| Recommend a Skill | Say "harness guide" or "which skill should I use" |
| Capture experience | Say "/claudeception" |
| Create a new Skill | "Help me create a skill for XX" → skill-creator |

---

## Re-initialization

If you need to reconfigure (e.g., add Skills, update hooks):
- Re-run `harness` — idempotent execution, only supplements missing parts, never overwrites existing content
