# Harness Guide — Skill Recommendation

---
description: Triggered when the user says "recommend skill", "which skill", "harness guide", "skill recommendation", "what skill should I use", or "suggest a skill". Matches the best Skill for the user's scenario, shows installation status and invocation method.
---

## Behavior

1. Read `references/skill-guide.md` for the scenario → Skill recommendation matrix
2. Scan `~/.claude/skills/` for installed Skill list
3. If user describes a specific scenario → precise match recommendation
4. If no scenario described → display full recommendation matrix + decision tree

---

## Matching Logic

### Scenario Keywords → Skill Mapping

```
security audit / code audit / vulnerability scan
  → Check if security-review-skill-for-<project> exists
    → Yes → "Use your project-specific audit Skill directly"
    → No → "Recommend generating one with security-review-skill-creator first"

Docker / container / Dockerfile
  → security-review-skill-for-docker

Terraform / IaC / infrastructure as code
  → security-review-skill-for-terraform

SCA / vulnerability denoising / dependency vulnerabilities / CVE
  → sca-ai-denoise

supply chain / dependency poisoning / typosquatting
  → supply-chain-audit

Skill audit / third-party Skill / Skill security
  → skills-audit

web vulnerability / pentest / XSS / SQLi
  → web-vuln-analyzer (note: requires Docker configuration)

Android / APK / reverse engineering / frida
  → android-vuln-analyzer (note: requires toolchain)

new feature / feature development
  → superpowers (brainstorming → TDD)

bug / debug / debugging
  → superpowers (systematic-debugging)

code review
  → superpowers (requesting-code-review)

plan / task breakdown / planning
  → planning-with-files

create Skill / codify workflow
  → skill-creator

capture experience / lessons learned / knowledge extraction
  → claudeception

frontend / UI / component
  → frontend-design

design / poster / chart
  → canvas-design
```

### Output Format

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🧭 Skill Recommendation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scenario: "your described scenario"

Recommended Skill:
  ✅ skill-name — description
     Invoke: "trigger keyword or command"

  Alternatives:
  ✅ alt-skill — description

Status legend:
  ✅ = Installed  ❌ = Not installed  ⚠️ = Needs configuration
```

If the recommended Skill is not installed:

```
❌ skill-name is not installed

Installation:
  Option A (Bundled): ln -sf ~/.claude/skills/harness-en/bundled-skills/skill-name ~/.claude/skills/skill-name
  Option B (Git):     cd ~/.claude/skills/ && git clone <url> skill-name
```

---

## No Scenario: Display Full Guide

Read `references/skill-guide.md` for the 4 categories + decision tree, combined with installation status.
