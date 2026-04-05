# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

**skills-audit** is a security auditing tool for AI Agent skills. It performs multi-phase analysis to detect malicious code, vulnerabilities, and supply chain risks in AI agent skills through:
- Static pattern matching (regex-based detection)
- AI semantic analysis (LLM-powered deep analysis)
- Deep code understanding (AI-enhanced complex attack chains)
- Threat intelligence validation (ThreatBook API integration)
- Risk scoring and synthesis

The tool is standalone and platform-agnostic, designed to integrate with Claude Code, custom AI platforms, and CI/CD pipelines.

**New in this version**:
- Bundled `claude-skill-framework` in `lib/` directory - no external dependency needed
- Subprocess/cron support for deep mode - automatically creates LLM client from config
- Simplified deployment to `~/.claude/skills/skills-audit`

## Architecture

### Core Analysis Pipeline

The audit follows a **5-phase analysis pipeline** orchestrated by `skill_audit/skill_security_audit.py`:

1. **Phase 0: Artifact Extraction** (`phases/phase0_extractor.py`)
   - Extracts skill manifest, code files, prompts, dependencies
   - Parses external references (IPs, domains, URLs)
   - Identifies sensitive files (.env, credentials)

2. **Phase 1: AI Semantic Analysis** (`phases/phase1_ai_analysis.py`)
   - LLM-powered deep semantic security analysis
   - Detects: RCE, credential leaks, data exfiltration, prompt injection
   - Weight: 40% of final risk score

3. **Phase 2A: Static Pattern Matching** (`phases/phase2_static_analysis.py`)
   - Regex-based detection using patterns defined in `patterns.py`
   - Detects: unsafe execution, obfuscation, hardcoded credentials, persistence mechanisms
   - Weight: 25% of final risk score

4. **Phase 2A2: Deep Code Understanding** (`phases/phase2a2_deep_analysis.py`)
   - AI-enhanced analysis for complex attack chains
   - Analyzes multi-step exploit paths and obfuscated code

5. **Phase 2B: Threat Intelligence** (`phases/phase2_tip_integration.py`)
   - Validates external addresses via ThreatBook API
   - Checks IPs, domains, URLs against threat databases
   - Weight: 25% of final risk score

6. **Phase 3: Risk Synthesis** (`phases/phase3_synthesis.py`)
   - Aggregates findings from all phases
   - Calculates composite risk score (0-100)
   - Generates final audit report with recommendations

### Data Schemas

`schemas.py` defines structured output formats:
- **RiskLevel**: CRITICAL, HIGH, MEDIUM, LOW, INFO
- **RiskCategory**: prompt_injection, privilege_escalation, data_exfiltration, remote_control, supply_chain, unsafe_execution
- **Evidence**: Structured finding with source, confidence, severity, code location
- **SkillAuditReport**: Final report with risk score, findings, recommendations

### Scoring System

`scoring.py` implements weighted risk scoring:
- AI Analysis: 40%
- Static Analysis: 25%
- Threat Intelligence: 25%
- Deep Analysis: 10%
- Final score: 0-100 scale with risk level thresholds

### Integration Points

`integrations/` provides external system integrations:
- **claude_code.py**: Claude Code environment adapter
- **git_hook.py**: Pre-commit/pre-push git hooks for blocking risky skills
- **ai_analysis_integrator.py**: Merges AI findings into static analysis reports

## Common Commands

### Installation

**Recommended: Use the install script**
```bash
# Clone/extract to recommended location
cd ~/.claude/skills
git clone <repo-url> skills-audit
cd skills-audit

# One-command installation (installs framework + dependencies)
./install.sh

# Verify installation
python3 -c "import skill_audit; print('skills-audit installed')"
```

**Manual installation**
```bash
# Install bundled framework
cd lib/claude-skill-framework
pip install -e .

# Install skills-audit dependencies
cd ../..
pip install -r requirements.txt

# Optional: Install with dev dependencies
pip install ".[dev]"
```

### Running Audits

```bash
# CLI usage (fast mode - static analysis only)
python3 -m skill_audit.cli_wrapper /path/to/skill --mode fast

# Standard mode (AI + static analysis)
python3 -m skill_audit.cli_wrapper /path/to/skill --mode standard

# Deep mode (full analysis including deep code understanding)
python3 -m skill_audit.cli_wrapper /path/to/skill --mode deep

# Expert mode (all phases including threat intelligence)
python3 -m skill_audit.cli_wrapper /path/to/skill --mode expert

# As a Claude Code skill
/skills-audit /path/to/skill --mode deep
```

### Testing

```bash
# Run tests (if test suite exists)
pytest tests/

# Test single phase
python3 -c "
from skill_audit.phases.phase0_extractor import create_skill_artifact_extractor
extractor = create_skill_artifact_extractor()
artifact = extractor.extract_from_path('/path/to/skill')
print(artifact.skill_name)
"
```

### Configuration

Edit `config/config.yml` to customize:

```yaml
# Set scan mode presets
scan_modes:
  fast: {enable_ai_analysis: false, enable_static_analysis: true, ...}
  standard: {enable_ai_analysis: true, enable_static_analysis: true, ...}
  deep: {enable_ai_analysis: true, enable_deep_analysis: true, ...}

# Configure LLM provider
llm:
  provider: anthropic
  model: claude-sonnet-4-5-20250929
  api_key: ${ANTHROPIC_AUTH_TOKEN}

# Enable notifications
notifications:
  enabled: true
  lark_webhook_url: "{{LARK_WEBHOOK_URL}}"
```

### Linting and Formatting

```bash
# Format code with black
black skill_audit/ --line-length 100

# Lint with ruff
ruff check skill_audit/

# Type checking (if configured)
mypy skill_audit/
```

## Key Development Patterns

### Adding New Detection Patterns

Edit `patterns.py` to add static detection rules:

```python
# Add to MaliciousPatterns class
PATTERNS = {
    'new_category': [
        {
            'pattern': r'regex_pattern_here',
            'description': 'What this detects',
            'severity': RiskLevel.HIGH,
            'category': RiskCategory.UNSAFE_EXECUTION,
        }
    ]
}
```

### Creating Custom Phases

New analysis phases should:
1. Inherit from `BaseSkill` or `CodeSkill` (from claude-skill-framework)
2. Implement `execute(context: SkillContext) -> SkillResult`
3. Return findings in `Evidence` format
4. Be registered in `skill_security_audit.py`

### Extending Integrations

Add new platform adapters in `integrations/`:
1. Create new file (e.g., `my_platform.py`)
2. Implement notification/reporting logic
3. Add configuration section in `config/config.yml`

## Important Implementation Notes

### Bundled Framework

This tool includes `claude-skill-framework` bundled in `lib/claude-skill-framework/`:
- No external dependency - framework is included in the repository
- Provides: `BaseSkill`, `CodeSkill`, `SkillContext`, `SkillResult`, `CompositeSkill`
- Installed automatically via `./install.sh` or `pip install -e ./lib/claude-skill-framework`

### Subprocess/Cron Support for Deep Mode

The tool now supports running `deep` and `expert` modes in subprocess/cron environments:
- **In Claude Code**: Uses the current Claude session (no API calls)
- **In subprocess/cron**: Automatically creates LLM client from config file
- **Configuration**: Set `ANTHROPIC_AUTH_TOKEN` environment variable or in config.yml
- **Implementation**: `llm_utils.py` provides `ensure_llm_client()` helper

### Scan Mode vs. Phase Configuration

The `--mode` flag is **authoritative** for controlling which phases run:
- `fast`: Static analysis only (1-2 seconds)
- `standard`: AI + static analysis (30s-2min)
- `deep`: AI + static + deep code understanding (2-5min)
- `expert`: All phases including threat intelligence (5-10min)

Do not use the `phases` section in config.yml - it has been removed to prevent conflicts with `--mode`.

### AI Analysis Context

- **In Claude Code**: AI analysis phases use the current Claude session (no API calls needed)
- **Standalone**: AI phases require `ANTHROPIC_API_KEY` environment variable
- Deep/expert modes perform comprehensive semantic analysis by Claude

### Self-Exclusion

The tool automatically excludes itself from scanning to avoid self-referential false positives:
- `EXCLUDED_DIRS` in `phase0_extractor.py` includes "skill-audit" and "skills-audit"
- Watcher configuration has `exclude_skills: [skills-audit, skill-audit]`

### Report Storage

Reports are saved to:
1. `~/.claude/audit-reports/` (default for Claude Code)
2. `./reports/` (relative to skill directory)
3. Custom path via `claude_code.custom_report_dir` in config

Format: `audit-{skill_name}-{timestamp}.json`

### Webhook Notifications

When `notifications.enabled: true`:
- Sends audit results to Lark (enterprise messaging)
- Includes: risk level, findings summary, host info, report link
- Configure `environment_label` to identify different servers

## Environment Variables

```bash
# LLM API (for standalone usage)
export ANTHROPIC_AUTH_TOKEN="sk-ant-..."
export ANTHROPIC_BASE_URL="https://api.anthropic.com"

# Threat Intelligence
export THREATBOOK_API_KEY="your-key"

# Scan mode override
export SCAN_MODE="deep"
```

## File Organization

```
~/.claude/skills/skills-audit/       # Recommended installation path
├── lib/                             # Bundled dependencies
│   └── claude-skill-framework/     # Framework bundled with project
├── skill_audit/                     # Core code
│   ├── __init__.py                 # Package entry point
│   ├── cli.py                      # CLI interface
│   ├── cli_wrapper.py              # Wrapper for Claude Code integration
│   ├── skill_security_audit.py     # Main orchestrator (5-phase pipeline)
│   ├── schemas.py                  # Data structures (Evidence, Report, etc.)
│   ├── patterns.py                 # Static detection patterns (15KB, 300+ rules)
│   ├── scoring.py                  # Risk scoring algorithms
│   ├── llm_utils.py                # LLM client helper for subprocess/cron
│   ├── integrate_ai_findings.py    # Merge AI findings into reports
│   ├── phases/                     # Analysis phases
│   │   ├── phase0_extractor.py    # Artifact extraction
│   │   ├── phase1_ai_analysis.py  # AI semantic analysis
│   │   ├── phase2_static_analysis.py # Static pattern matching
│   │   ├── phase2a2_deep_analysis.py # Deep code understanding
│   │   ├── phase2_tip_integration.py # Threat intelligence
│   │   └── phase3_synthesis.py    # Risk synthesis
│   └── integrations/               # External system integrations
│       ├── claude_code.py         # Claude Code adapter
│       ├── git_hook.py            # Git hooks
│       └── ai_analysis_integrator.py # AI findings merger
├── config/
│   └── config.example.yml          # Configuration template
├── prompts/
│   └── ai_analysis.md              # AI analysis prompt templates
└── SKILL.md                         # Claude Code skill entry point
```

## Deployment

### Development Deployment
```bash
# Install framework in editable mode
cd /path/to/claude-skill-framework
pip install -e .

# Install skills-audit dependencies
cd /path/to/skills-audit
pip install -r requirements.txt
```

### Production Deployment
```bash
# Build wheels
python3 -m build

# Install from wheels
pip install dist/skill_audit-1.0.0-py3-none-any.whl

# Or use deployment script
./deploy.sh
```
