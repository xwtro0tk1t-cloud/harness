"""
Skill Audit - Security audit tool for AI Agent skills

A standalone tool for auditing AI agent skills for security vulnerabilities,
malicious code, and supply chain risks.

Usage:
    # CLI
    skill-audit /path/to/skill --mode standard

    # Python API
    from skill_audit import create_skill_security_audit_skill
    audit_skill = create_skill_security_audit_skill(enable_ai_analysis=True)

    # Claude Code Skill
    /skill-audit /path/to/skill
"""

__version__ = '1.0.0'
__author__ = 'Winston Xu'

# Core classes from framework
from skill_framework import (
    SkillContext,
    SkillResult,
    BaseSkill,
    CodeSkill,
    SkillCategory,
    RiskLevel,
)

# Main audit skill factory
from .skill_security_audit import create_skill_security_audit_skill

__all__ = [
    # Core
    'SkillContext',
    'SkillResult',
    'BaseSkill',
    'CodeSkill',
    'SkillCategory',
    'RiskLevel',
    # Factory
    'create_skill_security_audit_skill',
    # Version
    '__version__',
]
