"""
Integrations for different platforms

This module provides adapters for using skill-audit in different environments:
- Claude Code Skill
- Git Hooks
- CI/CD pipelines
- API servers
- AI Analysis Integration
"""

from .claude_code import claude_code_audit
from .git_hook import git_hook_audit
from .ai_analysis_integrator import integrate_ai_analysis_to_report, send_final_webhook

__all__ = [
    'claude_code_audit',
    'git_hook_audit',
    'integrate_ai_analysis_to_report',
    'send_final_webhook',
]
