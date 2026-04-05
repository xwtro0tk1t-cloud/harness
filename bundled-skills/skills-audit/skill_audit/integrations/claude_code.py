"""
Claude Code integration

This module provides the backend for SKILL.md in Claude Code.

In Claude Code environment, AI analysis is performed by Claude directly,
not through API calls. This makes the skill work offline and without API keys.
"""
from pathlib import Path
from typing import Dict, Any, Optional
import yaml
import logging

from skill_framework import SkillContext
from ..skill_security_audit import create_skill_security_audit_skill

logger = logging.getLogger(__name__)


def load_config() -> Dict[str, Any]:
    """Load configuration from Claude Code skill directory"""
    config_paths = [
        Path(__file__).parent.parent.parent / 'config' / 'config.yml',  # Relative to module
        Path.home() / '.claude' / 'skills' / 'skills-audit' / 'config' / 'config.yml',  # User home
    ]

    for config_path in config_paths:
        if config_path.exists():
            try:
                with open(config_path) as f:
                    return yaml.safe_load(f)
            except:
                pass

    return {}


def get_scan_mode_config(mode: str, config: Dict[str, Any]) -> Dict[str, bool]:
    """
    Get scan mode configuration

    The --mode parameter is authoritative. The config.yml `phases` section
    is NOT used as an override — it was causing --mode to be silently ignored.

    Priority:
    1. scan_modes[mode] in config file (mode presets)
    2. default_modes (built-in defaults)
    """
    default_modes = {
        'fast': {
            'enable_ai_analysis': False,
            'enable_static_analysis': True,
            'enable_deep_analysis': False,
            'enable_tip_check': False,
        },
        'standard': {
            'enable_ai_analysis': True,
            'enable_static_analysis': True,
            'enable_deep_analysis': False,
            'enable_tip_check': False,
        },
        'deep': {
            'enable_ai_analysis': True,
            'enable_static_analysis': True,
            'enable_deep_analysis': True,
            'enable_tip_check': True,
        },
        'expert': {
            'enable_ai_analysis': True,
            'enable_static_analysis': True,
            'enable_deep_analysis': True,
            'enable_tip_check': True,
        },
    }

    # Use scan_modes[mode] preset or built-in defaults
    # --mode parameter is authoritative; phases config is NOT used as override
    if 'scan_modes' in config and mode in config['scan_modes']:
        result = config['scan_modes'][mode].copy()
    else:
        result = default_modes.get(mode, default_modes['deep']).copy()

    return result


def claude_code_audit(skill_path: str,
                      mode: str = 'deep',
                      config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Audit a skill from Claude Code

    This is the main entry point called by SKILL.md.

    Args:
        skill_path: Path to skill to audit
        mode: Scan mode (fast, standard, deep, expert)
        config: Optional configuration override

    Returns:
        Audit report dict
    """
    # Load config if not provided
    if config is None:
        config = load_config()

    # Get mode configuration
    mode_config = get_scan_mode_config(mode, config)

    # Debug: Print actual config being used
    print(f"\n{'='*60}")
    print(f"🔍 Skill Audit Configuration (Mode: {mode})")
    print(f"{'='*60}")
    print(f"  AI Analysis:     {'✓' if mode_config['enable_ai_analysis'] else '✗'} (by Claude)")
    print(f"  Static Analysis: {'✓' if mode_config['enable_static_analysis'] else '✗'}")
    print(f"  Deep Analysis:   {'✓' if mode_config['enable_deep_analysis'] else '✗'} (by Claude)")
    print(f"  TIP Check:       {'✓' if mode_config['enable_tip_check'] else '✗'}")
    print(f"{'='*60}\n")

    # Create audit skill
    audit_skill = create_skill_security_audit_skill(**mode_config)

    # Create context
    # In Claude Code environment, no llm_client needed - Claude executes directly
    context = SkillContext(
        task_description='Security audit',
        user_input=f'audit {skill_path}',
        workspace_dir=skill_path,
        session_id='claude-code',
        llm_client=None,  # No llm_client in Claude Code - Claude does analysis directly
        metadata={'mode': mode, 'claude_code': True, 'skill_path': skill_path}
    )

    # Execute audit
    result = audit_skill.execute(context)

    if result.success:
        return result.output.get('audit_report', {})
    else:
        return {
            'overall_risk': 'UNKNOWN',
            'overall_score': 0,
            'confidence': 0,
            'findings': [],
            'error': result.error,
        }
