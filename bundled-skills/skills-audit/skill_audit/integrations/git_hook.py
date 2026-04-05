"""
Git Hook integration

This module provides backend functions for Git hooks (pre-commit, pre-push, etc.)
to automatically run security audits on AI Agent skills.

Usage:
    # In a Git pre-commit hook:
    from skill_audit.integrations import git_hook_audit

    result = git_hook_audit(
        skill_path=".",
        mode="fast",
        exit_on_high_risk=True
    )

    if result["should_block"]:
        sys.exit(1)  # Block the commit/push
"""
import sys
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
import yaml

from skill_framework import SkillContext
from ..skill_security_audit import create_skill_security_audit_skill


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Load configuration for Git hooks

    Args:
        config_path: Optional path to config file

    Returns:
        Configuration dict
    """
    # Try multiple config locations
    if config_path and config_path.exists():
        paths_to_try = [config_path]
    else:
        paths_to_try = [
            Path.cwd() / '.skill-audit.yml',
            Path.cwd() / 'config' / 'config.yml',
            Path(__file__).parent.parent / 'config' / 'config.yml',  # Relative to module
            Path.home() / '.claude' / 'skills' / 'skills-audit' / 'config' / 'config.yml',  # User home
        ]

    for path in paths_to_try:
        if path.exists():
            try:
                with open(path) as f:
                    return yaml.safe_load(f)
            except Exception:
                pass

    return {}


def get_scan_mode_config(mode: str, config: Dict[str, Any]) -> Dict[str, bool]:
    """
    Get scan mode configuration

    Args:
        mode: Scan mode (fast, standard, deep)
        config: Configuration dict

    Returns:
        Mode configuration dict
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
    }

    if 'scan_modes' in config and mode in config['scan_modes']:
        return config['scan_modes'][mode]
    else:
        return default_modes.get(mode, default_modes['fast'])


def should_block_commit(report: Dict[str, Any],
                       block_on: List[str] = None) -> bool:
    """
    Determine if commit should be blocked based on risk level

    Args:
        report: Audit report dict
        block_on: List of risk levels to block on (default: ["CRITICAL", "HIGH"])

    Returns:
        True if commit should be blocked
    """
    if block_on is None:
        block_on = ["CRITICAL", "HIGH"]

    risk = report.get('overall_risk', 'UNKNOWN')
    return risk in block_on


def format_hook_output(report: Dict[str, Any],
                      verbose: bool = False) -> str:
    """
    Format audit report for Git hook output

    Args:
        report: Audit report dict
        verbose: Whether to show detailed findings

    Returns:
        Formatted string for console output
    """
    lines = []
    lines.append("")
    lines.append("=" * 70)
    lines.append("🔒 SKILL SECURITY AUDIT")
    lines.append("=" * 70)

    risk = report.get('overall_risk', 'UNKNOWN')
    score = report.get('overall_score', 0)

    # Color-coded risk level
    risk_icon = {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MEDIUM': '🟡',
        'LOW': '🟢',
        'INFO': 'ℹ️',
        'UNKNOWN': '❓',
    }.get(risk, '❓')

    lines.append(f"Risk Level: {risk_icon} {risk}")
    lines.append(f"Risk Score: {score:.1f}/100")
    lines.append("")

    findings = report.get('findings', [])

    if findings:
        lines.append(f"⚠️  Found {len(findings)} security issue(s):")
        lines.append("")

        for i, finding in enumerate(findings[:5], 1):  # Show max 5 findings
            severity = finding.get('severity', 'UNKNOWN')
            title = finding.get('title', 'Unknown')
            lines.append(f"  {i}. [{severity}] {title}")

            if verbose and 'evidence' in finding and finding['evidence']:
                evidence = finding['evidence'][0]
                desc = evidence.get('description', '')
                if desc:
                    lines.append(f"     • {desc}")

        if len(findings) > 5:
            lines.append(f"  ... and {len(findings) - 5} more")
        lines.append("")

    decision = report.get('decision', 'REVIEW')
    lines.append(f"Recommendation: {decision}")
    lines.append("=" * 70)

    return "\n".join(lines)


def git_hook_audit(skill_path: str = ".",
                  mode: str = "fast",
                  config_path: Optional[str] = None,
                  exit_on_high_risk: bool = True,
                  verbose: bool = False,
                  save_report: bool = True) -> Dict[str, Any]:
    """
    Run security audit in Git hook context

    This is the main entry point for Git hooks.

    Args:
        skill_path: Path to skill to audit (default: current directory)
        mode: Scan mode (fast, standard, deep)
        config_path: Optional path to config file
        exit_on_high_risk: Whether to exit(1) on CRITICAL/HIGH findings
        verbose: Whether to show detailed output
        save_report: Whether to save report to file

    Returns:
        Dict with:
            - report: Audit report
            - should_block: Whether commit should be blocked
            - exit_code: Suggested exit code
    """
    # Load configuration
    config_path_obj = Path(config_path) if config_path else None
    config = load_config(config_path_obj)

    # Get scan mode configuration
    mode_config = get_scan_mode_config(mode, config)

    # Create audit skill
    audit_skill = create_skill_security_audit_skill(**mode_config)

    # Create context
    context = SkillContext(
        task_description='Git hook security audit',
        user_input=f'audit {skill_path}',
        workspace_dir=str(Path(skill_path).absolute()),
        session_id='git-hook',
        metadata={'skill_path': str(Path(skill_path).absolute()), 'git_hook': True}
    )

    # Execute audit
    result = audit_skill.execute(context)

    # Process result
    if result.success:
        report = result.output.get('audit_report', {})

        # Determine if should block
        block_on = config.get('git_hooks', {}).get('block_on', ['CRITICAL', 'HIGH'])
        should_block = should_block_commit(report, block_on)

        # Print formatted output
        output = format_hook_output(report, verbose)
        print(output, file=sys.stderr)

        # Save report if requested
        if save_report:
            report_dir = Path(skill_path) / 'security-reports'
            report_dir.mkdir(exist_ok=True)

            from datetime import datetime
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            report_file = report_dir / f'git-hook-{timestamp}.json'

            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)

            print(f"\n📄 Full report saved to: {report_file}\n", file=sys.stderr)

        # Determine exit code
        if should_block and exit_on_high_risk:
            print("❌ COMMIT BLOCKED due to security issues!", file=sys.stderr)
            print("   Fix the issues above or use --no-verify to bypass\n", file=sys.stderr)
            exit_code = 1
        else:
            if should_block:
                print("⚠️  Security issues found, but not blocking commit", file=sys.stderr)
            else:
                print("✅ Security check passed\n", file=sys.stderr)
            exit_code = 0

        return {
            'report': report,
            'should_block': should_block,
            'exit_code': exit_code,
        }
    else:
        # Audit failed
        print(f"❌ Audit failed: {result.error}", file=sys.stderr)
        return {
            'report': {},
            'should_block': False,
            'exit_code': 0,  # Don't block on audit failure
        }


# CLI entry point for Git hooks
def main():
    """CLI entry point for Git hooks"""
    import argparse

    parser = argparse.ArgumentParser(
        prog='skill-audit-hook',
        description='Run skill security audit in Git hook'
    )

    parser.add_argument(
        'skill_path',
        nargs='?',
        default='.',
        help='Path to skill directory (default: current directory)'
    )

    parser.add_argument(
        '--mode',
        choices=['fast', 'standard', 'deep'],
        default='fast',
        help='Scan mode (default: fast)'
    )

    parser.add_argument(
        '--config',
        help='Path to config file'
    )

    parser.add_argument(
        '--no-exit',
        action='store_true',
        help='Do not exit(1) on high-risk findings'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose output'
    )

    parser.add_argument(
        '--no-save',
        action='store_true',
        help='Do not save report to file'
    )

    args = parser.parse_args()

    result = git_hook_audit(
        skill_path=args.skill_path,
        mode=args.mode,
        config_path=args.config,
        exit_on_high_risk=not args.no_exit,
        verbose=args.verbose,
        save_report=not args.no_save,
    )

    sys.exit(result['exit_code'])


if __name__ == '__main__':
    main()
