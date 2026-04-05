#!/usr/bin/env python3
"""
CLI interface for skill-audit

This provides a command-line interface for auditing AI Agent skills.

Usage:
    skill-audit /path/to/skill
    skill-audit /path/to/skill --mode standard
    skill-audit /path/to/skill --mode deep --output report.json
"""
import sys
import argparse
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional

from skill_framework import SkillContext
from .skill_security_audit import create_skill_security_audit_skill


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Load configuration file

    Args:
        config_path: Path to config file (optional)

    Returns:
        Configuration dict
    """
    # Try multiple config locations
    if config_path and config_path.exists():
        paths_to_try = [config_path]
    else:
        paths_to_try = [
            Path(__file__).parent.parent / 'config' / 'config.yml',  # Relative to module
            Path.cwd() / 'config' / 'config.yml',  # Current working directory
            Path.home() / '.claude' / 'skills' / 'skills-audit' / 'config' / 'config.yml',  # User home
        ]

    for path in paths_to_try:
        if path.exists():
            try:
                with open(path) as f:
                    return yaml.safe_load(f)
            except Exception as e:
                print(f"Warning: Failed to load config from {path}: {e}")

    return {}


def get_scan_mode_config(mode: str, config: Dict[str, Any]) -> Dict[str, bool]:
    """
    Get scan mode configuration

    Args:
        mode: Scan mode (fast, standard, deep, expert)
        config: Configuration dict

    Returns:
        Mode configuration dict
    """
    # Default scan modes
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

    # Get mode config from config file or defaults
    if 'scan_modes' in config and mode in config['scan_modes']:
        return config['scan_modes'][mode]
    elif mode in default_modes:
        return default_modes[mode]
    else:
        print(f"Warning: Unknown mode '{mode}', using 'fast' mode")
        return default_modes['fast']


def print_report(report: Dict[str, Any], verbose: bool = True) -> None:
    """
    Print audit report to console

    Args:
        report: Audit report dict
        verbose: Whether to print detailed information
    """
    print()
    print("=" * 70)
    print("SECURITY AUDIT REPORT")
    print("=" * 70)

    # Overall assessment
    risk = report.get('overall_risk', 'UNKNOWN')
    score = report.get('overall_score', 0)
    confidence = report.get('confidence', 0)

    print(f"Overall Risk:  {risk}")
    print(f"Risk Score:    {score:.1f}/100")
    print(f"Confidence:    {confidence:.0%}")
    print()

    # Findings
    findings = report.get('findings', [])

    if findings:
        print(f"Found {len(findings)} security issue(s):")
        print()

        for i, finding in enumerate(findings, 1):
            severity = finding.get('severity', 'UNKNOWN')
            title = finding.get('title', 'Unknown')

            print(f"{i}. [{severity}] {title}")

            if verbose and 'evidence' in finding and finding['evidence']:
                evidence = finding['evidence'][0]
                desc = evidence.get('description', '')
                location = evidence.get('code_location', '')

                if desc:
                    print(f"   - {desc}")
                if location:
                    print(f"   - Location: {location}")

            print()
    else:
        print("No security issues found!")
        print()

    # Recommendation
    decision = report.get('decision', 'REVIEW')
    print("=" * 70)
    print(f"RECOMMENDATION: {decision}")
    print("=" * 70)
    print()


def save_report(report: Dict[str, Any],
                output_path: Optional[Path] = None,
                format: str = 'json') -> Path:
    """
    Save report to file

    Args:
        report: Audit report dict
        output_path: Output file path (optional)
        format: Output format (json, yaml, markdown)

    Returns:
        Path to saved report
    """
    if not output_path:
        # Generate default filename
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        output_path = Path(f"audit-report-{timestamp}.{format}")

    # Save based on format
    if format == 'json':
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
    elif format == 'yaml':
        with open(output_path, 'w') as f:
            yaml.safe_dump(report, f, default_flow_style=False)
    elif format == 'markdown':
        # Simple markdown output
        with open(output_path, 'w') as f:
            f.write(f"# Security Audit Report\n\n")
            f.write(f"- **Risk Level**: {report.get('overall_risk')}\n")
            f.write(f"- **Risk Score**: {report.get('overall_score'):.1f}/100\n")
            f.write(f"- **Confidence**: {report.get('confidence'):.0%}\n\n")

            findings = report.get('findings', [])
            if findings:
                f.write(f"## Findings ({len(findings)})\n\n")
                for i, finding in enumerate(findings, 1):
                    f.write(f"### {i}. [{finding['severity']}] {finding['title']}\n\n")
                    f.write(f"{finding.get('description', '')}\n\n")

    print(f"Report saved to: {output_path}")

    return output_path


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        prog='skill-audit',
        description='Security audit tool for AI Agent skills',
        epilog='For more information, visit the project repository'
    )

    # Positional arguments
    parser.add_argument(
        'skill_path',
        help='Path to skill directory to audit'
    )

    # Optional arguments
    parser.add_argument(
        '--mode',
        choices=['fast', 'standard', 'deep', 'expert'],
        default='fast',
        help='Scan mode (default: fast)'
    )

    parser.add_argument(
        '--config',
        type=Path,
        help='Path to config file'
    )

    parser.add_argument(
        '--output',
        type=Path,
        help='Output report path'
    )

    parser.add_argument(
        '--format',
        choices=['json', 'yaml', 'markdown'],
        default='json',
        help='Output format (default: json)'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose output'
    )

    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Minimal output (only errors)'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )

    args = parser.parse_args()

    # Validate skill path
    skill_path = Path(args.skill_path)
    if not skill_path.exists():
        print(f"Error: Path does not exist: {skill_path}")
        return 1

    # Load configuration
    config = load_config(args.config)

    # Get scan mode configuration
    mode_config = get_scan_mode_config(args.mode, config)

    if not args.quiet:
        print(f"Target: {skill_path}")
        print(f"Mode: {args.mode.upper()}")
        print(f"   AI Analysis: {'Y' if mode_config['enable_ai_analysis'] else 'N'}")
        print(f"   Static Analysis: {'Y' if mode_config['enable_static_analysis'] else 'N'}")
        print(f"   Deep Analysis: {'Y' if mode_config['enable_deep_analysis'] else 'N'}")
        print(f"   Threat Intel: {'Y' if mode_config['enable_tip_check'] else 'N'}")
        print()
        print("Running security audit...")

    # Create audit skill
    audit_skill = create_skill_security_audit_skill(**mode_config)

    # Create context
    context = SkillContext(
        task_description='Security audit',
        user_input=f'audit {skill_path}',
        workspace_dir=str(skill_path),
        session_id='cli',
        metadata={'mode': args.mode, 'cli': True}
    )

    # Execute audit
    result = audit_skill.execute(context)

    # Process results
    if result.success:
        report = result.output.get('audit_report', {})

        # Print report
        if not args.quiet:
            print_report(report, verbose=args.verbose)

        # Save report
        save_report(report, args.output, args.format)

        # Exit code based on risk level
        risk = report.get('overall_risk', 'UNKNOWN')
        if risk == 'CRITICAL':
            return 2
        elif risk == 'HIGH':
            return 1
        else:
            return 0

    else:
        print(f"Error: {result.error}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
