#!/usr/bin/env python3
"""
CLI wrapper for skill-audit in Claude Code environment.

This script is called by SKILL.md to avoid showing long inline Python code
to users during permission prompts.
"""
import sys
import os
from pathlib import Path


def main():
    # === Parse arguments ===
    # Arguments are passed as a single string from SKILL.md
    args_str = sys.argv[1] if len(sys.argv) > 1 else ''
    args = args_str.split() if args_str else []

    skill_path = args[0] if args else '.'
    scan_mode = 'deep'  # Default: deep mode (AI + Static + Deep analysis)

    for i, arg in enumerate(args):
        if arg == '--mode' and i + 1 < len(args):
            scan_mode = args[i + 1]

    if not os.path.exists(skill_path):
        print(f'Error: Path does not exist: {skill_path}')
        sys.exit(1)

    # === Auto-detect skill-audit directory ===
    # Try multiple detection methods in order of preference
    skill_audit_dirs = [
        # 1. Environment variable override (highest priority)
        Path(os.environ.get('SKILL_AUDIT_HOME', ''))
        if os.environ.get('SKILL_AUDIT_HOME') else None,

        # 2. Infer from current script location (most reliable)
        Path(__file__).parent.parent,

        # 3. Standard user installation (~/.claude/skills/skills-audit)
        Path.home() / '.claude' / 'skills' / 'skills-audit',

        # 4. Alternative naming (skill-audit vs skills-audit)
        Path.home() / '.claude' / 'skills' / 'skill-audit',

        # 5. Current working directory (fallback)
        Path.cwd(),
    ]

    skill_audit_dir = None
    for dir_path in skill_audit_dirs:
        if dir_path and dir_path.exists() and (dir_path / 'skill_audit').exists():
            skill_audit_dir = dir_path
            break

    if not skill_audit_dir:
        print('Error: Cannot find skills-audit installation')
        print()
        print('Searched the following paths:')
        for i, path in enumerate(skill_audit_dirs, 1):
            if path:
                exists = 'Y' if path.exists() else 'N'
                print(f'  {i}. [{exists}] {path}')
        print()
        print('Solution: Set the SKILL_AUDIT_HOME environment variable to point to your skills-audit installation directory.')
        print()
        print('Example:')
        print('  export SKILL_AUDIT_HOME=/path/to/your/skills-audit')
        print('  # Then run this script again')
        print()
        sys.exit(1)

    print(f'Target: {skill_path}')
    print(f'Using: {skill_audit_dir}')
    print()

    sys.path.insert(0, str(skill_audit_dir))

    # === Import modules ===
    from skill_audit.integrations import claude_code_audit
    import json

    # === Load config ===
    try:
        import yaml
        config_path = skill_audit_dir / 'config' / 'config.yml'
        if config_path.exists():
            with open(config_path) as f:
                config = yaml.safe_load(f)
        else:
            config = {}
    except:
        config = {}

    # === Determine scan mode ===
    scan_modes = ['fast', 'standard', 'deep', 'expert']
    if scan_mode not in scan_modes:
        print(f'Warning: Unknown mode "{scan_mode}", using "deep" mode')
        scan_mode = 'deep'

    print(f'Scan Mode: {scan_mode.upper()}')

    # Get actual mode configuration that will be used (same logic as claude_code.py)
    from skill_audit.integrations.claude_code import get_scan_mode_config
    mode_config = get_scan_mode_config(scan_mode, config)

    print(f'   AI Analysis: {"Y" if mode_config["enable_ai_analysis"] else "N"}')
    print(f'   Static Analysis: {"Y" if mode_config["enable_static_analysis"] else "N"}')
    print(f'   Deep Analysis: {"Y" if mode_config["enable_deep_analysis"] else "N"}')
    print(f'   Threat Intel: {"Y" if mode_config["enable_tip_check"] else "N"}')
    print()

    print('Running security audit...')
    print()

    # === Execute audit ===
    report = claude_code_audit(
        skill_path=skill_path,
        mode=scan_mode,
        config=config,
    )

    # === Process results ===
    if report:
        print('=' * 70)
        print('SECURITY AUDIT REPORT')
        print('=' * 70)
        print(f"Overall Risk: {report.get('overall_risk', 'UNKNOWN')}")
        print(f"Risk Score: {report.get('overall_score', 0):.1f}/100")
        print(f"Confidence: {report.get('confidence', 0):.0%}")
        print()

        findings = report.get('findings', [])
        if findings:
            print(f'Found {len(findings)} security issue(s):')
            print()
            for i, finding in enumerate(findings, 1):
                severity = finding.get('severity', 'UNKNOWN')
                title = finding.get('title', 'Unknown')
                print(f"{i}. [{severity}] {title}")
                if 'evidence' in finding and finding['evidence']:
                    evidence = finding['evidence'][0]
                    desc = evidence.get('description', '')
                    location = evidence.get('code_location', '')
                    if desc:
                        print(f'   - {desc}')
                    if location:
                        print(f'   - Location: {location}')
                print()
        else:
            print('No security issues found!')
            print()

        # === Save report ===
        report_location = config.get('claude_code', {}).get('report_location', 'cwd')

        if report_location == 'custom':
            custom_dir = config.get('claude_code', {}).get('custom_report_dir', '')
            if custom_dir:
                report_dir = Path(os.path.expanduser(custom_dir))
                report_dir.mkdir(parents=True, exist_ok=True)
            else:
                report_dir = Path.cwd()
        elif report_location == 'skill_dir':
            report_dir = skill_audit_dir / 'reports'
            report_dir.mkdir(exist_ok=True)
        elif report_location == 'temp':
            import tempfile
            report_dir = Path(tempfile.gettempdir()) / 'skill-audit-reports'
            report_dir.mkdir(exist_ok=True)
        else:
            report_dir = Path.cwd()

        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        skill_name = Path(skill_path).name or 'unknown'

        # Set skill_name and skill_path in report for webhook to use
        report['skill_name'] = skill_name
        report['skill_path'] = os.path.abspath(skill_path)

        filename_template = config.get('output', {}).get('report_filename', 'audit-{skill_name}-{timestamp}.json')
        report_filename = filename_template.format(
            skill_name=skill_name,
            timestamp=timestamp,
            risk_level=report.get('overall_risk', 'UNKNOWN').lower()
        )
        report_path = report_dir / report_filename

        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        print(f'Detailed report saved to: {report_path}')
        print()

        # === Webhook notification ===
        # Webhook is ALWAYS deferred in all modes
        # It will be sent after Claude completes comprehensive analysis (false positive filtering)
        # via integrate_ai_findings.py which calls send_final_webhook()
        ai_analysis_enabled = mode_config.get('enable_ai_analysis', False)

        if not ai_analysis_enabled:
            # Fast mode (no AI analysis) - send webhook now since there's no AI step
            notifications_config = config.get('notifications', {})
            if notifications_config.get('enabled', False):
                webhook_url = notifications_config.get('lark_webhook_url')
                if webhook_url:
                    try:
                        from skill_audit.integrations.lark_notification import send_lark_notification

                        # Check notification condition
                        notify_on = notifications_config.get('notify_on', 'always')
                        risk = report.get('overall_risk', 'UNKNOWN')

                        should_notify = False
                        if notify_on == 'always':
                            should_notify = True
                        elif notify_on == 'on_risk':
                            should_notify = risk in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                        elif notify_on == 'critical_only':
                            should_notify = risk == 'CRITICAL'

                        if should_notify:
                            print('Sending Lark notification...')
                            send_lark_notification(
                                webhook_url=webhook_url,
                                skill_name=skill_name,
                                skill_path=skill_path,
                                report=report,
                                scan_mode=scan_mode,
                                report_path=str(report_path),
                                timeout=notifications_config.get('timeout', 10),
                                config=config,
                            )
                            print()
                    except ImportError:
                        print('Warning: lark_notification module not available, skipping webhook')
                        print()
        else:
            # AI analysis enabled - webhook deferred until after comprehensive analysis
            print('Webhook deferred -- will be sent after comprehensive AI analysis and false positive filtering')
            print()

        print('=' * 70)
        print(f"RECOMMENDATION: {report.get('decision', 'REVIEW')}")
        print('=' * 70)
    else:
        print('Error: Audit failed or returned no results')
        sys.exit(1)


if __name__ == '__main__':
    main()
