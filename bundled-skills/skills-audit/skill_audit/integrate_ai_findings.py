#!/usr/bin/env python3
"""
CLI wrapper to integrate AI analysis findings into audit report.

This script is called by Claude after performing manual AI semantic analysis
in SKILL.md. It takes AI findings as JSON input and integrates them into
the existing audit report.

IMPORTANT: Webhook is NOT sent during this step.
After Claude completes comprehensive analysis (false positive filtering etc.),
it should call send_final_webhook() or run send_webhook.py separately.
"""

import sys
import json
import tempfile
from pathlib import Path


def main():
    """
    Usage:
        python3 integrate_ai_findings.py <report_path> '<ai_findings_json>'

    ai_findings_json format:
        [
            {
                "title": "Finding title",
                "severity": "CRITICAL|HIGH|MEDIUM|LOW",
                "category": "category_name",
                "description": "Description",
                "location": "file:line",
                "code_snippet": "code",
                "risk": "Risk explanation",
                "scenario": "Attack scenario",
                "impact": {
                    "confidentiality": "CRITICAL",
                    "integrity": "CRITICAL",
                    "availability": "HIGH"
                },
                "impact_description": "Impact details",
                "recommendation": "How to fix",
                "cwe_ids": ["CWE-78", "CWE-94"]
            }
        ]
    """
    if len(sys.argv) < 3:
        print("❌ Error: Missing arguments")
        print("\nUsage:")
        print("  python3 integrate_ai_findings.py <report_path> '<ai_findings_json>'")
        print("\nExample:")
        print('  python3 integrate_ai_findings.py /path/to/report.json \'[{"title":"RCE","severity":"CRITICAL",...}]\'')
        sys.exit(1)

    report_path = sys.argv[1]
    ai_findings_json_str = sys.argv[2]

    # Validate report path
    if not Path(report_path).exists():
        print(f"❌ Error: Report file not found: {report_path}")
        sys.exit(1)

    # Parse AI findings
    try:
        ai_findings = json.loads(ai_findings_json_str)
        if not isinstance(ai_findings, list):
            raise ValueError("AI findings must be a JSON array")
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON in ai_findings: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

    print(f"✅ Report path: {report_path}")
    print(f"✅ AI findings: {len(ai_findings)} finding(s)")
    print()

    # Auto-detect skill-audit directory and add to path
    # Try multiple detection methods in order of preference
    skill_audit_dirs = [
        # 1. Infer from current script location (__file__)
        Path(__file__).parent.parent.resolve(),
        # 2. Standard user installation
        Path.home() / '.claude' / 'skills' / 'skills-audit',
    ]

    skill_audit_dir = None
    for dir_path in skill_audit_dirs:
        if dir_path and dir_path.exists() and (dir_path / 'skill_audit').exists():
            skill_audit_dir = dir_path
            break

    if not skill_audit_dir:
        print('❌ Error: Cannot find skills-audit installation')
        print(f'Searched paths:')
        for p in skill_audit_dirs:
            print(f'  - {p} (exists: {p.exists() if p else False})')
        sys.exit(1)

    sys.path.insert(0, str(skill_audit_dir))

    # Import integration function
    try:
        from skill_audit.integrations import integrate_ai_analysis_to_report
    except ImportError as e:
        print(f"❌ Error: Failed to import integration function: {e}")
        sys.exit(1)

    # Extract skill path from report
    try:
        with open(report_path, 'r') as f:
            report = json.load(f)
        skill_path = report.get('skill_artifact', {}).get('skill_path', '')
    except Exception as e:
        print(f"⚠️  Warning: Could not extract skill_path from report: {e}")
        skill_path = str(Path(report_path).parent)

    # Integrate AI findings (webhook NOT sent here)
    print("🔄 Integrating AI analysis into report...")
    print()

    try:
        updated_report = integrate_ai_analysis_to_report(
            report_path=report_path,
            ai_findings=ai_findings,
            skill_path=skill_path,
            config=None  # No config = no webhook stored
        )

        print()
        print("=" * 70)
        print("✅ AI ANALYSIS INTEGRATED (webhook deferred)")
        print("=" * 70)
        print(f"Overall Risk: {updated_report['overall_risk']}")
        print(f"Risk Score: {updated_report['overall_score']:.1f}/100")
        print(f"Confidence: {updated_report['confidence']:.0%}")
        print()
        print(f"Total Findings: {updated_report['total_findings']}")
        print(f"  • Critical: {updated_report['critical_count']}")
        print(f"  • High: {updated_report['high_count']}")
        print(f"  • Medium: {updated_report['medium_count']}")
        print(f"  • Low: {updated_report['low_count']}")
        print()
        print(f"Evidence Sources:")
        print(f"  • Static Analysis: {updated_report.get('static_evidence_count', 0)}")
        print(f"  • AI Analysis: {updated_report.get('ai_evidence_count', 0)}")
        print()
        print(f"💡 Decision: {updated_report.get('decision_recommendation', 'REVIEW')}")
        print("=" * 70)
        print()
        print("⏳ Webhook NOT sent — waiting for Claude's comprehensive analysis and false positive filtering")
        print("   After analysis, Claude should call send_final_webhook() to send the notification")

        return 0

    except Exception as e:
        print(f"❌ Error: Failed to integrate AI analysis: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    sys.exit(main())
