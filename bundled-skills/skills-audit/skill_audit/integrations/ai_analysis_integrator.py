"""
AI Analysis Integrator for Claude Code

This module provides functionality to integrate Claude's AI semantic analysis
results into existing audit reports after static analysis is complete.

Webhook is NOT sent automatically during integration.
Use send_final_webhook() after Claude completes comprehensive analysis.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


def _get_config_path() -> Path:
    """
    Get the config file path relative to this module.

    Returns:
        Path to config.yml
    """
    # Get the skills-audit root directory
    # This file is at: skills-audit/skill_audit/integrations/ai_analysis_integrator.py
    # Config is at: skills-audit/config/config.yml
    # So we need to go up 2 levels from this file's parent
    module_dir = Path(__file__).resolve().parent.parent.parent
    config_path = module_dir / "config" / "config.yml"
    return config_path

# Module-level state for deferred webhook
_pending_webhook_data = None


def integrate_ai_analysis_to_report(
    report_path: str,
    ai_findings: List[Dict[str, Any]],
    skill_path: str,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Integrate AI semantic analysis findings into an existing audit report.

    This function is called by Claude after performing manual AI semantic analysis
    in Claude Code environment. It:
    1. Loads the existing report (with static analysis results)
    2. Adds AI analysis findings
    3. Recalculates risk scores and overall assessment
    4. Saves the updated report
    5. Stores webhook data for deferred sending (does NOT send automatically)

    Args:
        report_path: Path to existing audit report JSON file
        ai_findings: List of AI analysis findings from Claude
        skill_path: Path to the skill that was audited
        config: Optional configuration for webhook notifications

    Returns:
        Updated audit report dict
    """
    global _pending_webhook_data

    try:
        # Load existing report
        report_path_obj = Path(report_path)
        if not report_path_obj.exists():
            raise FileNotFoundError(f"Report not found: {report_path}")

        with open(report_path_obj, 'r') as f:
            report = json.load(f)

        logger.info(f"Loaded existing report from {report_path}")
        logger.info(f"Integrating {len(ai_findings)} AI findings...")

        # Add AI findings to report
        updated_report = _merge_ai_findings(report, ai_findings)

        # Update metadata
        updated_report['metadata'] = updated_report.get('metadata', {})
        updated_report['metadata']['ai_integration_timestamp'] = datetime.now().isoformat()
        updated_report['metadata']['ai_analysis_completed'] = True

        # Recalculate risk scores
        updated_report = _recalculate_risk_scores(updated_report)

        # Save updated report
        with open(report_path_obj, 'w') as f:
            json.dump(updated_report, f, indent=2, ensure_ascii=False)

        logger.info(f"Updated report saved to {report_path}")
        logger.info(f"New overall risk: {updated_report['overall_risk']}")
        logger.info(f"New risk score: {updated_report['overall_score']:.1f}/100")

        # Store webhook data for deferred sending (NOT sent automatically)
        # Webhook will be sent after Claude completes comprehensive analysis
        if config:
            _pending_webhook_data = {
                'report': updated_report,
                'report_path': str(report_path_obj),
                'skill_path': skill_path,
                'config': config,
            }
            logger.info("Webhook data stored for deferred sending")

        return updated_report

    except Exception as e:
        logger.error(f"Failed to integrate AI analysis: {e}", exc_info=True)
        raise


def send_final_webhook(
    report_path: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Send the final webhook notification after Claude's comprehensive analysis.

    This should be called AFTER Claude has:
    1. Completed AI semantic analysis
    2. Integrated findings via integrate_ai_analysis_to_report()
    3. Performed false positive filtering and severity adjustments
    4. Updated the report with final results

    Can use stored pending data from integrate_ai_analysis_to_report(),
    or explicitly provide report_path and config.

    Args:
        report_path: Path to the final audit report (optional, uses pending data if not provided)
        config: Configuration dict (optional, uses pending data if not provided)

    Returns:
        True if webhook sent successfully, False otherwise
    """
    global _pending_webhook_data

    # Determine data source
    if report_path:
        # Explicit report path provided - load fresh data
        report_path_obj = Path(report_path)
        if not report_path_obj.exists():
            print(f"Error: Report not found: {report_path}")
            return False

        with open(report_path_obj, 'r') as f:
            report = json.load(f)

        # Sync overall_score with risk_score if FP filtering updated risk_score
        if 'risk_score' in report:
            report['overall_score'] = report['risk_score']

        skill_path = report.get('skill_path',
                        report.get('skill_artifact', {}).get('skill_path', 'unknown'))

        if config is None:
            # Try to load config
            try:
                import yaml
                config_path = _get_config_path()
                if config_path.exists():
                    with open(config_path) as f:
                        config = yaml.safe_load(f)
                else:
                    config = {}
            except:
                config = {}

        return _send_webhook_notification(
            report=report,
            report_path=str(report_path_obj),
            skill_path=skill_path,
            config=config
        )

    elif _pending_webhook_data:
        # Use stored pending data (re-load report in case it was updated after integration)
        pending = _pending_webhook_data
        _pending_webhook_data = None  # Clear pending data

        # Re-load the report to get the latest version (after FP filtering etc.)
        rp = Path(pending['report_path'])
        if rp.exists():
            with open(rp, 'r') as f:
                report = json.load(f)
        else:
            report = pending['report']

        # Sync overall_score with risk_score if FP filtering updated risk_score
        if 'risk_score' in report:
            report['overall_score'] = report['risk_score']

        return _send_webhook_notification(
            report=report,
            report_path=pending['report_path'],
            skill_path=pending['skill_path'],
            config=pending['config']
        )

    else:
        print("Warning: No webhook data available. Call integrate_ai_analysis_to_report() first or provide report_path.")
        return False


def _merge_ai_findings(report: Dict[str, Any], ai_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Merge AI findings into existing report.

    AI findings format expected:
    [
        {
            "title": "Finding title",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW",
            "category": "category_name",
            "description": "Detailed description",
            "location": "file:line or prompt_N",
            "code_snippet": "relevant code",
            "risk": "Risk explanation",
            "scenario": "Attack scenario",
            "impact": {
                "confidentiality": "CRITICAL|HIGH|MEDIUM|LOW",
                "integrity": "CRITICAL|HIGH|MEDIUM|LOW",
                "availability": "CRITICAL|HIGH|MEDIUM|LOW"
            },
            "recommendation": "How to fix"
        }
    ]
    """
    # Get existing findings
    existing_findings = report.get('findings', [])

    # Convert AI findings to Evidence format and add to report
    for ai_finding in ai_findings:
        # Create new finding entry
        finding = {
            "finding_id": f"AI-{len(existing_findings) + 1:03d}",
            "title": ai_finding.get('title', 'AI-detected Security Issue'),
            "severity": ai_finding.get('severity', 'HIGH'),
            "confidence": 0.90,  # AI analysis has high confidence
            "categories": [ai_finding.get('category', 'ai_semantic_analysis')],
            "description": ai_finding.get('description', ''),
            "evidence": [
                {
                    "source": "ai_analysis",
                    "confidence": 0.90,
                    "severity": ai_finding.get('severity', 'HIGH'),
                    "category": ai_finding.get('category', 'ai_semantic_analysis'),
                    "description": ai_finding.get('risk', ''),
                    "detail": ai_finding.get('scenario', ''),
                    "code_location": ai_finding.get('location', 'N/A'),
                    "code_snippet": ai_finding.get('code_snippet', ''),
                    "matched_pattern": None,
                    "threat_intel_data": None
                }
            ],
            "attack_scenario": {
                "title": ai_finding.get('title', ''),
                "steps": ai_finding.get('scenario', '').split('\n') if isinstance(ai_finding.get('scenario'), str) else [],
                "preconditions": ["Skill installation/execution"],
                "attacker_capability": "Skill access",
                "impact": ai_finding.get('impact_description', ai_finding.get('risk', ''))
            },
            "impact": ai_finding.get('impact', {
                "confidentiality": "HIGH",
                "integrity": "HIGH",
                "availability": "MEDIUM",
                "financial": "Potentially significant",
                "reputation": "Severe",
                "compliance": ["GDPR", "SOC2"]
            }),
            "recommendations": [
                {
                    "priority": "HIGH",
                    "title": "Address AI-detected security issue",
                    "description": ai_finding.get('recommendation', ''),
                    "effort": "MEDIUM",
                    "code_fix": None,
                    "references": ai_finding.get('cwe_ids', [])
                }
            ],
            "cwe_ids": ai_finding.get('cwe_ids', []),
            "metadata": {
                "evidence_count": 1,
                "sources": ["ai_analysis"],
                "ai_detected": True
            }
        }

        existing_findings.append(finding)

    # Update findings in report
    report['findings'] = existing_findings
    report['total_findings'] = len(existing_findings)

    # Update evidence counts
    report['ai_evidence_count'] = report.get('ai_evidence_count', 0) + len(ai_findings)

    return report


def _recalculate_risk_scores(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recalculate risk scores after adding AI findings.
    Excludes false positives from risk calculation.
    """
    all_findings = report.get('findings', [])

    # Filter out false positives for risk calculation
    findings = [f for f in all_findings if not f.get('false_positive', False)]

    # Count by severity (excluding false positives)
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    for finding in findings:
        severity = finding.get('severity', 'LOW')
        evidence_count = len(finding.get('evidence', []))

        if severity == 'CRITICAL':
            critical_count += evidence_count
        elif severity == 'HIGH':
            high_count += evidence_count
        elif severity == 'MEDIUM':
            medium_count += evidence_count
        elif severity == 'LOW':
            low_count += evidence_count

    # Update counts
    report['critical_count'] = critical_count
    report['high_count'] = high_count
    report['medium_count'] = medium_count
    report['low_count'] = low_count

    # Calculate overall score (weighted)
    total_score = (
        critical_count * 10.0 +
        high_count * 5.0 +
        medium_count * 2.0 +
        low_count * 0.5
    )

    # Cap at 100
    overall_score = min(100.0, total_score)
    report['overall_score'] = overall_score
    report['risk_score'] = overall_score  # Keep risk_score in sync

    # Determine risk level
    if critical_count > 0 or overall_score >= 80:
        risk_level = 'CRITICAL'
        decision = 'BLOCK'
    elif high_count > 0 or overall_score >= 60:
        risk_level = 'HIGH'
        decision = 'REVIEW'
    elif medium_count > 0 or overall_score >= 30:
        risk_level = 'MEDIUM'
        decision = 'REVIEW'
    elif low_count > 0:
        risk_level = 'LOW'
        decision = 'ALLOW'
    else:
        risk_level = 'INFO'
        decision = 'ALLOW'

    report['overall_risk'] = risk_level
    report['decision_recommendation'] = decision

    # Update confidence
    static_score = report.get('static_analysis_score', 0)
    ai_score = min(100.0, len(findings) * 10.0)  # Rough AI score based on findings count
    report['ai_analysis_score'] = ai_score

    # Combined confidence
    if static_score > 0 and ai_score > 0:
        report['confidence'] = 0.95  # High confidence when both agree
    elif static_score > 0 or ai_score > 0:
        report['confidence'] = 0.85
    else:
        report['confidence'] = 0.50

    # Update executive summary
    report['executive_summary'] = (
        f"Skill '{report.get('skill_artifact', {}).get('skill_name', 'unknown')}' "
        f"received an overall risk rating of **{risk_level}** "
        f"(score: {overall_score:.1f}/100, confidence: {report['confidence']:.0%}). "
        f"Analysis identified {len(findings)} security finding(s): "
        f"{critical_count} critical, {high_count} high, {medium_count} medium, {low_count} low severity. "
        f"**Recommendation**: {decision} this skill from installation/execution."
    )

    # Update key concerns
    key_concerns = [f['title'] for f in findings[:5]]  # Top 5 findings
    report['key_concerns'] = key_concerns

    return report


def _send_webhook_notification(
    report: Dict[str, Any],
    report_path: str,
    skill_path: str,
    config: Dict[str, Any]
) -> bool:
    """
    Send webhook notification with updated report.
    """
    try:
        notifications_config = config.get('notifications', {})
        if not notifications_config.get('enabled', False):
            logger.info("Webhook notifications disabled")
            return False

        lark_webhook = notifications_config.get('lark_webhook_url')
        if not lark_webhook:
            logger.warning("No Lark webhook URL configured")
            return False

        # Check if we should send notification
        notify_on = notifications_config.get('notify_on', 'always')
        risk_level = report.get('overall_risk', 'UNKNOWN')

        should_notify = False
        if notify_on == 'always':
            should_notify = True
        elif notify_on == 'on_risk' and risk_level in ['CRITICAL', 'HIGH', 'MEDIUM']:
            should_notify = True
        elif notify_on == 'critical_only' and risk_level == 'CRITICAL':
            should_notify = True

        if not should_notify:
            logger.info(f"Not sending notification (notify_on={notify_on}, risk={risk_level})")
            return False

        # Import and send (graceful fallback if lark_notification not available)
        try:
            from .lark_notification import send_lark_notification
        except ImportError:
            logger.warning("lark_notification module not available, skipping webhook")
            print('Warning: lark_notification module not available, skipping webhook')
            return False

        skill_name = Path(skill_path).name
        scan_mode = report.get('metadata', {}).get('scan_mode', 'deep')
        timeout = notifications_config.get('timeout', 10)

        print('Sending final notification to Lark (after comprehensive analysis)...')
        success = send_lark_notification(
            webhook_url=lark_webhook,
            skill_name=skill_name,
            skill_path=skill_path,
            report=report,
            scan_mode=scan_mode,
            report_path=report_path,
            timeout=timeout,
        )

        if success:
            print('Lark notification sent successfully')
        else:
            print('Warning: Lark notification failed')

        return success

    except Exception as e:
        logger.error(f"Failed to send webhook: {e}", exc_info=True)
        print(f'Warning: Failed to send Lark notification: {e}')
        return False


# Convenience function for CLI usage
def main():
    """
    CLI entry point for integrating AI analysis.

    Usage:
        python -m skill_audit.integrations.ai_analysis_integrator \
            <report_path> <ai_findings_json>
    """
    import sys

    if len(sys.argv) < 3:
        print("Usage: python -m skill_audit.integrations.ai_analysis_integrator "
              "<report_path> <ai_findings_json>")
        sys.exit(1)

    report_path = sys.argv[1]
    ai_findings_json = sys.argv[2]

    # Load AI findings
    with open(ai_findings_json, 'r') as f:
        ai_findings = json.load(f)

    # Load config
    try:
        import yaml
        config_path = _get_config_path()
        if config_path.exists():
            with open(config_path) as f:
                config = yaml.safe_load(f)
        else:
            config = {}
    except:
        config = {}

    # Integrate
    skill_path = Path(report_path).parent
    updated_report = integrate_ai_analysis_to_report(
        report_path=report_path,
        ai_findings=ai_findings,
        skill_path=str(skill_path),
        config=config
    )

    print(f"\nAI analysis integrated successfully")
    print(f"Overall Risk: {updated_report['overall_risk']}")
    print(f"Risk Score: {updated_report['overall_score']:.1f}/100")
    print(f"Total Findings: {updated_report['total_findings']}")


if __name__ == '__main__':
    main()
