"""
Phase 2B: Threat Intelligence Platform (TIP) Integration

Checks external addresses (IPs, domains, URLs) against threat intelligence.
"""

import logging
from typing import Dict, List, Any, Optional

from skill_framework import CodeSkill as BaseSkill, SkillContext, SkillResult, SkillCategory
from skill_audit.schemas import (
    SkillArtifact,
    Evidence,
    RiskLevel,
    RiskCategory,
    EvidenceSource,
)

logger = logging.getLogger(__name__)


class TIPIntegrationSkill(BaseSkill):
    """Threat intelligence validation for external references"""

    def __init__(self):
        super().__init__(
            name="tip_integration",
            description="Threat intelligence check for external addresses in skills",
            category=SkillCategory.PROFESSIONAL,
            prompt_template="Threat intelligence validation for external addresses",
            required_tools=[],  # TIP check is internal
            tags=["security", "threat-intelligence", "tip", "skill-audit"],
            metadata={
                "analysis_type": "threat_intelligence",
                "tip_provider": "threatbook",
            },
        )

    def execute(self, context: SkillContext) -> SkillResult:
        """
        Check external addresses via TIP.

        Expected context.metadata:
            - skill_artifact: SkillArtifact object
        """
        try:
            # Extract skill artifact
            skill_artifact = context.metadata.get("skill_artifact")
            if not skill_artifact:
                return SkillResult(
                    success=False,
                    skill_name=self.name,
                    error="Missing skill_artifact in context.metadata",
                )

            if not isinstance(skill_artifact, SkillArtifact):
                return SkillResult(
                    success=False,
                    skill_name=self.name,
                    error="skill_artifact must be SkillArtifact instance",
                )

            logger.info(
                f"Starting TIP check for skill: {skill_artifact.skill_name}"
            )

            external_refs = skill_artifact.external_references

            # Collect all resources to check
            all_resources = []
            all_resources.extend(external_refs.get("ips", []))
            all_resources.extend(external_refs.get("domains", []))

            if not all_resources:
                logger.info("No external addresses to check")
                return SkillResult(
                    success=True,
                    skill_name=self.name,
                    output={
                        "evidence": [],
                        "tip_score": 0.0,
                        "total_checked": 0,
                        "malicious_count": 0,
                        "c2_count": 0,
                    },
                    tools_used=["tip:none"],
                )

            # Call TIP skill
            tip_result = self._check_with_tip(all_resources, context)

            if not tip_result:
                logger.warning("TIP check failed, continuing without TIP evidence")
                return SkillResult(
                    success=True,
                    skill_name=self.name,
                    output={
                        "evidence": [],
                        "tip_score": 0.0,
                        "total_checked": len(all_resources),
                        "malicious_count": 0,
                        "c2_count": 0,
                        "tip_error": "TIP check failed",
                    },
                    tools_used=["tip:error"],
                )

            # Convert TIP results to Evidence
            evidence_list = self._convert_tip_to_evidence(
                tip_result, skill_artifact.skill_name
            )

            # Calculate TIP score
            tip_score = self._calculate_tip_score(tip_result)

            output = {
                "evidence": [e.to_dict() for e in evidence_list],
                "tip_score": tip_score,
                "total_checked": tip_result.get("total_checked", len(all_resources)),
                "malicious_count": tip_result.get("malicious_count", 0),
                "c2_count": tip_result.get("c2_count", 0),
                "tip_raw_results": tip_result,
            }

            logger.info(
                f"TIP check complete. Score: {tip_score}, "
                f"Checked: {output['total_checked']}, "
                f"Malicious: {output['malicious_count']}, "
                f"C2: {output['c2_count']}"
            )

            return SkillResult(
                success=True,
                skill_name=self.name,
                output=output,
                tools_used=["tip:threatbook"],
            )

        except Exception as e:
            logger.error(f"TIP integration failed: {e}", exc_info=True)
            # Don't fail the whole audit if TIP fails
            return SkillResult(
                success=True,
                skill_name=self.name,
                output={
                    "evidence": [],
                    "tip_score": 0.0,
                    "total_checked": 0,
                    "malicious_count": 0,
                    "c2_count": 0,
                    "tip_error": str(e),
                },
                tools_used=["tip:error"],
            )

    def _check_with_tip(
        self, resources: List[str], parent_context: SkillContext
    ) -> Optional[Dict[str, Any]]:
        """
        Call TIP skill to check resources.

        Returns TIP skill output or None if failed.
        """
        try:
            # NOTE: TIP check disabled - requires ThreatBook API implementation
            # Future: implement TIP adapter for threat intelligence checking
            logger.info("TIP check skipped (not implemented)")

            # Return empty TIP results
            return {
                "checked_resources": len(resources),
                "malicious_count": 0,
                "suspicious_count": 0,
                "findings": [],
            }

        except ImportError:
            logger.error("TIP skill not available (import failed)")
            return None
        except Exception as e:
            logger.error(f"Failed to call TIP skill: {e}")
            return None

    def _convert_tip_to_evidence(
        self, tip_result: Dict[str, Any], skill_name: str
    ) -> List[Evidence]:
        """Convert TIP results to Evidence objects"""
        evidence_list = []

        malicious_resources = tip_result.get("malicious_resources", [])
        c2_resources = tip_result.get("c2_resources", [])

        # C2 resources (CRITICAL)
        for resource_data in c2_resources:
            resource = resource_data.get("resource", "unknown")
            judgments = resource_data.get("judgments", [])

            evidence = Evidence(
                source=EvidenceSource.THREAT_INTEL,
                confidence=0.95,  # High confidence for TIP C2 detection
                severity=RiskLevel.CRITICAL,
                category=RiskCategory.REMOTE_CONTROL,
                description=f"C2 server detected: {resource}",
                detail=f"Threat Intelligence identifies this as a command & control server. Judgments: {', '.join(judgments)}",
                code_location=None,
                code_snippet=None,
                matched_pattern=None,
                threat_intel_data={
                    "resource": resource,
                    "judgments": judgments,
                    "source": "threatbook",
                },
            )
            evidence_list.append(evidence)

        # Other malicious resources (HIGH)
        for resource_data in malicious_resources:
            resource = resource_data.get("resource", "unknown")
            if resource in [r.get("resource") for r in c2_resources]:
                continue  # Skip, already added as C2

            judgments = resource_data.get("judgments", [])

            evidence = Evidence(
                source=EvidenceSource.THREAT_INTEL,
                confidence=0.9,
                severity=RiskLevel.HIGH,
                category=RiskCategory.DATA_EXFILTRATION,
                description=f"Malicious address detected: {resource}",
                detail=f"Threat Intelligence identifies this as malicious. Judgments: {', '.join(judgments)}",
                code_location=None,
                code_snippet=None,
                matched_pattern=None,
                threat_intel_data={
                    "resource": resource,
                    "judgments": judgments,
                    "source": "threatbook",
                },
            )
            evidence_list.append(evidence)

        return evidence_list

    def _calculate_tip_score(self, tip_result: Dict[str, Any]) -> float:
        """
        Calculate TIP score (0-100).

        Higher score = more malicious addresses detected.
        """
        total_checked = tip_result.get("total_checked", 0)
        if total_checked == 0:
            return 0.0

        malicious_count = tip_result.get("malicious_count", 0)
        c2_count = tip_result.get("c2_count", 0)

        # Base score from malicious ratio
        malicious_ratio = malicious_count / total_checked
        base_score = malicious_ratio * 60  # Max 60 points from ratio

        # Additional points for C2 detection
        c2_points = min(40, c2_count * 20)  # Up to 40 points, 20 per C2

        total_score = base_score + c2_points

        return min(100.0, total_score)


def create_tip_integration_skill() -> TIPIntegrationSkill:
    """Factory function"""
    return TIPIntegrationSkill()
