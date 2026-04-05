"""
Scoring Algorithms for Skill Security Audit

Implements weighted scoring that combines AI, static, and TIP evidence.
"""

import logging
from typing import List, Dict, Any, Tuple
from .schemas import (
    Evidence,
    RiskLevel,
    EvidenceSource,
)

logger = logging.getLogger(__name__)


class RiskScorer:
    """Calculates overall risk scores from multi-source evidence"""

    # Scoring weights (total = 100%)
    AI_WEIGHT = 0.40  # 40% weight for AI semantic analysis
    STATIC_WEIGHT = 0.20  # 20% weight for static regex rules
    DEEP_WEIGHT = 0.10  # 10% weight for deep code understanding
    TIP_WEIGHT = 0.30  # 30% weight for TIP

    # Risk boost multipliers
    C2_BOOST_MULTIPLIER = 1.5  # 50% boost if C2 detected
    CRITICAL_PATTERN_MULTIPLIER = 1.3  # 30% boost for critical patterns
    OBFUSCATION_BOOST_MULTIPLIER = 1.2  # 20% boost if obfuscation detected

    @classmethod
    def calculate_overall_risk_score(
        cls,
        ai_score: float,
        static_score: float,
        deep_score: float,
        tip_score: float,
        has_c2: bool = False,
        has_critical_patterns: bool = False,
        has_obfuscation: bool = False,
        active_phases: List[str] = None,
        ai_classification: dict = None,
    ) -> float:
        """
        Calculate weighted overall risk score (0-100).

        Args:
            ai_score: AI semantic analysis score (0-100)
            static_score: Static regex analysis score (0-100)
            deep_score: Deep code understanding score (0-100)
            tip_score: TIP analysis score (0-100)
            has_c2: Whether C2 servers were detected
            has_critical_patterns: Whether critical patterns were found
            has_obfuscation: Whether code obfuscation was detected
            active_phases: List of phase names that actually ran (for weight redistribution)
            ai_classification: Optional dict from AI phase with keys:
                purpose (str), purpose_confidence (float), justification (str).
                When AI confidently classifies skill as security_tool/educational,
                the critical override is suppressed to reduce false positives.

        Returns:
            Overall risk score (0-100)
        """
        # Critical override: high static score + critical patterns -> minimum 80
        # Suppress when AI confidently classifies as security/educational tool
        override_suppressed = False
        if ai_classification:
            purpose = ai_classification.get("purpose", "suspicious")
            purpose_confidence = ai_classification.get("purpose_confidence", 0.0)
            if purpose in ("security_tool", "educational") and purpose_confidence >= 0.8:
                override_suppressed = True
                logger.info(
                    f"Critical override suppressed: AI classified as {purpose} "
                    f"(confidence: {purpose_confidence:.2f})"
                )

        if has_critical_patterns and static_score >= 80 and not override_suppressed:
            logger.info(
                f"CRITICAL patterns detected with high static score ({static_score:.1f}). "
                "Enforcing minimum risk score of 80."
            )
            base_score = max(80.0, static_score)
        else:
            # Determine effective weights based on active phases
            phase_weights = {
                'ai': (cls.AI_WEIGHT, ai_score),
                'static': (cls.STATIC_WEIGHT, static_score),
                'deep': (cls.DEEP_WEIGHT, deep_score),
                'tip': (cls.TIP_WEIGHT, tip_score),
            }

            if active_phases:
                # Redistribute: only active phases get weight
                active_total = sum(
                    w for name, (w, _) in phase_weights.items() if name in active_phases
                )
                if active_total > 0:
                    base_score = sum(
                        score * (weight / active_total)
                        for name, (weight, score) in phase_weights.items()
                        if name in active_phases
                    )
                else:
                    base_score = 0.0
            else:
                # Default: use fixed weights (backward compatible)
                base_score = (
                    ai_score * cls.AI_WEIGHT
                    + static_score * cls.STATIC_WEIGHT
                    + deep_score * cls.DEEP_WEIGHT
                    + tip_score * cls.TIP_WEIGHT
                )

        # Apply boosters
        if has_c2:
            logger.info(f"Applying C2 boost: {cls.C2_BOOST_MULTIPLIER}x")
            base_score *= cls.C2_BOOST_MULTIPLIER

        if has_critical_patterns and not (has_critical_patterns and static_score >= 80):
            # Only apply multiplier if not already using CRITICAL override
            logger.info(f"Applying critical pattern boost: {cls.CRITICAL_PATTERN_MULTIPLIER}x")
            base_score *= cls.CRITICAL_PATTERN_MULTIPLIER

        if has_obfuscation:
            logger.info(f"Applying obfuscation boost: {cls.OBFUSCATION_BOOST_MULTIPLIER}x")
            base_score *= cls.OBFUSCATION_BOOST_MULTIPLIER

        # Cap at 100
        final_score = min(100.0, base_score)

        logger.info(
            f"Overall risk score calculated: {final_score:.2f} "
            f"(AI: {ai_score:.1f}, Static: {static_score:.1f}, Deep: {deep_score:.1f}, TIP: {tip_score:.1f})"
        )

        return final_score

    @classmethod
    def determine_risk_level(cls, score: float) -> RiskLevel:
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 30:
            return RiskLevel.MEDIUM
        elif score >= 10:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO

    @classmethod
    def calculate_confidence(cls, evidence_list: List[Evidence]) -> float:
        if not evidence_list:
            return 0.75

        severity_weights = {
            RiskLevel.CRITICAL: 1.0,
            RiskLevel.HIGH: 0.8,
            RiskLevel.MEDIUM: 0.6,
            RiskLevel.LOW: 0.4,
            RiskLevel.INFO: 0.2,
        }

        weighted_sum = 0.0
        total_weight = 0.0

        for evidence in evidence_list:
            weight = severity_weights.get(evidence.severity, 0.5)
            try:
                confidence = float(evidence.confidence)
            except (ValueError, TypeError):
                confidence = 0.5
            weighted_sum += confidence * weight
            total_weight += weight

        if total_weight == 0:
            return 0.5

        return weighted_sum / total_weight

    @classmethod
    def count_evidence_by_source(cls, evidence_list: List[Evidence]) -> Tuple[int, int, int]:
        ai_count = sum(1 for e in evidence_list if e.source == EvidenceSource.AI_ANALYSIS)
        static_count = sum(1 for e in evidence_list if e.source == EvidenceSource.STATIC_RULES)
        tip_count = sum(1 for e in evidence_list if e.source == EvidenceSource.THREAT_INTEL)
        return ai_count, static_count, tip_count

    @classmethod
    def count_evidence_by_severity(cls, evidence_list: List[Evidence]) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for evidence in evidence_list:
            severity_key = evidence.severity.value.lower()
            counts[severity_key] = counts.get(severity_key, 0) + 1
        return counts

    @classmethod
    def has_critical_patterns(cls, evidence_list: List[Evidence]) -> bool:
        return any(
            e.severity == RiskLevel.CRITICAL and e.confidence >= 0.8
            for e in evidence_list
        )

    @classmethod
    def detect_c2(cls, evidence_list: List[Evidence]) -> Tuple[bool, int]:
        c2_evidence = [
            e for e in evidence_list
            if e.source == EvidenceSource.THREAT_INTEL and "C2" in e.description.upper()
        ]
        return len(c2_evidence) > 0, len(c2_evidence)

    @classmethod
    def generate_decision_recommendation(cls, overall_score: float, confidence: float) -> str:
        if overall_score >= 70 and confidence >= 0.7:
            return "BLOCK"
        if overall_score < 30 and confidence >= 0.7:
            return "ALLOW"
        if overall_score >= 60:
            return "HITL_REVIEW"
        if overall_score >= 30:
            return "HITL_REVIEW"
        if confidence < 0.5:
            return "HITL_REVIEW"
        return "ALLOW"

    @classmethod
    def generate_executive_summary(
        cls, skill_name, overall_risk, overall_score, confidence,
        total_findings, critical_count, high_count, c2_detected,
    ) -> str:
        summary_parts = []
        summary_parts.append(
            f"Skill '{skill_name}' received an overall risk rating of **{overall_risk.value}** "
            f"(score: {overall_score:.1f}/100, confidence: {confidence:.0%})."
        )
        if total_findings == 0:
            summary_parts.append("No security concerns identified.")
        else:
            summary_parts.append(
                f"Analysis identified {total_findings} security finding(s): "
                f"{critical_count} critical, {high_count} high severity."
            )
        if c2_detected:
            summary_parts.append(
                "**CRITICAL**: Command & Control (C2) server communication detected. "
                "This skill may be used for remote control or data exfiltration."
            )
        decision = cls.generate_decision_recommendation(overall_score, confidence)
        if decision == "BLOCK":
            summary_parts.append("**Recommendation**: BLOCK this skill from installation/execution.")
        elif decision == "ALLOW":
            summary_parts.append("**Recommendation**: Skill appears safe for use.")
        else:
            summary_parts.append("**Recommendation**: Human review required before approval.")
        return " ".join(summary_parts)
