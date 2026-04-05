"""
Phase 3: Risk Attribution & Explanation Synthesis

Combines evidence from all sources and generates final audit report.
"""

import logging
import uuid
from datetime import datetime
from typing import Dict, List, Any, Set
from collections import defaultdict

from skill_framework import CodeSkill as BaseSkill, SkillContext, SkillResult, SkillCategory
from skill_audit.schemas import (
    SkillArtifact,
    SkillAuditReport,
    Finding,
    Evidence,
    Recommendation,
    RiskLevel,
    RiskCategory,
    EvidenceSource,
    AttackScenario,
    ImpactAssessment,
)
from skill_audit.scoring import RiskScorer

logger = logging.getLogger(__name__)


class RiskSynthesisSkill(BaseSkill):
    """Synthesizes multi-source evidence into final audit report"""

    def __init__(self):
        super().__init__(
            name="risk_synthesis",
            description="Synthesizes security evidence into audit report",
            category=SkillCategory.PROFESSIONAL,
            prompt_template="Risk synthesis and audit report generation",
            required_tools=[],  # Pure synthesis logic, no external tools
            tags=["security", "synthesis", "reporting", "skill-audit"],
            metadata={
                "analysis_type": "risk_synthesis",
                "scoring_algorithm": "weighted_40_30_30",
            },
        )
        self.scorer = RiskScorer()

    def execute(self, context: SkillContext) -> SkillResult:
        """
        Synthesize audit report from all phase results.

        Expected context.metadata:
            - skill_artifact: SkillArtifact
            - ai_result: Phase 1 output
            - static_result: Phase 2A output
            - deep_result: Phase 2A2 output 🆕
            - tip_result: Phase 2B output
            - analysis_start_time: float (timestamp)
        """
        try:
            # Extract inputs
            skill_artifact = context.metadata.get("skill_artifact")
            ai_result = context.metadata.get("ai_result", {})
            static_result = context.metadata.get("static_result", {})
            deep_result = context.metadata.get("deep_result", {})  # 🆕
            tip_result = context.metadata.get("tip_result", {})
            analysis_start_time = context.metadata.get("analysis_start_time", datetime.now().timestamp())

            if not skill_artifact:
                return SkillResult(
                    success=False,
                    skill_name=self.name,
                    output=None,
                    error="Missing skill_artifact in context.metadata",
                )

            logger.info(f"Synthesizing audit report for: {skill_artifact.skill_name}")

            # Extract scores (ensure float conversion)
            try:
                ai_score = float(ai_result.get("ai_score", 0.0))
            except (ValueError, TypeError):
                ai_score = 0.0

            try:
                static_score = float(static_result.get("static_score", 0.0))
            except (ValueError, TypeError):
                static_score = 0.0

            try:
                deep_score = float(deep_result.get("deep_score", 0.0))
            except (ValueError, TypeError):
                deep_score = 0.0

            try:
                tip_score = float(tip_result.get("tip_score", 0.0))
            except (ValueError, TypeError):
                tip_score = 0.0

            # Collect all evidence (including deep analysis)
            all_evidence = self._collect_all_evidence(ai_result, static_result, deep_result, tip_result)

            # Extract AI classification for downstream use
            ai_classification = ai_result.get("skill_classification", {})

            # Apply AI context filtering to reduce false positives
            ai_skipped = ai_result.get("ai_analysis", {}).get("mode") == "claude_code" or not ai_result.get("evidence")
            if not ai_skipped and ai_classification:
                all_evidence = self._apply_ai_context_filtering(all_evidence, ai_result)

                # For security_tool/educational skills, discount AI/Deep scores
                purpose = ai_classification.get("purpose", "suspicious")
                purpose_conf = ai_classification.get("purpose_confidence", 0.0)

                if purpose in ("security_tool", "educational") and purpose_conf >= 0.8:
                    fp_ratio = ai_result.get("false_positive_assessment", {}).get(
                        "likely_false_positive_ratio", 0.7
                    )
                    discount = max(0.2, 1.0 - fp_ratio)
                    ai_score *= discount
                    deep_score *= discount
                    logger.info(
                        f"Phase score discount for {purpose}: fp_ratio={fp_ratio:.2f}, "
                        f"discount={discount:.2f}, ai={ai_score:.1f}, deep={deep_score:.1f}"
                    )

            # Detect C2
            c2_detected, c2_count = self.scorer.detect_c2(all_evidence)

            # Check for critical patterns
            has_critical = self.scorer.has_critical_patterns(all_evidence)

            # Check for obfuscation (from deep analysis)
            has_obfuscation = deep_result.get("obfuscation_detected", False)

            # Determine which phases actually ran
            active_phases = []
            if ai_score > 0 or ai_result.get("evidence"):
                active_phases.append('ai')
            if static_score > 0 or static_result.get("evidence"):
                active_phases.append('static')
            if deep_score > 0 or deep_result.get("evidence"):
                active_phases.append('deep')
            if tip_score > 0 or tip_result.get("evidence"):
                active_phases.append('tip')

            # Calculate overall risk score with weight redistribution
            overall_score = self.scorer.calculate_overall_risk_score(
                ai_score=ai_score,
                static_score=static_score,
                deep_score=deep_score,
                tip_score=tip_score,
                has_c2=c2_detected,
                has_critical_patterns=has_critical,
                has_obfuscation=has_obfuscation,
                active_phases=active_phases if active_phases else None,
                ai_classification=ai_classification,
            )

            # Determine risk level
            overall_risk = self.scorer.determine_risk_level(overall_score)

            # Calculate confidence
            overall_confidence = self.scorer.calculate_confidence(all_evidence)

            # Generate findings — use higher threshold for known benign skill types
            finding_min_conf = 0.15
            if ai_classification:
                purpose = ai_classification.get("purpose", "suspicious")
                purpose_conf = ai_classification.get("purpose_confidence", 0.0)
                if purpose in ("security_tool", "educational") and purpose_conf >= 0.8:
                    finding_min_conf = 0.5
                elif purpose in ("development_tool", "general_utility") and purpose_conf >= 0.7:
                    finding_min_conf = 0.3

            findings = self._generate_findings_filtered(all_evidence, skill_artifact, finding_min_conf)

            # Count findings by severity
            severity_counts = self.scorer.count_evidence_by_severity(all_evidence)

            # Count evidence by source
            ai_count, static_count, tip_count = self.scorer.count_evidence_by_source(all_evidence)

            # Generate executive summary
            executive_summary = self.scorer.generate_executive_summary(
                skill_name=skill_artifact.skill_name,
                overall_risk=overall_risk,
                overall_score=overall_score,
                confidence=overall_confidence,
                total_findings=len(findings),
                critical_count=severity_counts["critical"],
                high_count=severity_counts["high"],
                c2_detected=c2_detected,
            )

            # Generate key concerns
            key_concerns = self._extract_key_concerns(findings)

            # Generate decision recommendation
            decision = self.scorer.generate_decision_recommendation(overall_score, overall_confidence)

            # Calculate analysis duration
            analysis_duration = datetime.now().timestamp() - analysis_start_time

            # Collect models/tools used
            models_used = ai_result.get("model_used", "none")
            if models_used != "none":
                models_used = [models_used]
            else:
                models_used = []

            tools_used = ["pattern_matching"]
            if tip_count > 0:
                tools_used.append("threatbook")

            # Create audit report
            audit_report = SkillAuditReport(
                audit_id=str(uuid.uuid4()),
                timestamp=datetime.now().isoformat(),
                skill_artifact=skill_artifact,
                overall_risk=overall_risk,
                overall_score=overall_score,
                confidence=overall_confidence,
                findings=findings,
                total_findings=len(findings),
                critical_count=severity_counts["critical"],
                high_count=severity_counts["high"],
                medium_count=severity_counts["medium"],
                low_count=severity_counts["low"],
                info_count=severity_counts["info"],
                ai_analysis_score=ai_score,
                static_analysis_score=static_score,
                threat_intel_score=tip_score,
                ai_evidence_count=ai_count,
                static_evidence_count=static_count,
                threat_intel_evidence_count=tip_count,
                c2_detected=c2_detected,
                c2_count=c2_count,
                executive_summary=executive_summary,
                key_concerns=key_concerns,
                decision_recommendation=decision,
                skill_classification=ai_classification or {},
                analysis_duration=analysis_duration,
                models_used=models_used,
                tools_used=tools_used,
            )

            logger.info(
                f"Audit report synthesized: {overall_risk.value} risk, "
                f"score {overall_score:.1f}, {len(findings)} findings"
            )

            return SkillResult(
                success=True,
                skill_name=self.name,
                output={"audit_report": audit_report.to_dict()},
                tools_used=["synthesis"],
            )

        except Exception as e:
            logger.error(f"Risk synthesis failed: {e}", exc_info=True)
            return SkillResult(
                success=False,
                skill_name=self.name,
                output=None,
                error=f"Risk synthesis failed: {str(e)}",
            )

    def _collect_all_evidence(
        self, ai_result: Dict, static_result: Dict, deep_result: Dict, tip_result: Dict
    ) -> List[Evidence]:
        """Collect and deduplicate evidence from all sources (including deep analysis)"""
        all_evidence = []

        # AI evidence (Phase 1)
        ai_evidence_dicts = ai_result.get("evidence", [])
        for ev_dict in ai_evidence_dicts:
            try:
                evidence = Evidence(**ev_dict)
                all_evidence.append(evidence)
            except Exception as e:
                logger.warning(f"Failed to parse AI evidence: {e}")

        # Static evidence (Phase 2A)
        static_evidence_dicts = static_result.get("evidence", [])
        for ev_dict in static_evidence_dicts:
            try:
                evidence = Evidence(**ev_dict)
                all_evidence.append(evidence)
            except Exception as e:
                logger.warning(f"Failed to parse static evidence: {e}")

        # Deep analysis evidence (Phase 2A2) 🆕
        deep_evidence_dicts = deep_result.get("evidence", [])
        for ev_dict in deep_evidence_dicts:
            try:
                evidence = Evidence(**ev_dict)
                all_evidence.append(evidence)
            except Exception as e:
                logger.warning(f"Failed to parse deep analysis evidence: {e}")

        # TIP evidence (Phase 2B)
        tip_evidence_dicts = tip_result.get("evidence", [])
        for ev_dict in tip_evidence_dicts:
            try:
                evidence = Evidence(**ev_dict)
                all_evidence.append(evidence)
            except Exception as e:
                logger.warning(f"Failed to parse TIP evidence: {e}")

        # Sort by severity (most severe first)
        severity_order = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 3,
            RiskLevel.INFO: 4,
        }
        all_evidence.sort(key=lambda e: severity_order.get(e.severity, 5))

        return all_evidence

    def _apply_ai_context_filtering(
        self,
        all_evidence: List[Evidence],
        ai_result: Dict,
    ) -> List[Evidence]:
        """
        Use AI's skill-purpose classification to adjust confidence of
        static findings that are likely false positives.

        Does NOT remove evidence — only adjusts confidence downward.
        This preserves auditability while reducing score impact.
        """
        classification = ai_result.get("skill_classification", {})
        purpose = classification.get("purpose", "suspicious")
        purpose_confidence = classification.get("purpose_confidence", 0.0)

        # Only apply for recognized benign purposes with high AI confidence
        if purpose in ("suspicious",) or purpose_confidence < 0.7:
            return all_evidence

        # Determine confidence multiplier based on skill purpose
        if purpose in ("security_tool", "educational"):
            multiplier = 0.3  # Heavy discount
        elif purpose in ("development_tool", "general_utility"):
            multiplier = 0.7  # Moderate discount
        else:
            # trading_tool: no discount (dangerous patterns in trading tools are suspicious)
            return all_evidence

        logger.info(
            f"Applying AI context filtering: purpose={purpose}, "
            f"confidence={purpose_confidence:.2f}, multiplier={multiplier}"
        )

        filtered = []
        for ev in all_evidence:
            # Only adjust STATIC_RULES evidence, preserve AI/TIP evidence
            if ev.source == EvidenceSource.STATIC_RULES:
                new_conf = ev.confidence * multiplier
                # Additional penalty for documentation context
                if ev.detail and "[documentation]" in ev.detail:
                    new_conf *= 0.5

                adjusted = Evidence(
                    source=ev.source,
                    confidence=max(0.05, new_conf),
                    severity=ev.severity,
                    category=ev.category,
                    description=ev.description,
                    detail=ev.detail + f" [confidence adjusted: {purpose}]" if ev.detail else f"[confidence adjusted: {purpose}]",
                    code_location=ev.code_location,
                    code_snippet=ev.code_snippet,
                    matched_pattern=ev.matched_pattern,
                    threat_intel_data=ev.threat_intel_data,
                )
                filtered.append(adjusted)
            else:
                filtered.append(ev)

        return filtered

    def _generate_findings_filtered(
        self, evidence_list: List[Evidence], skill_artifact: SkillArtifact,
        min_confidence: float = 0.15,
    ) -> List[Finding]:
        """
        Generate Finding objects from Evidence, filtering low-confidence items.

        Groups related evidence into findings. Filters out findings whose average
        confidence is below min_confidence to prevent low-confidence matches
        from appearing as findings.
        """
        # Group evidence by category
        evidence_by_category = defaultdict(list)
        for evidence in evidence_list:
            evidence_by_category[evidence.category].append(evidence)

        findings = []
        finding_counter = 1
        filtered_count = 0

        for category, category_evidence in evidence_by_category.items():
            # Group by severity within category
            evidence_by_severity = defaultdict(list)
            for ev in category_evidence:
                evidence_by_severity[ev.severity].append(ev)

            # Create finding for each severity group
            for severity, severity_evidence in evidence_by_severity.items():
                # Calculate average confidence
                confidences = []
                for e in severity_evidence:
                    try:
                        confidences.append(float(e.confidence))
                    except (ValueError, TypeError):
                        confidences.append(0.5)
                avg_confidence = sum(confidences) / len(confidences) if confidences else 0.5

                # Skip low-confidence findings
                if avg_confidence < min_confidence:
                    filtered_count += len(severity_evidence)
                    continue

                finding_id = f"SKILL-AUDIT-{finding_counter:03d}"
                finding_counter += 1

                title = self._generate_finding_title(category, severity, severity_evidence)
                description = self._generate_finding_description(category, severity_evidence)
                attack_scenario = self._generate_attack_scenario(category, severity_evidence)
                impact = self._generate_impact_assessment(category, severity)
                recommendations = self._generate_recommendations(category, severity, severity_evidence)
                cwe_ids = self._extract_cwe_ids(category)

                finding = Finding(
                    finding_id=finding_id,
                    title=title,
                    severity=severity,
                    confidence=avg_confidence,
                    categories=[category],
                    description=description,
                    evidence=severity_evidence,
                    attack_scenario=attack_scenario,
                    impact=impact,
                    recommendations=recommendations,
                    cwe_ids=cwe_ids,
                    metadata={
                        "evidence_count": len(severity_evidence),
                        "sources": list(set(e.source.value for e in severity_evidence)),
                    },
                )

                findings.append(finding)

        if filtered_count:
            logger.info(f"Filtered {filtered_count} low-confidence evidence items from findings")

        return findings

    def _generate_findings(
        self, evidence_list: List[Evidence], skill_artifact: SkillArtifact
    ) -> List[Finding]:
        """
        Generate Finding objects from Evidence.

        Groups related evidence into findings.
        """
        # Group evidence by category
        evidence_by_category = defaultdict(list)
        for evidence in evidence_list:
            evidence_by_category[evidence.category].append(evidence)

        findings = []
        finding_counter = 1

        for category, category_evidence in evidence_by_category.items():
            # Group by severity within category
            evidence_by_severity = defaultdict(list)
            for ev in category_evidence:
                evidence_by_severity[ev.severity].append(ev)

            # Create finding for each severity group
            for severity, severity_evidence in evidence_by_severity.items():
                finding_id = f"SKILL-AUDIT-{finding_counter:03d}"
                finding_counter += 1

                # Generate title
                title = self._generate_finding_title(category, severity, severity_evidence)

                # Generate description
                description = self._generate_finding_description(category, severity_evidence)

                # Calculate average confidence (ensure float conversion)
                confidences = []
                for e in severity_evidence:
                    try:
                        confidences.append(float(e.confidence))
                    except (ValueError, TypeError):
                        confidences.append(0.5)  # Default confidence
                avg_confidence = sum(confidences) / len(confidences) if confidences else 0.5

                # Generate attack scenario
                attack_scenario = self._generate_attack_scenario(category, severity_evidence)

                # Generate impact assessment
                impact = self._generate_impact_assessment(category, severity)

                # Generate recommendations
                recommendations = self._generate_recommendations(category, severity, severity_evidence)

                # Extract CWE IDs (if any)
                cwe_ids = self._extract_cwe_ids(category)

                finding = Finding(
                    finding_id=finding_id,
                    title=title,
                    severity=severity,
                    confidence=avg_confidence,
                    categories=[category],
                    description=description,
                    evidence=severity_evidence,
                    attack_scenario=attack_scenario,
                    impact=impact,
                    recommendations=recommendations,
                    cwe_ids=cwe_ids,
                    metadata={
                        "evidence_count": len(severity_evidence),
                        "sources": list(set(e.source.value for e in severity_evidence)),
                    },
                )

                findings.append(finding)

        return findings

    def _generate_finding_title(
        self, category: RiskCategory, severity: RiskLevel, evidence: List[Evidence]
    ) -> str:
        """Generate concise finding title"""
        category_titles = {
            RiskCategory.PROMPT_INJECTION: "Prompt Injection",
            RiskCategory.PRIVILEGE_ESCALATION: "Privilege Escalation",
            RiskCategory.DATA_EXFILTRATION: "Data Exfiltration Risk",
            RiskCategory.REMOTE_CONTROL: "Remote Control/C2 Activity",
            RiskCategory.SUPPLY_CHAIN: "Supply Chain Risk",
            RiskCategory.UNSAFE_EXECUTION: "Unsafe Code Execution",
            RiskCategory.AUTHORIZATION_BYPASS: "Authorization Bypass",
            RiskCategory.STATE_MANIPULATION: "State Manipulation",
        }

        base_title = category_titles.get(category, "Security Risk")

        # Add specifics if C2 detected
        if any("C2" in e.description for e in evidence):
            return f"{base_title}: C2 Server Communication Detected"

        return f"{base_title} Detected"

    def _generate_finding_description(
        self, category: RiskCategory, evidence: List[Evidence]
    ) -> str:
        """Generate detailed finding description"""
        descriptions = []

        # Aggregate unique descriptions
        unique_descriptions = set()
        for ev in evidence[:5]:  # Top 5 evidence items
            if ev.detail:
                unique_descriptions.add(ev.detail)
            elif ev.description:
                unique_descriptions.add(ev.description)

        for desc in unique_descriptions:
            descriptions.append(f"- {desc}")

        if len(evidence) > 5:
            descriptions.append(f"- ... and {len(evidence) - 5} more evidence item(s)")

        return "\n".join(descriptions) if descriptions else f"Multiple {category.value} indicators detected."

    def _generate_attack_scenario(
        self, category: RiskCategory, evidence: List[Evidence]
    ) -> AttackScenario:
        """Generate attack scenario for category"""
        # Category-specific scenarios
        scenarios = {
            RiskCategory.REMOTE_CONTROL: AttackScenario(
                title="Remote Command & Control Attack",
                steps=[
                    "Attacker deploys malicious skill on target system",
                    "Skill establishes C2 connection to attacker server",
                    "Attacker sends commands via C2 channel",
                    "Skill executes commands with agent privileges",
                    "Attacker gains persistent access to system",
                ],
                preconditions=["Skill installation permissions", "Network connectivity"],
                attacker_capability="Network access to C2 server",
                impact="Full system compromise, data exfiltration, persistent backdoor",
            ),
            RiskCategory.PROMPT_INJECTION: AttackScenario(
                title="Agent Behavior Manipulation via Prompt Injection",
                steps=[
                    "Malicious skill provides injected prompts to agent",
                    "Agent processes skill prompts without validation",
                    "Injected instructions override agent safety constraints",
                    "Agent executes unauthorized operations",
                    "Attacker achieves privilege escalation or data access",
                ],
                preconditions=["Agent lacks prompt injection defenses"],
                attacker_capability="Skill authoring/modification",
                impact="Agent behavior manipulation, security bypass, data leakage",
            ),
            RiskCategory.DATA_EXFILTRATION: AttackScenario(
                title="Sensitive Data Exfiltration",
                steps=[
                    "Skill accesses sensitive data (credentials, keys, user data)",
                    "Skill transmits data to external server",
                    "Attacker receives exfiltrated data",
                ],
                preconditions=["Network access", "Access to sensitive data"],
                attacker_capability="Control of external server",
                impact="Credential theft, privacy violation, data breach",
            ),
            RiskCategory.PRIVILEGE_ESCALATION: AttackScenario(
                title="Privilege Escalation Attack",
                steps=[
                    "Skill exploits permission vulnerabilities",
                    "Skill gains elevated privileges beyond declared permissions",
                    "Attacker performs unauthorized operations",
                ],
                preconditions=["Insufficient permission checks"],
                attacker_capability="Skill installation",
                impact="Unauthorized system access, security control bypass",
            ),
        }

        return scenarios.get(
            category,
            AttackScenario(
                title=f"Security Risk: {category.value}",
                steps=["Attacker exploits vulnerability", "System security compromised"],
                preconditions=["Vulnerable configuration"],
                attacker_capability="Skill access",
                impact="Security compromise",
            ),
        )

    def _generate_impact_assessment(
        self, category: RiskCategory, severity: RiskLevel
    ) -> ImpactAssessment:
        """Generate impact assessment"""
        # Default values based on severity
        if severity == RiskLevel.CRITICAL:
            return ImpactAssessment(
                confidentiality=RiskLevel.CRITICAL,
                integrity=RiskLevel.CRITICAL,
                availability=RiskLevel.HIGH,
                financial="Potentially significant (data breach, ransomware)",
                reputation="Severe (public incident, loss of trust)",
                compliance=["GDPR", "SOC2", "ISO27001"],
            )
        elif severity == RiskLevel.HIGH:
            return ImpactAssessment(
                confidentiality=RiskLevel.HIGH,
                integrity=RiskLevel.HIGH,
                availability=RiskLevel.MEDIUM,
                financial="Moderate (incident response, remediation)",
                reputation="Significant (customer notification required)",
                compliance=["GDPR", "SOC2"],
            )
        else:
            return ImpactAssessment(
                confidentiality=RiskLevel.MEDIUM,
                integrity=RiskLevel.MEDIUM,
                availability=RiskLevel.LOW,
                financial="Low (minimal operational impact)",
                reputation="Minor",
                compliance=None,
            )

    def _generate_recommendations(
        self, category: RiskCategory, severity: RiskLevel, evidence: List[Evidence]
    ) -> List[Recommendation]:
        """Generate remediation recommendations"""
        recommendations = []

        # Category-specific recommendations
        if category == RiskCategory.REMOTE_CONTROL:
            recommendations.append(
                Recommendation(
                    priority=RiskLevel.CRITICAL,
                    title="Block skill installation/execution immediately",
                    description="This skill contains C2 communication logic. Do not install or execute.",
                    effort="LOW",
                    references=["MITRE ATT&CK: T1071 - Application Layer Protocol"],
                )
            )
            recommendations.append(
                Recommendation(
                    priority=RiskLevel.HIGH,
                    title="Investigate skill origin and distribution",
                    description="Determine how this malicious skill was distributed. Check for other compromised skills.",
                    effort="MEDIUM",
                )
            )

        elif category == RiskCategory.PROMPT_INJECTION:
            recommendations.append(
                Recommendation(
                    priority=RiskLevel.HIGH,
                    title="Remove prompt injection instructions",
                    description="Remove or sanitize instructions that attempt to manipulate agent behavior.",
                    effort="LOW",
                    references=["OWASP LLM01: Prompt Injection"],
                )
            )
            recommendations.append(
                Recommendation(
                    priority=RiskLevel.MEDIUM,
                    title="Implement prompt validation",
                    description="Add validation to detect and reject prompt injection attempts.",
                    effort="MEDIUM",
                )
            )

        elif category == RiskCategory.DATA_EXFILTRATION:
            recommendations.append(
                Recommendation(
                    priority=RiskLevel.HIGH,
                    title="Review and restrict network access",
                    description="Remove unnecessary external connections. Whitelist approved endpoints.",
                    effort="MEDIUM",
                    references=["CWE-200: Exposure of Sensitive Information"],
                )
            )

        elif category == RiskCategory.UNSAFE_EXECUTION:
            recommendations.append(
                Recommendation(
                    priority=RiskLevel.HIGH,
                    title="Replace unsafe code execution patterns",
                    description="Replace eval(), exec(), and shell commands with safer alternatives.",
                    effort="MEDIUM",
                    references=["CWE-78: OS Command Injection", "CWE-94: Code Injection"],
                )
            )

        # If no specific recommendations, add generic one
        if not recommendations:
            recommendations.append(
                Recommendation(
                    priority=severity,
                    title="Review and remediate security findings",
                    description="Address security issues identified in this audit.",
                    effort="MEDIUM",
                )
            )

        return recommendations

    def _extract_cwe_ids(self, category: RiskCategory) -> List[str]:
        """Map category to CWE IDs"""
        cwe_mapping = {
            RiskCategory.REMOTE_CONTROL: ["CWE-78", "CWE-94"],
            RiskCategory.PROMPT_INJECTION: ["CWE-74", "CWE-913"],
            RiskCategory.DATA_EXFILTRATION: ["CWE-200", "CWE-319"],
            RiskCategory.PRIVILEGE_ESCALATION: ["CWE-269", "CWE-862"],
            RiskCategory.UNSAFE_EXECUTION: ["CWE-78", "CWE-94", "CWE-502"],
            RiskCategory.AUTHORIZATION_BYPASS: ["CWE-862", "CWE-863"],
        }
        return cwe_mapping.get(category, [])

    def _extract_key_concerns(self, findings: List[Finding]) -> List[str]:
        """Extract top concerns from findings"""
        concerns = []

        # Add CRITICAL and HIGH findings
        for finding in findings:
            if finding.severity in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                concerns.append(finding.title)

        # Limit to top 5
        return concerns[:5]


def create_risk_synthesis_skill() -> RiskSynthesisSkill:
    """Factory function"""
    return RiskSynthesisSkill()
