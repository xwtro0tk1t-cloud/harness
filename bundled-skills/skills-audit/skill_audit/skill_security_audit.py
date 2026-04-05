"""
Skill Security Audit - Main Orchestration

Provides comprehensive security auditing for AI Agent skills through
multi-phase analysis: artifact extraction, AI analysis, static rules,
threat intelligence, and risk synthesis.
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional

from skill_framework import SkillContext, SkillResult
from skill_framework import CompositeSkill
from .schemas import SkillArtifact, SkillAuditReport
from .phases.phase0_extractor import (
    create_skill_artifact_extractor,
)
from .phases.phase1_ai_analysis import (
    create_ai_semantic_analysis_skill,
)
from .phases.phase2_static_analysis import (
    create_static_rule_analysis_skill,
)
from .phases.phase2a2_deep_analysis import (
    create_deep_code_understanding_skill,
)
from .phases.phase2_tip_integration import (
    create_tip_integration_skill,
)
from .phases.phase3_synthesis import create_risk_synthesis_skill

logger = logging.getLogger(__name__)


class SkillSecurityAuditSkill(CompositeSkill):
    """
    Main skill for comprehensive skill security auditing.

    Orchestrates 5-phase analysis:
    - Phase 0: Skill artifact extraction
    - Phase 1: AI semantic risk analysis
    - Phase 2A: Static pattern matching (regex)
    - Phase 2A2: Deep code understanding (AI-enhanced)
    - Phase 2B: Threat intelligence validation
    - Phase 3: Risk scoring and report synthesis
    """

    def __init__(
        self,
        enable_ai_analysis: bool = True,
        enable_static_analysis: bool = True,
        enable_deep_analysis: bool = True,
        enable_tip_check: bool = True,
    ):
        """
        Initialize skill security audit.

        Args:
            enable_ai_analysis: Enable Phase 1 (AI semantic analysis)
            enable_static_analysis: Enable Phase 2A (static regex rules)
            enable_deep_analysis: Enable Phase 2A2 (deep code understanding)
            enable_tip_check: Enable Phase 2B (TIP)
        """
        # CompositeSkill doesn't actually compose sub-skills here
        # We manually orchestrate phases instead
        # Use dummy sub_skill_names for interface compatibility
        super().__init__(
            name="skill_security_audit",
            description="Comprehensive security audit for AI Agent skills",
            sub_skill_names=[],  # We don't use sub-skill composition
            execution_strategy="sequential",
        )

        # Configuration
        self.enable_ai_analysis = enable_ai_analysis
        self.enable_static_analysis = enable_static_analysis
        self.enable_deep_analysis = enable_deep_analysis
        self.enable_tip_check = enable_tip_check

        # Initialize phase skills
        self.extractor = create_skill_artifact_extractor()
        self.ai_skill = create_ai_semantic_analysis_skill()
        self.static_skill = create_static_rule_analysis_skill()
        self.deep_skill = create_deep_code_understanding_skill()
        self.tip_skill = create_tip_integration_skill()
        self.synthesis_skill = create_risk_synthesis_skill()

        logger.info(
            f"SkillSecurityAuditSkill initialized "
            f"(AI: {enable_ai_analysis}, Static: {enable_static_analysis}, "
            f"Deep: {enable_deep_analysis}, TIP: {enable_tip_check})"
        )

    def execute(self, context: SkillContext) -> SkillResult:
        """
        Execute skill security audit.

        Expected context.metadata:
            - skill_path: str - Path to skill directory or file to audit

        Returns:
            SkillResult with audit_report in output
        """
        analysis_start_time = datetime.now().timestamp()

        try:
            # Extract skill path
            skill_path = context.metadata.get("skill_path")
            if not skill_path:
                return SkillResult(
                    success=False,
                    skill_name=self.name,
                    output=None,
                    error="Missing skill_path in context.metadata",
                )

            logger.info(f"Starting skill security audit for: {skill_path}")

            # ========== Phase 0: Artifact Extraction ==========
            logger.info("Phase 0: Extracting skill artifact...")
            try:
                skill_artifact = self.extractor.extract_from_path(skill_path)
                logger.info(f"Artifact extracted: {skill_artifact.skill_name}")
            except Exception as e:
                logger.error(f"Phase 0 failed: {e}", exc_info=True)
                return SkillResult(
                    success=False,
                    skill_name=self.name,
                    output=None,
                    error=f"Failed to extract skill artifact: {str(e)}",
                )

            # ========== Phase 1: AI Semantic Analysis ==========
            ai_result = {}
            if self.enable_ai_analysis:
                logger.info("Phase 1: Running AI semantic analysis...")
                ai_result = self._run_phase(
                    self.ai_skill, context, skill_artifact, "Phase 1 (AI)"
                )
            else:
                logger.info("Phase 1: AI analysis disabled")
                ai_result = {"ai_score": 0.0, "evidence": []}

            # ========== Phase 2A: Static Rule Analysis ==========
            static_result = {}
            if self.enable_static_analysis:
                logger.info("Phase 2A: Running static rule analysis...")
                static_result = self._run_phase(
                    self.static_skill, context, skill_artifact, "Phase 2A (Static)"
                )
            else:
                logger.info("Phase 2A: Static analysis disabled")
                static_result = {"static_score": 0.0, "evidence": []}

            # ========== Phase 2A2: Deep Code Understanding ==========
            deep_result = {}
            if self.enable_deep_analysis:
                logger.info("Phase 2A2: Running deep code understanding...")
                # Pass static_result to deep analysis for context
                deep_context = SkillContext(
                    task_description="Execute deep code understanding",
                    user_input="",
                    workspace_dir=context.workspace_dir,
                    metadata={
                        "skill_artifact": skill_artifact,
                        "static_result": static_result,  # Provide context from static analysis
                    },
                )
                deep_skill_result = self.deep_skill.execute_with_guards(deep_context)
                if deep_skill_result.success:
                    deep_result = deep_skill_result.output
                    logger.info(f"Phase 2A2 completed: {deep_result.get('deep_score', 0):.1f} score")
                else:
                    logger.warning(f"Phase 2A2 failed: {deep_skill_result.error}")
                    deep_result = {"deep_score": 0.0, "evidence": []}
            else:
                logger.info("Phase 2A2: Deep analysis disabled")
                deep_result = {"deep_score": 0.0, "evidence": []}

            # ========== Phase 2B: TIP Integration ==========
            tip_result = {}
            if self.enable_tip_check:
                logger.info("Phase 2B: Running threat intelligence check...")
                tip_result = self._run_phase(
                    self.tip_skill, context, skill_artifact, "Phase 2B (TIP)"
                )
            else:
                logger.info("Phase 2B: TIP check disabled")
                tip_result = {"tip_score": 0.0, "evidence": [], "c2_count": 0}

            # ========== Phase 3: Risk Synthesis ==========
            logger.info("Phase 3: Synthesizing audit report...")
            synthesis_context = SkillContext(
                task_description="Synthesize skill security audit report",
                user_input="",  # Not used
                workspace_dir=context.workspace_dir,
                metadata={
                    "skill_artifact": skill_artifact,
                    "ai_result": ai_result,
                    "static_result": static_result,
                    "deep_result": deep_result,
                    "tip_result": tip_result,
                    "analysis_start_time": analysis_start_time,
                },
            )

            synthesis_result = self.synthesis_skill.execute_with_guards(synthesis_context)

            if not synthesis_result.success:
                logger.error(f"Phase 3 failed: {synthesis_result.error}")
                return SkillResult(
                    success=False,
                    skill_name=self.name,
                    output=None,
                    error=f"Synthesis failed: {synthesis_result.error}",
                )

            audit_report_dict = synthesis_result.output.get("audit_report", {})

            logger.info(
                f"Skill security audit complete: "
                f"{audit_report_dict.get('overall_risk', 'UNKNOWN')} risk, "
                f"score {audit_report_dict.get('overall_score', 0):.1f}"
            )

            # Return audit report
            return SkillResult(
                success=True,
                skill_name=self.name,
                output={
                    "audit_report": audit_report_dict,
                    "skill_name": skill_artifact.skill_name,
                    "skill_path": skill_artifact.skill_path,
                },
                metadata={
                    "audit_id": audit_report_dict.get("audit_id"),
                    "overall_risk": audit_report_dict.get("overall_risk"),
                    "overall_score": audit_report_dict.get("overall_score"),
                    "decision": audit_report_dict.get("decision_recommendation"),
                },
                tools_used=[
                    "artifact_extraction",
                    "ai_analysis" if self.enable_ai_analysis else None,
                    "static_analysis" if self.enable_static_analysis else None,
                    "tip_check" if self.enable_tip_check else None,
                    "synthesis",
                ],
            )

        except Exception as e:
            logger.error(f"Skill security audit failed: {e}", exc_info=True)
            return SkillResult(
                success=False,
                skill_name=self.name,
                output=None,  # Required parameter
                error=f"Audit failed: {str(e)}",
            )

    def _run_phase(
        self,
        skill: Any,
        parent_context: SkillContext,
        skill_artifact: SkillArtifact,
        phase_name: str,
    ) -> Dict[str, Any]:
        """
        Run a phase skill.

        Returns phase output dict (or empty dict on failure).
        """
        try:
            phase_context = SkillContext(
                task_description=f"Execute {phase_name}",
                user_input="",  # Not used
                workspace_dir=parent_context.workspace_dir,
                llm_client=parent_context.llm_client,  # Pass LLM client for AI phases
                metadata={"skill_artifact": skill_artifact},
            )

            result = skill.execute_with_guards(phase_context)

            if result.success:
                logger.info(f"{phase_name} completed successfully")
                return result.output
            else:
                logger.warning(f"{phase_name} failed: {result.error}")
                # Return empty result to continue audit
                return self._get_empty_phase_result(phase_name)

        except Exception as e:
            logger.error(f"{phase_name} error: {e}", exc_info=True)
            return self._get_empty_phase_result(phase_name)

    def _get_empty_phase_result(self, phase_name: str) -> Dict[str, Any]:
        """Get empty result for failed phase"""
        if "AI" in phase_name:
            return {"ai_score": 0.0, "evidence": []}
        elif "Static" in phase_name:
            return {"static_score": 0.0, "evidence": []}
        elif "TIP" in phase_name:
            return {"tip_score": 0.0, "evidence": [], "c2_count": 0}
        else:
            return {}


def create_skill_security_audit_skill(
    enable_ai_analysis: bool = True,
    enable_static_analysis: bool = True,
    enable_deep_analysis: bool = True,
    enable_tip_check: bool = True,
) -> SkillSecurityAuditSkill:
    """
    Factory function to create skill security audit skill.

    Args:
        enable_ai_analysis: Enable AI semantic analysis (Phase 1)
        enable_static_analysis: Enable static pattern analysis (Phase 2A)
        enable_deep_analysis: Enable deep code understanding (Phase 2A2)
        enable_tip_check: Enable threat intelligence check (Phase 2B)

    Returns:
        SkillSecurityAuditSkill instance
    """
    return SkillSecurityAuditSkill(
        enable_ai_analysis=enable_ai_analysis,
        enable_static_analysis=enable_static_analysis,
        enable_deep_analysis=enable_deep_analysis,
        enable_tip_check=enable_tip_check,
    )
