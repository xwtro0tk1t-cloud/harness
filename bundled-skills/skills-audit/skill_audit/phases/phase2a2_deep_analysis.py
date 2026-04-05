"""
Phase 2A2: Deep Code Understanding (AI-Enhanced Static Analysis)

Uses LLM to perform deep code analysis that goes beyond regex pattern matching.
Detects obfuscated code, logic chains, and complex attack patterns.
"""

import json
import logging
import base64
from typing import Dict, List, Any, Optional

from skill_framework import SkillContext, SkillResult, SkillCategory
from skill_framework import PromptSkill
from skill_audit.schemas import (
    SkillArtifact,
    Evidence,
    RiskLevel,
    RiskCategory,
    EvidenceSource,
)
from skill_audit.llm_utils import ensure_llm_client

logger = logging.getLogger(__name__)


class DeepCodeUnderstandingSkill(PromptSkill):
    """AI-driven deep code understanding for obfuscation and logic chain detection"""

    def __init__(self):
        # Get prompt file path (relative to this file's location)
        from pathlib import Path
        prompt_file = str(Path(__file__).parent.parent / "prompts" / "deep_analysis.md")

        super().__init__(
            name="deep_code_understanding",
            description="AI-driven deep code analysis for obfuscated and complex attack patterns",
            category=SkillCategory.PROFESSIONAL,
            prompt_file=prompt_file,
            required_tools=["llm"],
        )

        # Store metadata as instance attribute for later use
        self.metadata = {
            "preferred_model": "sonnet",
            "analysis_type": "deep_code_understanding",
            "capabilities": [
                "obfuscation_decoding",
                "logic_chain_tracing",
                "permission_combination_analysis",
                "prompt_injection_detection",
            ],
        }

    def execute(self, context: SkillContext) -> SkillResult:
        """
        Execute deep code understanding analysis.

        Expected context.metadata:
            - skill_artifact: SkillArtifact object
            - static_result: Static analysis results (optional, for context)
            - claude_code: bool - If True, deep analysis done by Claude directly

        In Claude Code environment:
            - No LLM API call is made
            - Returns placeholder result
            - Actual deep analysis is performed by Claude following SKILL.md instructions
        """
        try:
            # Check if running in Claude Code environment
            is_claude_code = context.metadata.get('claude_code', False)

            # Ensure LLM client is available (creates from config if needed)
            llm_client = ensure_llm_client(context, is_claude_code)

            # In Claude Code: skip LLM API call, Claude will do deep analysis directly
            if not llm_client and is_claude_code:
                logger.info(
                    "Running in Claude Code environment - "
                    "Deep code analysis will be performed by Claude directly (no API call)"
                )
                return SkillResult(
                    success=True,
                    skill_name=self.name,
                    output={
                        "deep_analysis": {
                            "mode": "claude_code",
                            "note": "Deep code understanding performed by Claude following SKILL.md instructions"
                        },
                        "evidence": [],
                        "deep_score": 0.0,  # Will be calculated by Claude
                        "model_used": "claude-in-session",
                    },
                    tools_used=["claude:direct"],
                )

            # For non-Claude Code environments: require LLM client
            if not llm_client:
                return SkillResult(
                    success=False,
                    skill_name=self.name,
                    output=None,
                    error="LLM client required for deep code analysis. "
                           "Set ANTHROPIC_AUTH_TOKEN environment variable or configure llm.api_key in config.yml",
                )

            # Extract skill artifact
            skill_artifact = context.metadata.get("skill_artifact")
            if not skill_artifact:
                return SkillResult(
                    success=False,
                    skill_name=self.name,
                    output=None,
                    error="Missing skill_artifact in context.metadata",
                )

            if not isinstance(skill_artifact, SkillArtifact):
                return SkillResult(
                    success=False,
                    skill_name=self.name,
                    output=None,
                    error="skill_artifact must be SkillArtifact instance",
                )

            logger.info(
                f"Starting deep code analysis for skill: {skill_artifact.skill_name}"
            )

            # Get static analysis results for context
            static_result = context.metadata.get("static_result", {})

            # Prepare prompt variables
            prompt_vars = self._prepare_prompt_variables(skill_artifact, static_result)

            # Execute LLM analysis
            llm_response = self._execute_llm_analysis(context, prompt_vars)

            # Parse LLM response
            analysis_result = self._parse_llm_response(llm_response)

            # Convert to Evidence objects
            evidence_list = self._convert_to_evidence(
                analysis_result, skill_artifact.skill_name
            )

            # Calculate deep analysis score (0-100)
            deep_score = self._calculate_deep_score(analysis_result)

            # Get model preference from metadata
            model_used = self.metadata.get("preferred_model", "unknown")

            output = {
                "deep_analysis": analysis_result,
                "evidence": [e.to_dict() for e in evidence_list],
                "deep_score": deep_score,
                "model_used": model_used,
                "obfuscation_detected": analysis_result.get("summary", {}).get(
                    "obfuscation_detected", False
                ),
                "logic_chains_detected": analysis_result.get("summary", {}).get(
                    "logic_chains_detected", 0
                ),
            }

            logger.info(
                f"Deep code analysis complete. Score: {deep_score}, "
                f"Findings: {len(analysis_result.get('deep_analysis_findings', []))}, "
                f"Obfuscation: {output['obfuscation_detected']}, "
                f"Logic chains: {output['logic_chains_detected']}"
            )

            return SkillResult(
                success=True,
                skill_name=self.name,
                output=output,
                tools_used=[f"llm:{model_used}"],
            )

        except Exception as e:
            logger.error(f"Deep code analysis failed: {e}", exc_info=True)
            return SkillResult(
                success=False,
                skill_name=self.name,
                output=None,
                error=f"Deep analysis failed: {str(e)}",
            )

    def _prepare_prompt_variables(
        self, artifact: SkillArtifact, static_result: Dict
    ) -> Dict[str, str]:
        """Prepare variables for prompt template"""
        # Format code files for display
        code_files_text = self._format_code_files(artifact.code_files)

        # Format prompts/descriptions
        prompts_text = "\n\n---\n\n".join(artifact.prompts) if artifact.prompts else "No prompts found"

        # Add skill description
        if artifact.description:
            prompts_text = f"**Skill Description**:\n{artifact.description}\n\n---\n\n{prompts_text}"

        # Format static analysis findings (for context)
        static_findings = static_result.get("patterns_matched", [])
        static_findings_text = self._format_static_findings(static_findings)

        return {
            "skill_name": artifact.skill_name,
            "code_files": code_files_text,
            "prompts": prompts_text,
            "static_findings": static_findings_text,
        }

    def _execute_llm_analysis(
        self, context: SkillContext, prompt_vars: Dict[str, str]
    ) -> str:
        """
        Execute LLM analysis using loaded prompt template and variables.

        Args:
            context: SkillContext with LLM client
            prompt_vars: Variables to substitute into prompt template

        Returns:
            LLM response string
        """
        # Load prompt template
        template = self.load_prompt_template()
        if not template:
            # Fallback to embedded template if file not found
            template = self._get_fallback_template()

        # Format prompt with variables using PromptSkill's format_prompt method
        system_prompt = self.format_prompt(template, prompt_vars)

        # Combine system prompt and user prompt for LLM
        full_prompt = system_prompt + "\n\n" + (
            f"Perform deep code analysis on skill '{prompt_vars['skill_name']}'. "
            f"Focus on threats that regex cannot detect: "
            f"obfuscated code, logic chains, permission combinations, and prompt injection."
        )

        # Call LLM client (using generate method, not chat)
        llm_client = context.llm_client
        response = llm_client.generate(full_prompt, max_tokens=4096)

        return response

    def _format_code_files(
        self, code_files: Dict[str, str], max_lines: int = 800
    ) -> str:
        """Format code files for LLM analysis (more generous limit for deep analysis)"""
        if not code_files:
            return "No code files found"

        formatted = []
        for filename, content in code_files.items():
            lines = content.split("\n")
            if len(lines) > max_lines:
                # Truncate very long files
                content = (
                    "\n".join(lines[:max_lines])
                    + f"\n... (truncated, total {len(lines)} lines)"
                )

            formatted.append(f"=== {filename} ===\n{content}\n")

        return "\n".join(formatted)

    def _format_static_findings(self, patterns_matched: List[Dict]) -> str:
        """Format static analysis findings for context"""
        if not patterns_matched:
            return "No static patterns matched (or static analysis skipped)"

        findings = []
        for pattern in patterns_matched[:20]:  # Limit to top 20
            findings.append(
                f"- {pattern.get('severity', 'UNKNOWN')}: {pattern.get('description', 'Unknown pattern')} "
                f"(Location: {pattern.get('location', 'unknown')})"
            )

        result = "\n".join(findings)
        if len(patterns_matched) > 20:
            result += f"\n... and {len(patterns_matched) - 20} more patterns"

        return result

    def _parse_llm_response(self, llm_response: str) -> Dict[str, Any]:
        """
        Parse LLM response into structured data.

        LLM should return JSON, but may include markdown code blocks.
        """
        try:
            # Try to extract JSON from markdown code block
            import re

            json_match = re.search(
                r"```(?:json)?\s*(\{.+?\})\s*```", llm_response, re.DOTALL
            )
            if json_match:
                json_str = json_match.group(1)
            else:
                # Try to find raw JSON
                json_match = re.search(r"\{.+\}", llm_response, re.DOTALL)
                if json_match:
                    json_str = json_match.group(0)
                else:
                    # No JSON found, return empty result
                    logger.warning("No JSON found in LLM response for deep analysis")
                    return {
                        "deep_analysis_findings": [],
                        "summary": {
                            "total_findings": 0,
                            "critical": 0,
                            "high": 0,
                            "medium": 0,
                            "low": 0,
                            "obfuscation_detected": False,
                            "logic_chains_detected": 0,
                        },
                    }

            # Parse JSON
            result = json.loads(json_str)
            return result

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse deep analysis JSON response: {e}")
            logger.debug(f"LLM response: {llm_response}")
            return {
                "deep_analysis_findings": [],
                "summary": {
                    "total_findings": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "obfuscation_detected": False,
                    "logic_chains_detected": 0,
                },
            }

    def _convert_to_evidence(
        self, analysis_result: Dict[str, Any], skill_name: str
    ) -> List[Evidence]:
        """Convert deep analysis results to Evidence objects"""
        evidence_list = []

        findings = analysis_result.get("deep_analysis_findings", [])

        for idx, finding in enumerate(findings):
            try:
                # Parse severity
                severity_str = finding.get("severity", "MEDIUM")
                try:
                    severity = RiskLevel(severity_str)
                except ValueError:
                    severity = RiskLevel.MEDIUM

                # Parse category
                category_str = finding.get("category", "unsafe_execution")
                category_map = {
                    "prompt_injection": RiskCategory.PROMPT_INJECTION,
                    "obfuscation": RiskCategory.SUPPLY_CHAIN_POISONING,
                    "exfiltration_chain": RiskCategory.DATA_EXFILTRATION,
                    "privilege_persistence": RiskCategory.PRIVILEGE_ESCALATION,
                    "covert_channel": RiskCategory.REMOTE_CONTROL,
                }
                category = category_map.get(category_str, RiskCategory.UNSAFE_EXECUTION)

                # Extract evidence details
                evidence_data = finding.get("evidence", {})
                code_location = evidence_data.get("code_location")
                code_snippet = evidence_data.get("code_snippet")
                decoded_content = evidence_data.get("decoded_content")

                # Build detail string
                detail = finding.get("description", "")
                if decoded_content:
                    detail += f"\n\n**Decoded content**: {decoded_content}"
                if "logic_chain" in evidence_data:
                    logic_chain = evidence_data["logic_chain"]
                    detail += f"\n\n**Attack chain**:\n" + "\n".join(
                        f"{i+1}. {step}" for i, step in enumerate(logic_chain)
                    )
                if "why_regex_missed" in finding:
                    detail += f"\n\n**Why regex missed this**: {finding['why_regex_missed']}"

                # Get confidence
                confidence = finding.get("confidence", 0.8)

                # Create Evidence object
                evidence = Evidence(
                    source=EvidenceSource.AI_ANALYSIS,  # Deep analysis is still AI-based
                    confidence=confidence,
                    severity=severity,
                    category=category,
                    description=finding.get("title", f"Deep analysis finding {idx+1}"),
                    detail=detail,
                    code_location=code_location,
                    code_snippet=code_snippet,
                    metadata={
                        "analysis_type": "deep_code_understanding",
                        "impact": finding.get("impact"),
                        "recommendation": finding.get("recommendation"),
                    },
                )

                evidence_list.append(evidence)

            except Exception as e:
                logger.warning(f"Failed to convert deep finding to evidence: {e}")
                continue

        return evidence_list

    def _calculate_deep_score(self, analysis_result: Dict[str, Any]) -> float:
        """
        Calculate deep analysis score (0-100).

        Higher score = higher risk.
        """
        summary = analysis_result.get("summary", {})

        # Base score from findings severity
        critical = summary.get("critical", 0)
        high = summary.get("high", 0)
        medium = summary.get("medium", 0)
        low = summary.get("low", 0)

        base_score = float((critical * 25) + (high * 15) + (medium * 5) + (low * 1))

        # Boost for obfuscation detection (indicates attempt to hide malicious code)
        if summary.get("obfuscation_detected", False):
            base_score *= 1.3

        # Boost for logic chains (indicates sophisticated attack)
        logic_chains = summary.get("logic_chains_detected", 0)
        if logic_chains > 0:
            base_score += logic_chains * 10

        # Cap at 100
        return min(100.0, float(base_score))


    def _get_fallback_template(self) -> str:
        """Return embedded fallback template if prompt file not found."""
        return """# Deep Code Understanding Analysis

You are a security expert performing deep code analysis for AI agent skills.

## INPUT

**Skill Name**: {{skill_name}}
**Code Files**: {{code_files}}
**Static Analysis Results**: {{static_results}}

## TASK

Analyze for threats that regex cannot detect:
- Obfuscated code (base64, encoding tricks)
- Multi-step logic chains
- Permission combination attacks
- Subtle prompt injection

Return JSON with: summary (obfuscation_detected, logic_chains_detected), findings[]
"""


def create_deep_code_understanding_skill() -> DeepCodeUnderstandingSkill:
    """Factory function"""
    return DeepCodeUnderstandingSkill()
