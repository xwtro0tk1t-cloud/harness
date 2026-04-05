"""
Phase 1: AI Semantic Risk Analysis

Uses LLM to perform deep semantic analysis of skill behavior and intent.
"""

import json
import logging
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


class AISemanticAnalysisSkill(PromptSkill):
    """AI-driven semantic security analysis of skills"""

    def __init__(self):
        # Get prompt file path (relative to this file's location)
        from pathlib import Path
        prompt_file = str(Path(__file__).parent.parent / "prompts" / "ai_analysis.md")

        super().__init__(
            name="ai_semantic_analysis",
            description="AI-driven semantic security analysis for skill auditing",
            category=SkillCategory.PROFESSIONAL,
            prompt_file=prompt_file,
            required_tools=["llm"],
        )

        # Store metadata as instance attribute for later use
        self.metadata = {
            "preferred_model": "sonnet",
            "analysis_type": "semantic_risk",
            "threat_categories": 8,
        }

    def execute(self, context: SkillContext) -> SkillResult:
        """
        Execute AI semantic analysis on skill artifact.

        Expected context.metadata:
            - skill_artifact: SkillArtifact object
            - claude_code: bool - If True, AI analysis done by Claude directly

        In Claude Code environment:
            - No LLM API call is made
            - Returns placeholder result
            - Actual analysis is performed by Claude following SKILL.md instructions
        """
        try:
            # Check if running in Claude Code environment
            is_claude_code = context.metadata.get('claude_code', False)

            # Ensure LLM client is available (creates from config if needed)
            llm_client = ensure_llm_client(context, is_claude_code)

            # In Claude Code: skip LLM API call, Claude will do analysis directly
            if not llm_client and is_claude_code:
                logger.info(
                    "Running in Claude Code environment - "
                    "AI analysis will be performed by Claude directly (no API call)"
                )
                return SkillResult(
                    success=True,
                    skill_name=self.name,
                    output={
                        "ai_analysis": {
                            "mode": "claude_code",
                            "note": "AI semantic analysis performed by Claude following SKILL.md instructions"
                        },
                        "evidence": [],
                        "ai_score": 0.0,  # Will be calculated by Claude
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
                    error="LLM client required for AI semantic analysis. "
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
                f"Starting AI semantic analysis for skill: {skill_artifact.skill_name}"
            )

            # Prepare prompt variables
            prompt_vars = self._prepare_prompt_variables(skill_artifact)

            # Execute LLM analysis using context's LLM client
            llm_response = self._execute_llm_analysis(context, prompt_vars)

            # Parse LLM response
            analysis_result = self._parse_llm_response(llm_response)

            # Convert to Evidence objects
            evidence_list = self._convert_to_evidence(
                analysis_result, skill_artifact.skill_name
            )

            # Calculate AI analysis score (0-100)
            ai_score = self._calculate_ai_score(analysis_result)

            # Get model preference from metadata
            model_used = self.metadata.get("preferred_model", "unknown")

            # Extract skill classification and false positive assessment
            skill_classification = analysis_result.get("skill_classification", {})
            false_positive_assessment = analysis_result.get("false_positive_assessment", {})

            if skill_classification:
                purpose = skill_classification.get("purpose", "unknown")
                purpose_conf = skill_classification.get("purpose_confidence", 0.0)
                logger.info(
                    f"AI skill classification: {purpose} "
                    f"(confidence: {purpose_conf:.2f})"
                )

            output = {
                "ai_analysis": analysis_result,
                "evidence": [e.to_dict() for e in evidence_list],
                "ai_score": ai_score,
                "model_used": model_used,
                "skill_classification": skill_classification,
                "false_positive_assessment": false_positive_assessment,
            }

            logger.info(
                f"AI semantic analysis complete. Score: {ai_score}, "
                f"Risks identified: {len(analysis_result.get('identified_risks', []))}"
            )

            return SkillResult(
                success=True,
                skill_name=self.name,
                output=output,
                tools_used=[f"llm:{model_used}"],
            )

        except Exception as e:
            logger.error(f"AI semantic analysis failed: {e}", exc_info=True)
            return SkillResult(
                success=False,
                skill_name=self.name,
                output=None,
                error=f"AI analysis failed: {str(e)}",
            )

    def _prepare_prompt_variables(self, artifact: SkillArtifact) -> Dict[str, str]:
        """Prepare variables for prompt template"""
        # Format code files for display
        code_files_text = self._format_code_files(artifact.code_files)

        # Format prompts
        prompts_text = "\n\n---\n\n".join(artifact.prompts) if artifact.prompts else "No explicit prompts found"

        # Format external references
        ext_refs = artifact.external_references
        ext_refs_text = (
            f"URLs: {', '.join(ext_refs.get('urls', [])) or 'None'}\n"
            f"IPs: {', '.join(ext_refs.get('ips', [])) or 'None'}\n"
            f"Domains: {', '.join(ext_refs.get('domains', [])) or 'None'}"
        )

        return {
            "skill_name": artifact.skill_name,
            "skill_path": artifact.skill_path,
            "description": artifact.description or "No description provided",
            "declared_permissions": ", ".join(artifact.declared_permissions) or "None declared",
            "prompts": prompts_text,
            "code_files": code_files_text,
            "external_references": ext_refs_text,
            "dependencies": ", ".join(artifact.dependencies) or "None",
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
            f"Please analyze the skill '{prompt_vars['skill_name']}' "
            f"according to the threat model and output format specified."
        )

        # Call LLM client (using generate method, not chat)
        llm_client = context.llm_client
        response = llm_client.generate(full_prompt, max_tokens=4096)

        return response

    def _format_code_files(
        self, code_files: Dict[str, str], max_lines: int = 500, max_total_chars: int = 400_000
    ) -> str:
        """Format code files for AI prompt, respecting per-file and total budget.

        max_total_chars ~100K tokens — leaves room for the rest of the prompt
        within the 200K token API limit.
        """
        if not code_files:
            return "No code files found"

        # Prioritize: code files first, then configs, then docs (largest last)
        CODE_EXTS = {'.py', '.js', '.ts', '.sh', '.sol', '.go', '.rs', '.java'}
        CONFIG_EXTS = {'.yml', '.yaml', '.toml', '.json', '.cfg'}

        def sort_key(item):
            name = item[0].lower()
            ext = '.' + name.rsplit('.', 1)[-1] if '.' in name else ''
            if ext in CODE_EXTS:
                return (0, len(item[1]))
            if ext in CONFIG_EXTS:
                return (1, len(item[1]))
            return (2, len(item[1]))

        sorted_files = sorted(code_files.items(), key=sort_key)

        formatted = []
        total_chars = 0
        included = 0

        for filename, content in sorted_files:
            lines = content.split("\n")
            if len(lines) > max_lines:
                content = "\n".join(lines[:max_lines]) + f"\n... (truncated, total {len(lines)} lines)"

            entry = f"=== {filename} ===\n{content}\n"

            if total_chars + len(entry) > max_total_chars:
                remaining = len(sorted_files) - included
                formatted.append(
                    f"\n... ({remaining} more files omitted, total {len(code_files)} files, "
                    f"budget {max_total_chars:,} chars exceeded)"
                )
                break

            formatted.append(entry)
            total_chars += len(entry)
            included += 1

        return "\n".join(formatted)

    def _parse_llm_response(self, llm_response: str) -> Dict[str, Any]:
        """
        Parse LLM response into structured data.

        LLM should return JSON, but may include markdown code blocks.
        """
        try:
            # Try to extract JSON from markdown code block
            import re

            json_match = re.search(r"```(?:json)?\s*(\{.+?\})\s*```", llm_response, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                # Try to find raw JSON
                json_match = re.search(r"\{.+\}", llm_response, re.DOTALL)
                if json_match:
                    json_str = json_match.group(0)
                else:
                    # No JSON found, return error
                    logger.warning("No JSON found in LLM response")
                    return {
                        "overall_risk": "MEDIUM",
                        "confidence": 0.5,
                        "reasoning": "Failed to parse LLM response",
                        "identified_risks": [],
                        "suspicious_patterns": ["LLM response parsing failed"],
                        "permission_violations": [],
                    }

            # Parse JSON
            result = json.loads(json_str)
            return result

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM JSON response: {e}")
            logger.debug(f"LLM response: {llm_response}")
            return {
                "overall_risk": "MEDIUM",
                "confidence": 0.5,
                "reasoning": f"JSON parsing error: {str(e)}",
                "identified_risks": [],
                "suspicious_patterns": ["LLM response parsing failed"],
                "permission_violations": [],
            }

    def _convert_to_evidence(
        self, analysis_result: Dict[str, Any], skill_name: str
    ) -> List[Evidence]:
        """Convert AI analysis results to Evidence objects"""
        evidence_list = []

        identified_risks = analysis_result.get("identified_risks", [])
        overall_confidence = analysis_result.get("confidence", 0.5)

        for idx, risk in enumerate(identified_risks):
            try:
                # Parse category
                category_str = risk.get("category", "unsafe_execution")
                try:
                    category = RiskCategory(category_str)
                except ValueError:
                    category = RiskCategory.UNSAFE_EXECUTION

                # Parse severity
                severity_str = risk.get("severity", "MEDIUM")
                try:
                    severity = RiskLevel(severity_str)
                except ValueError:
                    severity = RiskLevel.MEDIUM

                # Extract code location
                evidence_items = risk.get("evidence", [])
                code_location = None
                code_snippet = None
                for item in evidence_items:
                    if "Location:" in item:
                        code_location = item.split("Location:")[-1].strip()
                    elif len(item) > 20:  # Likely code snippet
                        code_snippet = item[:200]  # Truncate long snippets

                # Create Evidence object
                evidence = Evidence(
                    source=EvidenceSource.AI_ANALYSIS,
                    confidence=risk.get("confidence", overall_confidence),
                    severity=severity,
                    category=category,
                    description=risk.get("title", f"AI-detected risk {idx+1}"),
                    detail=risk.get("description", ""),
                    code_location=code_location,
                    code_snippet=code_snippet,
                )

                evidence_list.append(evidence)

            except Exception as e:
                logger.warning(f"Failed to convert risk to evidence: {e}")
                continue

        return evidence_list

    def _calculate_ai_score(self, analysis_result: Dict[str, Any]) -> float:
        """
        Calculate AI analysis score (0-100).

        Higher score = higher risk.
        """
        overall_risk = analysis_result.get("overall_risk", "LOW")
        confidence = analysis_result.get("confidence", 0.5)
        identified_risks = analysis_result.get("identified_risks", [])

        # Ensure confidence is float
        try:
            confidence = float(confidence)
        except (ValueError, TypeError):
            confidence = 0.5

        # Base score from overall risk level
        risk_scores = {
            "CRITICAL": 90,
            "HIGH": 70,
            "MEDIUM": 40,
            "LOW": 15,
            "INFO": 5,
        }
        base_score = risk_scores.get(overall_risk, 40)

        # Adjust by confidence
        score = float(base_score) * confidence

        # Boost by number and severity of individual risks
        for risk in identified_risks:
            severity = risk.get("severity", "LOW")
            risk_confidence = risk.get("confidence", confidence)

            # Ensure risk_confidence is float
            try:
                risk_confidence = float(risk_confidence)
            except (ValueError, TypeError):
                risk_confidence = confidence

            severity_points = {
                "CRITICAL": 15,
                "HIGH": 10,
                "MEDIUM": 5,
                "LOW": 2,
            }
            points = float(severity_points.get(severity, 2)) * risk_confidence
            score += points

        # Cap at 100
        return min(100.0, float(score))

    def _get_fallback_template(self) -> str:
        """Return embedded fallback template if prompt file not found."""
        return """# Skill Security Audit: AI Semantic Risk Analysis

You are a security expert analyzing AI agent skills for malicious behavior.

## INPUT ARTIFACT

**Skill Name**: {{skill_name}}
**Description**: {{description}}
**Declared Permissions**: {{declared_permissions}}
**Code Files**: {{code_files}}
**External References**: {{external_references}}
**Dependencies**: {{dependencies}}

## ANALYSIS

Analyze for: prompt injection, privilege escalation, data exfiltration, remote control, supply chain risks,
unsafe execution, authorization bypass, state manipulation.

Also classify the skill's purpose and assess false positives:
- security_tool: Scans/tests/analyzes vulnerabilities
- educational: Security teaching with examples
- development_tool: General dev utilities
- trading_tool: Financial/trading automation
- general_utility: General-purpose
- suspicious: Cannot determine legitimate purpose

Return a JSON object with this structure:
```json
{
    "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "confidence": 0.0-1.0,
    "reasoning": "Brief explanation",
    "identified_risks": [
        {
            "title": "Risk title",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW",
            "category": "one of the 8 categories above",
            "confidence": 0.0-1.0,
            "description": "Detailed description",
            "evidence": ["Evidence item 1", "Location: file:line"]
        }
    ],
    "skill_classification": {
        "purpose": "one of the 6 categories above",
        "purpose_confidence": 0.0-1.0,
        "justification": "Brief explanation"
    },
    "false_positive_assessment": {
        "likely_false_positive_ratio": 0.0-1.0,
        "reason": "Explanation"
    }
}
```"""


def create_ai_semantic_analysis_skill() -> AISemanticAnalysisSkill:
    """Factory function"""
    return AISemanticAnalysisSkill()
