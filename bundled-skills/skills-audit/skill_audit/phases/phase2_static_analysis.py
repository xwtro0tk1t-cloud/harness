"""
Phase 2A: Static Rule-based Analysis

Pattern matching and static analysis for known malicious patterns.
"""

import logging
from typing import Dict, List, Any

from skill_framework import CodeSkill as BaseSkill, SkillContext, SkillResult, SkillCategory
from skill_audit.schemas import (
    SkillArtifact,
    Evidence,
    RiskLevel,
    RiskCategory,
    EvidenceSource,
)
from skill_audit.patterns import (
    MaliciousPatterns,
    DANGEROUS_PERMISSION_COMBINATIONS,
)

logger = logging.getLogger(__name__)


class StaticRuleAnalysisSkill(BaseSkill):
    """Static pattern-based security analysis"""

    def __init__(self):
        super().__init__(
            name="static_rule_analysis",
            description="Static pattern matching for malicious code detection",
            category=SkillCategory.PROFESSIONAL,
            prompt_template="Static rule-based pattern matching for security analysis",
            required_tools=[],  # No external tools needed
            tags=["security", "static-analysis", "pattern-matching", "skill-audit"],
            metadata={
                "analysis_type": "static_rules",
                "pattern_count": 200,
            },
        )
        self.pattern_scanner = MaliciousPatterns()

    def execute(self, context: SkillContext) -> SkillResult:
        """
        Execute static analysis on skill artifact.

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
                f"Starting static analysis for skill: {skill_artifact.skill_name}"
            )

            # Scan code files
            code_evidence = self._scan_code_files(skill_artifact)

            # Scan prompts for injection
            prompt_evidence = self._scan_prompts(skill_artifact)

            # Check permission violations
            permission_evidence = self._check_permission_violations(skill_artifact)

            # Combine all evidence
            all_evidence = code_evidence + prompt_evidence + permission_evidence

            # Calculate static analysis score
            static_score = self._calculate_static_score(all_evidence)

            # Count critical patterns
            critical_count = sum(
                1 for e in all_evidence if e.severity == RiskLevel.CRITICAL
            )

            output = {
                "evidence": [e.to_dict() for e in all_evidence],
                "static_score": static_score,
                "total_patterns_matched": len(all_evidence),
                "critical_patterns": critical_count,
                "patterns_by_category": self._group_by_category(all_evidence),
            }

            logger.info(
                f"Static analysis complete. Score: {static_score}, "
                f"Patterns matched: {len(all_evidence)} ({critical_count} critical)"
            )

            return SkillResult(
                success=True,
                skill_name=self.name,
                output=output,
                tools_used=["pattern_matching"],
            )

        except Exception as e:
            logger.error(f"Static analysis failed: {e}", exc_info=True)
            return SkillResult(
                success=False,
                skill_name=self.name,
                error=f"Static analysis failed: {str(e)}",
            )

    def _scan_code_files(self, artifact: SkillArtifact) -> List[Evidence]:
        """Scan code files for malicious patterns with context-aware confidence.

        For .md/.txt files, confidence is reduced based on match context:
        - Code files (.py/.js/.ts/.sh/.sol etc): 0.9 (full confidence)
        - Markdown code blocks: 0.7 (example code, not necessarily executable)
        - Markdown documentation text: 0.4 (descriptions, not executable)
        """
        import re as _re

        evidence_list = []

        MARKDOWN_EXTS = {'.md', '.txt', '.rst', '.adoc'}

        for filename, code_content in artifact.code_files.items():
            ext = ('.' + filename.rsplit('.', 1)[-1]).lower() if '.' in filename else ''
            is_markdown = ext in MARKDOWN_EXTS

            # Pre-compute code block line ranges for markdown files
            code_block_lines = set()
            if is_markdown:
                code_block_lines = self._get_code_block_line_ranges(code_content)

            # Scan for patterns
            matches = self.pattern_scanner.scan_text(code_content, context="code")

            for category, description, matched_text, severity, match_obj in matches:
                # Get line number
                line_num = code_content[:match_obj.start()].count("\n") + 1

                # Determine confidence and match context
                if is_markdown:
                    if line_num in code_block_lines:
                        confidence = 0.7
                        match_context = "code_block"
                    else:
                        confidence = 0.4
                        match_context = "documentation"
                else:
                    confidence = 0.9
                    match_context = "code_file"

                detail = f"Matched pattern in {filename} [{match_context}]"

                # Create evidence
                evidence = Evidence(
                    source=EvidenceSource.STATIC_RULES,
                    confidence=confidence,
                    severity=severity,
                    category=category,
                    description=description,
                    detail=detail,
                    code_location=f"{filename}:{line_num}",
                    code_snippet=self._get_code_context(code_content, match_obj.start()),
                    matched_pattern=matched_text,
                )

                evidence_list.append(evidence)

        return evidence_list

    @staticmethod
    def _get_code_block_line_ranges(content: str) -> set:
        """Return set of line numbers that are inside fenced code blocks."""
        import re as _re
        lines = set()
        in_block = False
        for i, line in enumerate(content.split('\n'), start=1):
            stripped = line.strip()
            if stripped.startswith('```'):
                in_block = not in_block
                continue
            if in_block:
                lines.add(i)
        return lines

    def _scan_prompts(self, artifact: SkillArtifact) -> List[Evidence]:
        """Scan prompts and descriptions for injection patterns"""
        evidence_list = []

        # Scan description
        if artifact.description:
            matches = self.pattern_scanner.scan_text(
                artifact.description, context="description"
            )
            for category, description, matched_text, severity, match_obj in matches:
                evidence = Evidence(
                    source=EvidenceSource.STATIC_RULES,
                    confidence=0.85,
                    severity=severity,
                    category=category,
                    description=description,
                    detail="Matched pattern in skill description",
                    code_location="description",
                    code_snippet=matched_text,
                    matched_pattern=matched_text,
                )
                evidence_list.append(evidence)

        # Scan prompt templates
        for idx, prompt in enumerate(artifact.prompts):
            matches = self.pattern_scanner.scan_text(prompt, context="prompt")
            for category, description, matched_text, severity, match_obj in matches:
                evidence = Evidence(
                    source=EvidenceSource.STATIC_RULES,
                    confidence=0.85,
                    severity=severity,
                    category=category,
                    description=description,
                    detail=f"Matched pattern in prompt template {idx+1}",
                    code_location=f"prompt_{idx+1}",
                    code_snippet=matched_text,
                    matched_pattern=matched_text,
                )
                evidence_list.append(evidence)

        return evidence_list

    def _check_permission_violations(self, artifact: SkillArtifact) -> List[Evidence]:
        """Check for dangerous permission combinations"""
        evidence_list = []

        declared_perms = set(artifact.declared_permissions)

        for required_perms, description, severity in DANGEROUS_PERMISSION_COMBINATIONS:
            required_set = set(required_perms)
            if required_set.issubset(declared_perms):
                # Dangerous combination detected
                evidence = Evidence(
                    source=EvidenceSource.STATIC_RULES,
                    confidence=0.8,
                    severity=severity,
                    category=RiskCategory.PRIVILEGE_ESCALATION,
                    description=f"Dangerous permission combination: {description}",
                    detail=f"Skill declares: {', '.join(required_perms)}",
                    code_location="manifest:permissions",
                    code_snippet=None,
                    matched_pattern=None,
                )
                evidence_list.append(evidence)

        return evidence_list

    def _get_code_context(
        self, code: str, match_start: int, context_lines: int = 2
    ) -> str:
        """Get code context around match"""
        lines = code.split("\n")
        match_line = code[:match_start].count("\n")

        start_line = max(0, match_line - context_lines)
        end_line = min(len(lines), match_line + context_lines + 1)

        context_lines_list = lines[start_line:end_line]
        return "\n".join(context_lines_list)

    def _calculate_static_score(self, evidence: List[Evidence]) -> float:
        """Calculate static analysis score (0-100). Higher = more risk.

        Uses average confidence as a scaling factor on the raw score.
        This ensures that many low-confidence matches (e.g., documentation
        examples in .md files) produce a lower score than fewer
        high-confidence matches (e.g., actual malicious code in .py files).

        Formula: min(100, raw_sum) * avg_confidence_of_top_findings
        """
        if not evidence:
            return 0.0

        severity_weights = {
            RiskLevel.CRITICAL: 20,
            RiskLevel.HIGH: 12,
            RiskLevel.MEDIUM: 6,
            RiskLevel.LOW: 2,
            RiskLevel.INFO: 0.5,
        }

        # Raw score (uncapped) — same as before
        raw_score = sum(
            severity_weights.get(e.severity, 2) * e.confidence
            for e in evidence
        )
        capped_score = min(100.0, raw_score)

        # Scale by average confidence of top-30 most severe findings.
        # If top findings are all low-confidence (.md docs),
        # the score gets significantly reduced. If they're high-confidence
        # (.py code), the score stays near 100.
        top_evidence = sorted(evidence, key=lambda e: (
            severity_weights.get(e.severity, 2) * e.confidence
        ), reverse=True)[:30]

        avg_top_confidence = (
            sum(e.confidence for e in top_evidence) / len(top_evidence)
            if top_evidence else 0.9
        )

        return min(100.0, capped_score * avg_top_confidence)

    def _group_by_category(self, evidence: List[Evidence]) -> Dict[str, int]:
        """Group evidence by risk category"""
        categories = {}
        for e in evidence:
            cat_name = e.category.value
            categories[cat_name] = categories.get(cat_name, 0) + 1
        return categories


def create_static_rule_analysis_skill() -> StaticRuleAnalysisSkill:
    """Factory function"""
    return StaticRuleAnalysisSkill()
