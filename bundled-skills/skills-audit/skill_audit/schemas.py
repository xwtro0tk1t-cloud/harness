"""
Data schemas for Skill Security Audit

Defines structured output format for skill audit reports.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime


class RiskLevel(str, Enum):
    """Risk severity levels"""

    CRITICAL = "CRITICAL"  # Immediate threat, high confidence
    HIGH = "HIGH"  # Serious vulnerability, needs attention
    MEDIUM = "MEDIUM"  # Moderate risk, should be addressed
    LOW = "LOW"  # Minor concern, low impact
    INFO = "INFO"  # Informational, no security impact


class RiskCategory(str, Enum):
    """Types of skill security risks"""

    PROMPT_INJECTION = "prompt_injection"  # Manipulates agent behavior via prompts
    PRIVILEGE_ESCALATION = "privilege_escalation"  # Exceeds declared permissions
    DATA_EXFILTRATION = "data_exfiltration"  # Leaks sensitive data externally
    REMOTE_CONTROL = "remote_control"  # C2 communication, backdoor
    SUPPLY_CHAIN = "supply_chain"  # Malicious dependencies, obfuscation
    UNSAFE_EXECUTION = "unsafe_execution"  # Code injection, dangerous operations
    AUTHORIZATION_BYPASS = "authorization_bypass"  # Bypasses access controls
    STATE_MANIPULATION = "state_manipulation"  # Corrupts agent state


class EvidenceSource(str, Enum):
    """Source of security evidence"""

    AI_ANALYSIS = "ai_analysis"  # LLM semantic analysis
    STATIC_RULES = "static_rules"  # Pattern matching
    THREAT_INTEL = "threat_intel"  # TIP / C2 detection


@dataclass
class Evidence:
    """Security evidence from analysis"""

    source: EvidenceSource
    confidence: float  # 0.0 - 1.0
    severity: RiskLevel
    category: RiskCategory
    description: str
    detail: str
    code_location: Optional[str] = None
    code_snippet: Optional[str] = None
    matched_pattern: Optional[str] = None  # For static rules
    threat_intel_data: Optional[Dict[str, Any]] = None  # For TIP results

    def __post_init__(self):
        """Convert string values to enums if needed (for deserialization)"""
        if isinstance(self.source, str):
            self.source = EvidenceSource(self.source)
        if isinstance(self.severity, str):
            self.severity = RiskLevel(self.severity)
        if isinstance(self.category, str):
            self.category = RiskCategory(self.category)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source.value,
            "confidence": self.confidence,
            "severity": self.severity.value,
            "category": self.category.value,
            "description": self.description,
            "detail": self.detail,
            "code_location": self.code_location,
            "code_snippet": self.code_snippet,
            "matched_pattern": self.matched_pattern,
            "threat_intel_data": self.threat_intel_data,
        }


@dataclass
class AttackScenario:
    """Description of how vulnerability could be exploited"""

    title: str
    steps: List[str]
    preconditions: List[str]
    attacker_capability: str  # e.g., "network access", "local user"
    impact: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "steps": self.steps,
            "preconditions": self.preconditions,
            "attacker_capability": self.attacker_capability,
            "impact": self.impact,
        }


@dataclass
class ImpactAssessment:
    """Assessment of potential damage from vulnerability"""

    confidentiality: RiskLevel  # Data leak risk
    integrity: RiskLevel  # Data/state corruption risk
    availability: RiskLevel  # Service disruption risk
    financial: Optional[str] = None  # Estimated financial impact
    reputation: Optional[str] = None  # Reputation damage
    compliance: Optional[List[str]] = None  # Violated regulations (e.g., GDPR)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "confidentiality": self.confidentiality.value,
            "integrity": self.integrity.value,
            "availability": self.availability.value,
            "financial": self.financial,
            "reputation": self.reputation,
            "compliance": self.compliance,
        }


@dataclass
class Recommendation:
    """Security remediation recommendation"""

    priority: RiskLevel
    title: str
    description: str
    effort: str  # "LOW", "MEDIUM", "HIGH"
    code_fix: Optional[str] = None  # Example code fix
    references: Optional[List[str]] = None  # CWE, OWASP, etc.

    def to_dict(self) -> Dict[str, Any]:
        return {
            "priority": self.priority.value,
            "title": self.title,
            "description": self.description,
            "effort": self.effort,
            "code_fix": self.code_fix,
            "references": self.references,
        }


@dataclass
class Finding:
    """A single security finding"""

    finding_id: str  # e.g., "SKILL-AUDIT-001"
    title: str
    severity: RiskLevel
    confidence: float  # 0.0 - 1.0
    categories: List[RiskCategory]
    description: str
    evidence: List[Evidence]
    attack_scenario: Optional[AttackScenario] = None
    impact: Optional[ImpactAssessment] = None
    recommendations: List[Recommendation] = field(default_factory=list)
    cwe_ids: Optional[List[str]] = None  # e.g., ["CWE-78", "CWE-94"]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "categories": [c.value for c in self.categories],
            "description": self.description,
            "evidence": [e.to_dict() for e in self.evidence],
            "attack_scenario": self.attack_scenario.to_dict()
            if self.attack_scenario
            else None,
            "impact": self.impact.to_dict() if self.impact else None,
            "recommendations": [r.to_dict() for r in self.recommendations],
            "cwe_ids": self.cwe_ids,
            "metadata": self.metadata,
        }


@dataclass
class SkillArtifact:
    """Extracted skill artifact data (Phase 0)"""

    skill_name: str
    skill_path: str
    manifest: Dict[str, Any]  # Parsed manifest/metadata
    description: str
    prompts: List[str]  # Prompt templates
    declared_permissions: List[str]
    code_files: Dict[str, str]  # filename -> content
    external_references: Dict[str, List[str]]  # urls, ips, domains
    dependencies: List[str]  # External packages

    def to_dict(self) -> Dict[str, Any]:
        return {
            "skill_name": self.skill_name,
            "skill_path": self.skill_path,
            "manifest": self.manifest,
            "description": self.description,
            "prompts": self.prompts,
            "declared_permissions": self.declared_permissions,
            "code_files": self.code_files,
            "external_references": self.external_references,
            "dependencies": self.dependencies,
        }


@dataclass
class SkillAuditReport:
    """Complete skill security audit report"""

    # Metadata
    audit_id: str
    timestamp: str
    skill_artifact: SkillArtifact

    # Overall assessment
    overall_risk: RiskLevel
    overall_score: float  # 0-100 (weighted score)
    confidence: float  # 0.0 - 1.0

    # Findings
    findings: List[Finding]
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int

    # Phase results
    ai_analysis_score: float  # 0-100
    static_analysis_score: float  # 0-100
    threat_intel_score: float  # 0-100

    # Evidence summary
    ai_evidence_count: int
    static_evidence_count: int
    threat_intel_evidence_count: int
    c2_detected: bool
    c2_count: int

    # Summary
    executive_summary: str
    key_concerns: List[str]
    decision_recommendation: str  # "BLOCK", "ALLOW", "HITL_REVIEW"

    # AI classification
    skill_classification: Dict[str, Any] = field(default_factory=dict)

    # Metadata
    analysis_duration: float = 0.0  # seconds
    models_used: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "timestamp": self.timestamp,
            "skill_artifact": self.skill_artifact.to_dict(),
            "overall_risk": self.overall_risk.value,
            "overall_score": self.overall_score,
            "confidence": self.confidence,
            "findings": [f.to_dict() for f in self.findings],
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "ai_analysis_score": self.ai_analysis_score,
            "static_analysis_score": self.static_analysis_score,
            "threat_intel_score": self.threat_intel_score,
            "ai_evidence_count": self.ai_evidence_count,
            "static_evidence_count": self.static_evidence_count,
            "threat_intel_evidence_count": self.threat_intel_evidence_count,
            "c2_detected": self.c2_detected,
            "c2_count": self.c2_count,
            "executive_summary": self.executive_summary,
            "key_concerns": self.key_concerns,
            "decision_recommendation": self.decision_recommendation,
            "skill_classification": self.skill_classification,
            "analysis_duration": self.analysis_duration,
            "models_used": self.models_used,
            "tools_used": self.tools_used,
        }
