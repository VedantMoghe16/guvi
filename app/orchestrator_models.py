"""Structured output models for advanced scam detection orchestrator.

These Pydantic models enforce schema validation for LLM responses,
ensuring consistent and reliable JSON output.
"""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Scam risk severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RecommendedAction(str, Enum):
    """Actions to take based on scam analysis."""
    PASS = "pass"          # Benign message, allow through
    MONITOR = "monitor"    # Log and watch for escalation
    ENGAGE = "engage"      # Trigger honeypot engagement
    BLOCK = "block"        # Block immediately
    ALERT_HUMAN = "alert_human"  # Escalate to human moderator


class ScamType(str, Enum):
    """Known scam categories."""
    BANK_FRAUD = "bank_fraud"
    UPI_FRAUD = "upi_fraud"
    PHISHING = "phishing"
    LOTTERY_SCAM = "lottery_scam"
    JOB_SCAM = "job_scam"
    IMPERSONATION = "impersonation"
    TECH_SUPPORT = "tech_support"
    ROMANCE_SCAM = "romance_scam"
    INVESTMENT_SCAM = "investment_scam"
    UNKNOWN = "unknown"


class ExtractedEntities(BaseModel):
    """Entities extracted from suspected scam message."""
    phone_numbers: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    bank_accounts: list[str] = Field(default_factory=list)
    upi_ids: list[str] = Field(default_factory=list)
    email_addresses: list[str] = Field(default_factory=list)
    names_mentioned: list[str] = Field(default_factory=list)


class Level1Result(BaseModel):
    """Result from Level 1 regex-based analysis."""
    confidence: float = Field(..., ge=0.0, le=1.0)
    scam_type: Optional[ScamType] = None
    matched_patterns: list[str] = Field(default_factory=list)
    urgency_score: float = Field(default=0.0, ge=0.0, le=1.0)
    financial_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    normalized_text: str = ""


class ScamAnalysisResponse(BaseModel):
    """
    Complete scam analysis response combining L1 and L2 analysis.
    
    This is the enforced JSON schema for LLM output.
    Chain-of-thought reasoning helps improve accuracy.
    """
    # Reasoning
    chain_of_thought: str = Field(
        ..., 
        description="Step-by-step reasoning explaining analysis"
    )
    
    # Core detection
    is_scam: bool = Field(..., description="Whether message is a scam")
    confidence: float = Field(
        ..., 
        ge=0.0, 
        le=1.0, 
        description="Confidence score 0.0-1.0"
    )
    
    # Classification
    scam_type: Optional[ScamType] = Field(
        None, 
        description="Type of scam if detected"
    )
    risk_level: RiskLevel = Field(
        RiskLevel.LOW, 
        description="Overall risk level"
    )
    
    # Actionable output
    recommended_action: RecommendedAction = Field(
        RecommendedAction.PASS,
        description="Recommended action to take"
    )
    
    # Intelligence
    extracted_entities: ExtractedEntities = Field(
        default_factory=ExtractedEntities,
        description="Extracted indicators of compromise"
    )
    
    # Metadata
    analysis_source: str = Field(
        "level1_regex",
        description="Which level performed final analysis"
    )
    matched_patterns: list[str] = Field(
        default_factory=list,
        description="Regex patterns that matched"
    )

    def to_legacy_format(self) -> dict:
        """Convert to legacy ScamDetectionResult format for compatibility."""
        return {
            "is_scam": self.is_scam,
            "confidence": self.confidence,
            "scam_type": self.scam_type.value if self.scam_type else None,
            "matched_patterns": self.matched_patterns,
        }
