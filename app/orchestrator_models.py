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


class EngagementPhase(str, Enum):
    """Phases of honeypot engagement."""
    INITIAL_CONTACT = "initial_contact"      # First message, build rapport
    BUILDING_TRUST = "building_trust"        # Show confusion, gain scammer trust
    EXTRACTING_INTEL = "extracting_intel"    # Actively probe for details
    CONFIRMING_INTEL = "confirming_intel"    # Verify extracted info
    FINALIZING = "finalizing"                # Ready to conclude


class IntelExtractionProgress(BaseModel):
    """Tracks what intel has been extracted."""
    phone_numbers_found: int = 0
    upi_ids_found: int = 0
    bank_accounts_found: int = 0
    phishing_links_found: int = 0
    emails_found: int = 0
    
    @property
    def total_intel_count(self) -> int:
        """Total number of intel pieces extracted."""
        return (
            self.phone_numbers_found +
            self.upi_ids_found +
            self.bank_accounts_found +
            self.phishing_links_found +
            self.emails_found
        )
    
    @property
    def extraction_complete(self) -> bool:
        """Check if minimum intel has been extracted."""
        # At least 2 pieces of intel or 1 critical piece (phone/bank)
        return (
            self.total_intel_count >= 2 or
            self.phone_numbers_found > 0 or
            self.bank_accounts_found > 0 or
            self.upi_ids_found > 0
        )


class EngagementStrategy(BaseModel):
    """
    Strategy for honeypot engagement.
    
    Key insight: Detection != Action
    - We can DETECT a scam early
    - But we DELAY action to extract intel first
    """
    # Detection (informational)
    scam_detected: bool = False
    scam_confidence: float = 0.0
    scam_type: Optional[ScamType] = None
    
    # Engagement state
    current_phase: EngagementPhase = EngagementPhase.INITIAL_CONTACT
    messages_exchanged: int = 0
    intel_progress: IntelExtractionProgress = Field(
        default_factory=IntelExtractionProgress
    )
    
    # Action (deferred until intel extracted)
    ready_to_finalize: bool = False
    recommended_action: RecommendedAction = RecommendedAction.ENGAGE
    
    # Thresholds (configurable)
    min_messages_before_finalize: int = 5
    min_intel_before_finalize: int = 1
    
    def should_continue_engagement(self) -> bool:
        """
        Determine if we should keep engaging or finalize.
        
        Even if scam is detected, continue if:
        1. Not enough messages exchanged
        2. No intel extracted yet
        """
        if not self.scam_detected:
            return True  # Not a scam, continue normally
        
        # Scam detected - but have we extracted enough?
        if self.messages_exchanged < self.min_messages_before_finalize:
            return True  # Keep engaging, not enough messages
        
        if self.intel_progress.total_intel_count < self.min_intel_before_finalize:
            return True  # Keep engaging, no intel yet
        
        # We have enough - can finalize
        return False
    
    def update_phase(self) -> None:
        """Update engagement phase based on state."""
        if self.messages_exchanged <= 1:
            self.current_phase = EngagementPhase.INITIAL_CONTACT
        elif self.messages_exchanged <= 3:
            self.current_phase = EngagementPhase.BUILDING_TRUST
        elif self.intel_progress.total_intel_count == 0:
            self.current_phase = EngagementPhase.EXTRACTING_INTEL
        elif not self.intel_progress.extraction_complete:
            self.current_phase = EngagementPhase.CONFIRMING_INTEL
        else:
            self.current_phase = EngagementPhase.FINALIZING
            self.ready_to_finalize = True
    
    def get_agent_guidance(self) -> str:
        """Get guidance for agent based on current phase."""
        guidance = {
            EngagementPhase.INITIAL_CONTACT: (
                "Act confused. Ask who they are and what they want. "
                "Don't reveal you understand the scam."
            ),
            EngagementPhase.BUILDING_TRUST: (
                "Show concern about your account. Ask clarifying questions. "
                "Mention needing to ask family for help."
            ),
            EngagementPhase.EXTRACTING_INTEL: (
                "Appear willing to cooperate. Ask WHERE to send money, "
                "WHAT number to call, WHICH UPI to use. Extract their details."
            ),
            EngagementPhase.CONFIRMING_INTEL: (
                "Pretend to have technical issues. Ask them to repeat "
                "their phone/UPI/account number to confirm."
            ),
            EngagementPhase.FINALIZING: (
                "Stall with minor excuses. We have enough intel. "
                "Keep them engaged while we process."
            ),
        }
        return guidance.get(self.current_phase, "Continue engaging cautiously.")
