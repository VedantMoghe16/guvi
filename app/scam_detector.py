"""Scam intent detection engine."""

import re
from dataclasses import dataclass
from typing import Optional

from app.models import Message


@dataclass
class ScamDetectionResult:
    """Result of scam detection analysis."""
    is_scam: bool
    confidence: float
    scam_type: Optional[str]
    matched_patterns: list[str]


class ScamDetector:
    """Detects scam intent in messages using pattern matching and heuristics."""
    
    # Scam patterns organized by type
    SCAM_PATTERNS = {
        "bank_fraud": [
            r"account.*block",
            r"bank.*suspend",
            r"kyc.*expir",
            r"verify.*immediately",
            r"update.*bank.*details",
            r"account.*freez",
            r"unauthori[sz]ed.*transaction",
            r"security.*alert",
            r"debit.*card.*block",
            r"credit.*card.*block",
        ],
        "upi_fraud": [
            r"share.*upi",
            r"upi.*id",
            r"send.*upi.*pin",
            r"payment.*pending",
            r"request.*money",
            r"collect.*request",
            r"gpay|phonepe|paytm.*request",
            r"refund.*upi",
            r"upi.*verify",
        ],
        "phishing": [
            r"click.*link",
            r"login.*here",
            r"verify.*account",
            r"confirm.*identity",
            r"update.*password",
            r"suspicious.*activity",
            r"secure.*account",
            r"bit\.ly|tinyurl|short",
        ],
        "lottery_scam": [
            r"won.*prize",
            r"lottery.*winner",
            r"claim.*reward",
            r"congratulations.*selected",
            r"lucky.*draw",
            r"cash.*prize",
        ],
        "job_scam": [
            r"work.*from.*home",
            r"earn.*daily",
            r"easy.*money",
            r"part.*time.*job",
            r"registration.*fee",
            r"guaranteed.*income",
        ],
        "impersonation": [
            r"rbi.*officer",
            r"bank.*manager",
            r"police.*cyber",
            r"government.*official",
            r"income.*tax",
            r"it.*department",
        ],
    }
    
    # Urgency indicators that boost scam confidence
    URGENCY_PATTERNS = [
        r"urgent",
        r"immediate",
        r"today.*only",
        r"within.*hours",
        r"act.*now",
        r"last.*chance",
        r"expir.*soon",
        r"avoid.*penalty",
        r"avoid.*suspension",
        r"legal.*action",
        r"or.*else",
    ]
    
    # Financial request patterns
    FINANCIAL_REQUEST_PATTERNS = [
        r"otp",
        r"pin",
        r"cvv",
        r"account.*number",
        r"card.*number",
        r"bank.*details",
        r"transfer.*money",
        r"send.*amount",
        r"processing.*fee",
    ]
    
    def __init__(self):
        """Initialize the scam detector with compiled patterns."""
        self._compiled_patterns = {}
        for scam_type, patterns in self.SCAM_PATTERNS.items():
            self._compiled_patterns[scam_type] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]
        
        self._urgency_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.URGENCY_PATTERNS
        ]
        self._financial_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.FINANCIAL_REQUEST_PATTERNS
        ]
    
    def detect(
        self, 
        text: str, 
        conversation_history: list[Message] = None
    ) -> ScamDetectionResult:
        """
        Analyze a message for scam intent.
        
        Args:
            text: The message text to analyze
            conversation_history: Previous messages for context
            
        Returns:
            ScamDetectionResult with detection details
        """
        if conversation_history is None:
            conversation_history = []
        
        # Combine current message with history for full context
        full_text = text
        for msg in conversation_history:
            if msg.sender == "scammer":
                full_text += " " + msg.text
        
        matched_patterns = []
        scam_scores = {}
        
        # Check each scam type
        for scam_type, patterns in self._compiled_patterns.items():
            score = 0
            for pattern in patterns:
                if pattern.search(text):
                    score += 1
                    matched_patterns.append(f"{scam_type}:{pattern.pattern}")
                # Also check full conversation context
                elif pattern.search(full_text):
                    score += 0.5
            scam_scores[scam_type] = score
        
        # Check urgency indicators
        urgency_score = 0
        for pattern in self._urgency_patterns:
            if pattern.search(text):
                urgency_score += 1
                matched_patterns.append(f"urgency:{pattern.pattern}")
        
        # Check financial request patterns
        financial_score = 0
        for pattern in self._financial_patterns:
            if pattern.search(text):
                financial_score += 1
                matched_patterns.append(f"financial:{pattern.pattern}")
        
        # Calculate overall confidence
        max_scam_type = max(scam_scores, key=scam_scores.get) if scam_scores else None
        max_scam_score = scam_scores.get(max_scam_type, 0) if max_scam_type else 0
        
        # Confidence calculation:
        # - Base confidence from scam type matches
        # - Bonus for urgency tactics
        # - Bonus for financial requests
        base_confidence = min(max_scam_score * 0.3, 0.6)
        urgency_bonus = min(urgency_score * 0.15, 0.2)
        financial_bonus = min(financial_score * 0.15, 0.2)
        
        total_confidence = base_confidence + urgency_bonus + financial_bonus
        total_confidence = min(total_confidence, 1.0)
        
        # Determine if it's a scam based on confidence threshold
        is_scam = total_confidence >= 0.5
        
        return ScamDetectionResult(
            is_scam=is_scam,
            confidence=round(total_confidence, 2),
            scam_type=max_scam_type if is_scam else None,
            matched_patterns=matched_patterns
        )
    
    def get_suspicious_keywords(self, text: str) -> list[str]:
        """Extract suspicious keywords from text."""
        keywords = []
        
        for pattern in self._urgency_patterns:
            match = pattern.search(text)
            if match:
                keywords.append(match.group().lower())
        
        for pattern in self._financial_patterns:
            match = pattern.search(text)
            if match:
                keywords.append(match.group().lower())
        
        return list(set(keywords))


# Global instance
scam_detector = ScamDetector()
