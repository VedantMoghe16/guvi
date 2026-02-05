"""Advanced Scam Detection Orchestrator.

Two-level async orchestrator for production-grade scam detection:
- Level 1: Enhanced regex gatekeeper with fuzzy matching
- Level 2: LLM analyst with Chain-of-Thought and structured JSON output
"""

import asyncio
import json
import logging
import re
from typing import Optional

from openai import OpenAI

try:
    from google import genai
except ImportError:
    genai = None

from app.config import config
from app.models import Message
from app.orchestrator_models import (
    ExtractedEntities,
    Level1Result,
    RecommendedAction,
    RiskLevel,
    ScamAnalysisResponse,
    ScamType,
)
from app.text_normalizer import text_normalizer

logger = logging.getLogger(__name__)


class AdvancedScamOrchestrator:
    """
    Production-grade scam detection orchestrator.
    
    Architecture:
        Level 1 (Regex): High-speed gatekeeper with fuzzy matching
        Level 2 (LLM): Deep semantic analysis for ambiguous cases
    """
    
    # Confidence thresholds
    HIGH_CONFIDENCE_THRESHOLD = 0.9  # Skip LLM, definitely scam
    LOW_CONFIDENCE_THRESHOLD = 0.1   # Skip LLM, probably benign
    LLM_TRIGGER_THRESHOLD = 0.2      # Trigger LLM analysis if above this
    
    # Scam patterns (same as original but enhanced)
    SCAM_PATTERNS: dict[str, list[str]] = {
        "bank_fraud": [
            r"account.*block",
            r"bank.*suspend",
            r"kyc.*expir",
            r"verify.*immediate",
            r"update.*bank.*details",
            r"account.*freez",
            r"unauthori[sz]ed.*transaction",
            r"security.*alert",
            r"debit.*card.*block",
            r"credit.*card.*block",
            r"rbi.*notic",
            r"account.*dormant",
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
            r"upi.*link",
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
            r"http.*verify",
            r"click.*below",
        ],
        "lottery_scam": [
            r"won.*prize",
            r"lottery.*winner",
            r"claim.*reward",
            r"congratulations.*selected",
            r"lucky.*draw",
            r"cash.*prize",
            r"crore.*rupee",
            r"lakh.*prize",
        ],
        "job_scam": [
            r"work.*from.*home",
            r"earn.*daily",
            r"easy.*money",
            r"part.*time.*job",
            r"registration.*fee",
            r"guaranteed.*income",
            r"earn.*\d+.*per.*day",
            r"online.*typing.*job",
        ],
        "impersonation": [
            r"rbi.*officer",
            r"bank.*manager",
            r"police.*cyber",
            r"government.*official",
            r"income.*tax",
            r"it.*department",
            r"cbi.*officer",
            r"customs.*officer",
        ],
        "tech_support": [
            r"computer.*infected",
            r"virus.*detected",
            r"microsoft.*support",
            r"remote.*access",
            r"anydesk|teamviewer",
            r"tech.*support",
        ],
        "investment_scam": [
            r"invest.*double",
            r"guaranteed.*return",
            r"crypto.*opportunity",
            r"quick.*profit",
            r"trading.*signal",
            r"forex.*profit",
        ],
    }
    
    URGENCY_PATTERNS = [
        r"urgent",
        r"immediate",
        r"today.*only",
        r"within.*\d+.*hour",
        r"act.*now",
        r"last.*chance",
        r"expir.*soon",
        r"avoid.*penalty",
        r"avoid.*suspens",
        r"legal.*action",
        r"or.*else",
        r"time.*running",
        r"deadline",
    ]
    
    FINANCIAL_REQUEST_PATTERNS = [
        r"\botp\b",
        r"\bpin\b",
        r"\bcvv\b",
        r"account.*number",
        r"card.*number",
        r"bank.*details",
        r"transfer.*money",
        r"send.*amount",
        r"processing.*fee",
        r"advance.*payment",
        r"debit.*card",
        r"credit.*card",
        r"ifsc.*code",
    ]
    
    LLM_SYSTEM_PROMPT = """You are a Security Analyst AI specialized in detecting scam messages, particularly those targeting Indian users. Your task is to analyze messages and provide a structured assessment.

ANALYSIS FRAMEWORK:
1. Intent Analysis: What is the sender trying to achieve?
2. Urgency Tactics: Are they creating artificial urgency?
3. Financial Requests: Are they asking for money, credentials, or sensitive info?
4. Credibility Check: Are they impersonating legitimate entities?
5. Language Patterns: Are there manipulation or social engineering tactics?

SCAM INDICATORS (Indian context):
- Fake RBI/Bank/Government officials
- UPI/OTP/PIN requests
- Lottery/Prize claims
- Work-from-home job scams
- Investment doubling schemes
- KYC expiry threats

RESPOND IN JSON FORMAT with these exact fields:
{
    "chain_of_thought": "Your step-by-step reasoning (2-3 sentences)",
    "is_scam": true/false,
    "confidence": 0.0-1.0,
    "scam_type": "bank_fraud|upi_fraud|phishing|lottery_scam|job_scam|impersonation|tech_support|romance_scam|investment_scam|unknown" or null,
    "risk_level": "low|medium|high|critical",
    "recommended_action": "pass|monitor|engage|block|alert_human"
}

CONFIDENCE GUIDE:
- 0.9-1.0: Definite scam, clear patterns
- 0.7-0.9: Very likely scam
- 0.5-0.7: Suspicious, needs monitoring
- 0.3-0.5: Possibly suspicious
- 0.0-0.3: Likely benign

RECOMMENDED ACTIONS:
- pass: Benign message
- monitor: Suspicious but not confirmed
- engage: Confirmed scam, engage honeypot
- block: Dangerous, block immediately
- alert_human: Complex case needing human review"""

    def __init__(self):
        """Initialize orchestrator with LLM clients and compiled patterns."""
        self.llm_provider = config.LLM_PROVIDER
        self.openai_client = None
        self.gemini_client = None
        
        # Initialize LLM clients
        if self.llm_provider == "openai" and config.OPENAI_API_KEY:
            try:
                self.openai_client = OpenAI(api_key=config.OPENAI_API_KEY)
                logger.info("Orchestrator: OpenAI client initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize OpenAI: {e}")
        elif self.llm_provider == "gemini" and config.GOOGLE_API_KEY and genai:
            try:
                self.gemini_client = genai.Client(api_key=config.GOOGLE_API_KEY)
                logger.info("Orchestrator: Gemini client initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Gemini: {e}")
        
        # Compile regex patterns
        self._compiled_patterns: dict[str, list[re.Pattern]] = {}
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
    
    async def analyze(
        self,
        text: str,
        conversation_history: Optional[list[Message]] = None,
    ) -> ScamAnalysisResponse:
        """
        Perform two-level scam analysis.
        
        Args:
            text: Message text to analyze
            conversation_history: Previous messages for context
            
        Returns:
            Structured ScamAnalysisResponse with reasoning
        """
        if conversation_history is None:
            conversation_history = []
        
        # Level 1: Fast regex-based analysis with normalization
        level1_result = self._level1_regex_analysis(text, conversation_history)
        
        logger.info(
            f"L1 Analysis: confidence={level1_result.confidence:.2f}, "
            f"type={level1_result.scam_type}, "
            f"patterns={len(level1_result.matched_patterns)}"
        )
        
        # Fast path: High confidence scam
        if level1_result.confidence >= self.HIGH_CONFIDENCE_THRESHOLD:
            return self._create_response_from_level1(level1_result, "level1_high_confidence")
        
        # Fast path: Low confidence (benign)
        if level1_result.confidence < self.LOW_CONFIDENCE_THRESHOLD:
            return self._create_response_from_level1(level1_result, "level1_low_confidence")
        
        # Level 2: LLM analysis for ambiguous cases
        if level1_result.confidence >= self.LLM_TRIGGER_THRESHOLD:
            if self._has_llm_client():
                try:
                    return await self._level2_llm_analysis(
                        text, conversation_history, level1_result
                    )
                except Exception as e:
                    logger.error(f"L2 LLM analysis failed: {e}")
                    # Fall back to L1 result
        
        # Default: Use Level 1 result
        return self._create_response_from_level1(level1_result, "level1_default")
    
    def _level1_regex_analysis(
        self,
        text: str,
        conversation_history: list[Message],
    ) -> Level1Result:
        """
        Level 1: Fast regex-based analysis with text normalization.
        """
        # Normalize text to defeat evasion tactics
        normalized_text = text_normalizer.normalize(text)
        evasion_score = text_normalizer.get_evasion_score(text, normalized_text)
        
        # Build full context
        full_text = normalized_text
        for msg in conversation_history:
            if msg.sender == "scammer":
                full_text += " " + text_normalizer.normalize(msg.text)
        
        matched_patterns = []
        scam_scores: dict[str, float] = {}
        
        # Check each scam type
        for scam_type, patterns in self._compiled_patterns.items():
            score = 0.0
            for pattern in patterns:
                if pattern.search(normalized_text):
                    score += 1.0
                    matched_patterns.append(f"{scam_type}:{pattern.pattern}")
                elif pattern.search(full_text):
                    score += 0.5
            scam_scores[scam_type] = score
        
        # Check urgency indicators
        urgency_score = 0.0
        for pattern in self._urgency_patterns:
            if pattern.search(normalized_text):
                urgency_score += 1.0
                matched_patterns.append(f"urgency:{pattern.pattern}")
        urgency_normalized = min(urgency_score / 3.0, 1.0)
        
        # Check financial requests
        financial_score = 0.0
        for pattern in self._financial_patterns:
            if pattern.search(normalized_text):
                financial_score += 1.0
                matched_patterns.append(f"financial:{pattern.pattern}")
        financial_normalized = min(financial_score / 2.0, 1.0)
        
        # Calculate overall confidence
        max_scam_type = max(scam_scores, key=scam_scores.get) if scam_scores else None
        max_scam_score = scam_scores.get(max_scam_type, 0) if max_scam_type else 0
        
        # Confidence formula (tuned for better detection)
        base_confidence = min(max_scam_score * 0.3, 0.6)
        urgency_bonus = urgency_normalized * 0.2
        financial_bonus = financial_normalized * 0.2
        evasion_bonus = evasion_score * 0.1  # Evasion attempts increase suspicion
        
        total_confidence = base_confidence + urgency_bonus + financial_bonus + evasion_bonus
        total_confidence = min(total_confidence, 1.0)
        
        return Level1Result(
            confidence=round(total_confidence, 3),
            scam_type=ScamType(max_scam_type) if max_scam_type and max_scam_score > 0 else None,
            matched_patterns=matched_patterns,
            urgency_score=urgency_normalized,
            financial_risk_score=financial_normalized,
            normalized_text=normalized_text,
        )
    
    async def _level2_llm_analysis(
        self,
        text: str,
        conversation_history: list[Message],
        level1_result: Level1Result,
    ) -> ScamAnalysisResponse:
        """
        Level 2: LLM-based deep semantic analysis with Chain-of-Thought.
        """
        # Build context for LLM
        context = self._build_llm_context(text, conversation_history, level1_result)
        
        logger.info("L2 LLM analysis triggered")
        
        try:
            if self.llm_provider == "openai" and self.openai_client:
                response_json = await self._call_openai(context)
            elif self.llm_provider == "gemini" and self.gemini_client:
                response_json = await self._call_gemini(context)
            else:
                raise ValueError("No LLM client available")
            
            # Parse and validate response
            return self._parse_llm_response(response_json, level1_result)
            
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            # Return enhanced L1 result on failure
            return self._create_response_from_level1(level1_result, "level1_fallback")
    
    def _build_llm_context(
        self,
        text: str,
        history: list[Message],
        level1_result: Level1Result,
    ) -> str:
        """Build context string for LLM analysis."""
        context_parts = [
            "ANALYZE THIS MESSAGE FOR SCAM INDICATORS:",
            f"\nMessage: \"{text}\"",
            f"\nNormalized (anti-evasion): \"{level1_result.normalized_text}\"",
        ]
        
        if level1_result.matched_patterns:
            context_parts.append(
                f"\nLevel 1 patterns detected: {', '.join(level1_result.matched_patterns[:10])}"
            )
        
        context_parts.append(f"\nLevel 1 confidence: {level1_result.confidence:.2f}")
        
        if history:
            context_parts.append("\nConversation history:")
            for msg in history[-5:]:
                context_parts.append(f"  [{msg.sender}]: {msg.text[:100]}")
        
        context_parts.append("\nProvide your analysis in JSON format:")
        
        return "\n".join(context_parts)
    
    async def _call_openai(self, context: str) -> str:
        """Call OpenAI API for analysis."""
        response = self.openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": self.LLM_SYSTEM_PROMPT},
                {"role": "user", "content": context},
            ],
            max_tokens=300,
            temperature=0.3,  # Lower temp for more consistent analysis
        )
        return response.choices[0].message.content
    
    async def _call_gemini(self, context: str) -> str:
        """Call Gemini API for analysis."""
        prompt = f"{self.LLM_SYSTEM_PROMPT}\n\n{context}"
        response = self.gemini_client.models.generate_content(
            model="gemini-1.5-flash",
            contents=prompt,
        )
        return response.text
    
    def _parse_llm_response(
        self,
        response_text: str,
        level1_result: Level1Result,
    ) -> ScamAnalysisResponse:
        """Parse and validate LLM JSON response."""
        try:
            # Extract JSON from response (handle markdown code blocks)
            json_text = response_text
            if "```json" in json_text:
                json_text = json_text.split("```json")[1].split("```")[0]
            elif "```" in json_text:
                json_text = json_text.split("```")[1].split("```")[0]
            
            data = json.loads(json_text.strip())
            
            # Validate and extract fields
            scam_type = None
            if data.get("scam_type"):
                try:
                    scam_type = ScamType(data["scam_type"])
                except ValueError:
                    scam_type = ScamType.UNKNOWN
            
            return ScamAnalysisResponse(
                chain_of_thought=data.get("chain_of_thought", "LLM analysis completed"),
                is_scam=data.get("is_scam", level1_result.confidence > 0.5),
                confidence=float(data.get("confidence", level1_result.confidence)),
                scam_type=scam_type,
                risk_level=RiskLevel(data.get("risk_level", "medium")),
                recommended_action=RecommendedAction(data.get("recommended_action", "monitor")),
                extracted_entities=ExtractedEntities(),
                analysis_source="level2_llm",
                matched_patterns=level1_result.matched_patterns,
            )
            
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            # Return L1 result on parse failure
            return self._create_response_from_level1(level1_result, "level1_parse_failure")
    
    def _create_response_from_level1(
        self,
        level1_result: Level1Result,
        source: str,
    ) -> ScamAnalysisResponse:
        """Create ScamAnalysisResponse from Level 1 result."""
        is_scam = level1_result.confidence >= 0.3
        
        # Determine risk level
        if level1_result.confidence >= 0.8:
            risk_level = RiskLevel.CRITICAL
        elif level1_result.confidence >= 0.6:
            risk_level = RiskLevel.HIGH
        elif level1_result.confidence >= 0.4:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        # Determine recommended action
        if level1_result.confidence >= 0.8:
            action = RecommendedAction.ENGAGE
        elif level1_result.confidence >= 0.5:
            action = RecommendedAction.MONITOR
        elif level1_result.confidence >= 0.3:
            action = RecommendedAction.MONITOR
        else:
            action = RecommendedAction.PASS
        
        # Build chain of thought
        cot_parts = []
        if level1_result.matched_patterns:
            cot_parts.append(f"Matched {len(level1_result.matched_patterns)} patterns")
        if level1_result.urgency_score > 0:
            cot_parts.append(f"urgency={level1_result.urgency_score:.1f}")
        if level1_result.financial_risk_score > 0:
            cot_parts.append(f"financial_risk={level1_result.financial_risk_score:.1f}")
        
        chain_of_thought = f"L1 regex analysis: {', '.join(cot_parts) or 'no significant indicators'}. Confidence: {level1_result.confidence:.2f}"
        
        return ScamAnalysisResponse(
            chain_of_thought=chain_of_thought,
            is_scam=is_scam,
            confidence=level1_result.confidence,
            scam_type=level1_result.scam_type,
            risk_level=risk_level,
            recommended_action=action,
            extracted_entities=ExtractedEntities(),
            analysis_source=source,
            matched_patterns=level1_result.matched_patterns,
        )
    
    def _has_llm_client(self) -> bool:
        """Check if any LLM client is available."""
        return bool(self.openai_client or self.gemini_client)


# Global instance
scam_orchestrator = AdvancedScamOrchestrator()
