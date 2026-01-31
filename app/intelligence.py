"""Intelligence extraction from scam conversations."""

import re
from dataclasses import dataclass, field

from app.models import Message, ExtractedIntelligence


class IntelligenceExtractor:
    """Extracts actionable intelligence from scam conversations."""
    
    # Regex patterns for different intelligence types
    PATTERNS = {
        "bank_accounts": [
            r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",  # 16-digit card
            r"\b\d{9,18}\b",  # Account numbers
        ],
        "upi_ids": [
            r"\b[\w.+-]+@(?:upi|paytm|ybl|oksbi|okicici|okaxis|okhdfcbank|apl|ibl|axl|sbi|pnb|kotak)\b",
            r"\b[\w.+-]+@[\w]+bank\b",
        ],
        "phone_numbers": [
            r"(?:\+91[-\s]?)?[6-9]\d{9}\b",  # Indian mobile
            r"(?:\+\d{1,3}[-\s]?)?\d{10,12}\b",  # International
        ],
        "phishing_links": [
            r"https?://[^\s<>\"']+",
            r"(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|short\.link)[/\w.?=-]*",
        ],
    }
    
    # Suspicious keywords to extract
    SUSPICIOUS_KEYWORDS = [
        "urgent", "immediately", "verify", "blocked", "suspended",
        "kyc", "expired", "update", "confirm", "otp", "pin", "cvv",
        "account", "transfer", "refund", "claim", "prize", "winner",
        "limited time", "act now", "avoid", "penalty", "legal action",
        "freeze", "unauthorized", "suspicious", "security alert"
    ]
    
    def __init__(self):
        """Initialize with compiled patterns."""
        self._compiled = {}
        for intel_type, patterns in self.PATTERNS.items():
            self._compiled[intel_type] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]
    
    def extract(self, messages: list[Message]) -> ExtractedIntelligence:
        """
        Extract all intelligence from conversation messages.
        
        Args:
            messages: List of conversation messages
            
        Returns:
            ExtractedIntelligence with all found data
        """
        # Combine all message text
        all_text = " ".join(msg.text for msg in messages)
        
        # Extract each type
        bank_accounts = self._extract_pattern("bank_accounts", all_text)
        upi_ids = self._extract_pattern("upi_ids", all_text)
        phone_numbers = self._extract_pattern("phone_numbers", all_text)
        phishing_links = self._extract_pattern("phishing_links", all_text)
        
        # Filter out likely false positives
        phone_numbers = self._filter_phone_numbers(phone_numbers)
        phishing_links = self._filter_links(phishing_links)
        
        # Extract suspicious keywords
        keywords = self._extract_keywords(all_text)
        
        return ExtractedIntelligence(
            bankAccounts=list(set(bank_accounts)),
            upiIds=list(set(upi_ids)),
            phoneNumbers=list(set(phone_numbers)),
            phishingLinks=list(set(phishing_links)),
            suspiciousKeywords=list(set(keywords)),
        )
    
    def _extract_pattern(self, pattern_type: str, text: str) -> list[str]:
        """Extract matches for a specific pattern type."""
        matches = []
        for pattern in self._compiled.get(pattern_type, []):
            found = pattern.findall(text)
            matches.extend(found)
        return matches
    
    def _extract_keywords(self, text: str) -> list[str]:
        """Find suspicious keywords in text."""
        text_lower = text.lower()
        found = []
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in text_lower:
                found.append(keyword)
        return found
    
    def _filter_phone_numbers(self, numbers: list[str]) -> list[str]:
        """Filter out unlikely phone numbers."""
        filtered = []
        for num in numbers:
            # Clean the number
            clean = re.sub(r"[\s-]", "", num)
            # Keep only valid length numbers
            if 10 <= len(clean.replace("+", "")) <= 13:
                filtered.append(num)
        return filtered
    
    def _filter_links(self, links: list[str]) -> list[str]:
        """Filter and clean extracted links."""
        # Known legitimate domains to exclude
        safe_domains = [
            "google.com", "facebook.com", "twitter.com", 
            "linkedin.com", "github.com", "microsoft.com",
            "apple.com", "amazon.com"
        ]
        
        filtered = []
        for link in links:
            is_safe = any(domain in link.lower() for domain in safe_domains)
            if not is_safe:
                filtered.append(link)
        return filtered
    
    def extract_from_single_message(self, text: str) -> dict:
        """Quick extraction from a single message."""
        messages = [Message(sender="unknown", text=text, timestamp="")]
        result = self.extract(messages)
        return {
            "bankAccounts": result.bankAccounts,
            "upiIds": result.upiIds,
            "phoneNumbers": result.phoneNumbers,
            "phishingLinks": result.phishingLinks,
            "suspiciousKeywords": result.suspiciousKeywords,
        }


# Global instance
intelligence_extractor = IntelligenceExtractor()
