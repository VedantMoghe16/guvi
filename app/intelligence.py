"""Intelligence extraction from scam conversations."""

import re
from dataclasses import dataclass, field

from app.models import Message, ExtractedIntelligence


class IntelligenceExtractor:
    """Extracts actionable intelligence from scam conversations."""
    
    # Regex patterns for different intelligence types
    PATTERNS = {
        # Bank accounts - extract FIRST to avoid confusion with phones
        "bank_accounts": [
            r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",  # 16-digit card/account
            r"\b\d{14,18}\b",  # Long account numbers (14-18 digits)
            r"account\s*(?:number|no\.?|#)?\s*[:\s]?\s*(\d{9,18})",  # "account number: XXXXX"
        ],
        # UPI IDs
        "upi_ids": [
            r"\b[\w.+-]+@(?:upi|paytm|ybl|oksbi|okicici|okaxis|okhdfcbank|apl|ibl|axl|sbi|pnb|kotak|fakebank|fraudbank|scambank|scam)\b",
            r"\b[\w.+-]+@[\w]+bank\b",
        ],
        # Phone numbers - use explicit Indian format
        "phone_numbers": [
            r"\+91[-\s]?[1-9]\d{9}\b",  # +91-9876543210 or +91 9876543210
            r"\b(?:91[-\s]?)?[1-9]\d{9}\b",  # 91-9876543210 or just 9876543210
        ],
        # Phishing links
        "phishing_links": [
            r"https?://[^\s<>\"']+",
            r"(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|short\.link)[/\w.?=-]*",
        ],
        # Emails (NEW)
        "emails": [
            r"\b[\w.+-]+@[\w.-]+\.\w{2,}\b",  # standard email
            r"\b[\w.+-]+@[\w]+\b",  # short format like scammer@fakebank
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
        
        # Extract bank accounts FIRST (to exclude from phone matching)
        bank_accounts = self._extract_pattern("bank_accounts", all_text)
        bank_accounts = self._clean_bank_accounts(bank_accounts)
        
        # Extract phones, then filter out account number fragments
        phone_numbers = self._extract_pattern("phone_numbers", all_text)
        phone_numbers = self._filter_phone_numbers(phone_numbers, bank_accounts)
        
        # Extract other types
        upi_ids = self._extract_pattern("upi_ids", all_text)
        phishing_links = self._extract_pattern("phishing_links", all_text)
        emails = self._extract_pattern("emails", all_text)
        
        # Filter links
        phishing_links = self._filter_links(phishing_links)
        
        # Merge emails into UPI if they look like scam contact
        # (UPIs often look like emails, so combine for reporting)
        all_contact_ids = list(set(upi_ids + emails))
        
        # Extract suspicious keywords
        keywords = self._extract_keywords(all_text)
        
        return ExtractedIntelligence(
            bankAccounts=list(set(bank_accounts)),
            upiIds=list(set(all_contact_ids)),  # Combined UPI + emails
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
    
    def _filter_phone_numbers(self, numbers: list[str], bank_accounts: list[str]) -> list[str]:
        """
        Filter out unlikely phone numbers and exclude account number fragments.
        
        Args:
            numbers: Raw extracted phone numbers
            bank_accounts: Already extracted bank accounts (to exclude)
        """
        # Create set of account digit sequences for comparison
        account_digits = set()
        for acc in bank_accounts:
            clean_acc = re.sub(r"[\s-]", "", acc)
            account_digits.add(clean_acc)
            # Also add substrings that might match as phones
            if len(clean_acc) >= 10:
                for i in range(len(clean_acc) - 9):
                    account_digits.add(clean_acc[i:i+10])
        
        filtered = []
        for num in numbers:
            # Clean the number
            clean = re.sub(r"[\s+-]", "", num)
            
            # Skip if this is part of a bank account
            is_account_fragment = any(
                clean in acc or acc in clean 
                for acc in account_digits
            )
            if is_account_fragment:
                continue
            
            # Keep only valid Indian mobile numbers (10 digits, starting with 6-9)
            digits_only = re.sub(r"\D", "", clean)
            if len(digits_only) == 10 and digits_only[0] in "6789":
                filtered.append(num)
            elif len(digits_only) == 12 and digits_only[:2] == "91" and digits_only[2] in "6789":
                filtered.append(num)
        
        return filtered
    
    def _clean_bank_accounts(self, accounts: list[str]) -> list[str]:
        """Clean and validate extracted bank account numbers."""
        cleaned = []
        for acc in accounts:
            # Remove spaces and dashes
            clean = re.sub(r"[\s-]", "", acc)
            # Keep only if it looks like an account (9+ digits)
            if len(clean) >= 9 and clean.isdigit():
                cleaned.append(clean)
        return cleaned
    
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


class IntelWhitelist:
    """Whitelist for filtering out agent's own details."""
    
    # Fake persona details to ignore
    IGNORED_NUMBERS = ["9999999999", "8888888888", "1234567890"]
    IGNORED_UPI = ["shanti@upi", "test@upi"]
    IGNORED_ACCOUNTS = ["123456789", "000000000"]
    
    @classmethod
    def is_whitelisted(cls, value: str, intel_type: str) -> bool:
        """Check if a value is in the whitelist."""
        value = value.lower().strip()
        
        if intel_type == "phone_numbers":
            clean_num = re.sub(r"[\s+-]", "", value)
            return any(ignored in clean_num for ignored in cls.IGNORED_NUMBERS)
            
        elif intel_type == "upi_ids":
            return value in cls.IGNORED_UPI
            
        elif intel_type == "bank_accounts":
            clean_acc = re.sub(r"[\s-]", "", value)
            return any(ignored in clean_acc for ignored in cls.IGNORED_ACCOUNTS)
            
        return False


# Modify IntelligenceExtractor to use whitelist
# Note: In a real app, we'd inject this dependency.
# For now, we perform post-filtering in the extract method.
def _apply_whitelist(intel: ExtractedIntelligence) -> ExtractedIntelligence:
    """Filter extracted intelligence using whitelist."""
    intel.phoneNumbers = [
        n for n in intel.phoneNumbers 
        if not IntelWhitelist.is_whitelisted(n, "phone_numbers")
    ]
    intel.upiIds = [
        u for u in intel.upiIds 
        if not IntelWhitelist.is_whitelisted(u, "upi_ids")
    ]
    intel.bankAccounts = [
        b for b in intel.bankAccounts 
        if not IntelWhitelist.is_whitelisted(b, "bank_accounts")
    ]
    return intel


# Global instance
intelligence_extractor = IntelligenceExtractor()
# Monkey-patch extract method to apply whitelist automatically
_original_extract = intelligence_extractor.extract
def _extract_with_whitelist(messages: list[Message]) -> ExtractedIntelligence:
    result = _original_extract(messages)
    return _apply_whitelist(result)
intelligence_extractor.extract = _extract_with_whitelist
