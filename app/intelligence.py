"""Intelligence extraction from scam conversations."""

import re
import json
import logging
from dataclasses import dataclass, field
from typing import Optional

from openai import OpenAI
try:
    from google import genai
except ImportError:
    genai = None

from app.models import Message, ExtractedIntelligence
from app.config import config

logger = logging.getLogger(__name__)


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


class LLMIntelExtractor:
    """
    LLM-powered intelligence extractor for catching what regex misses.
    Uses the LLM to analyze conversation and extract all actionable intel.
    """
    
    EXTRACTION_PROMPT = """You are an intelligence analyst. Analyze this scam conversation and extract ALL actionable information the scammer revealed.

CONVERSATION:
{conversation}

Extract the following information that the SCAMMER mentioned (not the victim):
1. Phone numbers (any format: +91-xxx, with spaces, etc.)
2. Bank account numbers (any length)
3. UPI IDs (like xxx@upi, xxx@paytm, etc.)
4. Email addresses
5. Names or designations the scammer claimed
6. Bank names or branch names mentioned
7. Any URLs or links

Return ONLY a JSON object in this exact format:
{{
    "phoneNumbers": ["list of phone numbers found"],
    "bankAccounts": ["list of account numbers found"],
    "upiIds": ["list of UPI IDs found"],
    "emails": ["list of emails found"],
    "names": ["names the scammer claimed"],
    "bankNames": ["bank names mentioned"],
    "links": ["any URLs found"]
}}

IMPORTANT: 
- Extract ONLY what the scammer revealed, not what the victim said
- Include ALL variations (e.g., if they said "98765 43210", include it as "9876543210")
- If nothing found for a category, use empty list []
- Return ONLY the JSON, no explanation"""

    def __init__(self):
        """Initialize LLM clients."""
        self.openai_client = None
        self.gemini_client = None
        
        if config.LLM_PROVIDER == "openai" and config.OPENAI_API_KEY:
            try:
                self.openai_client = OpenAI(api_key=config.OPENAI_API_KEY)
            except Exception as e:
                logger.warning(f"Failed to init OpenAI for intel: {e}")
        elif config.LLM_PROVIDER == "gemini" and config.GOOGLE_API_KEY and genai:
            try:
                self.gemini_client = genai.Client(api_key=config.GOOGLE_API_KEY)
            except Exception as e:
                logger.warning(f"Failed to init Gemini for intel: {e}")
    
    async def extract_with_llm(self, messages: list[Message]) -> dict:
        """
        Use LLM to extract intelligence from conversation.
        Returns dict with all extracted intel.
        """
        if not self.openai_client and not self.gemini_client:
            logger.info("No LLM available for intel extraction")
            return {}
        
        # Build conversation text (only scammer messages for focus)
        conversation_text = "\n".join([
            f"{'SCAMMER' if msg.sender != 'agent' else 'VICTIM'}: {msg.text}"
            for msg in messages
        ])
        
        prompt = self.EXTRACTION_PROMPT.format(conversation=conversation_text)
        
        try:
            if self.openai_client:
                response = self.openai_client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=500,
                    temperature=0.1,  # Low temp for accuracy
                )
                result_text = response.choices[0].message.content
            elif self.gemini_client:
                response = self.gemini_client.models.generate_content(
                    model='gemini-1.5-flash',
                    contents=prompt
                )
                result_text = response.text
            else:
                return {}
            
            # Parse JSON response
            # Clean up potential markdown code blocks
            result_text = result_text.strip()
            if result_text.startswith("```"):
                result_text = result_text.split("```")[1]
                if result_text.startswith("json"):
                    result_text = result_text[4:]
            
            return json.loads(result_text)
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM intel response: {e}")
            return {}
        except Exception as e:
            logger.error(f"LLM intel extraction failed: {e}")
            return {}
    
    def merge_with_regex(
        self, 
        regex_intel: ExtractedIntelligence, 
        llm_intel: dict
    ) -> ExtractedIntelligence:
        """Merge LLM-extracted intel with regex-extracted intel."""
        # Add LLM findings to existing regex findings
        if llm_intel.get("phoneNumbers"):
            for phone in llm_intel["phoneNumbers"]:
                clean_phone = re.sub(r"[\s-]", "", phone)
                if clean_phone not in " ".join(regex_intel.phoneNumbers):
                    regex_intel.phoneNumbers.append(phone)
        
        if llm_intel.get("bankAccounts"):
            for acc in llm_intel["bankAccounts"]:
                if acc not in regex_intel.bankAccounts:
                    regex_intel.bankAccounts.append(acc)
        
        if llm_intel.get("upiIds"):
            for upi in llm_intel["upiIds"]:
                if upi.lower() not in [u.lower() for u in regex_intel.upiIds]:
                    regex_intel.upiIds.append(upi)
        
        if llm_intel.get("emails"):
            for email in llm_intel["emails"]:
                if email.lower() not in [u.lower() for u in regex_intel.upiIds]:
                    regex_intel.upiIds.append(email)
        
        if llm_intel.get("links"):
            for link in llm_intel["links"]:
                if link not in regex_intel.phishingLinks:
                    regex_intel.phishingLinks.append(link)
        
        return regex_intel


# Global LLM extractor instance
llm_intel_extractor = LLMIntelExtractor()
