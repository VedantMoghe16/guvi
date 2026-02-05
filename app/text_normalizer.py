"""Text normalization engine for scam detection.

Handles common scammer evasion tactics:
- Leet-speak: 0TP -> OTP, b4nk -> bank
- Unicode homoglyphs: Cyrillic 'а' -> Latin 'a'
- Creative spacing: O T P -> OTP
- Common typos and variations
"""

import re
import unicodedata
from functools import lru_cache


class TextNormalizer:
    """Normalizes text to defeat scammer evasion tactics."""
    
    # Leet-speak substitutions
    LEET_MAP: dict[str, str] = {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "9": "g",
        "@": "a",
        "$": "s",
        "!": "i",
        "|": "l",
        "+": "t",
        "€": "e",
        "£": "e",
    }
    
    # Unicode homoglyphs (Cyrillic and look-alikes)
    HOMOGLYPHS: dict[str, str] = {
        "а": "a",  # Cyrillic
        "е": "e",  # Cyrillic
        "о": "o",  # Cyrillic
        "р": "p",  # Cyrillic
        "с": "c",  # Cyrillic
        "у": "y",  # Cyrillic
        "х": "x",  # Cyrillic
        "і": "i",  # Ukrainian
        "ѕ": "s",  # Cyrillic
        "ј": "j",  # Cyrillic
        "ԁ": "d",  # Cyrillic
        "ɑ": "a",  # Latin alpha
        "ɡ": "g",  # Latin small g
        "ℓ": "l",  # Script small l
        "ɪ": "i",  # Small capital I
        "ο": "o",  # Greek omicron
        "ρ": "p",  # Greek rho
        "ν": "v",  # Greek nu
        "κ": "k",  # Greek kappa
        "Α": "A",  # Greek Alpha
        "Β": "B",  # Greek Beta
        "Ε": "E",  # Greek Epsilon
        "Ζ": "Z",  # Greek Zeta
        "Η": "H",  # Greek Eta
        "Ι": "I",  # Greek Iota
        "Κ": "K",  # Greek Kappa
        "Μ": "M",  # Greek Mu
        "Ν": "N",  # Greek Nu
        "Ο": "O",  # Greek Omicron
        "Ρ": "P",  # Greek Rho
        "Τ": "T",  # Greek Tau
        "Υ": "Y",  # Greek Upsilon
        "Χ": "X",  # Greek Chi
    }
    
    # Common scam-specific typo patterns
    TYPO_PATTERNS: list[tuple[str, str]] = [
        (r"\b0tp\b", "otp"),
        (r"\bp!n\b", "pin"),
        (r"\bc4rd\b", "card"),
        (r"\bb4nk\b", "bank"),
        (r"\b4cc[o0]unt\b", "account"),
        (r"\bv[3e]r[1i]fy\b", "verify"),
        (r"\bur[g9][3e]nt\b", "urgent"),
        (r"\bp4ym[3e]nt\b", "payment"),
        (r"\btr4nsf[3e]r\b", "transfer"),
        (r"\bbl[o0]ck\b", "block"),
        (r"\bsusp[3e]nd\b", "suspend"),
        (r"\bcl[1i]ck\b", "click"),
        (r"\bl[1i]nk\b", "link"),
        (r"\bw[o0]n\b", "won"),
        (r"\bpr[1i]z[3e]\b", "prize"),
    ]
    
    def __init__(self):
        """Initialize normalizer with compiled patterns."""
        self._compiled_typos = [
            (re.compile(pattern, re.IGNORECASE), replacement)
            for pattern, replacement in self.TYPO_PATTERNS
        ]
    
    @lru_cache(maxsize=1024)
    def normalize(self, text: str) -> str:
        """
        Apply all normalization techniques to input text.
        
        Args:
            text: Raw input text
            
        Returns:
            Normalized text with evasion tactics defeated
        """
        if not text:
            return text
        
        result = text
        
        # Step 1: Remove invisible characters and normalize unicode
        result = self._normalize_unicode(result)
        
        # Step 2: Replace homoglyphs
        result = self._replace_homoglyphs(result)
        
        # Step 3: Replace leet-speak
        result = self._replace_leet_speak(result)
        
        # Step 4: Remove creative spacing (O T P -> OTP)
        result = self._remove_creative_spacing(result)
        
        # Step 5: Apply typo patterns
        result = self._apply_typo_patterns(result)
        
        # Step 6: Normalize whitespace
        result = " ".join(result.split())
        
        return result
    
    def _normalize_unicode(self, text: str) -> str:
        """Normalize Unicode and remove invisible characters."""
        # Normalize to NFKC form
        normalized = unicodedata.normalize("NFKC", text)
        
        # Remove zero-width and invisible characters
        invisible_chars = [
            "\u200b",  # Zero-width space
            "\u200c",  # Zero-width non-joiner
            "\u200d",  # Zero-width joiner
            "\u2060",  # Word joiner
            "\ufeff",  # Zero-width no-break space
            "\u00ad",  # Soft hyphen
        ]
        for char in invisible_chars:
            normalized = normalized.replace(char, "")
        
        return normalized
    
    def _replace_homoglyphs(self, text: str) -> str:
        """Replace Unicode homoglyphs with ASCII equivalents."""
        result = []
        for char in text:
            result.append(self.HOMOGLYPHS.get(char, char))
        return "".join(result)
    
    def _replace_leet_speak(self, text: str) -> str:
        """Replace leet-speak characters with letters."""
        result = []
        for char in text:
            result.append(self.LEET_MAP.get(char, char))
        return "".join(result)
    
    def _remove_creative_spacing(self, text: str) -> str:
        """
        Remove creative spacing used to evade detection.
        
        Examples:
            "O T P" -> "OTP"
            "U P I" -> "UPI"
            "B A N K" -> "BANK"
        """
        # Pattern: single letters separated by spaces (3+ letters)
        pattern = r"\b([A-Za-z])\s+([A-Za-z])\s+([A-Za-z])\b"
        
        def rejoin(match):
            return match.group(1) + match.group(2) + match.group(3)
        
        result = text
        # Apply multiple times to catch longer sequences
        for _ in range(3):
            new_result = re.sub(pattern, rejoin, result)
            if new_result == result:
                break
            result = new_result
        
        # Also handle 2-letter pairs that form known keywords
        two_letter_keywords = [
            (r"\bO\s*T\s*P\b", "OTP"),
            (r"\bU\s*P\s*I\b", "UPI"),
            (r"\bP\s*I\s*N\b", "PIN"),
            (r"\bC\s*V\s*V\b", "CVV"),
            (r"\bK\s*Y\s*C\b", "KYC"),
            (r"\bR\s*B\s*I\b", "RBI"),
            (r"\bS\s*M\s*S\b", "SMS"),
        ]
        
        for pattern, replacement in two_letter_keywords:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
        
        return result
    
    def _apply_typo_patterns(self, text: str) -> str:
        """Apply known typo pattern corrections."""
        result = text
        for pattern, replacement in self._compiled_typos:
            result = pattern.sub(replacement, result)
        return result
    
    def get_evasion_score(self, original: str, normalized: str) -> float:
        """
        Calculate how much evasion was attempted.
        
        Higher score = more manipulation detected.
        """
        if not original or not normalized:
            return 0.0
        
        # Calculate edit distance ratio
        original_lower = original.lower()
        normalized_lower = normalized.lower()
        
        if original_lower == normalized_lower:
            return 0.0
        
        # Count character differences
        diff_count = sum(
            1 for a, b in zip(original_lower, normalized_lower) if a != b
        )
        diff_count += abs(len(original_lower) - len(normalized_lower))
        
        # Calculate ratio
        max_len = max(len(original), len(normalized), 1)
        evasion_score = min(diff_count / max_len, 1.0)
        
        return round(evasion_score, 3)


# Global instance for convenience
text_normalizer = TextNormalizer()
