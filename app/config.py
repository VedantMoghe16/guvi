"""Configuration management for the honeypot system."""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Application configuration loaded from environment variables."""
    
    # API Authentication
    API_KEY: str = os.getenv("API_KEY", "default-api-key")
    
    # LLM Provider Configuration
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "openai")  # openai or gemini
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    GOOGLE_API_KEY: str = os.getenv("GOOGLE_API_KEY", "")
    
    # GUVI Callback
    GUVI_CALLBACK_URL: str = os.getenv(
        "GUVI_CALLBACK_URL", 
        "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    )
    
    # Session Configuration
    MIN_MESSAGES_FOR_CALLBACK: int = int(os.getenv("MIN_MESSAGES_FOR_CALLBACK", "5"))
    
    @classmethod
    def validate(cls) -> bool:
        """Validate that required configuration is present."""
        if cls.LLM_PROVIDER == "openai" and not cls.OPENAI_API_KEY:
            return False
        if cls.LLM_PROVIDER == "gemini" and not cls.GOOGLE_API_KEY:
            return False
        return True


config = Config()
