"""Pydantic models for request/response validation."""

from datetime import datetime
from typing import Optional, Union
from pydantic import BaseModel, Field, field_validator


class Message(BaseModel):
    """Individual message in a conversation."""
    sender: str = Field(..., description="Either 'scammer' or 'user'")
    text: str = Field(..., description="Message content")
    timestamp: str = Field(..., description="ISO-8601 timestamp or Unix timestamp")
    
    @field_validator('timestamp', mode='before')
    @classmethod
    def convert_timestamp_to_string(cls, v):
        """Convert integer timestamps to string format."""
        if isinstance(v, int):
            return str(v)
        return v


class Metadata(BaseModel):
    """Optional metadata about the conversation context."""
    channel: Optional[str] = Field(None, description="SMS, WhatsApp, Email, or Chat")
    language: Optional[str] = Field("English", description="Language used")
    locale: Optional[str] = Field("IN", description="Country or region")


class MessageRequest(BaseModel):
    """Incoming API request format."""
    sessionId: str = Field(..., description="Unique session identifier")
    message: Message = Field(..., description="Current message")
    conversationHistory: list[Message] = Field(
        default_factory=list, 
        description="Previous messages in conversation"
    )
    metadata: Optional[Metadata] = Field(None, description="Optional context metadata")


class MessageResponse(BaseModel):
    """API response format."""
    status: str = Field(..., description="Response status: success or error")
    reply: str = Field(..., description="Agent's reply message")


class ExtractedIntelligence(BaseModel):
    """Extracted scam-related intelligence."""
    bankAccounts: list[str] = Field(default_factory=list)
    upiIds: list[str] = Field(default_factory=list)
    phishingLinks: list[str] = Field(default_factory=list)
    phoneNumbers: list[str] = Field(default_factory=list)
    suspiciousKeywords: list[str] = Field(default_factory=list)


class GUVICallbackPayload(BaseModel):
    """Payload format for GUVI evaluation callback."""
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: dict
    agentNotes: str
