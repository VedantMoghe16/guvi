"""Session management for tracking conversation state."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from threading import RLock


@dataclass
class SessionData:
    """Data stored for each conversation session."""
    session_id: str
    scam_detected: bool = False
    scam_type: Optional[str] = None
    scam_confidence: float = 0.0
    message_count: int = 0
    agent_responses: list[str] = field(default_factory=list)
    scammer_messages: list[str] = field(default_factory=list)
    trust_level: int = 0  # 0-5 scale, how much "trust" agent shows
    callback_sent: bool = False
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    agent_notes: list[str] = field(default_factory=list)


class SessionManager:
    """Thread-safe in-memory session storage."""
    
    def __init__(self):
        """Initialize the session manager."""
        self._sessions: dict[str, SessionData] = {}
        self._lock = RLock()
    
    def get_session(self, session_id: str) -> SessionData:
        """
        Get or create a session.
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            SessionData for the session
        """
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = SessionData(session_id=session_id)
            return self._sessions[session_id]
    
    def update_session(
        self,
        session_id: str,
        scam_detected: Optional[bool] = None,
        scam_type: Optional[str] = None,
        scam_confidence: Optional[float] = None,
        agent_response: Optional[str] = None,
        scammer_message: Optional[str] = None,
        increment_trust: bool = False,
        agent_note: Optional[str] = None,
    ) -> SessionData:
        """
        Update session data.
        
        Args:
            session_id: Session to update
            scam_detected: Whether scam was detected
            scam_type: Type of scam detected
            scam_confidence: Confidence score
            agent_response: Agent's latest response
            scammer_message: Scammer's latest message
            increment_trust: Whether to increase trust level
            agent_note: Note about scammer behavior
            
        Returns:
            Updated SessionData
        """
        with self._lock:
            session = self.get_session(session_id)
            
            if scam_detected is not None:
                session.scam_detected = scam_detected
            
            if scam_type is not None:
                session.scam_type = scam_type
            
            if scam_confidence is not None:
                session.scam_confidence = max(session.scam_confidence, scam_confidence)
            
            if agent_response:
                session.agent_responses.append(agent_response)
                session.message_count += 1
            
            if scammer_message:
                session.scammer_messages.append(scammer_message)
                session.message_count += 1
            
            if increment_trust and session.trust_level < 5:
                session.trust_level += 1
            
            if agent_note:
                session.agent_notes.append(agent_note)
            
            session.last_updated = datetime.now()
            return session
    
    def mark_callback_sent(self, session_id: str) -> None:
        """Mark that GUVI callback was sent for this session."""
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].callback_sent = True
    
    def should_send_callback(self, session_id: str, min_messages: int = 5) -> bool:
        """
        Check if we should send the GUVI callback.
        
        Args:
            session_id: Session to check
            min_messages: Minimum messages before callback
            
        Returns:
            True if callback should be sent
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False
            
            return (
                session.scam_detected 
                and session.message_count >= min_messages 
                and not session.callback_sent
            )
    
    def get_session_summary(self, session_id: str) -> str:
        """Generate a summary of scammer behavior for agent notes."""
        session = self.get_session(session_id)
        
        notes = []
        if session.scam_type:
            notes.append(f"Scam type: {session.scam_type}")
        
        if session.agent_notes:
            notes.extend(session.agent_notes)
        
        # Add behavioral observations
        if session.message_count >= 3:
            notes.append("Scammer engaged in multi-turn conversation")
        
        if session.scam_confidence >= 0.7:
            notes.append("High confidence in scam intent")
        
        return "; ".join(notes) if notes else "Scammer used typical fraud tactics"


# Global instance
session_manager = SessionManager()
