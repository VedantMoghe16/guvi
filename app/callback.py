"""GUVI callback handler for reporting final results."""

import httpx
import logging
from typing import Optional

from app.config import config
from app.models import ExtractedIntelligence, Message
from app.session_manager import SessionData
from app.intelligence import intelligence_extractor

logger = logging.getLogger(__name__)


async def send_final_result(
    session_data: SessionData,
    conversation_history: list[Message],
) -> bool:
    """
    Send final extracted intelligence to GUVI evaluation endpoint.
    
    Args:
        session_data: Session tracking data
        conversation_history: Full conversation history
        
    Returns:
        True if callback was successful
    """
    try:
        # Extract intelligence from conversation
        intelligence = intelligence_extractor.extract(conversation_history)
        
        # Build payload
        payload = {
            "sessionId": session_data.session_id,
            "scamDetected": session_data.scam_detected,
            "totalMessagesExchanged": session_data.message_count,
            "extractedIntelligence": {
                "bankAccounts": intelligence.bankAccounts,
                "upiIds": intelligence.upiIds,
                "phishingLinks": intelligence.phishingLinks,
                "phoneNumbers": intelligence.phoneNumbers,
                "suspiciousKeywords": intelligence.suspiciousKeywords,
            },
            "agentNotes": _generate_agent_notes(session_data, intelligence),
        }
        
        logger.info(f"Sending GUVI callback for session {session_data.session_id}")
        logger.debug(f"Payload: {payload}")
        
        # Send to GUVI endpoint
        async with httpx.AsyncClient() as client:
            response = await client.post(
                config.GUVI_CALLBACK_URL,
                json=payload,
                timeout=10.0,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                logger.info(f"GUVI callback successful for session {session_data.session_id}")
                return True
            else:
                logger.error(
                    f"GUVI callback failed: {response.status_code} - {response.text}"
                )
                return False
                
    except httpx.TimeoutException:
        logger.error(f"GUVI callback timeout for session {session_data.session_id}")
        return False
    except Exception as e:
        logger.error(f"GUVI callback error: {e}")
        return False


def _generate_agent_notes(
    session_data: SessionData, 
    intelligence: ExtractedIntelligence
) -> str:
    """Generate a summary of scammer behavior for agent notes."""
    notes = []
    
    # Add scam type
    if session_data.scam_type:
        scam_type_readable = session_data.scam_type.replace("_", " ").title()
        notes.append(f"Scam type identified: {scam_type_readable}")
    
    # Add behavioral observations
    if session_data.message_count >= 5:
        notes.append("Scammer engaged in extended conversation")
    
    if session_data.scam_confidence >= 0.7:
        notes.append("High confidence scam indicators detected")
    
    # Summarize tactics used
    tactics = []
    if any(kw in ["urgent", "immediately", "today"] for kw in intelligence.suspiciousKeywords):
        tactics.append("urgency tactics")
    if any(kw in ["blocked", "suspended", "freeze"] for kw in intelligence.suspiciousKeywords):
        tactics.append("account threats")
    if intelligence.upiIds or "upi" in " ".join(intelligence.suspiciousKeywords):
        tactics.append("payment redirection")
    if intelligence.phishingLinks:
        tactics.append("phishing links")
    
    if tactics:
        notes.append(f"Tactics used: {', '.join(tactics)}")
    
    # Add session notes
    if session_data.agent_notes:
        notes.extend(session_data.agent_notes[:3])  # Limit to 3 notes
    
    return "; ".join(notes) if notes else "Scammer used typical fraud tactics"
