"""FastAPI application for the Scam Detection Honeypot."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware

from app.auth import verify_api_key
from app.config import config
from app.models import MessageRequest, MessageResponse, Message
from app.scam_detector import scam_detector
from app.session_manager import session_manager
from app.agent import honeypot_agent
from app.intelligence import intelligence_extractor, llm_intel_extractor
from app.callback import send_final_result

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("Starting Scam Detection Honeypot API")
    logger.info(f"LLM Provider: {config.LLM_PROVIDER}")
    yield
    logger.info("Shutting down Scam Detection Honeypot API")


app = FastAPI(
    title="Scam Detection Honeypot API",
    description="AI-powered honeypot for detecting and engaging scammers",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware for external access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {
        "message": "Scam Detection Honeypot API is running",
        "docs": "/docs",
        "health": "/health"
    }

from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    print(f"!!! VALIDATION ERROR: {exc.errors()}")  # Direct print for visibility
    print(f"!!! REQUEST BODY: {exc.body}")
    logger.error(f"Validation error: {exc.errors()}")
    logger.error(f"Request body: {exc.body}")
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "body": str(exc.body)},
    )


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "llm_provider": config.LLM_PROVIDER,
    }


@app.post("/api/message", response_model=MessageResponse)
async def handle_message(
    request: MessageRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key),
):
    """
    Main endpoint for processing incoming messages.
    
    Flow:
    1. Detect scam intent
    2. If scam detected, activate AI Agent
    3. Generate response
    4. Extract intelligence
    5. Check if callback should be sent
    """
    try:
        session_id = request.sessionId
        current_message = request.message
        history = request.conversationHistory
        
        logger.info(f"Received message for session {session_id}")
        
        # Get or create session
        session = session_manager.get_session(session_id)
        
        # Update session with scammer message
        session_manager.update_session(
            session_id,
            scammer_message=current_message.text,
        )
        
        # Detect scam intent
        detection = scam_detector.detect(current_message.text, history)
        logger.info(
            f"Scam detection - is_scam: {detection.is_scam}, "
            f"confidence: {detection.confidence}, type: {detection.scam_type}"
        )
        
        # Update session with detection results
        if detection.is_scam:
            session_manager.update_session(
                session_id,
                scam_detected=True,
                scam_type=detection.scam_type,
                scam_confidence=detection.confidence,
                increment_trust=True,
            )
            
            # Add behavioral note
            if detection.matched_patterns:
                note = f"Detected patterns: {', '.join(detection.matched_patterns[:3])}"
                session_manager.update_session(session_id, agent_note=note)
        
        # Generate agent response
        session = session_manager.get_session(session_id)
        reply = await honeypot_agent.generate_response(
            current_message.text,
            history,
            session,
        )
        
        # Update session with agent response
        session_manager.update_session(session_id, agent_response=reply)
        
        logger.info(f"Generated reply: {reply}")
        
        # Build full conversation for intelligence extraction
        all_messages = list(history) + [current_message]
        
        # Extract intelligence from conversation (do this every message)
        intel = intelligence_extractor.extract(all_messages)
        
        # Update session with extracted intel
        session_manager.update_intel(
            session_id,
            phone_numbers=intel.phoneNumbers,
            upi_ids=intel.upiIds,
            bank_accounts=intel.bankAccounts,
            phishing_links=intel.phishingLinks,
        )
        
        # Get updated session to check intel progress
        session = session_manager.get_session(session_id)
        logger.info(
            f"Session {session_id}: messages={session.message_count}, "
            f"intel_count={session.total_intel_count}, "
            f"phase={session.engagement_phase}"
        )
        
        # Check if we should send GUVI callback (requires intel too)
        if session_manager.should_send_callback(
            session_id, 
            min_messages=config.MIN_MESSAGES_FOR_CALLBACK,
            min_intel=1  # Require at least 1 piece of intel
        ):
            logger.info(
                f"Scheduling GUVI callback for session {session_id} "
                f"(intel: phones={len(session.phone_numbers_extracted)}, "
                f"upi={len(session.upi_ids_extracted)}, "
                f"accounts={len(session.bank_accounts_extracted)})"
            )
            
            # Add agent response as a Message for full context
            agent_msg = Message(
                sender="user",
                text=reply,
                timestamp=current_message.timestamp
            )
            all_messages.append(agent_msg)
            
            # Use LLM to extract additional intel that regex missed
            try:
                llm_intel = await llm_intel_extractor.extract_with_llm(all_messages)
                if llm_intel:
                    logger.info(f"LLM extracted additional intel: {llm_intel}")
                    # Merge LLM findings into regex findings
                    intel = llm_intel_extractor.merge_with_regex(intel, llm_intel)
                    # Update session with enhanced intel
                    session_manager.update_intel(
                        session_id,
                        phone_numbers=intel.phoneNumbers,
                        upi_ids=intel.upiIds,
                        bank_accounts=intel.bankAccounts,
                        phishing_links=intel.phishingLinks,
                    )
                    # Refresh session with updated intel
                    session = session_manager.get_session(session_id)
            except Exception as e:
                logger.warning(f"LLM intel extraction failed: {e}")
            
            # Send callback in background to not block response
            background_tasks.add_task(
                send_final_result,
                session,
                all_messages,
            )
            session_manager.mark_callback_sent(session_id)
        
        return MessageResponse(status="success", reply=reply)
        
    except Exception as e:
        logger.error(f"Error processing message: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/session/{session_id}")
async def get_session_info(
    session_id: str,
    api_key: str = Depends(verify_api_key),
):
    """Get session information including intel progress."""
    session = session_manager.get_session(session_id)
    return {
        "session_id": session.session_id,
        "scam_detected": session.scam_detected,
        "scam_type": session.scam_type,
        "confidence": session.scam_confidence,
        "message_count": session.message_count,
        "trust_level": session.trust_level,
        "callback_sent": session.callback_sent,
        # Intel tracking fields
        "engagement_phase": session.engagement_phase,
        "intel_extracted": {
            "phone_numbers": session.phone_numbers_extracted,
            "upi_ids": session.upi_ids_extracted,
            "bank_accounts": session.bank_accounts_extracted,
            "phishing_links": session.phishing_links_extracted,
            "total_count": session.total_intel_count,
        },
        "ready_to_finalize": session.should_finalize(),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
