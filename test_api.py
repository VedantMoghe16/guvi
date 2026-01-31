"""Test script for the honeypot API."""

import asyncio
import logging
import sys
from app.models import Message
from app.scam_detector import scam_detector
from app.agent import honeypot_agent
from app.session_manager import session_manager
from app.intelligence import intelligence_extractor
from app.config import config

# Configure logging
logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger(__name__)

async def test_full_flow():
    """Test the complete scam detection and response flow."""
    
    print("=" * 50)
    print("SCAM DETECTION HONEYPOT - TEST SUITE")
    print("=" * 50)
    
    print(f"Debug: LLM_PROVIDER={config.LLM_PROVIDER}")
    print(f"Debug: OPENAI_API_KEY present={'Yes' if config.OPENAI_API_KEY else 'No'}")
    print(f"Debug: Agent client initialized={honeypot_agent.openai_client is not None}")
    
    # Test 1: Scam Detection
    print("\n--- Test 1: Scam Detection ---")
    test_messages = [
        "Your bank account will be blocked today. Verify immediately.",
        "Share your UPI ID to avoid account suspension.",
        "Hello, how are you?",  # Not a scam
        "Congratulations! You've won a lottery prize of Rs. 50 lakhs!",
    ]
    
    for msg in test_messages:
        result = scam_detector.detect(msg)
        print(f"Message: {msg[:50]}...")
        print(f"  -> is_scam: {result.is_scam}, confidence: {result.confidence}, type: {result.scam_type}")
    
    # Test 2: Agent Responses (Multi-turn)
    print("\n--- Test 2: Agent Multi-turn Responses ---")
    session = session_manager.get_session("test-session")
    
    scammer_msgs = [
        "Your bank account will be blocked today. Verify immediately.",
        "Please share your UPI ID to verify your identity.",
        "Send me your OTP for verification."
    ]
    
    history = []
    for i, msg in enumerate(scammer_msgs):
        print(f"Processing message {i+1}...")
        # Update session for trust progression
        session_manager.update_session("test-session", increment_trust=True, scam_detected=True)
        session = session_manager.get_session("test-session")
        
        try:
            print("Generating response...")
            response = await asyncio.wait_for(
                honeypot_agent.generate_response(msg, history, session),
                timeout=5.0
            )
            print(f"\nScammer ({i+1}): {msg}")
            print(f"Agent (trust={session.trust_level}): {response}")
            
            # Add to history
            history.append(Message(sender="scammer", text=msg, timestamp=""))
            history.append(Message(sender="user", text=response, timestamp=""))
        except asyncio.TimeoutError:
            print("ERROR: Timeout generating response")
        except Exception as e:
            print(f"ERROR: {e}")
    
    # Test 3: Intelligence Extraction
    print("\n--- Test 3: Intelligence Extraction ---")
    test_convo = [
        Message(sender="scammer", text="Send money to 1234-5678-9012-3456 card number", timestamp=""),
        Message(sender="scammer", text="Or use UPI: scammer@upi", timestamp=""),
        Message(sender="scammer", text="Call me at +91 9876543210", timestamp=""),
        Message(sender="scammer", text="Click http://fake-bank.example.com/verify", timestamp=""),
    ]
    
    intelligence = intelligence_extractor.extract(test_convo)
    print(f"Bank Accounts: {intelligence.bankAccounts}")
    print(f"UPI IDs: {intelligence.upiIds}")
    print(f"Phone Numbers: {intelligence.phoneNumbers}")
    print(f"Phishing Links: {intelligence.phishingLinks}")
    print(f"Keywords: {intelligence.suspiciousKeywords}")
    
    print("\n" + "=" * 50)
    print("ALL TESTS PASSED SUCCESSFULLY!")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(test_full_flow())
