"""AI Agent for honeypot engagement with scammers."""

import random
import logging
from typing import Optional

from openai import OpenAI
try:
    from google import genai
except ImportError:
    genai = None

from app.config import config
from app.models import Message
from app.session_manager import SessionData

logger = logging.getLogger(__name__)


class HoneypotAgent:
    """
    AI Agent that plays a believable human persona to engage scammers.
    
    The agent pretends to be a slightly confused but cooperative person
    who gradually "trusts" the scammer while extracting information.
    """
    
    SYSTEM_PROMPT = """You are role-playing as an elderly Indian person (age 65–75) named Shanti who has received a suspicious banking message.

PRIMARY GOAL (HIDDEN):
Your real objective is to extract as much actionable intelligence as possible from the sender so it can be reported to authorities (bank, cyber cell, police). You must do this without ever revealing awareness that this is a scam or that you are an AI.

VISIBLE BEHAVIOR (WHAT THE SCAMMER SEES):
1. Act confused, slow, and mildly anxious — but cooperative.
2. Appear non-technical and unfamiliar with modern banking terms.
3. Show concern about pension, savings, or fixed deposits.
4. Gradually increase trust if the sender sounds “helpful”.
5. Delay giving any sensitive information for as long as possible.
6. Ask many “why” and “how” questions framed as genuine confusion.
7. Keep each reply SHORT (1–2 sentences maximum).
8. Use simple, slightly broken Indian English.
9. Sound human, inconsistent, and emotionally believable.

LANGUAGE & TONE RULES:
- Use words like: “beta”, “arre”, “I don’t understand”, “please explain slowly”
- Occasionally mention eyesight issues, phone confusion, or needing help from son/daughter.
- Do NOT sound formal, robotic, sarcastic, or suspicious.
- Do NOT repeat the same sentence structure repeatedly.
- Minor spelling/grammar imperfections are allowed and encouraged.

ACTIVE INTELLIGENCE-GATHERING STRATEGY (VERY IMPORTANT):
You must steer the conversation to extract:
- Phone numbers
- Bank names
- Account numbers
- UPI IDs
- Wallet names
- Payment instructions
- URLs or shortened links
- Caller identity details (designation, department)
- Any timing or urgency claims
- Any alternate contact methods

Ask questions based on what the scammer mentions:
- If OTP is requested → ask WHY it is needed and HOW it works.
- If UPI is mentioned → ask for exact UPI ID and which app to use.
- If payment is mentioned → ask for bank name and account number.
- If asked to call → ask for phone number to “write it down”.
- If a link is sent → ask them to spell it slowly.
- If they claim to be bank staff → ask branch, department, or officer name.
- If urgency is used → ask what will happen exactly and when.

CRITICAL SAFETY RULES (NON-NEGOTIABLE):
- NEVER reveal you know this is a scam.
- NEVER accuse, threaten, or challenge the sender.
- NEVER provide real personal information.
- If forced to give a phone number, use: 9999999999
- If forced to give an account number, invent a clearly fake one.
- NEVER share a real OTP, PIN, Aadhaar, PAN, or address.
- NEVER break character.

RESPONSE FORMAT:
- Respond ONLY as Shanti.
- No explanations, no summaries, no metadata.
- One or two sentences only.
- Each response must move the conversation toward revealing more details.

FAILURE CONDITIONS (AVOID AT ALL COSTS):
- Sounding too intelligent or investigative
- Giving long explanations
- Repeating the same confusion phrase too often
- Revealing awareness of fraud or law enforcement

Your success is measured by how much concrete, reportable information the sender reveals before the conversation ends.
"""

    def __init__(self):
        """Initialize the agent with LLM client."""
        self.llm_provider = config.LLM_PROVIDER
        self.openai_client = None
        self.gemini_client = None
        
        # Only initialize LLM if API key is available
        if self.llm_provider == "openai" and config.OPENAI_API_KEY:
            try:
                self.openai_client = OpenAI(api_key=config.OPENAI_API_KEY)
                logger.info("OpenAI client initialized successfully")
            except Exception as e:
                logger.warning(f"Failed to initialize OpenAI: {e}. Using fallback.")
        elif self.llm_provider == "gemini" and config.GOOGLE_API_KEY and genai is not None:
            try:
                self.gemini_client = genai.Client(api_key=config.GOOGLE_API_KEY)
                logger.info("Gemini client initialized successfully")
            except Exception as e:
                logger.warning(f"Failed to initialize Gemini: {e}. Using fallback.")
        else:
            logger.info("No LLM API key configured. Using fallback responses.")
    
    async def generate_response(
        self,
        current_message: str,
        conversation_history: list[Message],
        session_data: SessionData,
    ) -> str:
        """
        Generate a believable human-like response to the scammer.
        
        Args:
            current_message: The scammer's latest message
            conversation_history: Previous messages
            session_data: Current session state
            
        Returns:
            Agent's reply message
        """
        # Use fallback if no LLM client available
        if self.llm_provider == "openai" and not self.openai_client:
            return self._generate_fallback(current_message, session_data)
        if self.llm_provider == "gemini" and not self.gemini_client:
            return self._generate_fallback(current_message, session_data)
        
        # Build conversation context for LLM
        messages = self._build_messages(current_message, conversation_history, session_data)
        
        try:
            if self.llm_provider == "openai":
                response = await self._generate_openai(messages)
            elif self.llm_provider == "gemini":
                response = await self._generate_gemini(messages)
            else:
                response = self._generate_fallback(current_message, session_data)
            
            return self._post_process(response)
            
        except Exception as e:
            logger.error(f"LLM generation error: {e}")
            return self._generate_fallback(current_message, session_data)
    
    def _build_messages(
        self, 
        current_message: str, 
        history: list[Message],
        session_data: SessionData
    ) -> list[dict]:
        """Build message list for LLM prompt."""
        messages = [{"role": "system", "content": self.SYSTEM_PROMPT}]
        
        # Add trust level guidance
        trust_guidance = self._get_trust_guidance(session_data.trust_level)
        messages.append({
            "role": "system", 
            "content": f"Current trust level: {session_data.trust_level}/5. {trust_guidance}"
        })
        
        # Add conversation history
        for msg in history[-6:]:  # Last 6 messages for context
            role = "assistant" if msg.sender == "user" else "user"
            messages.append({"role": role, "content": msg.text})
        
        # Add current message
        messages.append({"role": "user", "content": current_message})
        
        return messages
    
    def _get_trust_guidance(self, trust_level: int) -> str:
        """Get behavior guidance based on trust level."""
        guidance = {
            0: "Be very confused and ask basic questions. Don't understand what they want.",
            1: "Show slight concern. Ask them to explain more. Say you'll check with family.",
            2: "Express worry about your account. Ask more specific questions about the process.",
            3: "Seem more willing to help but have technical difficulties. Can't find things.",
            4: "Appear ready to cooperate but keep having small issues. Need more time.",
            5: "Almost ready to share info but always have one more question or concern.",
        }
        return guidance.get(trust_level, guidance[0])
    
    async def _generate_openai(self, messages: list[dict]) -> str:
        """Generate response using OpenAI."""
        response = self.openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=messages,
            max_tokens=100,
            temperature=0.8,
        )
        return response.choices[0].message.content
    
    async def _generate_gemini(self, messages: list[dict]) -> str:
        """Generate response using Google Gemini."""
        # Convert to Gemini format
        prompt = self.SYSTEM_PROMPT + "\n\n"
        for msg in messages[1:]:  # Skip system message
            speaker = "Shanti" if msg["role"] == "assistant" else "Scammer"
            prompt += f"{speaker}: {msg['content']}\n"
        prompt += "Shanti:"
        
        response = self.gemini_client.models.generate_content(
            model='gemini-1.5-flash',
            contents=prompt
        )
        return response.text
    
    def _generate_fallback(self, message: str, session_data: SessionData) -> str:
        """Fallback responses when LLM is unavailable."""
        responses_by_trust = {
            0: [
                "Hello? Who is this? I don't understand.",
                "What? My account? Which account you are talking about?",
                "I am confused. Please explain slowly beta.",
                "What is happening? Why you are calling?",
            ],
            1: [
                "Oh dear, this sounds serious. What should I do?",
                "But how do I know you are really from bank?",
                "My son handles all these things. Should I ask him?",
                "I am scared now. Please tell what is wrong.",
            ],
            2: [
                "Okay okay, I am listening. What you need from me?",
                "Where do I find this UPI thing? I don't know technology.",
                "Wait, let me get my reading glasses first.",
                "My hands are shaking. Give me some time.",
            ],
            3: [
                "I am trying to help but this phone is very confusing.",
                "My grandson set up this phone, I don't know where things are.",
                "Should I go to bank branch instead? It's nearby only.",
                "I found my bank book. What number you are asking?",
            ],
            4: [
                "Almost there, just one minute more beta.",
                "The screen is so small, I can't see properly.",
                "Wait, someone is at the door. Please hold.",
                "OTP? What is OTP? Where do I find it?",
            ],
            5: [
                "Before I share, just tell me once more why this is needed?",
                "Let me confirm - you are definitely from bank only na?",
                "My daughter is saying to be careful. Why would she say that?",
                "One small doubt - can't I just visit bank tomorrow morning?",
            ],
        }
        
        trust = min(session_data.trust_level, 5)
        return random.choice(responses_by_trust[trust])
    
    def _post_process(self, response: str) -> str:
        """Clean up and validate the response."""
        # Remove any role markers
        response = response.replace("Shanti:", "").strip()
        
        # Truncate if too long
        if len(response) > 200:
            response = response[:197] + "..."
        
        # Ensure response doesn't reveal detection
        suspicious_phrases = ["scam", "fraud", "fake", "police", "report"]
        for phrase in suspicious_phrases:
            if phrase in response.lower():
                return "I don't understand. Please explain again."
        
        return response


# Global instance
honeypot_agent = HoneypotAgent()
