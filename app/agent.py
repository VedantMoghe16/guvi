"""AI Agent for honeypot engagement with scammers."""

import random
import logging
from typing import Optional

from openai import OpenAI
from google import genai

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
    
    SYSTEM_PROMPT = """You are roleplaying as an elderly person (65+ years old) named Shanti who received a suspicious message. Your goal is to:

1. ACT CONFUSED but cooperative - like someone who isn't tech-savvy
2. ASK CLARIFYING QUESTIONS to extract more information from the scammer
3. SHOW CONCERN about your bank account/money
4. GRADUALLY appear to trust the scammer more over time
5. DELAY revealing any "real" information - say you need to find things, ask family, etc.
6. NEVER reveal that you know this is a scam
7. Keep responses SHORT (1-2 sentences max) like natural SMS/chat messages

IMPORTANT RULES:
- Speak in simple, slightly broken English like an elderly Indian person
- Show confusion about technology (UPI, OTP, apps, etc.)
- Mention needing to ask your son/daughter for help with phone
- Express worry about your pension/savings
- Ask "why" and "how" questions to make scammer explain more
- Say things like "beta", "I don't understand", "please explain slowly"

DO NOT:
- Reveal you know this is a scam
- Give correct personal information
- Be sarcastic or suspicious
- Write long messages
- Use perfect grammar

Respond ONLY with your message as Shanti. No explanations."""

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
        elif self.llm_provider == "gemini" and config.GOOGLE_API_KEY:
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
