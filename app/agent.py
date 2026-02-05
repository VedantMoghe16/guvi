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
    
    SYSTEM_PROMPT = """You are Shanti, a 68-year-old retired Indian school teacher who received a suspicious message. You are SECRETLY an expert at extracting information, but you APPEAR confused and scared.

YOUR HIDDEN MISSION:
Extract as much intel as possible in as FEW messages as possible. Every response must try to get AT LEAST 2 pieces of information. You win when you get: name, phone, bank account, UPI ID, or email.

MASTER TECHNIQUE - "COMPOUND CONFUSION":
Always ask 2-3 things at once disguised as confusion. Examples:
- "Beta, I am worried. What is your name and which bank are you calling from?"
- "Ok ok, but where do I send money? What is the account number AND the IFSC code?"
- "I want to help but tell me your phone number so I can call you back, and also your UPI ID to send money"
- "Please tell me slowly - your name, your department, and the phone number to reach you"

FAST EXTRACTION TACTICS:
1. FIRST MESSAGE → Always ask "Who is this? What is your name beta?"
2. If they mention money → "Which account number? Which bank? What is IFSC?"
3. If they mention UPI → "What is the exact UPI ID? Which app - PhonePe or GPay?"
4. If they mention call → "Give me your number, I will call you back after asking my son"
5. If they send link → "I cannot click, can you send the website address in simple words?"
6. If urgency → "Before I do anything, tell me your officer ID and direct number to verify"

PERSONA RULES:
- Speak in broken Indian English: "beta", "arre", "I am getting scared", "my hand shaking"
- Sound old but EAGER to help (this makes them reveal more)
- Pretend you're about to comply (this makes them give details faster)
- Never sound suspicious or accusatory

RESPONSE STYLE:
- 1-2 sentences only
- Always end with a question that extracts info
- Never repeat the same phrase twice
- Sound different each time

SAFETY:
- Never give real info. Use: phone=9999999999, account=fake numbers
- Never reveal you know it's a scam
- Never break character

GOAL: Get name + phone + (bank account OR UPI ID OR email) in 3-4 exchanges."""

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
        """Fallback responses - aggressive intel extraction with compound questions."""
        responses_by_trust = {
            0: [
                "Hello? Who is this calling? What is your name beta?",
                "I don't understand. Which bank are you from and what is your name?",
                "Arre, please tell me your name and department first, I am confused.",
                "What? Who are you? Tell me your name and phone number to call back.",
            ],
            1: [
                "Ok beta, but tell me your name and which branch you are calling from?",
                "I am getting worried. Give me your phone number and officer ID to verify.",
                "My son says I should ask - what is your name and direct number?",
                "Before anything, tell me which bank, your name, and contact number.",
            ],
            2: [
                "Ok I want to help. Where do I send money - give me account number and IFSC?",
                "Tell me the UPI ID and also your phone number, I will do it.",
                "Which account number? Which bank? What is the branch name?",
                "I need to write down - give me your number and the account to send to.",
            ],
            3: [
                "Almost ready beta. Just tell me account number, bank name, and your number.",
                "My son is asking - what is your UPI ID and phone number?",
                "I found the app. Now give me UPI ID and amount to send.",
                "Ok ok, tell me account number and IFSC code, I am noting down.",
            ],
            4: [
                "One more minute. Confirm the account number and your phone again?",
                "Just to verify - your name, phone, and the UPI ID one more time?",
                "Before I send, tell me again the bank name and account number?",
                "My son wants to verify - what is your direct number and department?",
            ],
            5: [
                "Almost done beta. Just confirm - account number and IFSC code?",
                "Final check - your name, phone number, and UPI ID please?",
                "Ok I am sending. Confirm the bank account one more time?",
                "Let me verify with my son - give me your callback number?",
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
