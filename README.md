# Scam Detection Honeypot API

AI-powered agentic honeypot system for detecting scam messages, engaging scammers in multi-turn conversations, and extracting intelligence.

## Quick Start

### 1. Setup Environment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your API keys
```

### 2. Run Locally

```bash
uvicorn app.main:app --reload --port 8000
```

### 3. Test the API

```bash
curl -X POST http://localhost:8000/api/message \
  -H "x-api-key: Xk7pQm9RvT2nL5wY8hJcA1bN4fG6dS3e" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "test-123",
    "message":{
      "sender": "scammer",
      "text": "Your bank account will be blocked today. Verify immediately.",
      "timestamp": "2026-01-30T10:00:00Z"
    },
    "conversationHistory": []
  }'
```

## API Endpoints

### POST /api/message
Process incoming messages and generate responses.

**Headers:**
- `x-api-key`: Your API key
- `Content-Type`: application/json

**Request Body:**
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Message content",
    "timestamp": "2026-01-30T10:00:00Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "Agent's response message"
}
```

### GET /health
Health check endpoint.

## Docker Deployment

```bash
# Build
docker build -t scam-honeypot .

# Run
docker run -p 8000:8000 --env-file .env scam-honeypot
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `API_KEY` | API authentication key | Yes |
| `LLM_PROVIDER` | `openai` or `gemini` | Yes |
| `OPENAI_API_KEY` | OpenAI API key | If using OpenAI |
| `GOOGLE_API_KEY` | Google API key | If using Gemini |
| `MIN_MESSAGES_FOR_CALLBACK` | Messages before GUVI callback | No (default: 5) |

## Features

- **Scam Detection**: Pattern-based detection for bank fraud, UPI fraud, phishing, lottery scams, job scams, and impersonation
- **AI Agent**: Human-like persona that engages scammers without revealing detection
- **Intelligence Extraction**: Extracts bank accounts, UPI IDs, phone numbers, phishing links, and suspicious keywords
- **GUVI Callback**: Automatically reports results to evaluation endpoint
