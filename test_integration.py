import requests
import time
import sys
import json

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_health():
    """Test the health endpoint."""
    try:
        response = requests.get("http://localhost:8000/health")
        if response.status_code == 200:
            print("âœ… Health check passed")
            return True
        else:
            print(f"â Œ Health check failed with status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("â Œ Could not connect to server. Is it running?")
        return False

def test_message_flow():
    """Test the full message processing flow."""
    url = "http://localhost:8000/api/message"
    
    # Get API key from env, matching app config
    api_key = os.getenv("x_api_key") or os.getenv("x-api-key", "default-api-key")
    
    headers = {
        "x-api-key": api_key,
        "Content-Type": "application/json"
    }
    
    # Payload simulating a scam message
    payload = {
        "sessionId": "test-integration-" + str(int(time.time())),
        "message": {
            "sender": "scammer",
            "text": "Your bank account ending in 8844 is suspended. Click http://suspend-bank.com/verify to verify immediately or you lose funds.",
            "timestamp": "2026-01-30T10:00:00Z"
        },
        "conversationHistory": []
    }
    
    try:
        print("\nSending scam message...")
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code == 200:
            data = response.json()
            print("âœ… API Response Received:")
            print(json.dumps(data, indent=2))
            
            if "reply" in data and len(data["reply"]) > 0:
                print("âœ… Agent generated a reply")
            else:
                print("âŒ Agent did not generate a reply")
                
            return True
        elif response.status_code == 403:
             print("âŒ Authentication failed. Check API Key.")
             return False
        else:
            print(f"âŒ API Request failed: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        print(f"âŒ Error testing message flow: {e}")
        return False

if __name__ == "__main__":
    print("=== Integration Test Suite ===")
    print("Ensure server is running on localhost:8000")
    print("Command: uvicorn app.main:app --reload")
    
    if len(sys.argv) > 1 and sys.argv[1] == "--wait":
        # Wait for server up to 10s
        for _ in range(10):
            if test_health():
                break
            time.sleep(1)
            
    if test_health():
        test_message_flow()
    else:
        print("\nSkipping message flow test as server is not reachable.")
