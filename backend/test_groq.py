"""
Test Groq LLM integration for Sentinel Protocol
"""
import os
from dotenv import load_dotenv
from pathlib import Path
from groq import Groq

# Load environment
env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path)

api_key = os.getenv("GROQ_API_KEY")

print("\n" + "="*60)
print("🚀 GROQ LLM TEST - Sentinel Protocol")
print("="*60)

if not api_key:
    print("❌ GROQ_API_KEY not found in environment!")
    exit(1)

print(f"✅ API Key loaded: {api_key[:20]}...{api_key[-10:]}")

try:
    client = Groq(api_key=api_key)
    
    print("\n📞 Testing Groq API with Llama 3.3 70B...")
    print("   Model: llama-3.3-70b-versatile")
    
    # Test with a smart contract security analysis
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {
                "role": "system",
                "content": "You are a smart contract security expert."
            },
            {
                "role": "user",
                "content": """Analyze this Solidity function for security vulnerabilities:

function withdraw(uint amount) public {
    msg.sender.call{value: amount}("");
    balances[msg.sender] -= amount;
}

Identify the vulnerability and explain the risk."""
            }
        ],
        max_tokens=300,
        temperature=0.1
    )
    
    result = response.choices[0].message.content
    
    print("\n✅ GROQ API RESPONSE:")
    print("-" * 60)
    print(result)
    print("-" * 60)
    
    print(f"\n📊 Stats:")
    print(f"   Tokens used: {response.usage.total_tokens}")
    print(f"   Prompt: {response.usage.prompt_tokens}")
    print(f"   Completion: {response.usage.completion_tokens}")
    print(f"   Model: {response.model}")
    
    print("\n✅ GROQ IS WORKING PERFECTLY!")
    print("   Speed: Instant (Groq speciality)")
    print("   Cost: FREE")
    print("   Rate Limit: 30 req/min, 14,400/day")
    
except Exception as e:
    print(f"\n❌ Test Failed:")
    print(f"   {str(e)}")
    
    if "401" in str(e):
        print("\n⚠️  Invalid API key - check your Groq API key")
    elif "429" in str(e):
        print("\n⚠️  Rate limit exceeded - wait a moment")

print("\n" + "="*60)
