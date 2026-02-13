"""
Simple test to verify LLM (OpenRouter) is working
"""
import os
from dotenv import load_dotenv
from pathlib import Path
from openai import OpenAI

# Load environment
env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path)

api_key = os.getenv("OPENROUTER_API_KEY")

print("\n" + "="*60)
print("LLM (OpenRouter) Test")
print("="*60)

try:
    client = OpenAI(
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1"
    )
    
    print("\n📞 Calling OpenRouter API...")
    print(f"Model: anthropic/claude-3.5-sonnet")
    
    response = client.chat.completions.create(
        model="anthropic/claude-3.5-sonnet",
        messages=[
            {
                "role": "user",
                "content": "You are a smart contract security expert. Analyze this simple Solidity function and identify any security issues:\n\nfunction withdraw(uint amount) public {\n    msg.sender.call{value: amount}(\"\");\n    balances[msg.sender] -= amount;\n}\n\nProvide a brief analysis."
            }
        ],
        max_tokens=200
    )
    
    result = response.choices[0].message.content
    
    print("\ n✅ LLM Response:")
    print("-" * 60)
    print(result)
    print("-" * 60)
    print(f"\n📊 Tokens used: {response.usage.total_tokens}")
    print(f"   - Prompt: {response.usage.prompt_tokens}")
    print(f"   - Completion: {response.usage.completion_tokens}")
    print("\n✅ LLM is working!")
    
except Exception as e:
    error_str = str(e)
    print(f"\n❌ LLM Test Failed:")
    print(f"   {error_str[:300]}")
    
    if "402" in error_str or "credits" in error_str.lower():
        print("\n⚠️  ISSUE: Insufficient credits in OpenRouter account")
        print("   Solution: Add credits at https://openrouter.ai/settings")
    elif "401" in error_str or "unauthorized" in error_str.lower():
        print("\n⚠️  ISSUE: Invalid API key")
        print("   Solution: Check your OpenRouter API key")

print("\n" + "="*60)
