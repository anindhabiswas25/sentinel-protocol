"""Test Gemini API integration"""
import google.generativeai as genai

# Configure API
genai.configure(api_key='AIzaSyBmEFzrrb0bnPxM686fO0j-U3zuUrEH3Eo')

# Test model
print("🧪 Testing Gemini 2.5 Flash...")
model = genai.GenerativeModel('gemini-2.5-flash')

# Simple test
response = model.generate_content('What is 2+2?')
print(f"✅ Gemini API is working!")
print(f"Response: {response.text}\n")

# Smart contract test
test_contract = """
pragma solidity ^0.8.0;

contract SimpleToken {
    mapping(address => uint256) public balances;
    
    function transfer(address to, uint256 amount) public {
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
"""

print("🧪 Testing smart contract analysis...")
prompt = f"""Analyze this Solidity contract for security vulnerabilities. Return JSON only.

{test_contract}

Return format:
{{"vulnerabilities": [], "summary": "text", "risk_assessment": "Low|Medium|High"}}
"""

response = model.generate_content(prompt)
print(f"✅ Contract analysis response:")
print(response.text[:300])
print("\n✅ ALL TESTS PASSED! Gemini is ready!")
