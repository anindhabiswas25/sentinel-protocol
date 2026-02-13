import requests
import json

print("Testing Akutars NFT Contract...")
print("="*60)

response = requests.post(
    'http://localhost:8000/api/v1/analyze',
    json={
        'contract_address': '0xF42c318dbfBaab0EEE040279c6A2588Fa01a961d',
        'network': 'ethereum',
        'force_refresh': True  # Bypass cache to test new scoring logic
    }
)

result = response.json()

print("Full Response:")
print(json.dumps(result, indent=2))
print("="*60)

score = result.get('trust_score', {}).get('overall_score', 'N/A')
risk = result.get('trust_score', {}).get('risk_level', 'N/A')
contract_name = result.get('contract_name', 'Unknown')

print(f"\nContract: {contract_name}")
print(f"Score: {score}")
print(f"Risk Level: {risk}")
print(f"Expected: 45.0 (High Risk)")
print("="*60)

if score == 45.0:
    print("✅ PASS - Exploit penalty correctly applied!")
else:
    print(f"❌ FAIL - Expected 45.0, got {score}")
