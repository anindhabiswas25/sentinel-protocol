#!/usr/bin/env python3
"""
Final validation test for all 4 contract categories
"""
import requests
import json

API_URL = "http://localhost:8001/api/v1/analyze"

tests = [
    {
        "label": "✅ VERIFIED SAFE: USDT",
        "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
        "expected_risk": "Low",
        "expected_range": (75, 95)
    },
    {
        "label": "🚨 VERIFIED EXPLOITED: BadgerDAO ($120M)",
        "address": "0x19D97D8fA813EE2f51aD4B4e04EA08bAf4DFfC28",
        "expected_risk": "Critical",
        "expected_range": (0, 24)
    },
    {
        "label": "🚨 VERIFIED EXPLOITED: Merge Token",
        "address": "0x4a57e355bed70f6804084d1416e8f6e3f1d88690",
        "expected_risk": "Critical",
        "expected_range": (0, 24)
    },
    {
        "label": "🚨 KNOWN EXPLOIT: Nomad Bridge ($190M)",
        "address": "0x5d94309e5a0090b165fa4181519701637b6daeba",
        "expected_risk": "Critical",
        "expected_range": (0, 24)
    }
]

print("\n" + "="*70)
print("  🎯 FINAL VALIDATION - ALL 4 CONTRACT CATEGORIES")
print("="*70 + "\n")

passed = 0
failed = 0

for test in tests:
    print(f"{test['label']}")
    print(f"  Address: {test['address']}")
    
    try:
        response = requests.post(
            API_URL,
            json={"contract_address": test['address'], "network": "ethereum"},
            timeout=30
        )
        
        data = response.json()
        score = data['trust_score']['overall_score']
        risk = data['trust_score']['risk_level']
        method = data['summary']['analysis_method']
        
        print(f"  Result:  Score={score} Risk={risk} Method={method}")
        
        # Check if result is correct
        score_ok = test['expected_range'][0] <= score <= test['expected_range'][1]
        risk_ok = risk == test['expected_risk']
        
        if score_ok and risk_ok:
            print(f"  Status:  ✅ PASS\n")
            passed += 1
        else:
            print(f"  Status:  ❌ FAIL (Expected: {test['expected_risk']} in range {test['expected_range']})\n")
            failed += 1
            
    except Exception as e:
        print(f"  Status:  ❌ ERROR: {e}\n")
        failed += 1

print("="*70)
print(f"  Results: {passed} PASSED, {failed} FAILED")
print("="*70 + "\n")

if failed == 0:
    print("✅ ALL TESTS PASSED - System is ready for production!\n")
else:
    print(f"⚠️  {failed} test(s) failed - Review required\n")
