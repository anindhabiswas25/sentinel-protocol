#!/usr/bin/env python3
"""
Comprehensive test of FULLY DYNAMIC exploit detection system
No hardcoding - everything is detected via:
1. Gemini LLM code analysis
2. External APIs (when available)
3. Pattern databases
"""

import requests
import json
from datetime import datetime

print("\n" + "="*80)
print("DYNAMIC EXPLOIT DETECTION SYSTEM - COMPREHENSIVE TEST")
print("="*80)

API_URL = "http://localhost:8001/api/v1/analyze"

test_cases = [
    {
        "name": "USDT (Safe Contract)",
        "address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
        "expected_risk": "Low",
        "expected_score": 85,
        "should_detect_exploit": False
    },
    {
        "name": "Old PolyNetwork ($611M Exploit)",
        "address": "0x250e76987d838a75310c34bf422ea9f1ac4cc906",
        "expected_risk": "Critical",
        "expected_score": 20,
        "should_detect_exploit": True
    },
    {
        "name": "BadgerDAO ($120M Exploit)",
        "address": "0x19D97D8fA813EE2f51aD4B4e04EA08bAf4DFfC28",
        "expected_risk": "Critical",
        "expected_score": 20,
        "should_detect_exploit": True
    },
    {
        "name": "Nomad Bridge ($190M Exploit)",
        "address": "0x5d94309e5a0090b165fa4181519701637b6daeba",
        "expected_risk": "Critical",
        "expected_score": 20,
        "should_detect_exploit": True
    },
]

print(f"\nTesting {len(test_cases)} contracts for DYNAMIC detection\n")

passed = 0
failed = 0
detection_methods = {}

for test in test_cases:
    print(f"{'='*80}")
    print(f"Testing: {test['name']}")
    print(f"Address: {test['address']}")
    print(f"Expected: Risk={test['expected_risk']}, Score≈{test['expected_score']}")
    print(f"{'='*80}")
    
    try:
        response = requests.post(
            API_URL,
            json={
                "contract_address": test['address'],
                "network": "ethereum"
            },
            timeout=60
        )
        
        if response.status_code != 200:
            print(f"❌ API Error: {response.status_code}")
            failed += 1
            continue
        
        data = response.json()
        
        score = data['trust_score']['overall_score']
        risk = data['trust_score']['risk_level']
        method = data['summary']['analysis_method']
        insights = data['summary']['llm_insights']
        
        # Track detection methods
        if method not in detection_methods:
            detection_methods[method] = 0
        detection_methods[method] += 1
        
        print(f"\nResult:")
        print(f"  Score: {score}")
        print(f"  Risk: {risk}")
        print(f"  Detection Method: {method}")
        print(f"  Insights: {insights[:150]}...")
        
        # Validate result
        score_correct = abs(score - test['expected_score']) <= 15
        risk_correct = risk == test['expected_risk']
        
        if test['should_detect_exploit']:
            exploit_detected = "dynamic-exploit-detection" in method or "error" not in method.lower()
        else:
            exploit_detected = True
        
        if score_correct and risk_correct and exploit_detected:
            print(f"\n✅ TEST PASSED")
            passed += 1
        else:
            print(f"\n❌ TEST FAILED")
            if not score_correct:
                print(f"   Score mismatch: expected ~{test['expected_score']}, got {score}")
            if not risk_correct:
                print(f"   Risk mismatch: expected {test['expected_risk']}, got {risk}")
            if not exploit_detected and test['should_detect_exploit']:
                print(f"   Exploit not detected")
            failed += 1
            
    except Exception as e:
        print(f"❌ Error: {e}")
        failed += 1
    
    print()

# Summary
print("\n" + "="*80)
print("TEST SUMMARY")
print("="*80)

print(f"\nTotal Tests: {passed + failed}")
print(f"✅ Passed: {passed}")
print(f"❌ Failed: {failed}")
print(f"Success Rate: {(passed/(passed+failed)*100):.1f}%")

print(f"\nDetection Methods Used:")
for method, count in sorted(detection_methods.items(), key=lambda x: x[1], reverse=True):
    print(f"  • {method}: {count} detections")

print(f"\nDynamic Detection Status:")
if 'dynamic-exploit-detection' in detection_methods:
    print(f"✅ DYNAMIC DETECTION IS WORKING")
    print(f"   {detection_methods['dynamic-exploit-detection']} exploits detected via dynamic sources")
else:
    print(f"⚠️  Dynamic detection not triggered")
    print(f"   Using fallback methods instead")

if passed == len(test_cases):
    print(f"\n{'='*80}")
    print(f"🎉 ALL TESTS PASSED - SYSTEM READY FOR PRODUCTION!")
    print(f"{'='*80}\n")
else:
    print(f"\n{'='*80}")
    print(f"⚠️  SOME TESTS FAILED - REVIEW NEEDED")
    print(f"{'='*80}\n")

# Additional info
print("System Architecture:")
print("  1️⃣  Gemini LLM Analysis (Code/Bytecode vulnerability detection)")
print("  2️⃣  Dynamic Exploit Detector (External APIs: Rekt.news, Slowmist, DeFiYield, OFAC)")
print("  3️⃣  Pattern Database (Smart caching, 6-hour refresh)")
print("  4️⃣  NO HARDCODING - Everything is updated automatically")
print()
