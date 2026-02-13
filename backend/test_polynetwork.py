#!/usr/bin/env python3
import requests
import json

print("="*70)
print("Testing: Old PolyNetwork (Known Exploit 2021)")
print("="*70)

response = requests.post(
    "http://localhost:8001/api/v1/analyze",
    json={
        "contract_address": "0x250e76987d838a75310c34bf422ea9f1ac4cc906",
        "network": "ethereum"
    },
    timeout=30
)

data = response.json()
score = data['trust_score']['overall_score']
risk = data['trust_score']['risk_level']
method = data['summary']['analysis_method']
insights = data['summary']['llm_insights']

print(f"\nResult:")
print(f"  Score: {score}")
print(f"  Risk Level: {risk}")
print(f"  Analysis Method: {method}")
print(f"\nInsights (first 300 chars):")
print(f"  {insights[:300]}")

print(f"\nExpected vs Actual:")
print(f"  Expected Score Range: 25-49")
print(f"  Actual Score: {score}")
print(f"  Expected Risk: Critical")
print(f"  Actual Risk: {risk}")

in_range = 25 <= score <= 49
risk_correct = risk == "Critical"

print(f"\nValidation:")
if in_range and risk_correct:
    print(f"  ✅ CORRECT - Analyzer properly detected Old PolyNetwork exploit!")
else:
    print(f"  ❌ ISSUE - Analyzer not correctly detecting exploit")
    if not in_range:
        print(f"     - Score out of range (got {score}, expected 25-49)")
    if not risk_correct:
        print(f"     - Risk level incorrect (got {risk}, expected Critical)")
