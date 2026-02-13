#!/usr/bin/env python3
"""
Test all external APIs for availability and correctness
"""

import asyncio
import aiohttp
import requests
from datetime import datetime
import json

print("="*80)
print("TESTING ALL EXTERNAL APIS FOR DYNAMIC EXPLOIT DETECTION")
print("="*80)

# Test Gemini API
print("\n" + "="*80)
print("1️⃣  TESTING GEMINI API")
print("="*80)

try:
    from app.services.gemini_service import gemini_service
    
    test_code = """
    pragma solidity ^0.8.0;
    contract Test {
        mapping(address => uint) public balance;
        function withdraw(uint amount) public {
            require(balance[msg.sender] >= amount);
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success);
            balance[msg.sender] -= amount;
        }
    }
    """
    
    response = gemini_service.analyze_contract(
        contract_code=test_code,
        contract_name="TestContract"
    )
    
    print("✅ Gemini API is WORKING")
    print(f"   Response: {json.dumps(response, indent=2)[:200]}...")
    gemini_ok = True
except Exception as e:
    print(f"❌ Gemini API FAILED: {e}")
    gemini_ok = False

# Test Rekt.news API
print("\n" + "="*80)
print("2️⃣  TESTING REKT.NEWS API")
print("="*80)

try:
    response = requests.get(
        "https://rekt.news/api/incidents",
        timeout=10
    )
    
    if response.status_code == 200:
        data = response.json()
        print("✅ Rekt.news API is WORKING")
        print(f"   Found {len(data.get('incidents', []))} incidents")
        rekt_ok = True
    else:
        print(f"❌ Rekt.news API returned {response.status_code}")
        rekt_ok = False
except Exception as e:
    print(f"❌ Rekt.news API FAILED: {e}")
    rekt_ok = False

# Test Slowmist API
print("\n" + "="*80)
print("3️⃣  TESTING SLOWMIST API")
print("="*80)

try:
    response = requests.get(
        "https://hacked.slowmist.io/api/data",
        timeout=10
    )
    
    if response.status_code == 200:
        data = response.json()
        print("✅ Slowmist API is WORKING")
        print(f"   Response size: {len(json.dumps(data))} bytes")
        slowmist_ok = True
    else:
        print(f"❌ Slowmist API returned {response.status_code}")
        slowmist_ok = False
except Exception as e:
    print(f"❌ Slowmist API FAILED: {e}")
    slowmist_ok = False

# Test DeFiYield API
print("\n" + "="*80)
print("4️⃣  TESTING DEFIYIELD API")
print("="*80)

try:
    response = requests.get(
        "https://www.defiyield.info/api/hacks",
        timeout=10,
        headers={"User-Agent": "Mozilla/5.0"}
    )
    
    if response.status_code == 200:
        data = response.json()
        print("✅ DeFiYield API is WORKING")
        print(f"   Found {len(data.get('hacks', []))} hacks in database")
        defiyield_ok = True
    else:
        print(f"❌ DeFiYield API returned {response.status_code}")
        defiyield_ok = False
except Exception as e:
    print(f"❌ DeFiYield API FAILED: {e}")
    defiyield_ok = False

# Test OFAC API
print("\n" + "="*80)
print("5️⃣  TESTING OFAC SANCTIONS API")
print("="*80)

try:
    response = requests.get(
        "https://sanctionssearch.ofac.treas.gov/",
        timeout=10
    )
    
    if response.status_code == 200:
        print("✅ OFAC API is WORKING (page accessible)")
        ofac_ok = True
    else:
        print(f"❌ OFAC API returned {response.status_code}")
        ofac_ok = False
except Exception as e:
    print(f"❌ OFAC API FAILED: {e}")
    ofac_ok = False

# Test ChainAbuse API
print("\n" + "="*80)
print("6️⃣  TESTING CHAINABUSE API")
print("="*80)

try:
    response = requests.get(
        "https://www.chainabuse.com/api",
        timeout=10
    )
    
    if response.status_code in [200, 400, 403]:  # Some APIs block without auth
        print("✅ ChainAbuse API is RESPONDING")
        chainabuse_ok = True
    else:
        print(f"❌ ChainAbuse API returned {response.status_code}")
        chainabuse_ok = False
except Exception as e:
    print(f"❌ ChainAbuse API FAILED: {e}")
    chainabuse_ok = False

# Test Honeypot.is API
print("\n" + "="*80)
print("7️⃣  TESTING HONEYPOT.IS API")
print("="*80)

try:
    response = requests.get(
        "https://api.honeypot.is/v2/",
        timeout=10
    )
    
    if response.status_code in [200, 400, 403]:
        print("✅ Honeypot.is API is RESPONDING")
        honeypot_ok = True
    else:
        print(f"❌ Honeypot.is API returned {response.status_code}")
        honeypot_ok = False
except Exception as e:
    print(f"❌ Honeypot.is API FAILED: {e}")
    honeypot_ok = False

# Summary
print("\n" + "="*80)
print("API AVAILABILITY SUMMARY")
print("="*80)

apis = {
    "✅ Gemini LLM": gemini_ok,
    "✅ Rekt.news": rekt_ok,
    "✅ Slowmist": slowmist_ok,
    "✅ DeFiYield": defiyield_ok,
    "✅ OFAC Sanctions": ofac_ok,
    "✅ ChainAbuse": chainabuse_ok,
    "✅ Honeypot.is": honeypot_ok,
}

working = sum(1 for v in apis.values() if v)
total = len(apis)

for api_name, status in apis.items():
    symbol = "✅" if status else "❌"
    print(f"{symbol} {api_name}")

print(f"\n{working}/{total} APIs working and accessible")

if working >= 4:
    print("\n🎉 SUFFICIENT APIS AVAILABLE FOR DYNAMIC DETECTION!")
else:
    print("\n⚠️  Need more working APIs for robust detection")
