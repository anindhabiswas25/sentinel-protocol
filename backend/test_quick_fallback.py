#!/usr/bin/env python3
"""
Quick Test Suite - Dynamic Analyzer with Fallback Support
Tests key contracts to verify the fallback mechanism is working
"""

import asyncio
import aiohttp
import json
from datetime import datetime

API_URL = "http://localhost:8001/api/v1/analyze"

# Test contracts - VERIFIED SAFE & KNOWN EXPLOITS
TEST_CONTRACTS = {
    # Verified Safe (should be 75-95)
    "USDT": {
        "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        "expected_min": 75,
        "expected_max": 95,
        "expected_risk": "Low",
        "type": "SAFE"
    },
    # Known Exploited (should be 0-24) - Tests Fallback
    "BadgerDAO": {
        "address": "0x19D97D8fA813EE2f51aD4B4e04EA08bAf4DFfC28",
        "expected_min": 0,
        "expected_max": 24,
        "expected_risk": "Critical",
        "type": "EXPLOITED"
    },
    # Old PolyNetwork ($611M exploit)
    "PolyNetwork": {
        "address": "0x250e76987d838a75310c34bf422ea9f1ac4cc906",
        "expected_min": 0,
        "expected_max": 24,
        "expected_risk": "Critical",
        "type": "EXPLOITED"
    },
    # Nomad Bridge ($190M exploit)
    "NomadBridge": {
        "address": "0x5d94309e5a0090b165fa4181519701637b6daeba",
        "expected_min": 0,
        "expected_max": 24,
        "expected_risk": "Critical",
        "type": "EXPLOITED"
    },
    # Tornado Cash (OFAC) - Tests Fallback
    "TornadoCash": {
        "address": "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
        "expected_min": 0,
        "expected_max": 24,
        "expected_risk": "Critical",
        "type": "OFAC"
    },
}

async def test_contract(contract_name, contract_info):
    """Test a single contract"""
    try:
        payload = {
            "contract_address": contract_info["address"],
            "network": "ethereum",
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(API_URL, json=payload, timeout=30) as response:
                if response.status != 200:
                    return {
                        "name": contract_name,
                        "passed": False,
                        "issue": f"API returned status {response.status}",
                    }

                data = await response.json()
                score = data.get("trust_score", {}).get("overall_score", 0)
                risk_level = data.get("trust_score", {}).get("risk_level", "Unknown")
                method = data.get("summary", {}).get("analysis_method", "Unknown")

                # Check if within expected range
                score_ok = contract_info["expected_min"] <= score <= contract_info["expected_max"]
                risk_ok = risk_level.lower() == contract_info["expected_risk"].lower()

                passed = score_ok and risk_ok

                return {
                    "name": contract_name,
                    "type": contract_info["type"],
                    "passed": passed,
                    "score": score,
                    "risk_level": risk_level,
                    "method": method,
                    "expected_score": f"{contract_info['expected_min']}-{contract_info['expected_max']}",
                    "expected_risk": contract_info["expected_risk"],
                    "issue": (
                        f"Score {score} not in {contract_info['expected_min']}-{contract_info['expected_max']}. "
                        if not score_ok else ""
                    ) + (
                        f"Risk '{risk_level}' != '{contract_info['expected_risk']}'"
                        if not risk_ok else ""
                    )
                }

    except Exception as e:
        return {
            "name": contract_name,
            "passed": False,
            "issue": f"Exception: {str(e)}",
        }

async def main():
    """Run tests"""
    print("\n" + "=" * 80)
    print("QUICK TEST - DYNAMIC ANALYZER WITH FALLBACK SUPPORT".center(80))
    print("=" * 80)
    print(f"\n🚀 Testing {len(TEST_CONTRACTS)} key contracts...")
    print(f"   API: {API_URL}")
    print(f"   Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Run tests sequentially
    results = []
    for i, (name, info) in enumerate(TEST_CONTRACTS.items(), 1):
        print(f"[{i}/{len(TEST_CONTRACTS)}] Testing {name}...", end=" ", flush=True)
        result = await test_contract(name, info)
        results.append(result)
        status = "✅ PASS" if result["passed"] else "❌ FAIL"
        print(status)

    # Print results
    print("\n" + "=" * 80)
    print("TEST RESULTS SUMMARY".center(80))
    print("=" * 80)

    passed = sum(1 for r in results if r["passed"])
    failed = len(results) - passed

    print(f"\n📊 Overall: {passed}/{len(results)} PASSED ({(passed/len(results)*100):.1f}%)\n")

    for result in results:
        status = "✅" if result["passed"] else "❌"
        print(f"{status} {result['name']:20} Type: {result.get('type', 'N/A'):10}")
        print(f"   Score: {result.get('score', 'N/A'):5.1f} (expected: {result.get('expected_score', 'N/A')})")
        print(f"   Risk:  {result.get('risk_level', 'N/A'):10} (expected: {result.get('expected_risk', 'N/A')})")
        print(f"   Method: {result.get('method', 'N/A')}")
        if result.get("issue"):
            print(f"   ⚠️  Issue: {result['issue']}")
        print()

    # Final verdict
    print("=" * 80)
    if failed == 0:
        print("🎉 ALL TESTS PASSED - DYNAMIC ANALYZER WITH FALLBACK IS WORKING!".center(80))
    else:
        print(f"⚠️  {failed} TEST(S) FAILED - REVIEW ABOVE".center(80))
    print("=" * 80 + "\n")

    # Save results
    with open("test_results_quick.json", "w") as f:
        json.dump(
            {
                "summary": {
                    "total": len(results),
                    "passed": passed,
                    "failed": failed,
                    "success_rate": (passed / len(results) * 100),
                },
                "results": results,
                "timestamp": datetime.now().isoformat(),
            },
            f,
            indent=2,
        )

    print("📁 Results saved to: test_results_quick.json\n")

    return failed == 0

if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        exit(1)
