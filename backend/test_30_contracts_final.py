#!/usr/bin/env python3
"""
Comprehensive 30 Contract Test Suite - Optimized Version
Tests all 30 contract types to validate the dynamic analyzer
"""

import asyncio
import aiohttp
import json
import time
from datetime import datetime
from collections import defaultdict

# Test contracts from test.md
TEST_CONTRACTS = {
    # Category 1: Verified Safe (10)
    "1_USDT": ("0xdAC17F958D2ee523a2206206994597C13D831ec7", 88, 95, "Low", "SAFE"),
    "2_USDC": ("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 90, 95, "Low", "SAFE"),
    "3_WETH": ("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", 93, 95, "Low", "SAFE"),
    "4_DAI": ("0x6B175474E89094C44Da98b954EedeAC495271d0F", 85, 92, "Low", "SAFE"),
    "5_LINK": ("0x514910771AF9Ca656af840dff83E8264EcF986CA", 88, 94, "Low", "SAFE"),
    "6_AAVE": ("0x7Fc66500c84A76Ad7e9c93437E434122A1f9AcDd", 85, 92, "Low", "SAFE"),
    "7_SHIB": ("0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE", 70, 85, "Low", "SAFE"),
    "8_CRV": ("0xD533a949740bb3306d119CC777fa900bA034cd52", 80, 90, "Low", "SAFE"),
    "9_UNI": ("0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", 88, 95, "Low", "SAFE"),
    "10_MATIC": ("0x7D1AfA7B718fb893dB30A3aBc0Cfc608AaCfeBB0", 85, 92, "Low", "SAFE"),

    # Category 2: Known Exploited (8)
    "11_BadgerDAO": ("0x19D97D8fA813EE2f51aD4B4e04EA08bAf4DFfC28", 0, 24, "Critical", "EXPLOIT"),
    "12_NomadBridge": ("0x5d94309e5a0090b165fa4181519701637b6daeba", 0, 24, "Critical", "EXPLOIT"),
    "13_PolyNetwork": ("0x250e76987d838a75310c34bf422ea9f1ac4cc906", 0, 24, "Critical", "EXPLOIT"),
    "14_CreamFinance": ("0x2db0E83599a91b508Ac268a6197b8B14F5e72840", 0, 24, "Critical", "EXPLOIT"),
    "15_MergeToken": ("0x4a57e355bed70f6804084d1416e8f6e3f1d88690", 0, 24, "Critical", "EXPLOIT"),
    "16_YearnV1": ("0x5dbcF33D8c2E976c6b560249878e6F1491Bca25c", 25, 40, "High", "EXPLOIT"),
    "17_DForce": ("0x02285AcaafEB533e03A7306C55EC031297df9224", 0, 24, "Critical", "EXPLOIT"),
    "18_TornadoCash": ("0xd90e2f925da726b50c4ed8d0fb90ad053324f31b", 0, 24, "Critical", "EXPLOIT"),

    # Category 3: Unverified (5)
    "19_Unverified1": ("0x1234567890123456789012345678901234567890", 45, 65, "Medium", "UNVERIFIED"),
    "20_Unverified2": ("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd", 50, 70, "Medium", "UNVERIFIED"),
    "21_HoneypotUnverified": ("0x60e4d636d1343d9d622ee5e17b0abf1457e1be4d", 0, 30, "Critical", "UNVERIFIED"),
    "22_Malicious": ("0x8888888888888888888888888888888888888888", 10, 40, "High", "UNVERIFIED"),
    "23_LowLiquidity": ("0xfffffffffffffffffffffffffffffffffffffff0", 30, 50, "High", "UNVERIFIED"),

    # Category 4: OFAC (3)
    "24_TC_0.1": ("0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc", 0, 24, "Critical", "OFAC"),
    "25_TC_1": ("0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936", 0, 24, "Critical", "OFAC"),
    "26_TC_10": ("0x910cbd523d972eb0a6f4cae4618ad62622b39dbf", 0, 24, "Critical", "OFAC"),

    # Category 5: Honeypot/Scam (2)
    "27_ClassicFloki": ("0xF42c318dbfBaab0EEE040279c6A2588Fa01a961d", 5, 15, "Critical", "HONEYPOT"),
    "28_PandD": ("0xaabbccddaabbccddaabbccddaabbccddaabbccdd", 10, 25, "Critical", "HONEYPOT"),

    # Category 6: Edge Cases (2)
    "29_ZeroAddress": ("0x0000000000000000000000000000000000000000", 0, 100, "Unknown", "EDGE"),
    "30_InvalidAddress": ("0xINVALIDINVALIDINVALIDINVALIDINVALIDINVA", 0, 100, "Unknown", "EDGE"),
}

API_URL = "http://localhost:8001/api/v1/analyze"

async def test_contract(name, address, expected_min, expected_max, expected_risk):
    """Test a single contract"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                API_URL,
                json={"contract_address": address, "network": "ethereum"},
                timeout=30
            ) as response:
                if response.status != 200:
                    return {
                        "passed": False,
                        "issue": f"HTTP {response.status}",
                    }

                data = await response.json()
                score = data.get("trust_score", {}).get("overall_score", 0)
                risk = data.get("trust_score", {}).get("risk_level", "Unknown")
                method = data.get("summary", {}).get("analysis_method", "Unknown")

                score_ok = expected_min <= score <= expected_max
                risk_ok = risk.lower() == expected_risk.lower() or expected_risk == "Unknown"

                return {
                    "passed": score_ok and risk_ok,
                    "score": score,
                    "risk": risk,
                    "method": method,
                }

    except Exception as e:
        return {
            "passed": False,
            "issue": str(e),
        }

async def main():
    print("\n" + "=" * 80)
    print("COMPREHENSIVE 30-CONTRACT TEST SUITE".center(80))
    print("=" * 80)
    print(f"\n🚀 Testing {len(TEST_CONTRACTS)} contracts...")
    print(f"   Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    results = []
    passed = 0
    failed = 0
    stats = defaultdict(lambda: {"passed": 0, "failed": 0})

    start = time.time()

    # Run tests with concurrency limit
    semaphore = asyncio.Semaphore(3)  # Max 3 concurrent requests

    async def limited_test(name, addr, min_s, max_s, risk, category):
        async with semaphore:
            result = await test_contract(name, addr, min_s, max_s, risk)
            status = "✅" if result["passed"] else "❌"
            print(f"[{name:15}] {status}", end="\n" if name.endswith("_OFAC") else "", flush=True)
            return name, category, result

    tasks = [
        limited_test(name, addr, min_s, max_s, risk, category)
        for name, (addr, min_s, max_s, risk, category) in TEST_CONTRACTS.items()
    ]

    test_results = await asyncio.gather(*tasks)

    for name, category, result in test_results:
        results.append((name, category, result))
        if result["passed"]:
            passed += 1
            stats[category]["passed"] += 1
        else:
            failed += 1
            stats[category]["failed"] += 1

    elapsed = time.time() - start

    # Print summary
    print("\n" + "=" * 80)
    print("RESULTS SUMMARY".center(80))
    print("=" * 80)

    print(f"\n📊 Overall Statistics:")
    print(f"   Total Tests: {len(TEST_CONTRACTS)}")
    print(f"   ✅ Passed: {passed}")
    print(f"   ❌ Failed: {failed}")
    print(f"   Success Rate: {(passed/len(TEST_CONTRACTS)*100):.1f}%")
    print(f"   Execution Time: {elapsed:.1f}s")

    print(f"\n📈 By Category:")
    for category in ["SAFE", "EXPLOIT", "OFAC", "UNVERIFIED", "HONEYPOT", "EDGE"]:
        if category in stats:
            s = stats[category]
            total = s["passed"] + s["failed"]
            pct = (s["passed"] / total * 100) if total > 0 else 0
            symbol = "✅" if s["failed"] == 0 else "⚠️ "
            print(f"   {symbol} {category:12} {s['passed']:2}/{total:2} PASSED ({pct:5.1f}%)")

    # Detailed results
    print(f"\n📋 Detailed Results:")
    print("-" * 80)
    current_category = None
    for name, category, result in results:
        if current_category != category:
            print(f"\n{category}:")
            current_category = category

        status = "✅" if result["passed"] else "❌"
        print(f"  {status} {name:20} ", end="")
        if result["passed"]:
            print(f"Score: {result['score']:5.1f}, Risk: {result['risk']:10}, Method: {result['method']}")
        else:
            print(f"❌ {result.get('issue', 'Failed')}")

    # Final verdict
    print("\n" + "=" * 80)
    if failed == 0:
        print(f"🎉 ALL {len(TEST_CONTRACTS)} TESTS PASSED!".center(80))
        print("✅ Dynamic Analyzer is working perfectly!".center(80))
    else:
        print(f"⚠️  {failed}/{len(TEST_CONTRACTS)} tests failed".center(80))
    print("=" * 80 + "\n")

    # Save results
    with open("test_results_30_final.json", "w") as f:
        json.dump(
            {
                "summary": {
                    "total": len(TEST_CONTRACTS),
                    "passed": passed,
                    "failed": failed,
                    "success_rate": (passed / len(TEST_CONTRACTS) * 100),
                    "execution_time_seconds": elapsed,
                },
                "results": [
                    {
                        "name": name,
                        "category": category,
                        "passed": result["passed"],
                        "score": result.get("score"),
                        "risk": result.get("risk"),
                        "method": result.get("method"),
                    }
                    for name, category, result in results
                ],
            },
            f,
            indent=2,
        )

    print(f"📁 Results saved: test_results_30_final.json\n")

    return failed == 0

if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
        exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
