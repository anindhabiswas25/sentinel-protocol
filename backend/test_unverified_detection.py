#!/usr/bin/env python3
"""
Unverified Contract Detection Test
Tests both unverified safe and unsafe contracts
"""

import asyncio
import aiohttp
import json
from datetime import datetime

API_URL = "http://localhost:8001/api/v1/analyze"

# Real unverified contracts to test
TEST_CONTRACTS = {
    # Unverified SAFE contracts (Expected: 50-74, Risk: Medium)
    "UNVERIFIED_SAFE": [
        {
            "name": "Simple Token Contract",
            "address": "0x1234567890123456789012345678901234567890",
            "expected_min": 50,
            "expected_max": 74,
            "expected_risk": "Medium",
            "description": "Basic token without source code verification"
        },
        {
            "name": "Staking Pool (Unverified)",
            "address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "expected_min": 50,
            "expected_max": 74,
            "expected_risk": "Medium",
            "description": "Staking contract that hasn't been verified"
        },
    ],
    
    # Unverified UNSAFE contracts (Expected: 0-49, Risk: High/Critical)
    "UNVERIFIED_UNSAFE": [
        {
            "name": "Honeypot Token",
            "address": "0x60e4d636d1343d9d622ee5e17b0abf1457e1be4d",
            "expected_min": 0,
            "expected_max": 49,
            "expected_risk": "Critical",
            "description": "Token with hidden sell restrictions"
        },
        {
            "name": "Suspicious Contract",
            "address": "0x8888888888888888888888888888888888888888",
            "expected_min": 0,
            "expected_max": 49,
            "expected_risk": "High",
            "description": "Contract with suspicious patterns"
        },
        {
            "name": "Malicious Bytecode",
            "address": "0xfffffffffffffffffffffffffffffffffffffff0",
            "expected_min": 0,
            "expected_max": 49,
            "expected_risk": "High",
            "description": "Contract with dangerous bytecode patterns"
        },
    ]
}

async def test_contract(contract_info):
    """Test a single unverified contract"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                API_URL,
                json={
                    "contract_address": contract_info["address"],
                    "network": "ethereum"
                },
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status != 200:
                    return {
                        "passed": False,
                        "error": f"HTTP {response.status}",
                        "score": 0,
                        "risk": "ERROR"
                    }

                data = await response.json()
                score = data.get("trust_score", {}).get("overall_score", 0)
                risk = data.get("trust_score", {}).get("risk_level", "Unknown")
                method = data.get("summary", {}).get("analysis_method", "Unknown")
                is_verified = data.get("metadata", {}).get("is_verified", False)

                # Check if in expected range
                score_ok = contract_info["expected_min"] <= score <= contract_info["expected_max"]
                
                # For unverified unsafe, accept High or Critical
                if contract_info["expected_risk"] in ["High", "Critical"]:
                    risk_ok = risk in ["High", "Critical"]
                else:
                    risk_ok = risk == contract_info["expected_risk"]

                return {
                    "passed": score_ok and risk_ok and not is_verified,
                    "score": score,
                    "risk": risk,
                    "method": method,
                    "is_verified": is_verified,
                    "score_ok": score_ok,
                    "risk_ok": risk_ok,
                }

    except Exception as e:
        return {
            "passed": False,
            "error": str(e)[:100],
            "score": 0,
            "risk": "ERROR"
        }

async def main():
    print("\n" + "=" * 90)
    print("UNVERIFIED CONTRACT DETECTION TEST".center(90))
    print("=" * 90)
    print(f"\nTest Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    all_results = {}
    total_tests = 0
    total_passed = 0

    for category, contracts in TEST_CONTRACTS.items():
        print(f"\n{'=' * 90}")
        print(f"  {category}".ljust(90))
        print("=" * 90)

        if category == "UNVERIFIED_SAFE":
            print("Expected: Score 50-74 | Risk: Medium | Status: UNVERIFIED")
        else:
            print("Expected: Score 0-49 | Risk: High/Critical | Status: UNVERIFIED")
        print()

        category_results = []
        category_passed = 0

        for contract in contracts:
            print(f"Testing: {contract['name']}")
            print(f"  Address: {contract['address']}")
            print(f"  Description: {contract['description']}")
            
            result = await test_contract(contract)
            category_results.append((contract, result))

            if "error" in result:
                status = "❌ ERROR"
                print(f"  {status}: {result['error']}")
            else:
                status = "✅ PASS" if result["passed"] else "❌ FAIL"
                score_display = f"{result['score']:.1f}"
                
                print(f"  {status}")
                print(f"    Score: {score_display} (Expected: {contract['expected_min']}-{contract['expected_max']}) {'✅' if result['score_ok'] else '❌'}")
                print(f"    Risk: {result['risk']} (Expected: {contract['expected_risk']}) {'✅' if result['risk_ok'] else '❌'}")
                print(f"    Verified: {result['is_verified']} (Expected: False) {'✅' if not result['is_verified'] else '❌'}")
                print(f"    Method: {result['method']}")

                if result["passed"]:
                    category_passed += 1

            total_tests += 1
            if result.get("passed", False):
                total_passed += 1
            
            print()

        # Category summary
        pct = (category_passed / len(contracts) * 100) if contracts else 0
        print(f"Category Result: {category_passed}/{len(contracts)} PASSED ({pct:.0f}%)")

        all_results[category] = {
            "passed": category_passed,
            "total": len(contracts),
            "percentage": pct,
            "results": category_results,
        }

    # Final summary
    print("\n" + "=" * 90)
    print("FINAL RESULTS SUMMARY".center(90))
    print("=" * 90)

    print(f"\n  Total Tests: {total_tests}")
    print(f"  ✅ Passed: {total_passed}")
    print(f"  ❌ Failed: {total_tests - total_passed}")
    print(f"  Success Rate: {(total_passed/total_tests*100):.1f}%\n")

    print(f"  Category Breakdown:")
    for category, stats in all_results.items():
        pct = stats["percentage"]
        symbol = "✅" if stats["passed"] == stats["total"] else "⚠️ "
        print(f"    {symbol} {category:25} {stats['passed']:2}/{stats['total']:2} ({pct:5.1f}%)")

    # Final verdict
    print("\n" + "=" * 90)
    if total_passed == total_tests:
        print("🎉 PERFECT! All unverified contracts analyzed correctly!".center(90))
    elif total_passed >= total_tests * 0.7:
        print(f"✅ GOOD! {(total_passed/total_tests*100):.0f}% success rate".center(90))
        print("Unverified detection is working well!".center(90))
    else:
        print(f"⚠️  System needs improvement - {(total_passed/total_tests*100):.0f}% success rate".center(90))
    print("=" * 90 + "\n")

    # Analysis method breakdown
    print("\nDETECTION METHOD ANALYSIS:\n")
    
    print("📊 Unverified Safe Contracts:")
    safe_results = all_results.get("UNVERIFIED_SAFE", {}).get("results", [])
    for contract, result in safe_results:
        if "error" not in result:
            print(f"  • {contract['name']}: {result['method']}")
    
    print("\n📊 Unverified Unsafe Contracts:")
    unsafe_results = all_results.get("UNVERIFIED_UNSAFE", {}).get("results", [])
    for contract, result in unsafe_results:
        if "error" not in result:
            print(f"  • {contract['name']}: {result['method']}")

    # Save detailed results
    with open("test_results_unverified.json", "w") as f:
        json.dump(
            {
                "summary": {
                    "total": total_tests,
                    "passed": total_passed,
                    "failed": total_tests - total_passed,
                    "success_rate_percent": (total_passed / total_tests * 100),
                    "timestamp": datetime.now().isoformat(),
                },
                "categories": {
                    cat: {
                        "passed": stats["passed"],
                        "total": stats["total"],
                        "percentage": stats["percentage"],
                    }
                    for cat, stats in all_results.items()
                },
            },
            f,
            indent=2,
        )

    print(f"\n📁 Results saved: test_results_unverified.json\n")

    return total_passed >= total_tests * 0.7

if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⚠️  Test interrupted")
        exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
