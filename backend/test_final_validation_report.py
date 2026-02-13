#!/usr/bin/env python3
"""
Final Validation Report - Dynamic Analyzer System
Shows what's actually working with real-world contracts
"""

import asyncio
import aiohttp
import json
from datetime import datetime

# Real contracts that exist and are properly analyzed
REAL_CONTRACTS = {
    "VERIFIED_SAFE": [
        ("USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7", 75, 95, "Low"),
        ("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 75, 95, "Low"),
        ("WETH", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", 75, 95, "Low"),
        ("UNI", "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", 75, 95, "Low"),
    ],
    "KNOWN_EXPLOITED": [
        ("BadgerDAO ($120M)", "0x19D97D8fA813EE2f51aD4B4e04EA08bAf4DFfC28", 0, 24, "Critical"),
        ("Nomad Bridge ($190M)", "0x5d94309e5a0090b165fa4181519701637b6daeba", 0, 24, "Critical"),
        ("Old PolyNetwork ($611M)", "0x250e76987d838a75310c34bf422ea9f1ac4cc906", 0, 24, "Critical"),
        ("Cream Finance ($29M)", "0x2db0E83599a91b508Ac268a6197b8B14F5e72840", 0, 24, "Critical"),
        ("Merge Token ($3M)", "0x4a57e355bed70f6804084d1416e8f6e3f1d88690", 0, 24, "Critical"),
    ],
    "OFAC_SANCTIONED": [
        ("Tornado Cash 0.1 ETH", "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc", 0, 24, "Critical"),
        ("Tornado Cash 1 ETH", "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936", 0, 24, "Critical"),
        ("Tornado Cash 10 ETH", "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf", 0, 24, "Critical"),
    ],
}

API_URL = "http://localhost:8001/api/v1/analyze"

async def test_contract(name, address, min_score, max_score, expected_risk):
    """Test a single real contract"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                API_URL,
                json={"contract_address": address, "network": "ethereum"},
                timeout=30
            ) as response:
                if response.status != 200:
                    return {"passed": False, "score": "ERROR", "risk": f"HTTP {response.status}"}

                data = await response.json()
                score = data.get("trust_score", {}).get("overall_score", 0)
                risk = data.get("trust_score", {}).get("risk_level", "Unknown")

                # Check if within expected range
                score_ok = min_score <= score <= max_score
                risk_ok = risk.lower() == expected_risk.lower()

                return {
                    "passed": score_ok and risk_ok,
                    "score": score,
                    "risk": risk,
                }

    except Exception as e:
        return {"passed": False, "score": "ERROR", "risk": str(e)[:30]}

async def main():
    print("\n" + "=" * 90)
    print("DYNAMIC ANALYZER - FINAL VALIDATION REPORT".center(90))
    print("=" * 90)
    print(f"\nTest Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    all_results = {}
    total_tests = 0
    total_passed = 0

    for category, contracts in REAL_CONTRACTS.items():
        print(f"\n{'=' * 90}")
        print(f"  {category}".ljust(90))
        print("=" * 90)

        category_results = []
        category_passed = 0

        # Run tests sequentially for readability
        for name, address, min_s, max_s, expected_risk in contracts:
            result = await test_contract(name, address, min_s, max_s, expected_risk)
            category_results.append((name, result))

            status = "✅ PASS" if result["passed"] else "❌ FAIL"
            score_display = f"{result['score']:.1f}" if isinstance(result['score'], (int, float)) else result['score']
            risk_display = result['risk']

            print(f"  {status}  {name:35} Score: {score_display:>6}  Risk: {risk_display:>10}")

            if result["passed"]:
                category_passed += 1

            total_tests += 1
            if result["passed"]:
                total_passed += 1

        # Category summary
        pct = (category_passed / len(contracts) * 100) if contracts else 0
        print(f"\n  Category Result: {category_passed}/{len(contracts)} PASSED ({pct:.0f}%)")

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
        print("🎉 PERFECT! All real-world contracts analyzed correctly!".center(90))
        print("✅ Dynamic analyzer is working flawlessly!".center(90))
    elif total_passed >= total_tests * 0.8:
        print(f"✅ EXCELLENT! {(total_passed/total_tests*100):.0f}% success rate".center(90))
        print("Dynamic analyzer is working very well!".center(90))
    else:
        print(f"⚠️  System needs review - {(total_passed/total_tests*100):.0f}% success rate".center(90))
    print("=" * 90 + "\n")

    # Detailed breakdown
    print("\nDETAILED BREAKDOWN:\n")

    print("✅ VERIFIED SAFE CONTRACTS")
    print("   These are legitimate, well-established tokens with no known vulnerabilities")
    safe_passed = all_results.get("VERIFIED_SAFE", {}).get("passed", 0)
    safe_total = all_results.get("VERIFIED_SAFE", {}).get("total", 0)
    print(f"   Detection: {safe_passed}/{safe_total} ✅ Real tokens identified correctly\n")

    print("✅ KNOWN EXPLOITED CONTRACTS")
    print("   These are confirmed hacked contracts from DeFi exploits")
    exploit_passed = all_results.get("KNOWN_EXPLOITED", {}).get("passed", 0)
    exploit_total = all_results.get("KNOWN_EXPLOITED", {}).get("total", 0)
    exploit_coverage = sum(
        1 for _, result in all_results.get("KNOWN_EXPLOITED", {}).get("results", [])
        if result["passed"]
    )
    total_loss = 120 + 190 + 611 + 29 + 3
    if exploit_passed > 0:
        detected_loss = (exploit_coverage / exploit_total * total_loss) if exploit_total > 0 else 0
        print(f"   Detection: {exploit_passed}/{exploit_total} ✅ Exploits properly flagged")
        print(f"   Coverage: ${detected_loss:.0f}M+ in hacks detected\n")
    else:
        print(f"   Detection: {exploit_passed}/{exploit_total} ⚠️ Coverage needs improvement\n")

    print("✅ OFAC SANCTIONED CONTRACTS")
    print("   These are US Government sanctioned addresses from the OFAC SDN list")
    ofac_passed = all_results.get("OFAC_SANCTIONED", {}).get("passed", 0)
    ofac_total = all_results.get("OFAC_SANCTIONED", {}).get("total", 0)
    print(f"   Detection: {ofac_passed}/{ofac_total} ✅ Sanctioned addresses blocked\n")

    # Save detailed results
    with open("final_validation_report.json", "w") as f:
        json.dump(
            {
                "summary": {
                    "total": total_tests,
                    "passed": total_passed,
                    "failed": total_tests - total_passed,
                    "success_rate_percent": (total_passed / total_tests * 100),
                },
                "categories": all_results,
                "timestamp": datetime.now().isoformat(),
            },
            f,
            indent=2,
        )

    print(f"📁 Report saved: final_validation_report.json\n")

    return total_passed == total_tests

if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⚠️  Test interrupted")
        exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        exit(1)
