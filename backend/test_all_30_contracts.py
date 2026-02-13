#!/usr/bin/env python3
"""
Comprehensive Test Suite for Dynamic Analyzer - All 30 Contracts
Tests the dynamic exploit detection system against 30 different contract types
"""

import asyncio
import aiohttp
import json
import time
from datetime import datetime
from collections import defaultdict

# Test contracts from test.md
TEST_CONTRACTS = {
    # Category 1: Verified Safe Contracts (10)
    "1_USDT": {
        "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        "name": "USDT (Tether)",
        "category": "Verified Safe",
        "expected_score_min": 88,
        "expected_score_max": 95,
        "expected_risk": "Low",
    },
    "2_USDC": {
        "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "name": "USDC (Circle)",
        "category": "Verified Safe",
        "expected_score_min": 90,
        "expected_score_max": 95,
        "expected_risk": "Low",
    },
    "3_WETH": {
        "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        "name": "WETH (Wrapped Ether)",
        "category": "Verified Safe",
        "expected_score_min": 93,
        "expected_score_max": 95,
        "expected_risk": "Low",
    },
    "4_DAI": {
        "address": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
        "name": "DAI (MakerDAO)",
        "category": "Verified Safe",
        "expected_score_min": 85,
        "expected_score_max": 92,
        "expected_risk": "Low",
    },
    "5_LINK": {
        "address": "0x514910771AF9Ca656af840dff83E8264EcF986CA",
        "name": "LINK (Chainlink)",
        "category": "Verified Safe",
        "expected_score_min": 88,
        "expected_score_max": 94,
        "expected_risk": "Low",
    },
    "6_AAVE": {
        "address": "0x7Fc66500c84A76Ad7e9c93437E434122A1f9AcDd",
        "name": "AAVE (Aave)",
        "category": "Verified Safe",
        "expected_score_min": 85,
        "expected_score_max": 92,
        "expected_risk": "Low",
    },
    "7_SHIB": {
        "address": "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE",
        "name": "SHIB (Shiba Inu)",
        "category": "Verified Safe",
        "expected_score_min": 70,
        "expected_score_max": 85,
        "expected_risk": "Low",
    },
    "8_CRV": {
        "address": "0xD533a949740bb3306d119CC777fa900bA034cd52",
        "name": "CRV (Curve)",
        "category": "Verified Safe",
        "expected_score_min": 80,
        "expected_score_max": 90,
        "expected_risk": "Low",
    },
    "9_UNI": {
        "address": "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",
        "name": "UNI (Uniswap)",
        "category": "Verified Safe",
        "expected_score_min": 88,
        "expected_score_max": 95,
        "expected_risk": "Low",
    },
    "10_MATIC": {
        "address": "0x7D1AfA7B718fb893dB30A3aBc0Cfc608AaCfeBB0",
        "name": "MATIC (Polygon)",
        "category": "Verified Safe",
        "expected_score_min": 85,
        "expected_score_max": 92,
        "expected_risk": "Low",
    },

    # Category 2: Known Exploited Contracts (8)
    "11_BadgerDAO": {
        "address": "0x19D97D8fA813EE2f51aD4B4e04EA08bAf4DFfC28",
        "name": "BadgerDAO (Exploited - $120M)",
        "category": "Exploited",
        "expected_score_min": 0,
        "expected_score_max": 24,
        "expected_risk": "Critical",
    },
    "12_NomadBridge": {
        "address": "0x5d94309e5a0090b165fa4181519701637b6daeba",
        "name": "Nomad Bridge (Exploited - $190M)",
        "category": "Exploited",
        "expected_score_min": 0,
        "expected_score_max": 24,
        "expected_risk": "Critical",
    },
    "13_OldPolyNetwork": {
        "address": "0x250e76987d838a75310c34bf422ea9f1ac4cc906",
        "name": "Old PolyNetwork (Exploited - $611M)",
        "category": "Exploited",
        "expected_score_min": 0,
        "expected_score_max": 24,
        "expected_risk": "Critical",
    },
    "14_CreamFinance": {
        "address": "0x2db0E83599a91b508Ac268a6197b8B14F5e72840",
        "name": "Cream Finance (Exploited - $29M)",
        "category": "Exploited",
        "expected_score_min": 0,
        "expected_score_max": 24,
        "expected_risk": "Critical",
    },
    "15_MergeToken": {
        "address": "0x4a57e355bed70f6804084d1416e8f6e3f1d88690",
        "name": "Merge Token (Exploited - $3M)",
        "category": "Exploited",
        "expected_score_min": 0,
        "expected_score_max": 24,
        "expected_risk": "Critical",
    },
    "16_YearnV1": {
        "address": "0x5dbcF33D8c2E976c6b560249878e6F1491Bca25c",
        "name": "Yearn V1 (Deprecated)",
        "category": "Exploited",
        "expected_score_min": 25,
        "expected_score_max": 40,
        "expected_risk": "High",
    },
    "17_DForce": {
        "address": "0x02285AcaafEB533e03A7306C55EC031297df9224",
        "name": "DForce (Exploited - $25M)",
        "category": "Exploited",
        "expected_score_min": 0,
        "expected_score_max": 24,
        "expected_risk": "Critical",
    },
    "18_TornadoCash": {
        "address": "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
        "name": "Tornado Cash (OFAC - Router)",
        "category": "Exploited",
        "expected_score_min": 0,
        "expected_score_max": 24,
        "expected_risk": "Critical",
    },

    # Category 3: Unverified Contracts (5)
    "19_Unverified1": {
        "address": "0x1234567890123456789012345678901234567890",
        "name": "Random Unverified 1",
        "category": "Unverified",
        "expected_score_min": 45,
        "expected_score_max": 65,
        "expected_risk": "Medium",
    },
    "20_Unverified2": {
        "address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        "name": "Random Unverified 2",
        "category": "Unverified",
        "expected_score_min": 50,
        "expected_score_max": 70,
        "expected_risk": "Medium",
    },
    "21_HoneypotUnverified": {
        "address": "0x60e4d636d1343d9d622ee5e17b0abf1457e1be4d",
        "name": "Honeypot (Unverified)",
        "category": "Unverified",
        "expected_score_min": 0,
        "expected_score_max": 30,
        "expected_risk": "Critical",
    },
    "22_Malicious": {
        "address": "0x8888888888888888888888888888888888888888",
        "name": "Malicious (Unverified)",
        "category": "Unverified",
        "expected_score_min": 10,
        "expected_score_max": 40,
        "expected_risk": "High",
    },
    "23_LowLiquidity": {
        "address": "0xfffffffffffffffffffffffffffffffffffffff0",
        "name": "Low Liquidity (Unverified)",
        "category": "Unverified",
        "expected_score_min": 30,
        "expected_score_max": 50,
        "expected_risk": "High",
    },

    # Category 4: OFAC Sanctioned (3)
    "24_TornadoCash0.1": {
        "address": "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc",
        "name": "Tornado Cash 0.1 ETH",
        "category": "OFAC",
        "expected_score_min": 0,
        "expected_score_max": 24,
        "expected_risk": "Critical",
    },
    "25_TornadoCash1": {
        "address": "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936",
        "name": "Tornado Cash 1 ETH",
        "category": "OFAC",
        "expected_score_min": 0,
        "expected_score_max": 24,
        "expected_risk": "Critical",
    },
    "26_TornadoCash10": {
        "address": "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf",
        "name": "Tornado Cash 10 ETH",
        "category": "OFAC",
        "expected_score_min": 0,
        "expected_score_max": 24,
        "expected_risk": "Critical",
    },

    # Category 5: Honeypot/Scam (2)
    "27_ClassicFloki": {
        "address": "0xF42c318dbfBaab0EEE040279c6A2588Fa01a961d",
        "name": "ClassicFloki (Honeypot)",
        "category": "Honeypot",
        "expected_score_min": 5,
        "expected_score_max": 15,
        "expected_risk": "Critical",
    },
    "28_PandD": {
        "address": "0xaabbccddaabbccddaabbccddaabbccddaabbccdd",
        "name": "Pump & Dump Scheme",
        "category": "Honeypot",
        "expected_score_min": 10,
        "expected_score_max": 25,
        "expected_risk": "Critical",
    },

    # Category 6: Edge Cases (2)
    "29_ZeroAddress": {
        "address": "0x0000000000000000000000000000000000000000",
        "name": "Null Address",
        "category": "EdgeCase",
        "expected_score_min": 0,
        "expected_score_max": 100,
        "expected_risk": "Unknown",
    },
    "30_InvalidAddress": {
        "address": "0xINVALIDINVALIDINVALIDINVALIDINVALIDINVA",
        "name": "Invalid Address",
        "category": "EdgeCase",
        "expected_score_min": 0,
        "expected_score_max": 100,
        "expected_risk": "Unknown",
    },
}

API_URL = "http://localhost:8001/api/v1/analyze"


class TestResults:
    def __init__(self):
        self.results = []
        self.passed = 0
        self.failed = 0
        self.stats_by_category = defaultdict(lambda: {"passed": 0, "failed": 0, "total": 0})
        self.detection_methods = defaultdict(int)

    def add_result(self, test_id, name, category, result):
        self.results.append(
            {
                "id": test_id,
                "name": name,
                "category": category,
                "result": result,
                "timestamp": datetime.now().isoformat(),
            }
        )

        if result["passed"]:
            self.passed += 1
            self.stats_by_category[category]["passed"] += 1
        else:
            self.failed += 1
            self.stats_by_category[category]["failed"] += 1

        self.stats_by_category[category]["total"] += 1

        if "detection_method" in result:
            self.detection_methods[result["detection_method"]] += 1

    def print_summary(self):
        print("\n" + "=" * 80)
        print("COMPREHENSIVE TEST RESULTS - ALL 30 CONTRACTS".center(80))
        print("=" * 80)

        print(f"\n📊 OVERALL STATISTICS")
        print(f"   Total Tests: {len(self.results)}")
        print(f"   ✅ Passed: {self.passed}")
        print(f"   ❌ Failed: {self.failed}")
        print(f"   Success Rate: {(self.passed / len(self.results) * 100):.1f}%")

        print(f"\n📈 RESULTS BY CATEGORY")
        for category in sorted(self.stats_by_category.keys()):
            stats = self.stats_by_category[category]
            pass_rate = (
                (stats["passed"] / stats["total"] * 100)
                if stats["total"] > 0
                else 0
            )
            symbol = "✅" if stats["failed"] == 0 else "❌"
            print(
                f"   {symbol} {category:20} {stats['passed']:2}/{stats['total']:2} PASSED ({pass_rate:5.1f}%)"
            )

        print(f"\n🔍 DETECTION METHODS USED")
        for method, count in sorted(
            self.detection_methods.items(), key=lambda x: x[1], reverse=True
        ):
            print(f"   • {method}: {count} detections")

        print(f"\n📋 DETAILED RESULTS")
        print("-" * 80)

        for result in self.results:
            passed = result["result"]["passed"]
            status_icon = "✅" if passed else "❌"
            print(
                f"{status_icon} {result['id']:30} {result['name']}\n"
                f"   Category: {result['category']}\n"
                f"   Score: {result['result'].get('score', 'N/A')}\n"
                f"   Risk: {result['result'].get('risk_level', 'N/A')}\n"
                f"   Method: {result['result'].get('detection_method', 'N/A')}\n"
            )
            if not passed:
                print(f"   Issue: {result['result'].get('issue', 'Unknown')}\n")


async def test_contract(session, test_id, contract_info):
    """Test a single contract against the analyzer API"""

    try:
        payload = {
            "contract_address": contract_info["address"],
            "network": "ethereum",
        }

        start_time = time.time()
        async with session.post(API_URL, json=payload) as response:
            elapsed = time.time() - start_time

            if response.status != 200:
                return {
                    "passed": False,
                    "issue": f"API returned status {response.status}",
                    "response_time": elapsed,
                }

            data = await response.json()

            score = data.get("trust_score", {}).get("overall_score", 0)
            risk_level = data.get("trust_score", {}).get("risk_level", "Unknown")
            analysis_method = data.get("summary", {}).get("analysis_method", "Unknown")

            # Validate score is within expected range
            score_ok = (
                contract_info["expected_score_min"]
                <= score
                <= contract_info["expected_score_max"]
            )

            # Validate risk level matches expected (allow some flexibility)
            risk_ok = (
                risk_level.lower() == contract_info["expected_risk"].lower()
                or contract_info["expected_risk"] == "Unknown"
            )

            passed = score_ok and risk_ok
            issue = ""

            if not score_ok:
                issue += f"Score {score} not in expected range [{contract_info['expected_score_min']}-{contract_info['expected_score_max']}]. "

            if not risk_ok:
                issue += (
                    f"Risk '{risk_level}' doesn't match expected '{contract_info['expected_risk']}'"
                )

            return {
                "passed": passed,
                "score": score,
                "risk_level": risk_level,
                "detection_method": analysis_method,
                "response_time": elapsed,
                "issue": issue,
                "full_response": data,
            }

    except Exception as e:
        return {
            "passed": False,
            "issue": f"Exception: {str(e)}",
            "response_time": 0,
        }


async def run_all_tests():
    """Run all 30 contract tests"""

    results = TestResults()

    print("\n🚀 Starting Dynamic Analyzer Test Suite...")
    print(f"   Target API: {API_URL}")
    print(f"   Total Tests: {len(TEST_CONTRACTS)}")
    print(f"   Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    async with aiohttp.ClientSession() as session:
        tasks = []
        for test_id, contract_info in TEST_CONTRACTS.items():
            task = test_contract(session, test_id, contract_info)
            tasks.append((test_id, contract_info, task))

        # Run tests with progress indication
        for idx, (test_id, contract_info, task) in enumerate(tasks, 1):
            print(
                f"\r   Progress: {idx}/{len(TEST_CONTRACTS)} tests running...",
                end="",
                flush=True,
            )
            result = await task
            results.add_result(test_id, contract_info["name"], contract_info["category"], result)

        print("\r" + " " * 50 + "\r", end="")  # Clear progress line

    return results


async def main():
    """Main test execution"""

    try:
        results = await run_all_tests()
        results.print_summary()

        # Final verdict
        print("\n" + "=" * 80)
        if results.failed == 0:
            print("🎉 ALL TESTS PASSED - DYNAMIC ANALYZER IS WORKING CORRECTLY!".center(80))
        else:
            print(
                f"⚠️  {results.failed} TESTS FAILED - REVIEW RESULTS ABOVE".center(80)
            )
        print("=" * 80 + "\n")

        # Save detailed results
        with open("test_results_30_contracts.json", "w") as f:
            json.dump(
                {
                    "summary": {
                        "total": len(results.results),
                        "passed": results.passed,
                        "failed": results.failed,
                        "success_rate": (results.passed / len(results.results) * 100),
                    },
                    "results": results.results,
                    "detection_methods": dict(results.detection_methods),
                    "category_stats": {
                        k: dict(v) for k, v in results.stats_by_category.items()
                    },
                },
                f,
                indent=2,
            )
        print("📁 Detailed results saved to: test_results_30_contracts.json")

    except Exception as e:
        print(f"\n❌ Test execution failed: {str(e)}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
