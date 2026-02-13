"""
Batch test script for testing multiple contracts from testcontract.md
"""

import requests
import json
import time
from typing import List, Dict

API_URL = "http://localhost:8000/api/v1/analyze"

# Test contracts from testcontract.md
TEST_CONTRACTS = [
    # Category 1: Verified Safe (Expected 75-95)
    {"address": "0xdAC17F958D2ee523a2206206994597C13D831ec7", "name": "USDT", "expected_score": 82, "category": "Verified Safe"},
    {"address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "name": "USDC", "expected_score": 90, "category": "Verified Safe"},
    {"address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "name": "WETH", "expected_score": 93, "category": "Verified Safe"},
    {"address": "0x6B175474E89094C44Da98b954EedeAC495271d0F", "name": "DAI", "expected_score": 88, "category": "Verified Safe"},
    
    # Category 2: Verified Unsafe (Expected 25-49)
    {"address": "0x4a57E687b9126435a9B19E4A802113e266AdeBde", "name": "Merge Token (Reentrancy)", "expected_score": 35, "category": "Verified Unsafe"},
    {"address": "0x5dbcF33D8c2E976c6b560249878e6F1491Bca25c", "name": "Yearn v1 Vault", "expected_score": 42, "category": "Verified Unsafe"},
    
    # Category 3: Unverified Safe (Expected 50-74)
    {"address": "0x1234567890123456789012345678901234567890", "name": "Example Unverified", "expected_score": 58, "category": "Unverified Safe"},
    
    # Category 4: Unverified Unsafe (Expected 0-24)
    # These addresses need to be real unverified contracts for testing
]

def analyze_contract(address: str, network: str = "ethereum", force_refresh: bool = True) -> Dict:
    """Call the analyze API endpoint"""
    try:
        response = requests.post(
            API_URL,
            json={
                "contract_address": address,
                "network": network,
                "force_refresh": force_refresh
            },
            timeout=120
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"success": False, "error": str(e)}

def get_score_category(score: float) -> str:
    """Determine category based on score"""
    if score >= 75:
        return "🟢 Verified Safe (75-95)"
    elif score >= 50:
        return "🟡 Unverified Safe (50-74)"
    elif score >= 25:
        return "🟠 Verified Unsafe (25-49)"
    else:
        return "🔴 Unverified Unsafe (0-24)"

def run_batch_test():
    """Run batch analysis on all test contracts"""
    results = []
    
    print("=" * 100)
    print("SENTINEL PROTOCOL - BATCH CONTRACT TESTING")
    print("=" * 100)
    print()
    
    for i, contract in enumerate(TEST_CONTRACTS, 1):
        print(f"[{i}/{len(TEST_CONTRACTS)}] Testing: {contract['name']} ({contract['address'][:10]}...)")
        print(f"    Expected Category: {contract['category']} (Score: {contract['expected_score']})")
        
        # Analyze contract
        result = analyze_contract(contract['address'])
        
        if not result.get("success", False):
            print(f"    ❌ FAILED: {result.get('error', 'Unknown error')}")
            results.append({
                **contract,
                "actual_score": 0,
                "status": "ERROR",
                "error": result.get('error', 'Unknown')
            })
            print()
            continue
        
        # Extract results
        actual_score = result["trust_score"]["overall_score"]
        is_verified = result["metadata"]["is_verified"]
        risk_level = result["trust_score"]["risk_level"]
        vuln_count = result["summary"]["total_vulnerabilities"]
        analysis_method = result["summary"]["analysis_method"]
        detected_category = get_score_category(actual_score)
        
        # Calculate accuracy
        score_diff = abs(actual_score - contract['expected_score'])
        in_expected_range = (
            (contract['category'] == "Verified Safe" and 75 <= actual_score <= 95) or
            (contract['category'] == "Verified Unsafe" and 25 <= actual_score <= 49) or
            (contract['category'] == "Unverified Safe" and 50 <= actual_score <= 74) or
            (contract['category'] == "Unverified Unsafe" and 0 <= actual_score <= 24)
        )
        
        status = "✅ PASS" if in_expected_range else "⚠️ DIFF"
        
        print(f"    Actual Score: {actual_score:.1f}/100 ({detected_category})")
        print(f"    Verified: {is_verified} | Risk: {risk_level} | Method: {analysis_method}")
        print(f"    Vulnerabilities: {vuln_count} | Difference: {score_diff:.1f} points")
        print(f"    {status}")
        print()
        
        results.append({
            **contract,
            "actual_score": actual_score,
            "score_diff": score_diff,
            "is_verified": is_verified,
            "risk_level": risk_level,
            "vuln_count": vuln_count,
            "analysis_method": analysis_method,
            "detected_category": detected_category,
            "status": status
        })
        
        # Rate limiting delay
        time.sleep(2)
    
    # Print summary
    print("=" * 100)
    print("TEST SUMMARY")
    print("=" * 100)
    print()
    
    passed = sum(1 for r in results if "PASS" in r['status'])
    total = len(results)
    pass_rate = (passed / total * 100) if total > 0 else 0
    
    print(f"Tests Passed: {passed}/{total} ({pass_rate:.1f}%)")
    print()
    
    # Category breakdown
    print("Category Accuracy:")
    for category in ["Verified Safe", "Verified Unsafe", "Unverified Safe", "Unverified Unsafe"]:
        cat_results = [r for r in results if r['category'] == category]
        if cat_results:
            cat_passed = sum(1 for r in cat_results if "PASS" in r['status'])
            cat_total = len(cat_results)
            cat_pass_rate = (cat_passed / cat_total * 100) if cat_total > 0 else 0
            avg_score = sum(r['actual_score'] for r in cat_results) / cat_total
            print(f"  {category}: {cat_passed}/{cat_total} ({cat_pass_rate:.0f}%) - Avg Score: {avg_score:.1f}")
    
    print()
    print("Detailed Results:")
    print()
    print(f"{'Contract':<25} {'Expected':<10} {'Actual':<10} {'Diff':<10} {'Verified':<10} {'Status':<10}")
    print("-" * 100)
    
    for r in results:
        print(f"{r['name']:<25} {r['expected_score']:<10} {r['actual_score']:<10.1f} {r.get('score_diff', 0):<10.1f} {str(r.get('is_verified', False)):<10} {r['status']:<10}")
    
    # Save results to JSON
    with open("d:/New folder/sentinel-protocol/test_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print()
    print("Full results saved to: test_results.json")
    print("=" * 100)

if __name__ == "__main__":
    run_batch_test()
