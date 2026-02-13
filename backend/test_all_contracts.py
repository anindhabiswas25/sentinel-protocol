"""
Comprehensive test of all 22 real contracts from testcontract.md
Tests verified safe, verified unsafe categories
"""

import requests
import time
from datetime import datetime
import json

# Test configuration
API_URL = "http://localhost:8000/api/v1/analyze"
DELAY_BETWEEN_TESTS = 3  # seconds

# Contract test data from testcontract.md
TEST_CONTRACTS = {
    "Verified Safe (75-95)": [
        {"name": "USDT", "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7", "expected_min": 75, "expected_max": 95},
        {"name": "USDC", "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "expected_min": 75, "expected_max": 95},
        {"name": "WETH", "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "expected_min": 75, "expected_max": 95},
        {"name": "DAI", "address": "0x6B175474E89094C44Da98b954EedeAC495271d0F", "expected_min": 75, "expected_max": 95},
        {"name": "Uniswap V3 Router", "address": "0xE592427A0AEce92De3Edee1F18E0157C05861564", "expected_min": 75, "expected_max": 95},
        {"name": "Aave V3 Pool", "address": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", "expected_min": 75, "expected_max": 95},
        {"name": "Chainlink ETH/USD", "address": "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419", "expected_min": 75, "expected_max": 95},
        {"name": "LINK Token", "address": "0x514910771AF9Ca656af840dff83E8264EcF986CA", "expected_min": 75, "expected_max": 95},
        {"name": "Compound cUSDC", "address": "0x39AA39c021dfbaE8faC545936693aC917d5E7563", "expected_min": 75, "expected_max": 95},
        {"name": "MakerDAO DSChief", "address": "0x0a3f6849f78076aefaDf113F5BED87720274dDC0", "expected_min": 75, "expected_max": 95},
        {"name": "Curve 3pool", "address": "0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7", "expected_min": 75, "expected_max": 95},
        {"name": "Balancer Vault", "address": "0xBA12222222228d8Ba445958a75a0704d566BF2C8", "expected_min": 75, "expected_max": 95},
    ],
    "Verified Unsafe (25-49)": [
        {"name": "Merge Token", "address": "0x4a57E687b9126435a9B19E4A802113e266AdeBde", "expected_min": 25, "expected_max": 49},
        {"name": "Old PolyNetwork", "address": "0x250e76987d838a75310c34bf422ea9f1AC4Cc906", "expected_min": 25, "expected_max": 49},
        {"name": "BadgerDAO", "address": "0x19D97D8fA813EE2f51aD4B4e04EA08bAf4DFfC28", "expected_min": 25, "expected_max": 49},
        {"name": "Cream Finance", "address": "0x2db0E83599a91b508Ac268a6197b8B14F5e72840", "expected_min": 25, "expected_max": 49},
        {"name": "Yearn v1", "address": "0x5dbcF33D8c2E976c6b560249878e6F1491Bca25c", "expected_min": 25, "expected_max": 49},
        {"name": "DForce", "address": "0x02285AcaafEB533e03A7306C55EC031297df9224", "expected_min": 25, "expected_max": 49},
        {"name": "Pickle Finance", "address": "0x6949Bb624E8e8A90F87cD2058139fcd77D2F3F87", "expected_min": 25, "expected_max": 49},
        {"name": "Akutars NFT", "address": "0xF42c318dbfBaab0EEE040279c6A2588Fa01a961d", "expected_min": 25, "expected_max": 49},
        {"name": "Nomad Bridge", "address": "0x5D94309E5a0090b165FA4181519701637B6DAEBA", "expected_min": 25, "expected_max": 49},
        {"name": "Tornado Cash", "address": "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b", "expected_min": 25, "expected_max": 49},
    ]
}

def test_contract(contract_data, category):
    """Test a single contract and return results"""
    name = contract_data["name"]
    address = contract_data["address"]
    expected_min = contract_data["expected_min"]
    expected_max = contract_data["expected_max"]
    
    print(f"\n{'='*60}")
    print(f"Testing: {name} ({category})")
    print(f"Address: {address}")
    print(f"Expected Score: {expected_min}-{expected_max}")
    print(f"{'='*60}")
    
    try:
        response = requests.post(
            API_URL,
            json={
                "contract_address": address,
                "network": "ethereum",
                "force_refresh": True
            },
            timeout=120
        )
        
        if response.status_code == 200:
            result = response.json()
            score = result["trust_score"]["overall_score"]
            risk = result["trust_score"]["risk_level"]
            verified = result["metadata"]["is_verified"]
            contract_name = result["metadata"].get("name", "Unknown")
            
            critical = result["summary"]["critical_count"]
            high = result["summary"]["high_count"]
            medium = result["summary"]["medium_count"]
            
            # Check if score is in expected range
            in_range = expected_min <= score <= expected_max
            
            print(f"✓ Analysis Complete")
            print(f"  Contract Name: {contract_name}")
            print(f"  Verified: {verified}")
            print(f"  Score: {score:.1f} {'✅' if in_range else '❌ OUT OF RANGE'}")
            print(f"  Risk Level: {risk}")
            print(f"  Vulnerabilities: {critical}C / {high}H / {medium}M")
            
            return {
                "name": name,
                "address": address,
                "category": category,
                "score": score,
                "risk": risk,
                "verified": verified,
                "expected_range": f"{expected_min}-{expected_max}",
                "in_range": in_range,
                "critical": critical,
                "high": high,
                "medium": medium,
                "success": True
            }
        else:
            print(f"❌ API Error: {response.status_code}")
            return {
                "name": name,
                "address": address,
                "category": category,
                "error": f"HTTP {response.status_code}",
                "success": False
            }
            
    except requests.exceptions.Timeout:
        print(f"❌ Timeout - analysis took too long")
        return {
            "name": name,
            "address": address,
            "category": category,
            "error": "Timeout",
            "success": False
        }
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return {
            "name": name,
            "address": address,
            "category": category,
            "error": str(e),
            "success": False
        }

def generate_report(results):
    """Generate a comprehensive test report"""
    print("\n" + "="*80)
    print("=" * 80)
    print(" "*25 + "COMPREHENSIVE TEST REPORT")
    print("="*80)
    print("="*80 + "\n")
    
    total_tests = len(results)
    successful_tests = sum(1 for r in results if r["success"])
    in_range_tests = sum(1 for r in results if r.get("in_range", False))
    
    print(f"Total Tests: {total_tests}")
    print(f"Successful: {successful_tests}")
    print(f"In Expected Range: {in_range_tests}")
    print(f"Accuracy: {(in_range_tests/successful_tests*100):.1f}%\n" if successful_tests > 0 else "Accuracy: N/A\n")
    
    # Group by category
    categories = {}
    for result in results:
        cat = result["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(result)
    
    # Print results by category
    for category, cat_results in categories.items():
        print(f"\n{'='*80}")
        print(f"📋 {category}")
        print(f"{'='*80}")
        
        cat_success = [r for r in cat_results if r["success"]]
        cat_in_range = [r for r in cat_results if r.get("in_range", False)]
        
        print(f"Tests: {len(cat_results)} | Success: {len(cat_success)} | In Range: {len(cat_in_range)}")
        print(f"Category Accuracy: {(len(cat_in_range)/len(cat_success)*100):.1f}%\n" if cat_success else "Category Accuracy: N/A\n")
        
        for result in cat_results:
            if result["success"]:
                status = "✅ PASS" if result["in_range"] else "❌ FAIL"
                print(f"{status} | {result['name']:25} | Score: {result['score']:5.1f} (Expected: {result['expected_range']}) | Risk: {result['risk']:8} | {result['critical']}C/{result['high']}H")
            else:
                print(f"❌ ERROR | {result['name']:25} | {result.get('error', 'Unknown error')}")
    
    print("\n" + "="*80)
    print("="*80)
    
    # Summary
    if in_range_tests == successful_tests and successful_tests > 0:
        print("\n🎉 PERFECT SCORE! All contracts scored in expected ranges!")
    elif in_range_tests >= successful_tests * 0.85:
        print(f"\n✅ GOOD PERFORMANCE! {(in_range_tests/successful_tests*100):.1f}% accuracy")
    elif in_range_tests >= successful_tests * 0.70:
        print(f"\n⚠️ NEEDS IMPROVEMENT! {(in_range_tests/successful_tests*100):.1f}% accuracy")
    else:
        print(f"\n❌ POOR PERFORMANCE! {(in_range_tests/successful_tests*100):.1f}% accuracy - major tuning needed")
    
    return {
        "total": total_tests,
        "successful": successful_tests,
        "in_range": in_range_tests,
        "accuracy": (in_range_tests/successful_tests*100) if successful_tests > 0 else 0
    }

def main():
    """Run all tests"""
    print("\n" + "="*80)
    print("SENTINEL PROTOCOL - COMPREHENSIVE CONTRACT TESTING")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)
    
    all_results = []
    
    for category, contracts in TEST_CONTRACTS.items():
        print(f"\n\n{'#'*80}")
        print(f"# CATEGORY: {category}")
        print(f"# Contracts to test: {len(contracts)}")
        print(f"{'#'*80}\n")
        
        for contract in contracts:
            result = test_contract(contract, category)
            all_results.append(result)
            
            # Delay between tests to avoid rate limiting
            time.sleep(DELAY_BETWEEN_TESTS)
    
    # Generate final report
    summary = generate_report(all_results)
    
    # Save results to file
    output_file = f"test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "summary": summary,
            "results": all_results
        }, f, indent=2)
    
    print(f"\n📄 Results saved to: {output_file}")
    print(f"\nCompleted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
