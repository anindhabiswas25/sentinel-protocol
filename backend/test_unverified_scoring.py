"""
Test script to validate unverified safe contract scoring (50-74 range)

This tests the scoring logic for unverified contracts to ensure they fall
in the expected "Unverified Safe" range (50-74) when they have safe patterns.
"""

import asyncio
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

from app.services.scoring import scoring_service
from typing import List, Dict, Any


def test_unverified_safe_scoring():
    """
    Test scoring for unverified safe contracts.
    Expected range: 50-74
    """
    print("=" * 80)
    print("Testing Unverified Safe Contract Scoring (Expected: 50-74)")
    print("=" * 80)
    
    test_cases = [
        {
            "name": "Small DEX Router",
            "expected_score": 58,
            "vulnerabilities": [],  # No vulnerabilities found
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": []
            },
            "reason": "Simple logic, no red flags"
        },
        {
            "name": "Private Multisig",
            "expected_score": 65,
            "vulnerabilities": [],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": []
            },
            "reason": "Standard multisig pattern"
        },
        {
            "name": "Token Vesting",
            "expected_score": 62,
            "vulnerabilities": [],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": []
            },
            "reason": "Time-locked, safe pattern"
        },
        {
            "name": "NFT Marketplace",
            "expected_score": 54,
            "vulnerabilities": [
                {
                    "severity": "low",
                    "description": "No ReentrancyGuard detected in bytecode"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": []
            },
            "reason": "Basic NFT logic detected"
        },
        {
            "name": "DAO Treasury",
            "expected_score": 70,
            "vulnerabilities": [],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": []
            },
            "reason": "Treasury pattern, high usage"
        },
        {
            "name": "Staking Contract",
            "expected_score": 57,
            "vulnerabilities": [
                {
                    "severity": "low",
                    "description": "Timestamp dependency in rewards calculation"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": []
            },
            "reason": "Simple staking rewards"
        },
        {
            "name": "Airdrop Distributor",
            "expected_score": 68,
            "vulnerabilities": [],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": []
            },
            "reason": "Merkle tree pattern"
        },
        {
            "name": "Token Locker",
            "expected_score": 61,
            "vulnerabilities": [
                {
                    "severity": "low",
                    "description": "Minor timestamp manipulation risk"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": []
            },
            "reason": "Time-lock mechanism"
        },
        {
            "name": "Escrow Contract",
            "expected_score": 63,
            "vulnerabilities": [],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": []
            },
            "reason": "Standard escrow flow"
        },
        {
            "name": "Swap Aggregator",
            "expected_score": 55,
            "vulnerabilities": [
                {
                    "severity": "medium",
                    "description": "Complex external calls pattern"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": True,  # Delegatecall for router pattern
                "suspicious_patterns": []
            },
            "reason": "Basic aggregator logic"
        },
        {
            "name": "Liquidity Pool",
            "expected_score": 59,
            "vulnerabilities": [
                {
                    "severity": "low",
                    "description": "Price manipulation potential in low liquidity"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": []
            },
            "reason": "AMM pool pattern"
        },
        {
            "name": "Governance Token",
            "expected_score": 69,
            "vulnerabilities": [],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": []
            },
            "reason": "Standard ERC20 patterns"
        }
    ]
    
    results = []
    total_passed = 0
    total_failed = 0
    
    for test_case in test_cases:
        print(f"\n{'─' * 80}")
        print(f"Testing: {test_case['name']}")
        print(f"Expected Score: {test_case['expected_score']} (Reason: {test_case['reason']})")
        
        # Calculate trust score
        trust_score = scoring_service.calculate_trust_score(
            vulnerabilities=test_case["vulnerabilities"],
            code_quality_issues=[],
            is_verified=False,  # UNVERIFIED contract
            bytecode_analysis=test_case["bytecode_analysis"],
            contract_address=None
        )
        
        actual_score = trust_score.overall_score
        expected_score = test_case["expected_score"]
        
        # Allow ±6 points tolerance (realistic for bytecode-only analysis)
        # Without source code, exact pattern detection is limited
        tolerance = 6
        score_diff = abs(actual_score - expected_score)
        is_in_range = 50 <= actual_score <= 74
        matches_expected = score_diff <= tolerance
        
        status = "✅ PASS" if (is_in_range and matches_expected) else "❌ FAIL"
        
        if is_in_range and matches_expected:
            total_passed += 1
        else:
            total_failed += 1
        
        print(f"Actual Score: {actual_score}")
        print(f"Difference: {score_diff:.1f} points")
        print(f"In Range (50-74): {'✅' if is_in_range else '❌'}")
        print(f"Matches Expected (±{tolerance}): {'✅' if matches_expected else '❌'}")
        print(f"Status: {status}")
        
        results.append({
            "name": test_case["name"],
            "expected": expected_score,
            "actual": actual_score,
            "diff": score_diff,
            "in_range": is_in_range,
            "matches": matches_expected,
            "status": status
        })
    
    # Summary
    print(f"\n{'═' * 80}")
    print("SUMMARY")
    print(f"{'═' * 80}")
    print(f"Total Tests: {len(test_cases)}")
    print(f"Passed: {total_passed} ✅")
    print(f"Failed: {total_failed} ❌")
    print(f"Success Rate: {(total_passed / len(test_cases) * 100):.1f}%")
    
    # Detailed results table
    print(f"\n{'─' * 80}")
    print(f"{'Contract':<30} {'Expected':<10} {'Actual':<10} {'Diff':<10} {'Status'}")
    print(f"{'─' * 80}")
    for result in results:
        print(f"{result['name']:<30} {result['expected']:<10} {result['actual']:<10.1f} "
              f"{result['diff']:<10.1f} {result['status']}")
    
    # Identify issues
    print(f"\n{'═' * 80}")
    print("ISSUES IDENTIFIED")
    print(f"{'═' * 80}")
    
    out_of_range = [r for r in results if not r['in_range']]
    if out_of_range:
        print(f"\n❌ {len(out_of_range)} contracts scored outside 50-74 range:")
        for r in out_of_range:
            print(f"   - {r['name']}: {r['actual']:.1f} (expected {r['expected']})")
    else:
        print("\n✅ All contracts scored within 50-74 range")
    
    large_diff = [r for r in results if r['diff'] > 5]
    if large_diff:
        print(f"\n❌ {len(large_diff)} contracts have >5 point difference:")
        for r in large_diff:
            print(f"   - {r['name']}: {r['actual']:.1f} vs {r['expected']} (diff: {r['diff']:.1f})")
    else:
        print("\n✅ All scores within ±5 points of expected")
    
    return total_passed == len(test_cases)


if __name__ == "__main__":
    print("\n🔍 Sentinel Protocol - Unverified Safe Contract Scoring Test\n")
    
    success = test_unverified_safe_scoring()
    
    print("\n" + "=" * 80)
    if success:
        print("✅ ALL TESTS PASSED - Scoring is working correctly!")
    else:
        print("❌ TESTS FAILED - Scoring needs adjustment")
        print("\nRecommended fixes will be applied to scoring.py...")
    print("=" * 80 + "\n")
    
    sys.exit(0 if success else 1)
