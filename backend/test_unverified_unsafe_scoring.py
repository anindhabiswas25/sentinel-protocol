"""
Test script to validate unverified UNSAFE contract scoring (0-24 range)

This tests the scoring logic for unverified contracts with red flags to ensure
they fall in the expected "Unverified Unsafe" range (0-24) when they have
malicious patterns and vulnerabilities.
"""

import asyncio
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

from app.services.scoring import scoring_service
from typing import List, Dict, Any


def test_unverified_unsafe_scoring():
    """
    Test scoring for unverified UNSAFE contracts.
    Expected range: 0-24
    """
    print("=" * 80)
    print("Testing Unverified UNSAFE Contract Scoring (Expected: 0-24)")
    print("=" * 80)
    
    test_cases = [
        {
            "name": "Honeypot Token",
            "expected_score": 12,
            "vulnerabilities": [
                {
                    "severity": "critical",
                    "description": "Honeypot detected: Cannot sell tokens after purchase"
                },
                {
                    "severity": "high",
                    "description": "Hidden transfer restrictions"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": ["honeypot", "hidden_transfer_restriction"]
            },
            "risk": "Cannot sell tokens"
        },
        {
            "name": "Rug Pull Contract",
            "expected_score": 8,
            "vulnerabilities": [
                {
                    "severity": "critical",
                    "description": "Owner has unlimited withdrawal rights"
                },
                {
                    "severity": "critical",
                    "description": "No timelock or governance controls"
                },
                {
                    "severity": "high",
                    "description": "Centralized control risk"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": True,
                "has_delegatecall": False,
                "suspicious_patterns": ["owner_drain", "no_timelock"]
            },
            "risk": "Owner can drain funds"
        },
        {
            "name": "Fake Airdrop",
            "expected_score": 15,
            "vulnerabilities": [
                {
                    "severity": "critical",
                    "description": "Phishing pattern detected"
                },
                {
                    "severity": "high",
                    "description": "Approval harvesting mechanism"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": True,
                "suspicious_patterns": ["phishing", "approval_harvesting"]
            },
            "risk": "Phishing contract"
        },
        {
            "name": "Scam Token",
            "expected_score": 5,
            "vulnerabilities": [
                {
                    "severity": "critical",
                    "description": "Hidden mint function accessible by owner"
                },
                {
                    "severity": "critical",
                    "description": "Unlimited token inflation possible"
                },
                {
                    "severity": "high",
                    "description": "No max supply cap"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": ["hidden_mint", "unlimited_supply"]
            },
            "risk": "Hidden mint function"
        },
        {
            "name": "Malicious Proxy",
            "expected_score": 18,
            "vulnerabilities": [
                {
                    "severity": "critical",
                    "description": "Upgradeable to malicious implementation"
                },
                {
                    "severity": "medium",
                    "description": "No upgrade timelock"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": True,
                "suspicious_patterns": ["malicious_upgrade_path", "no_timelock"]
            },
            "risk": "Upgradeable to scam"
        },
        {
            "name": "Fake Uniswap",
            "expected_score": 10,
            "vulnerabilities": [
                {
                    "severity": "critical",
                    "description": "Impersonation of legitimate protocol"
                },
                {
                    "severity": "critical",
                    "description": "Fake swap mechanism steals tokens"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": True,
                "suspicious_patterns": ["impersonation", "token_theft"]
            },
            "risk": "Impersonation attack"
        },
        {
            "name": "Blacklist Token",
            "expected_score": 22,
            "vulnerabilities": [
                {
                    "severity": "high",
                    "description": "Arbitrary address blacklisting by owner"
                },
                {
                    "severity": "high",
                    "description": "Can freeze any user's funds"
                },
                {
                    "severity": "medium",
                    "description": "Centralization risk"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": ["arbitrary_blacklist"]
            },
            "risk": "Arbitrary blacklisting"
        },
        {
            "name": "Pausable Scam",
            "expected_score": 19,
            "vulnerabilities": [
                {
                    "severity": "critical",
                    "description": "Owner can pause contract anytime"
                },
                {
                    "severity": "high",
                    "description": "No unpause mechanism"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": ["permanent_pause_risk"]
            },
            "risk": "Can pause anytime"
        },
        {
            "name": "Fee Manipulator",
            "expected_score": 24,
            "vulnerabilities": [
                {
                    "severity": "high",
                    "description": "Owner can change fees to 100%"
                },
                {
                    "severity": "high",
                    "description": "No fee cap or limits"
                },
                {
                    "severity": "medium",
                    "description": "Fee manipulation detected"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": ["fee_manipulation"]
            },
            "risk": "Owner changes fees"
        },
        {
            "name": "Reflection Token Bug",
            "expected_score": 20,
            "vulnerabilities": [
                {
                    "severity": "critical",
                    "description": "Integer overflow in reflection calculation"
                },
                {
                    "severity": "medium",
                    "description": "Math errors in reward distribution"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": ["overflow_bug"]
            },
            "risk": "Math overflow bugs"
        },
        {
            "name": "Unaudited DeFi",
            "expected_score": 23,
            "vulnerabilities": [
                {
                    "severity": "high",
                    "description": "Complex DeFi logic without audit"
                },
                {
                    "severity": "high",
                    "description": "Multiple reentrancy risks"
                },
                {
                    "severity": "medium",
                    "description": "Unchecked external calls"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": True,
                "suspicious_patterns": ["complex_unaudited", "reentrancy_risk"]
            },
            "risk": "Complex + unverified"
        },
        {
            "name": "Anonymous Deployer",
            "expected_score": 17,
            "vulnerabilities": [
                {
                    "severity": "critical",
                    "description": "Deployed by suspicious address"
                },
                {
                    "severity": "high",
                    "description": "Hidden owner controls"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": ["anonymous_deployer", "hidden_controls"]
            },
            "risk": "Suspicious behavior"
        },
        {
            "name": "Hidden Backdoor",
            "expected_score": 11,
            "vulnerabilities": [
                {
                    "severity": "critical",
                    "description": "Assembly backdoor detected"
                },
                {
                    "severity": "critical",
                    "description": "Hidden admin functions in bytecode"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": True,
                "has_delegatecall": True,
                "suspicious_patterns": ["assembly_backdoor", "hidden_admin"]
            },
            "risk": "Assembly backdoor"
        },
        {
            "name": "Tax Token Scam",
            "expected_score": 14,
            "vulnerabilities": [
                {
                    "severity": "critical",
                    "description": "99% sell tax trap"
                },
                {
                    "severity": "high",
                    "description": "Cannot sell effectively"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": ["excessive_tax", "sell_trap"]
            },
            "risk": "99% sell tax trap"
        },
        {
            "name": "Liquidity Trap",
            "expected_score": 16,
            "vulnerabilities": [
                {
                    "severity": "critical",
                    "description": "LP tokens locked by scammer"
                },
                {
                    "severity": "high",
                    "description": "Cannot remove liquidity"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": ["lp_trap", "liquidity_lock_scam"]
            },
            "risk": "LP locked scam"
        },
        {
            "name": "Copycat Contract",
            "expected_score": 21,
            "vulnerabilities": [
                {
                    "severity": "high",
                    "description": "Malicious clone of legitimate contract"
                },
                {
                    "severity": "high",
                    "description": "Subtle changes to steal funds"
                }
            ],
            "bytecode_analysis": {
                "has_selfdestruct": False,
                "has_delegatecall": False,
                "suspicious_patterns": ["copycat_scam"]
            },
            "risk": "Malicious clone"
        }
    ]
    
    results = []
    total_passed = 0
    total_failed = 0
    
    for test_case in test_cases:
        print(f"\n{'─' * 80}")
        print(f"Testing: {test_case['name']}")
        print(f"Expected Score: {test_case['expected_score']} (Risk: {test_case['risk']})")
        
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
        
        # Allow ±7 points tolerance (realistic for dangerous contract scoring)
        # Bytecode-only analysis has limitations in distinguishing severity levels
        tolerance = 7
        score_diff = abs(actual_score - expected_score)
        is_in_range = 0 <= actual_score <= 24
        matches_expected = score_diff <= tolerance
        
        status = "✅ PASS" if (is_in_range and matches_expected) else "❌ FAIL"
        
        if is_in_range and matches_expected:
            total_passed += 1
        else:
            total_failed += 1
        
        print(f"Actual Score: {actual_score}")
        print(f"Difference: {score_diff:.1f} points")
        print(f"In Range (0-24): {'✅' if is_in_range else '❌'}")
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
        print(f"\n❌ {len(out_of_range)} contracts scored outside 0-24 range:")
        for r in out_of_range:
            print(f"   - {r['name']}: {r['actual']:.1f} (expected {r['expected']})")
    else:
        print("\n✅ All contracts scored within 0-24 range")
    
    large_diff = [r for r in results if r['diff'] > 5]
    if large_diff:
        print(f"\n❌ {len(large_diff)} contracts have >5 point difference:")
        for r in large_diff:
            print(f"   - {r['name']}: {r['actual']:.1f} vs {r['expected']} (diff: {r['diff']:.1f})")
    else:
        print("\n✅ All scores within ±5 points of expected")
    
    return total_passed == len(test_cases)


if __name__ == "__main__":
    print("\n🔍 Sentinel Protocol - Unverified UNSAFE Contract Scoring Test\n")
    
    success = test_unverified_unsafe_scoring()
    
    print("\n" + "=" * 80)
    if success:
        print("✅ ALL TESTS PASSED - Scoring is working correctly!")
    else:
        print("❌ TESTS FAILED - Scoring needs adjustment")
        print("\nRecommended fixes will be applied to scoring.py...")
    print("=" * 80 + "\n")
    
    sys.exit(0 if success else 1)
