"""
Test script to verify the scoring fix for all 4 categories
"""

import asyncio
import sys
from app.services.scoring import scoring_service

# Test cases for all 4 categories
test_cases = [
    # Category 1: Verified Safe (75-95)
    {
        "name": "USDT (Verified Safe - Clean)",
        "is_verified": True,
        "vulnerabilities": [],
        "expected_range": (75, 95),
        "category": "Verified Safe"
    },
    {
        "name": "DAI (Verified Safe - Minor Issues)",
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "low", "confidence": 0.7},
            {"severity": "low", "confidence": 0.6}
        ],
        "expected_range": (75, 95),
        "category": "Verified Safe"
    },
    {
        "name": "Uniswap (Verified Safe - Medium Issue)",
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "medium", "confidence": 0.8}
        ],
        "expected_range": (75, 95),
        "category": "Verified Safe"
    },
    
    # Category 2: Verified Unsafe (25-49)
    {
        "name": "Exploited Contract (Verified Unsafe - Critical)",
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.9, "title": "Reentrancy vulnerability"}
        ],
        "expected_range": (25, 49),
        "category": "Verified Unsafe"
    },
    {
        "name": "Akutars (Verified Unsafe - Multiple High)",
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "high", "confidence": 0.85},
            {"severity": "high", "confidence": 0.80}
        ],
        "expected_range": (25, 49),
        "category": "Verified Unsafe"
    },
    {
        "name": "Deprecated Contract (Verified Unsafe - Mixed)",
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "high", "confidence": 0.75},
            {"severity": "medium", "confidence": 0.80},
            {"severity": "medium", "confidence": 0.85},
            {"severity": "medium", "confidence": 0.70}
        ],
        "expected_range": (25, 49),
        "category": "Verified Unsafe"
    },
    
    # Category 3: Unverified Safe (50-74)
    {
        "name": "Simple DEX (Unverified Safe - Clean)",
        "is_verified": False,
        "vulnerabilities": [],
        "bytecode_analysis": {"has_selfdestruct": False, "has_delegatecall": False, "suspicious_patterns": []},
        "expected_range": (50, 74),
        "category": "Unverified Safe"
    },
    {
        "name": "Multisig (Unverified Safe - Minor Issues)",
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "low", "confidence": 0.6},
            {"severity": "low", "confidence": 0.5}
        ],
        "bytecode_analysis": {"has_selfdestruct": False, "has_delegatecall": False, "suspicious_patterns": []},
        "expected_range": (50, 74),
        "category": "Unverified Safe"
    },
    {
        "name": "Token Vesting (Unverified Safe - Medium Issue)",
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "medium", "confidence": 0.7}
        ],
        "bytecode_analysis": {"has_selfdestruct": False, "has_delegatecall": True, "suspicious_patterns": []},
        "expected_range": (50, 74),
        "category": "Unverified Safe"
    },
    
    # Category 4: Unverified Unsafe (0-24)
    {
        "name": "Honeypot (Unverified Unsafe - Critical)",
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.95, "title": "Cannot sell tokens"}
        ],
        "bytecode_analysis": {"has_selfdestruct": False, "has_delegatecall": False, "suspicious_patterns": ["hidden_transfer_restriction"]},
        "expected_range": (0, 24),
        "category": "Unverified Unsafe"
    },
    {
        "name": "Rug Pull Contract (Unverified Unsafe - Multiple Highs)",
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "high", "confidence": 0.90},
            {"severity": "high", "confidence": 0.85}
        ],
        "bytecode_analysis": {"has_selfdestruct": True, "has_delegatecall": False, "suspicious_patterns": ["owner_drain"]},
        "expected_range": (0, 24),
        "category": "Unverified Unsafe"
    },
    {
        "name": "Scam Token (Unverified Unsafe - Complex)",
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "high", "confidence": 0.80},
            {"severity": "medium", "confidence": 0.75},
            {"severity": "medium", "confidence": 0.80},
            {"severity": "medium", "confidence": 0.70}
        ],
        "bytecode_analysis": {"has_selfdestruct": False, "has_delegatecall": True, "suspicious_patterns": ["fee_manipulation", "hidden_mint"]},
        "expected_range": (0, 24),
        "category": "Unverified Unsafe"
    }
]


def test_scoring():
    """Test scoring for all categories"""
    print("=" * 80)
    print("TESTING SENTINEL PROTOCOL SCORING FIX")
    print("=" * 80)
    print()
    
    passed = 0
    failed = 0
    results = []
    
    for i, test_case in enumerate(test_cases, 1):
        name = test_case["name"]
        is_verified = test_case["is_verified"]
        vulnerabilities = test_case["vulnerabilities"]
        bytecode_analysis = test_case.get("bytecode_analysis", {})
        expected_range = test_case["expected_range"]
        category = test_case["category"]
        
        # Calculate score (without AI since we don't have bytecode)
        trust_score = scoring_service.calculate_trust_score(
            vulnerabilities=vulnerabilities,
            code_quality_issues=[],
            is_verified=is_verified,
            bytecode_analysis=bytecode_analysis,
            contract_address=f"0x{'0' * 40}",
            bytecode=None,  # Force traditional scoring
            use_ai_scoring=False
        )
        
        score = trust_score.overall_score
        min_expected, max_expected = expected_range
        
        # Check if score is in expected range
        in_range = min_expected <= score <= max_expected
        
        # Determine emoji
        if category == "Verified Safe":
            emoji = "🟢"
        elif category == "Verified Unsafe":
            emoji = "🟠"
        elif category == "Unverified Safe":
            emoji = "🟡"
        else:
            emoji = "🔴"
        
        status = "✅ PASS" if in_range else "❌ FAIL"
        
        if in_range:
            passed += 1
        else:
            failed += 1
        
        result = {
            "name": name,
            "category": category,
            "score": score,
            "expected": expected_range,
            "status": status,
            "emoji": emoji
        }
        results.append(result)
        
        print(f"{emoji} Test {i}: {name}")
        print(f"   Category: {category}")
        print(f"   Score: {score:.1f} (Expected: {min_expected}-{max_expected})")
        print(f"   Risk Level: {trust_score.risk_level}")
        print(f"   Status: {status}")
        print()
    
    # Print summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total Tests: {len(test_cases)}")
    print(f"Passed: {passed} ✅")
    print(f"Failed: {failed} ❌")
    print(f"Success Rate: {(passed/len(test_cases)*100):.1f}%")
    print()
    
    # Print by category
    print("=" * 80)
    print("RESULTS BY CATEGORY")
    print("=" * 80)
    
    categories = ["Verified Safe", "Verified Unsafe", "Unverified Safe", "Unverified Unsafe"]
    
    for cat in categories:
        cat_results = [r for r in results if r["category"] == cat]
        if cat_results:
            print(f"\n{cat_results[0]['emoji']} {cat}:")
            for r in cat_results:
                print(f"   {r['status']} {r['name']}: {r['score']:.1f}")
    
    print()
    print("=" * 80)
    
    # Return success status
    return failed == 0


if __name__ == "__main__":
    success = test_scoring()
    sys.exit(0 if success else 1)
