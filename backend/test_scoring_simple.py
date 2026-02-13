"""
Simplified test script to verify scoring fix without full dependencies
Tests the core scoring logic directly
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Mock the services that require external dependencies
class MockPatternDetector:
    def analyze_comprehensive(self, bytecode):
        return {
            "risk_score_adjustment": 0,
            "overall_risk_level": "safe",
            "malicious_patterns": []
        }

class MockSimilarityService:
    def find_similar_contracts(self, bytecode, top_k, min_similarity):
        return []
    
    def store_analysis(self, contract_address, bytecode, trust_score, is_verified, vulnerabilities):
        pass

# Mock the modules
sys.modules['app.services.pattern_detector'] = type('module', (), {'pattern_detector': MockPatternDetector()})
sys.modules['app.services.similarity_search'] = type('module', (), {'similarity_service': MockSimilarityService()})

# Now import the scoring service
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
    
    # Check for boundary issues
    print("\n🔍 BOUNDARY ANALYSIS")
    print("=" * 80)
    
    # Check no scores are at exactly 50, 75, 25 (would indicate hard boundaries)
    boundary_scores = [50.0, 75.0, 25.0]
    boundary_hits = [r for r in results if r['score'] in boundary_scores]
    
    if boundary_hits:
        print("⚠️  WARNING: Found scores at exact boundary points:")
        for r in boundary_hits:
            print(f"   {r['name']}: {r['score']}")
        print("   This may indicate residual hard boundary logic.")
    else:
        print("✅ No hard boundary artifacts detected")
    
    # Check for proper distribution
    verified_safe_scores = [r['score'] for r in results if r['category'] == 'Verified Safe']
    verified_unsafe_scores = [r['score'] for r in results if r['category'] == 'Verified Unsafe']
    unverified_safe_scores = [r['score'] for r in results if r['category'] == 'Unverified Safe']
    unverified_unsafe_scores = [r['score'] for r in results if r['category'] == 'Unverified Unsafe']
    
    print(f"\n📊 Score Distributions:")
    if verified_safe_scores:
        print(f"   Verified Safe: {min(verified_safe_scores):.1f} - {max(verified_safe_scores):.1f}")
    if verified_unsafe_scores:
        print(f"   Verified Unsafe: {min(verified_unsafe_scores):.1f} - {max(verified_unsafe_scores):.1f}")
    if unverified_safe_scores:
        print(f"   Unverified Safe: {min(unverified_safe_scores):.1f} - {max(unverified_safe_scores):.1f}")
    if unverified_unsafe_scores:
        print(f"   Unverified Unsafe: {min(unverified_unsafe_scores):.1f} - {max(unverified_unsafe_scores):.1f}")
    
    print()
    print("=" * 80)
    
    # Return success status
    return failed == 0


if __name__ == "__main__":
    success = test_scoring()
    sys.exit(0 if success else 1)
