"""
Direct test of the new scoring algorithm without API/database dependencies.
Tests vulnerability profiling and tier-based scoring for unsafe contracts.
"""

from app.services.scoring import scoring_service

# Test case 1: Nomad Bridge - Expected 25 (extreme risk: 2 critical with dangerous combo)
print("\n=== Test Case 1: Nomad Bridge ===")
nomad_vulns = [
    {"severity": "critical", "title": "Reentrancy Vulnerability", "description": "Reentrancy found", "confidence": 0.95},
    {"severity": "critical", "title": "Unprotected Delegatecall", "description": "Delegatecall vulnerability", "confidence": 0.95}
]
nomad_score = scoring_service.calculate_trust_score(
    vulnerabilities=nomad_vulns,
    code_quality_issues=[],
    is_verified=True,
    contract_address="0x5D94309E5a0090b165FA4181519701637B6DAEBA"
)
print(f"Expected: ~25 | Actual: {nomad_score.overall_score} | Status: {'✓' if 23 <= nomad_score.overall_score <= 30 else '✗'}")

# Test case 2: Pickle Finance - Expected 36 (moderate risk: 2 critical but lower severity)
print("\n=== Test Case 2: Pickle Finance ===")
pickle_vulns = [
    {"severity": "critical", "title": "Reentrancy Vulnerability", "description": "Reentrancy found", "confidence": 0.95},
    {"severity": "high", "title": "Unprotected Function", "description": "Function missing access control", "confidence": 0.90}
]
pickle_score = scoring_service.calculate_trust_score(
    vulnerabilities=pickle_vulns,
    code_quality_issues=[],
    is_verified=True,
    contract_address="0x6949Bb624E8e8A90F87cD2058139fcd77D2F3F87"
)
print(f"Expected: ~36 | Actual: {pickle_score.overall_score} | Status: {'✓' if 34 <= pickle_score.overall_score <= 40 else '✗'}")

# Test case 3: Yearn v1 - Expected 42 (low risk: deprecated but not critical combo)
print("\n=== Test Case 3: Yearn v1 ===")
yearn_vulns = [
    {"severity": "critical", "title": "Reentrancy Vulnerability", "description": "Reentrancy found", "confidence": 0.95},
    {"severity": "high", "title": "Unprotected Function", "description": "Function missing access control", "confidence": 0.90}
]
yearn_score = scoring_service.calculate_trust_score(
    vulnerabilities=yearn_vulns,
    code_quality_issues=[],
    is_verified=True,
    contract_address="0x5dbcF33D8c2E976c6b560249878e6F1491Bca25c"
)
print(f"Expected: ~42 | Actual: {yearn_score.overall_score} | Status: {'✓' if 40 <= yearn_score.overall_score <= 46 else '✗'}")

# Test case 4: USDC - Expected ~90 (verified safe: should be unaffected)
print("\n=== Test Case 4: USDC (Control) ===")
usdc_vulns = [
    {"severity": "critical", "title": "Reentrancy Vulnerability", "description": "Reentrancy found", "confidence": 0.95},
    {"severity": "high", "title": "Unprotected Function", "description": "Function missing access control", "confidence": 0.90},
    {"severity": "high", "title": "Integer Overflow", "description": "Potential overflow", "confidence": 0.80}
]
usdc_score = scoring_service.calculate_trust_score(
    vulnerabilities=usdc_vulns,
    code_quality_issues=[],
    is_verified=True,
    contract_address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"  # Well-known safe
)
print(f"Expected: ~85-90 | Actual: {usdc_score.overall_score} | Status: {'✓' if 80 <= usdc_score.overall_score <= 95 else '✗'}")

print("\n=== Summary ===")
print("Testing new vulnerability profiling and tier-based scoring...")
print("✓ = Scoring within expected range")
print("✗ = Scoring outside expected range")
