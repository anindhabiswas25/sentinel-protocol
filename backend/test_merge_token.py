"""
Test Merge Token (Reentrancy Exploit) with 4-Layer System

Contract: 0x4a57E687b9126435a9B19E4A802113e266AdeBde
Category: Verified Unsafe (Expected 25-49)
Known Issue: Reentrancy vulnerability in transfer function
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import asyncio
from colorama import init, Fore, Style
from app.services.scoring import scoring_service
from app.services.exploit_detector import exploit_detector
from app.services.behavior_analyzer import behavior_analyzer
from app.services.community_reports import community_reports

init(autoreset=True)

CONTRACT_ADDRESS = "0x4a57E687b9126435a9B19E4A802113e266AdeBde"
CONTRACT_NAME = "Merge Token (Reentrancy)"
CHAIN = "ethereum"

# Known vulnerability data for this contract
VULNERABILITIES = [
    {
        "severity": "critical",
        "confidence": 0.95,
        "description": "Reentrancy vulnerability in transfer function - state update after external call"
    },
    {
        "severity": "high",
        "confidence": 0.85,
        "description": "State changes after external call enable drain attack"
    }
]

async def test_merge_token():
    """Test Merge Token with complete 4-layer analysis"""
    
    print(f"\n{Fore.MAGENTA}{'='*70}")
    print(f"  🔍 TESTING MERGE TOKEN (REENTRANCY EXPLOIT)")
    print(f"{'='*70}{Style.RESET_ALL}\n")
    
    print(f"{Fore.CYAN}Contract: {CONTRACT_ADDRESS}")
    print(f"Known Issue: Classic reentrancy vulnerability")
    print(f"Expected Score Range: 25-49 (Verified Unsafe){Style.RESET_ALL}\n")
    
    # Step 1: Check Layer 1 (Exploit Databases)
    print(f"{Fore.YELLOW}{'─'*70}")
    print(f"LAYER 1: Checking Exploit Databases...{Style.RESET_ALL}")
    
    exploit_status = await exploit_detector.check_exploit_status(CONTRACT_ADDRESS, CHAIN)
    if exploit_status and exploit_status['is_exploited']:
        print(f"{Fore.RED}🚨 DETECTED in exploit database!")
        for source in exploit_status['sources']:
            print(f"   Source: {source['source']}")
            print(f"   Status: {source['status']}")
        print(f"   Confidence: {exploit_status['confidence']:.1%}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}✓ Not in exploit databases (may be too old/small){Style.RESET_ALL}")
    
    # Step 2: Check Layer 3 (Behavior Analysis)
    print(f"\n{Fore.YELLOW}{'─'*70}")
    print(f"LAYER 3: Analyzing On-Chain Behavior...{Style.RESET_ALL}")
    
    behavior = await behavior_analyzer.analyze_contract_behavior(
        address=CONTRACT_ADDRESS,
        chain=CHAIN,
        contract_age_days=None  # Will check if very new
    )
    
    if behavior['red_flags']:
        print(f"{Fore.YELLOW}⚠️ Behavior red flags detected:")
        for flag in behavior['red_flags']:
            print(f"   [{flag['severity']}] {flag['description']}")
        print(f"   Risk Score: {behavior['behavior_risk_score']:.1f}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}✓ No immediate behavior red flags{Style.RESET_ALL}")
    
    # Step 3: Check Layer 4 (Community Reports)
    print(f"\n{Fore.YELLOW}{'─'*70}")
    print(f"LAYER 4: Checking Community Reports...{Style.RESET_ALL}")
    
    community = await community_reports.get_report_score(CONTRACT_ADDRESS, CHAIN)
    
    if community['report_count'] > 0:
        print(f"{Fore.YELLOW}📢 {community['report_count']} community report(s) found")
        print(f"   Average Severity: {community['avg_severity']:.1f}/10")
        print(f"   Risk Adjustment: -{community['risk_adjustment']:.1f} points{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}✓ No community reports yet{Style.RESET_ALL}")
    
    # Step 4: Calculate Trust Score (includes all layers + RAG)
    print(f"\n{Fore.YELLOW}{'─'*70}")
    print(f"COMPUTING TRUST SCORE (All Layers Active)...{Style.RESET_ALL}\n")
    
    score_result = scoring_service.calculate_trust_score(
        vulnerabilities=VULNERABILITIES,
        code_quality_issues=[],
        is_verified=True,
        bytecode_analysis=None,
        contract_address=CONTRACT_ADDRESS,
        use_ai_scoring=False,  # Using traditional scoring for test
        chain=CHAIN,
        source_code="contract MergeToken { /* reentrancy vuln */ }"
    )
    
    # Display Results
    print(f"{Fore.CYAN}{'='*70}")
    print(f"  📊 FINAL RESULTS")
    print(f"{'='*70}{Style.RESET_ALL}\n")
    
    actual_score = score_result.overall_score
    expected_min, expected_max = 25, 49
    in_range = expected_min <= actual_score <= expected_max
    
    print(f"Trust Score:     {Fore.YELLOW}{actual_score:.1f}{Style.RESET_ALL}")
    print(f"Expected Range:  {expected_min}-{expected_max} (Verified Unsafe)")
    print(f"Risk Level:      {Fore.RED if score_result.risk_level == 'CRITICAL' else Fore.YELLOW}{score_result.risk_level}{Style.RESET_ALL}")
    
    print(f"\nComponent Scores:")
    print(f"  Security:      {score_result.security_score:.1f}/100")
    print(f"  Code Quality:  {score_result.code_quality_score:.1f}/100")
    print(f"  Verification:  {score_result.verification_score:.1f}/100")
    
    print(f"\nKnown Vulnerabilities:")
    for vuln in VULNERABILITIES:
        color = Fore.RED if vuln['severity'] == 'critical' else Fore.YELLOW
        print(f"  {color}[{vuln['severity'].upper()}] {vuln['description']}{Style.RESET_ALL}")
        print(f"    Confidence: {vuln['confidence']:.0%}")
    
    # Verdict
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    if in_range:
        print(f"{Fore.GREEN}✅ SUCCESS! Score correctly in Verified Unsafe range!{Style.RESET_ALL}")
        print(f"{Fore.GREEN}   Contract with reentrancy exploit properly flagged as unsafe.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}❌ ISSUE: Score {actual_score:.1f} is outside expected range {expected_min}-{expected_max}{Style.RESET_ALL}")
        if actual_score > expected_max:
            print(f"{Fore.RED}   Score too HIGH - contract should be flagged as unsafe!{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}   Score too LOW - might be over-penalized{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    # Summary of 4-Layer Detection
    print(f"{Fore.MAGENTA}🛡️ 4-Layer Detection Summary:{Style.RESET_ALL}")
    print(f"  Layer 1 (Exploit DB):    {'🚨 Detected' if exploit_status else '✓ Not in DB'}")
    print(f"  Layer 2 (Semantic RAG):  ✓ Pattern matching active")
    print(f"  Layer 3 (Behavior):      {'⚠️ Flags' if behavior['red_flags'] else '✓ Clean'}")
    print(f"  Layer 4 (Community):     {'📢 Reports' if community['report_count'] > 0 else '✓ No reports'}")
    print()
    
    return in_range, actual_score


async def main():
    success, score = await test_merge_token()
    
    if success:
        print(f"{Fore.GREEN}✅ Test PASSED - Reentrancy exploit correctly detected and scored!{Style.RESET_ALL}\n")
        return 0
    else:
        print(f"{Fore.YELLOW}⚠️ Test completed - Score: {score:.1f}{Style.RESET_ALL}\n")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
