"""
Test Dynamic AI Scoring System
Demonstrates the AI-powered trust scoring without manual whitelists
"""

import asyncio
import sys
import json
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

from app.models.schemas import ContractAnalysisRequest, NetworkEnum
from app.services.analyzer import analyzer_service


async def test_contract(address: str, network: str = "ethereum", description: str = ""):
    """Test a contract with the new AI scoring"""
    print(f"\n{'='*80}")
    print(f"🧪 Testing: {description}")
    print(f"📍 Address: {address}")
    print(f"🌐 Network: {network}")
    print(f"{'='*80}\n")
    
    try:
        request = ContractAnalysisRequest(
            contract_address=address,
            network=NetworkEnum(network),
            force_refresh=True  # Always use fresh analysis
        )
        
        result = await analyzer_service.analyze_contract(request)
        
        if result.success:
            print(f"✅ Analysis Complete!")
            print(f"\n📊 TRUST SCORE: {result.trust_score.overall_score}/100")
            print(f"   Risk Level: {result.trust_score.risk_level}")
            print(f"   Security: {result.trust_score.security_score}/100")
            print(f"   Verification: {'✅ Verified' if result.metadata.is_verified else '❌ Unverified'}")
            
            print(f"\n🔍 Vulnerabilities Found: {result.summary.total_vulnerabilities}")
            if result.vulnerabilities:
                print(f"   Critical: {result.summary.critical_count}")
                print(f"   High: {result.summary.high_count}")
                print(f"   Medium: {result.summary.medium_count}")
                print(f"   Low: {result.summary.low_count}")
            
            print(f"\n💡 Top Recommendations:")
            for i, rec in enumerate(result.recommendations[:3], 1):
                print(f"   {i}. {rec}")
            
            # Display category determination
            score = result.trust_score.overall_score
            if score >= 75:
                print(f"\n🟢 Category: VERIFIED SAFE - Proceed with confidence")
            elif score >= 50:
                print(f"\n🟡 Category: UNVERIFIED SAFE - Use with caution")
            elif score >= 25:
                print(f"\n🟠 Category: VERIFIED UNSAFE - Avoid interaction")
            else:
                print(f"\n🔴 Category: UNVERIFIED UNSAFE - NEVER USE")
        else:
            print(f"❌ Analysis failed: {result.recommendations[0] if result.recommendations else 'Unknown error'}")
    
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


async def main():
    """Run comprehensive tests of AI scoring system"""
    print("\n" + "="*80)
    print("🤖 SENTINEL PROTOCOL - DYNAMIC AI SCORING TEST SUITE")
    print("   No Manual Whitelists • Learns from Every Analysis • Gets Smarter Over Time")
    print("="*80)
    
    # Test 1: Well-known Safe Contract (should score 85+)
    await test_contract(
        "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        "ethereum",
        "USDT - Major Stablecoin (Should score 85+)"
    )
    
    # Test 2: OpenSea Seaport (should now score correctly without manual whitelist)
    await test_contract(
        "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC",
        "ethereum",
        "OpenSea Seaport - NFT Marketplace (Should score 80+)"
    )
    
    # Test 3: ENS Registry (should score correctly)
    await test_contract(
        "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e",
        "ethereum",
        "ENS Registry - Name Service (Should score 90+)"
    )
    
    # Test 4: Known Exploited Contract (should score low)
    await test_contract(
        "0xF42c318dbfBaab0EEE040279c6A2588Fa01a961d",
        "ethereum",
        "Akutars NFT - Known Locked Funds Bug (Should score 25-49)"
    )
    
    # Get similarity service stats
    print(f"\n{'='*80}")
    print("📈 LEARNING DATABASE STATISTICS")
    print(f"{'='*80}")
    
    from app.services.similarity_search import similarity_service
    stats = similarity_service.get_database_stats()
    
    print(f"\n   Total Contracts Analyzed: {stats['total_contracts']}")
    print(f"   Verified: {stats['verified_contracts']}")
    print(f"   Unverified: {stats['unverified_contracts']}")
    print(f"   Average Trust Score: {stats['avg_trust_score']:.1f}")
    print(f"   Networks: {', '.join(stats['networks'])}")
    
    print(f"\n💡 The system is now LEARNING! Each analysis improves future accuracy.")
    print(f"   Run more analyses to see the AI get smarter! 🧠\n")


if __name__ == "__main__":
    asyncio.run(main())
