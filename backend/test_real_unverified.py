"""
Test unverified contract detection with REAL addresses.
Strategy: Test contracts we know exist, let the system determine verification status.
"""
import asyncio
import aiohttp
from datetime import datetime
from typing import Dict, List

# Test contracts - mix of known verified and potentially unverified
TEST_CONTRACTS = {
    # Known VERIFIED (for baseline comparison)
    "verified_safe": [
        {
            "name": "USDT (Baseline Verified Safe)",
            "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            "network": "ethereum",
            "expected": "Should score 75-100 (verified safe)"
        },
    ],
    
    # Potentially UNVERIFIED contracts to test bytecode analysis
    "potentially_unverified": [
        {
            "name": "Deprecated Old Contract 1",
            "address": "0x06012c8cf97bead5deae237070f9587f8e7a266d",  # CryptoKitties - old, might be unverified
            "network": "ethereum",
            "expected": "Should analyze bytecode if unverified"
        },
        {
            "name": "Random ERC20 Token 1",
            "address": "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE",  # SHIB - check if verified
            "network": "ethereum",
            "expected": "Should handle verified or unverified"
        },
        {
            "name": "Old MEV Contract",
            "address": "0x000000000035b5e5ad9019092c665357240f594e",  # MEV bot - likely unverified
            "network": "ethereum",
            "expected": "Check bytecode analysis quality"
        },
        {
            "name": "Proxy Contract",
            "address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC (proxy) - compare
            "network": "ethereum",
            "expected": "Should handle proxy pattern"
        },
    ],
    
    # Known exploited (some might be unverified)
    "exploited_contracts": [
        {
            "name": "Merge Token (Known Exploit)",
            "address": "0x4a57e355bed70f6804084d1416e8f6e3f1d88690",
            "network": "ethereum",
            "expected": "Should detect exploit regardless of verification"
        },
    ]
}

async def analyze_contract(
    address: str,
    network: str,
    session: aiohttp.ClientSession
) -> Dict:
    """Call the analyzer API"""
    url = "http://localhost:8001/api/v1/analyze"
    
    try:
        async with session.post(
            url,
            json={"contract_address": address, "network": network},
            timeout=aiohttp.ClientTimeout(total=60)
        ) as response:
            return await response.json()
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "trust_score": {"overall_score": 0.0, "risk_level": "Error"}
        }

async def test_unverified_detection():
    """Test the system's ability to handle unverified contracts"""
    
    print("=" * 80)
    print("REAL UNVERIFIED CONTRACT DETECTION TEST")
    print("=" * 80)
    print(f"Test started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    results = {
        "verified_baseline": [],
        "potentially_unverified": [],
        "exploited_contracts": []
    }
    
    async with aiohttp.ClientSession() as session:
        # Test verified baseline
        print("\n📊 CATEGORY 1: VERIFIED SAFE (Baseline)")
        print("-" * 80)
        for contract in TEST_CONTRACTS["verified_safe"]:
            print(f"\n🔍 Testing: {contract['name']}")
            print(f"   Address: {contract['address']}")
            
            result = await analyze_contract(
                contract["address"],
                contract["network"],
                session
            )
            
            is_verified = result.get("metadata", {}).get("is_verified", False)
            score = result.get("trust_score", {}).get("overall_score", 0)
            risk = result.get("trust_score", {}).get("risk_level", "Unknown")
            method = result.get("summary", {}).get("analysis_method", "unknown")
            success = result.get("success", False)
            
            print(f"   ✅ Success: {success}")
            print(f"   📝 Verified: {is_verified}")
            print(f"   📊 Score: {score}")
            print(f"   ⚠️  Risk: {risk}")
            print(f"   🔧 Method: {method}")
            
            results["verified_baseline"].append({
                "name": contract["name"],
                "address": contract["address"],
                "verified": is_verified,
                "score": score,
                "risk": risk,
                "method": method,
                "success": success
            })
        
        # Test potentially unverified
        print("\n\n📊 CATEGORY 2: POTENTIALLY UNVERIFIED (Bytecode Analysis Test)")
        print("-" * 80)
        for contract in TEST_CONTRACTS["potentially_unverified"]:
            print(f"\n🔍 Testing: {contract['name']}")
            print(f"   Address: {contract['address']}")
            print(f"   Expected: {contract['expected']}")
            
            result = await analyze_contract(
                contract["address"],
                contract["network"],
                session
            )
            
            is_verified = result.get("metadata", {}).get("is_verified", False)
            score = result.get("trust_score", {}).get("overall_score", 0)
            risk = result.get("trust_score", {}).get("risk_level", "Unknown")
            method = result.get("summary", {}).get("analysis_method", "unknown")
            success = result.get("success", False)
            
            print(f"   ✅ Success: {success}")
            print(f"   📝 Verified: {is_verified}")
            print(f"   📊 Score: {score}")
            print(f"   ⚠️  Risk: {risk}")
            print(f"   🔧 Method: {method}")
            
            if not is_verified and method == "bytecode_only":
                print(f"   ✨ BYTECODE ANALYSIS WORKING!")
            elif is_verified:
                print(f"   ℹ️  Contract is verified (not unverified test case)")
            
            results["potentially_unverified"].append({
                "name": contract["name"],
                "address": contract["address"],
                "verified": is_verified,
                "score": score,
                "risk": risk,
                "method": method,
                "success": success
            })
        
        # Test exploited contracts
        print("\n\n📊 CATEGORY 3: EXPLOITED CONTRACTS")
        print("-" * 80)
        for contract in TEST_CONTRACTS["exploited_contracts"]:
            print(f"\n🔍 Testing: {contract['name']}")
            print(f"   Address: {contract['address']}")
            
            result = await analyze_contract(
                contract["address"],
                contract["network"],
                session
            )
            
            is_verified = result.get("metadata", {}).get("is_verified", False)
            score = result.get("trust_score", {}).get("overall_score", 0)
            risk = result.get("trust_score", {}).get("risk_level", "Unknown")
            method = result.get("summary", {}).get("analysis_method", "unknown")
            success = result.get("success", False)
            is_exploit = result.get("security_check", {}).get("is_exploited", False)
            
            print(f"   ✅ Success: {success}")
            print(f"   📝 Verified: {is_verified}")
            print(f"   💀 Exploited: {is_exploit}")
            print(f"   📊 Score: {score}")
            print(f"   ⚠️  Risk: {risk}")
            print(f"   🔧 Method: {method}")
            
            results["exploited_contracts"].append({
                "name": contract["name"],
                "address": contract["address"],
                "verified": is_verified,
                "exploited": is_exploit,
                "score": score,
                "risk": risk,
                "method": method,
                "success": success
            })
    
    # Summary
    print("\n\n" + "=" * 80)
    print("📈 UNVERIFIED DETECTION CAPABILITY SUMMARY")
    print("=" * 80)
    
    # Count unverified contracts tested
    unverified_count = sum(
        1 for r in results["potentially_unverified"] 
        if not r["verified"] and r["success"]
    )
    bytecode_analysis_count = sum(
        1 for r in results["potentially_unverified"]
        if r["method"] == "bytecode_only" and r["success"]
    )
    
    print(f"\n✅ Total Contracts Tested: {sum(len(v) for v in results.values())}")
    print(f"📝 Verified Baseline: {len(results['verified_baseline'])} contracts")
    print(f"🔍 Unverified Detected: {unverified_count} contracts")
    print(f"🧬 Bytecode Analysis Used: {bytecode_analysis_count} times")
    print(f"💀 Exploited Contracts: {len(results['exploited_contracts'])} contracts")
    
    if bytecode_analysis_count > 0:
        print(f"\n✨ UNVERIFIED CONTRACT DETECTION: WORKING ✅")
        print(f"   System successfully analyzed {bytecode_analysis_count} contracts using bytecode-only method")
    else:
        print(f"\n⚠️  NO UNVERIFIED CONTRACTS FOUND IN TEST SET")
        print(f"   All test contracts were verified or had errors")
        print(f"   Recommendation: Search Etherscan for unverified contracts to test bytecode analysis")
    
    # Detailed breakdown
    print(f"\n📊 DETAILED RESULTS BY CATEGORY:")
    
    for category, contracts in results.items():
        print(f"\n{category.upper().replace('_', ' ')}:")
        for c in contracts:
            status = "✅" if c["success"] else "❌"
            verify_badge = "📝" if c["verified"] else "🔍"
            print(f"  {status} {verify_badge} {c['name']}")
            print(f"      Score: {c['score']}, Risk: {c['risk']}, Method: {c['method']}")

if __name__ == "__main__":
    asyncio.run(test_unverified_detection())
