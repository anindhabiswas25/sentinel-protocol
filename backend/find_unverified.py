"""
Find REAL unverified contracts to test bytecode analysis.
Strategy: Test contracts that likely don't have verified source code.
"""
import asyncio
import aiohttp

# Real unverified/honeypot/scam contracts (curated list)
UNVERIFIED_TEST_ADDRESSES = [
    # These are REAL addresses of contracts that are likely unverified
    # Found from honeypot databases and scam reports
    
    {
        "name": "Suspected Honeypot 1",
        "address": "0x7d89c67d3eb67B7141210fE93Fa6Cb7b96f3654A",  # Known honeypot
        "network": "ethereum",
        "category": "unverified_unsafe"
    },
    {
        "name": "Suspected Honeypot 2",
        "address": "0x98ea0b09d9C3b3Baa30d8dF61DC3Cc5F0e7D0Dc7",  # Another honeypot
        "network": "ethereum",
        "category": "unverified_unsafe"
    },
    {
        "name": "Old Unverified Token",
        "address": "0x3d1ba9be9f66b8ee101911bc36d3fb562eac2244",  # RFox token (might be unverified)
        "network": "ethereum",
        "category": "potentially_safe"
    },
    {
        "name": "Random Old Contract",
        "address": "0x8888889213dd4da823ebdd1e235b09590633c150",  # Old contract
        "network": "ethereum",
        "category": "unknown"
    },
    {
        "name": "MEV Bot Contract",
        "address": "0x00000000008c4fb1c916e0c88fd4cc402d935e7d",  # MEV bot
        "network": "ethereum",
        "category": "unknown"
    },
]

async def check_contract(address: str, network: str):
    """Quick check if contract is unverified and can be analyzed"""
    url = "http://localhost:8001/api/v1/analyze"
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(
                url,
                json={"contract_address": address, "network": network},
                timeout=aiohttp.ClientTimeout(total=60)
            ) as response:
                result = await response.json()
                
                is_verified = result.get("metadata", {}).get("is_verified", False)
                method = result.get("summary", {}).get("analysis_method", "unknown")
                score = result.get("trust_score", {}).get("overall_score", 0)
                risk = result.get("trust_score", {}).get("risk_level", "Unknown")
                success = result.get("success", False)
                
                return {
                    "address": address,
                    "success": success,
                    "verified": is_verified,
                    "method": method,
                    "score": score,
                    "risk": risk
                }
        except Exception as e:
            return {
                "address": address,
                "success": False,
                "error": str(e)
            }

async def main():
    print("=" * 80)
    print("SEARCHING FOR UNVERIFIED CONTRACTS")
    print("=" * 80)
    print()
    
    bytecode_analyzed = []
    verified_contracts = []
    failed_contracts = []
    
    for contract in UNVERIFIED_TEST_ADDRESSES:
        print(f"🔍 Testing: {contract['name']}")
        print(f"   Address: {contract['address']}")
        print(f"   Category: {contract['category']}")
        
        result = await check_contract(contract['address'], contract['network'])
        
        if result.get("success"):
            print(f"   ✅ Success: True")
            print(f"   📝 Verified: {result['verified']}")
            print(f"   🔧 Method: {result['method']}")
            print(f"   📊 Score: {result['score']}")
            print(f"   ⚠️  Risk: {result['risk']}")
            
            if result['method'] == 'bytecode_only':
                print(f"   ✨ BYTECODE ANALYSIS WORKING!")
                bytecode_analyzed.append({**contract, **result})
            elif result['verified']:
                print(f"   ℹ️  Contract is verified")
                verified_contracts.append({**contract, **result})
            else:
                print(f"   ℹ️  Detected via other method: {result['method']}")
        else:
            print(f"   ❌ Failed: {result.get('error', 'Unknown error')}")
            failed_contracts.append({**contract, **result})
        
        print()
    
    # Summary
    print("\n" + "=" * 80)
    print("📊 SUMMARY")
    print("=" * 80)
    print(f"\n✅ Total Tested: {len(UNVERIFIED_TEST_ADDRESSES)}")
    print(f"🧬 Bytecode Analysis Used: {len(bytecode_analyzed)}")
    print(f"📝 Verified (not unverified): {len(verified_contracts)}")
    print(f"❌ Failed: {len(failed_contracts)}")
    
    if bytecode_analyzed:
        print(f"\n✨ UNVERIFIED BYTECODE ANALYSIS WORKING! ✅")
        print(f"\nContracts analyzed via bytecode:")
        for c in bytecode_analyzed:
            print(f"  • {c['name']}: Score {c['score']}, Risk {c['risk']}")
    else:
        print(f"\n⚠️  NO UNVERIFIED CONTRACTS FOUND")
        print(f"   All test contracts were either:")
        print(f"   - Verified on Etherscan")
        print(f"   - In seed database (detected via dynamic-exploit-detection)")
        print(f"   - Failed to load")

if __name__ == "__main__":
    asyncio.run(main())
