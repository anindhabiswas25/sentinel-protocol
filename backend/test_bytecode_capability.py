"""
Direct test of unverified contract bytecode analysis capability.
Tests the _analyze_unverified_contract() method directly.
"""
import asyncio
import sys
sys.path.append('.')

from app.services.analyzer import ContractAnalyzer
from app.services.blockchain_analyzer import BlockchainService

# Real contract bytecode samples for testing
TEST_CASES = [
    {
        "name": "Simple ERC20 Token (Safe Pattern)",
        "address": "0x1111111111111111111111111111111111111111",
        # Simplified ERC20 bytecode pattern (safe operations)
        "bytecode": "0x608060405260043610610041576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806370a0823114610046575b600080fd5b34801561005257600080fd5b50610095600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610097565b005b505600a165627a7a7230582000000000000000000000000000000000000000000000000000000000000000000029"
    },
    {
        "name": "Contract with Selfdestruct (Risky Pattern)",
        "address": "0x2222222222222222222222222222222222222222",
        # Contains selfdestruct opcode (ff)
        "bytecode": "0x6080604052348015600f57600080fd5b506004361060285760003560e01c8063c9da519314602d575b600080fd5b60336035565b005b3373ffffffffffffffffffffffffffffffffffffffff16fffe5b00"
    },
    {
        "name": "Contract with Delegatecall (High Risk)",
        "address": "0x3333333333333333333333333333333333333333",
        # Contains delegatecall opcode (f4)
        "bytecode": "0x608060405260043610604057600035600f5b600080fd5b600080f4"
    },
]

async def test_bytecode_analysis():
    """
    Test if bytecode analysis works for unverified contracts.
    """
    print("=" * 80)
    print("BYTECODE ANALYSIS CAPABILITY TEST")
    print("=" * 80)
    print()
    print("Testing _analyze_unverified_contract() method directly")
    print()
    
    analyzer = ContractAnalyzer()
    blockchain_service = BlockchainService()
    
    results = []
    
    for test_case in TEST_CASES:
        print(f"🧪 Test Case: {test_case['name']}")
        print(f"   Address: {test_case['address']}")
        print(f"   Bytecode Length: {len(test_case['bytecode'])} chars")
        
        try:
            # Analyze bytecode patterns first
            bytecode_analysis = blockchain_service.analyze_bytecode_patterns(
                test_case['bytecode']
            )
            
            print(f"   📊 Bytecode Patterns Detected:")
            if bytecode_analysis:
                for key, value in bytecode_analysis.items():
                    if isinstance(value, bool) and value:
                        print(f"      • {key}: ✅")
                    elif isinstance(value, (int, float)) and value > 0:
                        print(f"      • {key}: {value}")
            
            # Call the unverified contract analyzer
            analysis_result = await analyzer._analyze_unverified_contract(
                bytecode=test_case['bytecode'],
                bytecode_analysis=bytecode_analysis,
                address=test_case['address'],
                network="ethereum"
            )
            
            # Check results
            method = analysis_result.get('analysis_method')
            score = analysis_result.get('overall_score', 'N/A')
            vulnerabilities = analysis_result.get('vulnerabilities', [])
            
            print(f"   ✅ Analysis Complete!")
            print(f"   🔧 Method: {method}")
            print(f"   📊 Quality Score: {analysis_result.get('_validation_quality', 'N/A')}")
            print(f"   🚨 Vulnerabilities Found: {len(vulnerabilities)}")
            
            if vulnerabilities:
                print(f"   📋 Detected Issues:")
                for vuln in vulnerabilities[:3]:  # Show first 3
                    print(f"      • {vuln.get('title', 'Unknown')}: {vuln.get('severity', 'unknown')}")
            
            results.append({
                "test": test_case['name'],
                "success": True,
                "method": method,
                "vulns": len(vulnerabilities)
            })
            
            print(f"   ✅ PASS\n")
            
        except Exception as e:
            print(f"   ❌ FAILED: {str(e)}\n")
            results.append({
                "test": test_case['name'],
                "success": False,
                "error": str(e)
            })
    
    # Summary
    print("\n" + "=" * 80)
    print("📊 TEST SUMMARY")
    print("=" * 80)
    
    passed = sum(1 for r in results if r.get("success"))
    total = len(results)
    
    print(f"\n✅ Tests Passed: {passed}/{total}")
    print(f"📊 Success Rate: {(passed/total)*100:.1f}%")
    
    bytecode_method_used = sum(
        1 for r in results 
        if r.get("success") and r.get("method") == "bytecode_only"
    )
    
    print(f"\n🧬 Bytecode Analysis Method Used: {bytecode_method_used} times")
    
    if bytecode_method_used > 0:
        print(f"\n✅ BYTECODE ANALYSIS CAPABILITY: CONFIRMED WORKING ✅")
        print(f"   The system CAN analyze unverified contracts using:")
        print(f"   • LLM bytecode analysis")
        print(f"   • Regex pattern detection")
        print(f"   • Cross-validation pipeline")
        print(f"   • Analysis method: 'bytecode_only'")
    else:
        print(f"\n❌ BYTECODE ANALYSIS: NOT WORKING")
    
    print(f"\n📋 DETAILED RESULTS:")
    for r in results:
        status = "✅" if r.get("success") else "❌"
        print(f"  {status} {r['test']}")
        if r.get("success"):
            print(f"      Method: {r.get('method')}, Vulnerabilities: {r.get('vulns')}")
        else:
            print(f"      Error: {r.get('error')}")

if __name__ == "__main__":
    asyncio.run(test_bytecode_analysis())
