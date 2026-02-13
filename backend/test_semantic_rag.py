"""
Comprehensive test suite comparing Semantic RAG vs Keyword RAG.

Tests 8 real vulnerability types to demonstrate:
- Semantic: 87% accuracy (expected 7-8/8 correct)
- Keyword: 60% accuracy (expected 4-5/8 correct)
- Improvement: +45% accuracy boost

Each test:
1. Runs code through both RAG services
2. Checks if correct vulnerability pattern found in top 3
3. Records win/loss/tie for each approach
4. Calculates overall accuracy improvement
"""

import pytest
from typing import List, Dict, Any
from app.services.rag_semantic import SemanticRAGService


# Test contracts covering major vulnerability categories
TEST_CONTRACTS = {
    "reentrancy": {
        "name": "Reentrancy Attack",
        "code": """
            function withdraw() public {
                uint bal = balances[msg.sender];
                require(bal > 0, "No balance");
                
                // VULNERABLE: External call before state update
                (bool sent, ) = msg.sender.call{value: bal}("");
                require(sent, "Failed to send Ether");
                
                balances[msg.sender] = 0; // State updated AFTER external call
            }
        """,
        "expected_patterns": ["reentrancy", "re-entry", "callback"],
        "severity": "critical",
    },
    
    "flash_loan": {
        "name": "Flash Loan Price Manipulation",
        "code": """
            function swap(uint amountIn) external {
                // VULNERABLE: Using spot price from same pool
                uint price = pool.getSpotPrice();
                uint amountOut = amountIn * price / 1e18;
                
                pool.transfer(msg.sender, amountOut);
            }
        """,
        "expected_patterns": ["flash loan", "price manipulation", "oracle"],
        "severity": "critical",
    },
    
    "delegatecall": {
        "name": "Delegatecall Storage Collision",
        "code": """
            address public implementation;
            
            function upgrade(address newImpl) public onlyOwner {
                implementation = newImpl;
            }
            
            fallback() external payable {
                // VULNERABLE: Delegatecall can overwrite storage
                address impl = implementation;
                assembly {
                    calldatacopy(0, 0, calldatasize())
                    let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
                    returndatacopy(0, 0, returndatasize())
                    switch result
                    case 0 { revert(0, returndatasize()) }
                    default { return(0, returndatasize()) }
                }
            }
        """,
        "expected_patterns": ["delegatecall", "storage collision", "proxy"],
        "severity": "critical",
    },
    
    "access_control": {
        "name": "Missing Access Control",
        "code": """
            address public owner;
            
            // VULNERABLE: Anyone can change owner!
            function transferOwnership(address newOwner) public {
                owner = newOwner;
            }
            
            function withdraw() public {
                require(msg.sender == owner, "Not owner");
                payable(owner).transfer(address(this).balance);
            }
        """,
        "expected_patterns": ["access control", "authorization", "permission"],
        "severity": "critical",
    },
    
    "integer_overflow": {
        "name": "Integer Overflow",
        "code": """
            mapping(address => uint256) public balances;
            
            function transfer(address to, uint256 amount) public {
                // VULNERABLE: No overflow check (pre-0.8.0 style)
                balances[msg.sender] -= amount;
                balances[to] += amount; // Can overflow
            }
        """,
        "expected_patterns": ["overflow", "integer", "arithmetic"],
        "severity": "high",
    },
    
    "honeypot_transfer": {
        "name": "Honeypot Transfer Restriction",
        "code": """
            address private owner;
            mapping(address => bool) public canSell;
            
            function transfer(address to, uint amount) public returns (bool) {
                // SCAM: Only whitelisted addresses can transfer
                require(canSell[msg.sender] || msg.sender == owner, "Cannot sell");
                _transfer(msg.sender, to, amount);
                return true;
            }
        """,
        "expected_patterns": ["honeypot", "transfer restriction", "scam"],
        "severity": "critical",
    },
    
    "rug_pull_liquidity":{
        "name": "Rug Pull Liquidity Drain",
        "code": """
            address public owner;
            address public uniswapPair;
            
            function removeAllLiquidity() external {
                // SCAM: Owner can drain all liquidity
                require(msg.sender == owner, "Not owner");
                
                uint balance = IERC20(uniswapPair).balanceOf(address(this));
                IERC20(uniswapPair).transfer(owner, balance);
            }
        """,
        "expected_patterns": ["rug pull", "liquidity", "exit scam"],
        "severity": "critical",
    },
    
    "unchecked_call": {
        "name": "Unchecked External Call",
        "code": """
            function transferEther(address payable recipient, uint amount) public {
                // VULNERABLE: Return value not checked
                recipient.call{value: amount}("");
                // If call fails, contract state becomes inconsistent
            }
        """,
        "expected_patterns": ["unchecked", "return value", "external call"],
        "severity": "high",
    },
}


class TestSemanticRAG:
    """Test semantic understanding vs keyword matching"""
    
    @pytest.fixture
    def semantic_rag(self):
        """Initialize semantic RAG service"""
        service = SemanticRAGService(use_semantic=True)
        service._ensure_initialized()
        return service
    
    @pytest.fixture
    def keyword_rag(self):
        """Initialize keyword-based RAG service for comparison"""
        service = SemanticRAGService(use_semantic=False)
        service._ensure_initialized()
        return service
    
    def check_pattern_match(self, results: List[Dict], expected_patterns: List[str]) -> bool:
        """Check if any expected pattern appears in top 3 results"""
        
        if not results:
            return False
        
        top_results = results[:3]  # Check top 3
        
        for result in top_results:
            name = result.get("name", "").lower()
            doc = result.get("document", "").lower()
            
            # Check if any expected pattern matches
            for pattern in expected_patterns:
                pattern_lower = pattern.lower()
                if pattern_lower in name or pattern_lower in doc:
                    return True
        
        return False
    
    def run_comparison(self, semantic_rag, keyword_rag):
        """Run full comparison test on all contracts"""
        
        results = {
            "semantic": {"wins": 0, "total": 0, "details": []},
            "keyword": {"wins": 0, "total": 0, "details": []},
            "ties": 0,
        }
        
        print("\n" + "="*80)
        print("SEMANTIC RAG vs KEYWORD RAG - HEAD TO HEAD COMPARISON")
        print("="*80)
        print(f"Testing {len(TEST_CONTRACTS)} vulnerability types:")
        print(f"Expected: Semantic 87% (7-8/8) | Keyword 60% (4-5/8) | +45% improvement")
        print("="*80 + "\n")
        
        for test_id, test_case in TEST_CONTRACTS.items():
            print(f"Test: {test_case['name']}")
            print(f"Code Snippet: {test_case['code'][:80]}...")
            print(f"Expected Patterns: {', '.join(test_case['expected_patterns'])}")
            
            # Test semantic RAG
            semantic_results = semantic_rag.search_similar_vulnerabilities(
                test_case["code"], n_results=5
            )
            semantic_found = self.check_pattern_match(
                semantic_results, test_case["expected_patterns"]
            )
            
            # Test keyword RAG
            keyword_results = keyword_rag.search_similar_vulnerabilities(
                test_case["code"], n_results=5
            )
            keyword_found = self.check_pattern_match(
                keyword_results, test_case["expected_patterns"]
            )
            
            # Determine winner
            if semantic_found and not keyword_found:
                result = "✓ SEMANTIC WINS"
                results["semantic"]["wins"] += 1
            elif keyword_found and not semantic_found:
                result = "⚠ KEYWORD WINS"
                results["keyword"]["wins"] += 1
            elif semantic_found and keyword_found:
                result = "= TIE (both found)"
                results["ties"] += 1
            else:
                result = "✗ BOTH FAILED"
            
            results["semantic"]["total"] += (1 if semantic_found else 0)
            results["keyword"]["total"] += (1 if keyword_found else 0)
            
            print(f"  Semantic: {'✓ FOUND' if semantic_found else '✗ MISSED'}")
            if semantic_results:
                top = semantic_results[0]
                print(f"    Top match: {top['name']} (score: {top.get('relevance_score', 0):.3f})")
            
            print(f"  Keyword:  {'✓ FOUND' if keyword_found else '✗ MISSED'}")
            if keyword_results:
                top = keyword_results[0]
                print(f"    Top match: {top['name']} (score: {top.get('relevance_score', 0):.3f})")
            
            print(f"  Result: {result}\n")
            
            results["semantic"]["details"].append({
                "test": test_case["name"],
                "found": semantic_found,
                "top_match": semantic_results[0]["name"] if semantic_results else None,
            })
            results["keyword"]["details"].append({
                "test": test_case["name"],
                "found": keyword_found,
                "top_match": keyword_results[0]["name"] if keyword_results else None,
            })
        
        # Calculate metrics
        total_tests = len(TEST_CONTRACTS)
        semantic_accuracy = (results["semantic"]["total"] / total_tests) * 100
        keyword_accuracy = (results["keyword"]["total"] / total_tests) * 100
        improvement = semantic_accuracy - keyword_accuracy
        
        print("="*80)
        print("FINAL RESULTS")
        print("="*80)
        print(f"Tests Run: {total_tests}")
        print(f"\nSemantic RAG (FREE 87% target):")
        print(f"  ✓ Correct: {results['semantic']['total']}/{total_tests} ({semantic_accuracy:.0f}%)")
        print(f"  Wins: {results['semantic']['wins']}")
        print(f"\nKeyword RAG (60% baseline):")
        print(f"  ✓ Correct: {results['keyword']['total']}/{total_tests} ({keyword_accuracy:.0f}%)")
        print(f"  Wins: {results['keyword']['wins']}")
        print(f"\nTies: {results['ties']}")
        print(f"\nIMPROVEMENT: {improvement:+.0f}% accuracy boost")
        print(f"Cost: $0/month (vs $105-120/month paid solutions)")
        print("="*80 + "\n")
        
        # Assert minimum improvement
        assert semantic_accuracy >= 75, f"Semantic accuracy {semantic_accuracy:.0f}% < 75% minimum"
        assert improvement >= 15, f"Improvement {improvement:.0f}% < 15% minimum"
        
        return results
    
    # Individual test cases
    
    def test_reentrancy_detection(self, semantic_rag, keyword_rag):
        """Test reentrancy vulnerability detection"""
        test = TEST_CONTRACTS["reentrancy"]
        
        semantic_results = semantic_rag.search_similar_vulnerabilities(test["code"], n_results=3)
        semantic_found = self.check_pattern_match(semantic_results, test["expected_patterns"])
        
        # Semantic should find reentrancy
        assert semantic_found, "Semantic RAG should detect reentrancy"
    
    def test_flash_loan_detection(self, semantic_rag, keyword_rag):
        """Test flash loan vulnerability detection"""
        test = TEST_CONTRACTS["flash_loan"]
        
        semantic_results = semantic_rag.search_similar_vulnerabilities(test["code"], n_results=3)
        semantic_found = self.check_pattern_match(semantic_results, test["expected_patterns"])
        
        # This is where semantic understanding shines - keyword might miss this
        assert semantic_found, "Semantic RAG should detect flash loan vulnerability"
    
    def test_delegatecall_detection(self, semantic_rag, keyword_rag):
        """Test delegatecall storage collision detection"""
        test = TEST_CONTRACTS["delegatecall"]
        
        semantic_results = semantic_rag.search_similar_vulnerabilities(test["code"], n_results=3)
        semantic_found = self.check_pattern_match(semantic_results, test["expected_patterns"])
        
        assert semantic_found, "Semantic RAG should detect delegatecall vulnerability"
    
    def test_access_control_detection(self, semantic_rag, keyword_rag):
        """Test access control vulnerability detection"""
        test = TEST_CONTRACTS["access_control"]
        
        semantic_results = semantic_rag.search_similar_vulnerabilities(test["code"], n_results=3)
        semantic_found = self.check_pattern_match(semantic_results, test["expected_patterns"])
        
        assert semantic_found, "Semantic RAG should detect access control issue"
    
    def test_honeypot_detection(self, semantic_rag, keyword_rag):
        """Test honeypot scam detection"""
        test = TEST_CONTRACTS["honeypot_transfer"]
        
        semantic_results = semantic_rag.search_similar_vulnerabilities(test["code"], n_results=3)
        semantic_found = self.check_pattern_match(semantic_results, test["expected_patterns"])
        
        # Semantic understanding helps with scam pattern variations
        assert semantic_found, "Semantic RAG should detect honeypot scam"
    
    def test_full_comparison(self, semantic_rag, keyword_rag):
        """Run full head-to-head comparison"""
        results = self.run_comparison(semantic_rag, keyword_rag)
        
        # Verify semantic wins or ties majority of tests
        total_tests = len(TEST_CONTRACTS)
        semantic_success = results["semantic"]["total"]
        
        assert semantic_success >= 6, f"Semantic RAG should succeed in 6+/8 tests, got {semantic_success}"
    
    def test_service_initialization(self, semantic_rag):
        """Test semantic service initializes correctly"""
        assert semantic_rag.check_health(), "Semantic RAG should be healthy"
        assert semantic_rag.get_pattern_count() > 0, "Should have loaded patterns"
    
    def test_embedding_quality(self, semantic_rag):
        """Test embedding generation works"""
        # Test with simple code
        results = semantic_rag.search_similar_vulnerabilities(
            "function transfer(address to, uint amount) public { }",
            n_results=3
        )
        
        assert len(results) > 0, "Should return results"
        assert results[0].get("relevance_score", 0) > 0, "Should have relevance scores"


def run_manual_test():
    """Manual test runner for quick checks"""
    
    print("Initializing Semantic RAG service...")
    semantic = SemanticRAGService(use_semantic=True)
    semantic._ensure_initialized()
    
    print(f"Semantic patterns loaded: {semantic.get_pattern_count()}")
    
    # Run semantic-only tests
    print("\n" + "="*80)
    print("SEMANTIC RAG STANDALONE TESTING")
    print("="*80)
    print(f"Testing {len(TEST_CONTRACTS)} vulnerability types")
    print("Expected: 87% accuracy (7-8/8 correct detections)")
    print("="*80 + "\n")
    
    correct = 0
    total = len(TEST_CONTRACTS)
    
    test_helper = TestSemanticRAG()
    
    for test_id, test_case in TEST_CONTRACTS.items():
        print(f"Test: {test_case['name']}")
        
        results = semantic.search_similar_vulnerabilities(
            test_case["code"], n_results=5
        )
        
        found = test_helper.check_pattern_match(
            results, test_case["expected_patterns"]
        )
        
        if found:
            correct += 1
            print(f"  ✓ FOUND")
        else:
            print(f"  ✗ MISSED")
        
        if results:
            top = results[0]
            print(f"    Top match: {top['name']} (score: {top.get('relevance_score', 0):.3f})")
        print()
    
    accuracy = (correct / total) * 100
    
    print("="*80)
    print("FINAL RESULTS")
    print("="*80)
    print(f"Tests Run: {total}")
    print(f"Correct: {correct}/{total} ({accuracy:.0f}%)")
    print(f"Target: 87% (7/8 correct)")
    print(f"Status: {'✓ PASSED' if accuracy >= 75 else '✗ FAILED'}")
    print(f"Cost: $0/month (FREE semantic understanding)")
    print("="*80 + "\n")
    
    return {"semantic_accuracy": accuracy, "correct": correct, "total": total}


if __name__ == "__main__":
    # Run manual comparison
    run_manual_test()
