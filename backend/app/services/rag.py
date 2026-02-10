"""
RAG (Retrieval-Augmented Generation) service using in-memory vector store for vulnerability pattern matching.
Note: ChromaDB has compatibility issues with Python 3.14, using simple similarity search instead.
"""

from typing import List, Dict, Any, Optional
import json
import logging
import os
import re
from collections import defaultdict

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class SimpleVectorStore:
    """
    Simple in-memory vector store using keyword-based similarity.
    This is a fallback implementation for Python 3.14 compatibility.
    For production, consider using ChromaDB with Python 3.12.
    """
    
    def __init__(self):
        self.documents: Dict[str, Dict[str, Any]] = {}
    
    def add(self, doc_id: str, document: str, metadata: Dict[str, Any]):
        """Add a document to the store"""
        # Create simple keyword index
        keywords = self._extract_keywords(document)
        self.documents[doc_id] = {
            "document": document,
            "metadata": metadata,
            "keywords": keywords,
        }
    
    def _extract_keywords(self, text: str) -> set:
        """Extract keywords from text for matching"""
        # Common Solidity/security keywords
        text_lower = text.lower()
        words = re.findall(r'\b[a-z_]+\b', text_lower)
        # Filter to meaningful keywords
        stopwords = {'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 
                     'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will',
                     'would', 'could', 'should', 'may', 'might', 'must', 'can',
                     'to', 'of', 'in', 'for', 'on', 'with', 'at', 'by', 'from',
                     'as', 'or', 'and', 'but', 'if', 'this', 'that', 'which'}
        return {w for w in words if len(w) > 2 and w not in stopwords}
    
    def search(self, query: str, n_results: int = 5, 
               severity_filter: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Search for similar documents"""
        query_keywords = self._extract_keywords(query)
        
        scores = []
        for doc_id, doc_data in self.documents.items():
            # Apply severity filter
            if severity_filter:
                doc_severity = doc_data["metadata"].get("severity", "")
                if doc_severity not in severity_filter:
                    continue
            
            # Calculate similarity score based on keyword overlap
            doc_keywords = doc_data["keywords"]
            if not doc_keywords:
                continue
            
            overlap = len(query_keywords & doc_keywords)
            score = overlap / max(len(doc_keywords), 1)
            
            scores.append({
                "id": doc_id,
                "document": doc_data["document"],
                "metadata": doc_data["metadata"],
                "score": score,
            })
        
        # Sort by score and return top results
        scores.sort(key=lambda x: x["score"], reverse=True)
        return scores[:n_results]
    
    def count(self) -> int:
        """Return number of documents"""
        return len(self.documents)
    
    def clear(self):
        """Clear all documents"""
        self.documents.clear()


class RAGService:
    """
    RAG service for vulnerability pattern matching.
    
    This service:
    1. Stores known vulnerability patterns in memory
    2. Retrieves similar vulnerabilities when analyzing new contracts
    3. Provides context to the LLM for more accurate analysis
    """
    
    def __init__(self):
        self.store = SimpleVectorStore()
        self._initialized = False
    
    def _ensure_initialized(self):
        """Lazy initialization"""
        if not self._initialized:
            logger.info("RAG Service initialized with in-memory store")
            self._initialized = True
    
    def add_vulnerability_patterns(self, patterns: List[Dict[str, Any]]) -> int:
        """
        Add vulnerability patterns to the vector store.
        
        Args:
            patterns: List of vulnerability pattern dictionaries with:
                - id: Unique identifier
                - name: Vulnerability name
                - description: Detailed description
                - severity: critical/high/medium/low/informational
                - code_example: Example vulnerable code (optional)
                - recommendation: Fix recommendation
        
        Returns:
            Number of patterns added
        """
        self._ensure_initialized()
        
        if not patterns:
            return 0
        
        count = 0
        for pattern in patterns:
            pattern_id = pattern.get("id", pattern.get("pattern_id", ""))
            if not pattern_id:
                continue
            
            # Create searchable document from pattern
            document = self._create_document(pattern)
            
            metadata = {
                "name": pattern.get("name", ""),
                "severity": pattern.get("severity", "medium"),
                "cwe_id": pattern.get("cwe_id", ""),
                "category": pattern.get("category", "general"),
            }
            
            self.store.add(pattern_id, document, metadata)
            count += 1
        
        logger.info(f"Added/updated {count} vulnerability patterns")
        return count
    
    def _create_document(self, pattern: Dict[str, Any]) -> str:
        """Create a searchable document from a vulnerability pattern"""
        parts = [
            f"Vulnerability: {pattern.get('name', 'Unknown')}",
            f"Severity: {pattern.get('severity', 'medium')}",
            f"Description: {pattern.get('description', '')}",
        ]
        
        if pattern.get("code_example"):
            parts.append(f"Example Code:\n{pattern['code_example']}")
        
        if pattern.get("recommendation"):
            parts.append(f"Recommendation: {pattern['recommendation']}")
        
        if pattern.get("cwe_id"):
            parts.append(f"CWE: {pattern['cwe_id']}")
        
        return "\n".join(parts)
    
    def search_similar_vulnerabilities(
        self, 
        code_snippet: str, 
        n_results: int = 5,
        severity_filter: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for similar vulnerability patterns based on code snippet.
        """
        self._ensure_initialized()
        
        results = self.store.search(code_snippet, n_results=n_results, 
                                     severity_filter=severity_filter)
        
        similar_patterns = []
        for result in results:
            similar_patterns.append({
                "id": result["id"],
                "name": result["metadata"].get("name", ""),
                "severity": result["metadata"].get("severity", ""),
                "cwe_id": result["metadata"].get("cwe_id", ""),
                "document": result["document"],
                "distance": 1 - result["score"],
                "relevance_score": result["score"],
            })
        
        return similar_patterns
    
    def get_context_for_analysis(
        self, 
        source_code: str,
        top_k: int = 10
    ) -> str:
        """
        Get relevant vulnerability context for LLM analysis.
        
        This method retrieves the most relevant vulnerability patterns
        to provide as context to the LLM for more accurate analysis.
        
        Args:
            source_code: Full contract source code
            top_k: Number of patterns to retrieve
        
        Returns:
            Formatted context string for LLM
        """
        # Search for relevant patterns
        patterns = self.search_similar_vulnerabilities(source_code, n_results=top_k)
        
        if not patterns:
            return "No relevant vulnerability patterns found in knowledge base."
        
        # Format context
        context_parts = ["## Relevant Vulnerability Patterns from Knowledge Base:\n"]
        
        for i, pattern in enumerate(patterns, 1):
            relevance = pattern.get('relevance_score', 0) * 100
            context_parts.append(f"""
### {i}. {pattern.get('name', 'Unknown')} (Relevance: {relevance:.1f}%)
- **Severity**: {pattern.get('severity', 'N/A')}
- **CWE**: {pattern.get('cwe_id', 'N/A')}
- **Details**: {pattern.get('document', 'N/A')[:500]}...
""")
        
        return "\n".join(context_parts)
    
    def get_pattern_count(self) -> int:
        """Get total number of patterns in the database"""
        self._ensure_initialized()
        return self.store.count()
    
    def clear_patterns(self):
        """Clear all patterns from the collection (use with caution)"""
        self.store.clear()
        logger.info("Cleared all vulnerability patterns")
    
    def check_health(self) -> bool:
        """Check if the RAG store is healthy"""
        return True


# Singleton instance
rag_service = RAGService()


# ===== Default Vulnerability Patterns =====

DEFAULT_VULNERABILITY_PATTERNS = [
    {
        "id": "reentrancy",
        "name": "Reentrancy",
        "severity": "critical",
        "category": "security",
        "cwe_id": "CWE-841",
        "description": "A reentrancy attack occurs when a contract makes an external call before updating its state, allowing the called contract to re-enter and exploit the inconsistent state.",
        "code_example": """
// Vulnerable code
function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount;  // State update after external call
}
        """,
        "recommendation": "Use the checks-effects-interactions pattern: update state before making external calls. Consider using ReentrancyGuard from OpenZeppelin."
    },
    {
        "id": "overflow-underflow",
        "name": "Integer Overflow/Underflow",
        "severity": "high",
        "category": "arithmetic",
        "cwe_id": "CWE-190",
        "description": "Integer overflow or underflow occurs when arithmetic operations exceed the maximum or minimum value a variable can hold, wrapping around to unexpected values.",
        "code_example": """
// Vulnerable in Solidity < 0.8.0
uint8 balance = 255;
balance += 1;  // Overflows to 0
        """,
        "recommendation": "Use Solidity 0.8.0+ which has built-in overflow checks, or use SafeMath library for older versions."
    },
    {
        "id": "access-control",
        "name": "Missing Access Control",
        "severity": "critical",
        "category": "access-control",
        "cwe_id": "CWE-284",
        "description": "Critical functions lacking proper access controls can be called by anyone, potentially leading to unauthorized state changes or fund theft.",
        "code_example": """
// Vulnerable - anyone can call
function setOwner(address newOwner) public {
    owner = newOwner;
}
        """,
        "recommendation": "Implement proper access control using modifiers like onlyOwner, or use OpenZeppelin's AccessControl or Ownable contracts."
    },
    {
        "id": "unchecked-return",
        "name": "Unchecked Return Values",
        "severity": "medium",
        "category": "error-handling",
        "cwe_id": "CWE-252",
        "description": "Failing to check return values of external calls can lead to silent failures and unexpected behavior.",
        "code_example": """
// Vulnerable - return value not checked
token.transfer(recipient, amount);
        """,
        "recommendation": "Always check return values of external calls. Use SafeERC20 library for token transfers."
    },
    {
        "id": "tx-origin",
        "name": "tx.origin Authentication",
        "severity": "high",
        "category": "authentication",
        "cwe_id": "CWE-287",
        "description": "Using tx.origin for authentication is vulnerable to phishing attacks where a malicious contract tricks users into calling it.",
        "code_example": """
// Vulnerable
require(tx.origin == owner, "Not owner");
        """,
        "recommendation": "Use msg.sender instead of tx.origin for authentication."
    },
    {
        "id": "front-running",
        "name": "Front-Running Vulnerability",
        "severity": "medium",
        "category": "timing",
        "cwe_id": "CWE-362",
        "description": "Transactions visible in the mempool can be front-run by miners or bots who submit competing transactions with higher gas prices.",
        "code_example": """
// Vulnerable to front-running
function claimReward(bytes32 answer) public {
    require(keccak256(abi.encodePacked(answer)) == storedHash);
    // Winner can be front-run
}
        """,
        "recommendation": "Use commit-reveal schemes, submarine sends, or other techniques to prevent front-running."
    },
    {
        "id": "delegatecall",
        "name": "Unsafe Delegatecall",
        "severity": "critical",
        "category": "security",
        "cwe_id": "CWE-829",
        "description": "Delegatecall executes code in the context of the calling contract, which can lead to storage corruption if not handled carefully.",
        "code_example": """
// Dangerous if target is untrusted
function execute(address target, bytes calldata data) public {
    target.delegatecall(data);
}
        """,
        "recommendation": "Only delegatecall to trusted, immutable contract addresses. Never delegatecall to user-supplied addresses."
    },
    {
        "id": "selfdestruct",
        "name": "Unprotected Selfdestruct",
        "severity": "critical",
        "category": "security",
        "cwe_id": "CWE-749",
        "description": "Selfdestruct can permanently destroy a contract and send remaining funds to a specified address. If unprotected, attackers can destroy the contract.",
        "code_example": """
// Vulnerable - anyone can destroy
function destroy(address payable recipient) public {
    selfdestruct(recipient);
}
        """,
        "recommendation": "Restrict selfdestruct to owner only, or remove it entirely as it's deprecated in newer Ethereum versions."
    },
    {
        "id": "block-timestamp",
        "name": "Block Timestamp Manipulation",
        "severity": "low",
        "category": "timing",
        "cwe_id": "CWE-367",
        "description": "Block timestamps can be slightly manipulated by miners (within ~15 seconds), making them unreliable for precise time-sensitive operations.",
        "code_example": """
// Potentially vulnerable
if (block.timestamp >= deadline) {
    // Time-sensitive action
}
        """,
        "recommendation": "Avoid using block.timestamp for critical time-sensitive operations. Allow for timestamp tolerance in time-based logic."
    },
    {
        "id": "dos-gas",
        "name": "Denial of Service (Gas Limit)",
        "severity": "medium",
        "category": "dos",
        "cwe_id": "CWE-400",
        "description": "Loops over unbounded arrays or expensive operations can cause transactions to exceed gas limits, making functions unusable.",
        "code_example": """
// Vulnerable to DoS
function distribute() public {
    for (uint i = 0; i < recipients.length; i++) {
        recipients[i].transfer(amounts[i]);
    }
}
        """,
        "recommendation": "Implement pull-over-push patterns, pagination, or gas limits for loops."
    },
    {
        "id": "flash-loan",
        "name": "Flash Loan Attack Vector",
        "severity": "high",
        "category": "defi",
        "cwe_id": "CWE-669",
        "description": "Contracts relying on token balances for price or governance decisions can be manipulated using flash loans.",
        "code_example": """
// Vulnerable to flash loan manipulation
function getPrice() public view returns (uint) {
    return token.balanceOf(address(this)) / totalSupply;
}
        """,
        "recommendation": "Use time-weighted average prices (TWAP), oracle solutions like Chainlink, or implement flash loan guards."
    },
    {
        "id": "oracle-manipulation",
        "name": "Price Oracle Manipulation",
        "severity": "critical",
        "category": "defi",
        "cwe_id": "CWE-346",
        "description": "Relying on easily manipulated price sources like spot prices on DEXs can lead to significant financial losses.",
        "code_example": """
// Vulnerable - single source oracle
uint price = uniswapPair.getReserves();
        """,
        "recommendation": "Use decentralized oracles like Chainlink, implement TWAP, or use multiple oracle sources with deviation checks."
    },
]


def seed_default_patterns():
    """Seed the database with default vulnerability patterns"""
    try:
        count = rag_service.add_vulnerability_patterns(DEFAULT_VULNERABILITY_PATTERNS)
        logger.info(f"Seeded {count} default vulnerability patterns")
        return count
    except Exception as e:
        logger.error(f"Failed to seed patterns: {e}")
        return 0
