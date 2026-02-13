"""
Contract Similarity Search Service
Learns from historical contract analyses to improve scoring accuracy
"""

import logging
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from sentence_transformers import SentenceTransformer
import numpy as np

logger = logging.getLogger(__name__)


class ContractSimilarityService:
    """
    AI-powered contract similarity search.
    Learns from previous analyses to improve accuracy over time.
    
    How it works:
    1. Stores each analyzed contract with its trust score
    2. When analyzing new contracts, finds similar ones
    3. Uses similar contracts' scores to adjust new contract scores
    4. System gets smarter with every analysis!
    """
    
    def __init__(self):
        """Initialize similarity search with semantic model"""
        # Use lightweight semantic model
        logger.info("Loading contract similarity model...")
        self.model = SentenceTransformer("all-MiniLM-L6-v2")
        
        # In-memory storage (in production, use actual ChromaDB or Postgres)
        self.contract_database: Dict[str, Dict[str, Any]] = {}
        
        logger.info("Contract similarity service ready")
    
    def store_analysis(
        self,
        contract_address: str,
        bytecode: str,
        trust_score: float,
        is_verified: bool,
        vulnerabilities: List[Dict],
        network: str = "ethereum"
    ):
        """
        Store contract analysis for future similarity searches.
        This is how the system learns!
        
        Args:
            contract_address: Contract address
            bytecode: Contract bytecode
            trust_score: Calculated trust score
            is_verified: Whether source code is verified
            vulnerabilities: List of detected vulnerabilities
            network: Blockchain network
        """
        try:
            # Generate unique ID
            contract_id = f"{network}_{contract_address.lower()}"
            
            # Create bytecode signature (for privacy, only store hash + patterns)
            bytecode_signature = self._create_bytecode_signature(bytecode)
            
            # Generate embedding for similarity search
            embedding = self._generate_embedding(bytecode, bytecode_signature)
            
            # Store analysis
            self.contract_database[contract_id] = {
                "address": contract_address,
                "network": network,
                "bytecode_signature": bytecode_signature,
                "embedding": embedding,
                "trust_score": trust_score,
                "is_verified": is_verified,
                "vulnerability_count": len(vulnerabilities),
                "critical_count": sum(1 for v in vulnerabilities if v.get("severity") == "critical"),
                "high_count": sum(1 for v in vulnerabilities if v.get("severity") == "high"),
                "timestamp": datetime.utcnow().isoformat(),
            }
            
            logger.info(f"Stored analysis for {contract_address} (total: {len(self.contract_database)})")
            
        except Exception as e:
            logger.error(f"Failed to store contract analysis: {e}")
    
    def find_similar_contracts(
        self,
        bytecode: str,
        top_k: int = 10,
        min_similarity: float = 0.7
    ) -> List[Dict[str, Any]]:
        """
        Find similar contracts based on bytecode patterns.
        
        Args:
            bytecode: Bytecode of contract to analyze
            top_k: Number of similar contracts to return
            min_similarity: Minimum similarity score (0-1)
        
        Returns:
            List of similar contracts with their trust scores
        """
        if not self.contract_database:
            logger.debug("No contracts in database yet")
            return []
        
        try:
            # Generate signature and embedding for query contract
            bytecode_signature = self._create_bytecode_signature(bytecode)
            query_embedding = self._generate_embedding(bytecode, bytecode_signature)
            
            # Calculate similarity with all stored contracts
            similarities = []
            
            for contract_id, contract_data in self.contract_database.items():
                stored_embedding = contract_data["embedding"]
                
                # Calculate cosine similarity
                similarity = self._cosine_similarity(query_embedding, stored_embedding)
                
                if similarity >= min_similarity:
                    similarities.append({
                        "contract_id": contract_id,
                        "address": contract_data["address"],
                        "network": contract_data["network"],
                        "similarity_score": float(similarity),
                        "trust_score": contract_data["trust_score"],
                        "is_verified": contract_data["is_verified"],
                        "vulnerability_count": contract_data["vulnerability_count"],
                        "critical_count": contract_data["critical_count"],
                        "high_count": contract_data["high_count"],
                    })
            
            # Sort by similarity (descending)
            similarities.sort(key=lambda x: x["similarity_score"], reverse=True)
            
            # Return top K
            results = similarities[:top_k]
            
            if results:
                logger.info(
                    f"Found {len(results)} similar contracts "
                    f"(best match: {results[0]['similarity_score']:.2f})"
                )
            
            return results
            
        except Exception as e:
            logger.error(f"Similarity search failed: {e}")
            return []
    
    def calculate_learned_score_adjustment(
        self,
        similar_contracts: List[Dict[str, Any]],
        base_score: float,
        learning_weight: float = 0.25
    ) -> tuple[float, str]:
        """
        Adjust trust score based on similar contracts' historical scores.
        This is the "learning" component!
        
        Args:
            similar_contracts: List of similar contracts from find_similar_contracts()
            base_score: Base trust score calculated from analysis
            learning_weight: How much to weight similar contracts (0-1)
        
        Returns:
            Tuple of (adjusted_score, explanation)
        """
        if not similar_contracts:
            return base_score, "No similar contracts found for comparison"
        
        try:
            # Calculate weighted average of similar contracts
            total_weight = 0
            weighted_sum = 0
            
            for contract in similar_contracts[:5]:  # Use top 5
                similarity = contract["similarity_score"]
                trust_score = contract["trust_score"]
                
                # Weight by similarity (more similar = more influence)
                weight = similarity ** 2  # Square to emphasize high similarity
                weighted_sum += trust_score * weight
                total_weight += weight
            
            if total_weight == 0:
                return base_score, "Similar contracts found but insufficient data"
            
            # Calculate average trust score of similar contracts
            similar_avg = weighted_sum / total_weight
            
            # Blend base score with learned score
            adjusted_score = (base_score * (1 - learning_weight)) + (similar_avg * learning_weight)
            
            # Generate explanation
            score_diff = adjusted_score - base_score
            direction = "increased" if score_diff > 0 else "decreased"
            
            explanation = (
                f"Score {direction} by {abs(score_diff):.1f} points based on "
                f"{len(similar_contracts)} similar contracts "
                f"(avg similarity: {np.mean([c['similarity_score'] for c in similar_contracts[:5]]):.2f})"
            )
            
            logger.info(f"Learned adjustment: {base_score:.1f} → {adjusted_score:.1f}")
            
            return adjusted_score, explanation
            
        except Exception as e:
            logger.error(f"Score adjustment calculation failed: {e}")
            return base_score, f"Adjustment failed: {str(e)}"
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get statistics about the learning database"""
        if not self.contract_database:
            return {
                "total_contracts": 0,
                "verified_contracts": 0,
                "unverified_contracts": 0,
                "networks": [],
                "avg_trust_score": 0,
                "median_trust_score": 0,
                "min_trust_score": 0,
                "max_trust_score": 0,
            }
        
        verified_count = sum(1 for c in self.contract_database.values() if c["is_verified"])
        trust_scores = [c["trust_score"] for c in self.contract_database.values()]
        networks = set(c["network"] for c in self.contract_database.values())
        
        return {
            "total_contracts": len(self.contract_database),
            "verified_contracts": verified_count,
            "unverified_contracts": len(self.contract_database) - verified_count,
            "networks": list(networks),
            "avg_trust_score": np.mean(trust_scores) if trust_scores else 0,
            "median_trust_score": np.median(trust_scores) if trust_scores else 0,
            "min_trust_score": min(trust_scores) if trust_scores else 0,
            "max_trust_score": max(trust_scores) if trust_scores else 0,
        }
    
    # ==================== Helper Methods ====================
    
    def _create_bytecode_signature(self, bytecode: str) -> Dict[str, Any]:
        """
        Create a compact signature of bytecode for similarity comparison.
        Extracts key patterns without storing full bytecode.
        """
        if not bytecode or bytecode == "0x":
            return {}
        
        bytecode_lower = bytecode.lower().replace("0x", "")
        
        # Extract key patterns
        signature = {
            "size": len(bytecode_lower) // 2,
            "hash": hashlib.sha256(bytecode_lower.encode()).hexdigest()[:16],
            
            # Opcode frequency (detect similar logic patterns)
            "opcodes": {
                "call": bytecode_lower.count("f1"),
                "delegatecall": bytecode_lower.count("f4"),
                "sstore": bytecode_lower.count("55"),
                "sload": bytecode_lower.count("54"),
                "selfdestruct": bytecode_lower.count("ff"),
                "caller": bytecode_lower.count("33"),
                "jump": bytecode_lower.count("56") + bytecode_lower.count("57"),
            },
            
            # Detect common function selectors (standardized interfaces)
            "standard_functions": self._detect_standard_functions(bytecode_lower),
            
            # Constructor pattern
            "has_constructor": bytecode_lower.startswith("60806040"),
        }
        
        return signature
    
    def _detect_standard_functions(self, bytecode: str) -> List[str]:
        """Detect standard ERC function selectors"""
        standard_selectors = {
            "18160ddd": "totalSupply",
            "70a08231": "balanceOf",
            "a9059cbb": "transfer",
            "23b872dd": "transferFrom",
            "095ea7b3": "approve",
            "dd62ed3e": "allowance",
            "06fdde03": "name",
            "95d89b41": "symbol",
            "313ce567": "decimals",
        }
        
        found = []
        for selector, name in standard_selectors.items():
            if selector in bytecode:
                found.append(name)
        
        return found
    
    def _generate_embedding(self, bytecode: str, signature: Dict) -> np.ndarray:
        """
        Generate semantic embedding for contract similarity.
        Combines bytecode patterns with signature features.
        """
        # Create a text representation of the contract for embedding
        text_features = [
            f"size_{signature.get('size', 0)}",
            f"calls_{signature['opcodes'].get('call', 0)}",
            f"delegatecalls_{signature['opcodes'].get('delegatecall', 0)}",
            f"storage_ops_{signature['opcodes'].get('sstore', 0) + signature['opcodes'].get('sload', 0)}",
        ]
        
        # Add standard functions
        text_features.extend(signature.get("standard_functions", []))
        
        # Create text for embedding
        feature_text = " ".join(text_features)
        
        # Add bytecode samples (first 1000 chars for pattern recognition)
        bytecode_sample = bytecode[:1000] if len(bytecode) > 1000 else bytecode
        combined_text = f"{feature_text} {bytecode_sample}"
        
        # Generate embedding
        embedding = self.model.encode(
            combined_text,
            convert_to_numpy=True,
            show_progress_bar=False
        )
        
        return embedding.astype('float32')
    
    def _cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Calculate cosine similarity between two vectors"""
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)


# Singleton instance
similarity_service = ContractSimilarityService()
