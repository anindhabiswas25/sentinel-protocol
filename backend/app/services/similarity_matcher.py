"""
Bytecode Similarity Matching
Detects clones and forks of known scam contracts
"""

import logging
import hashlib
from typing import Dict, List, Optional
from difflib import SequenceMatcher
import sqlite3
import os

logger = logging.getLogger(__name__)

class BytecodeSimilarityMatcher:
    """Match bytecode against known scam patterns"""
    
    def __init__(self, db_path: str = "data/scam_bytecodes.db"):
        self.db_path = db_path
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize SQLite database for scam bytecodes"""
        try:
            # Ensure data directory exists
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scam_bytecodes (
                    address TEXT PRIMARY KEY,
                    bytecode_hash TEXT,
                    bytecode TEXT,
                    trust_score INTEGER,
                    scam_type TEXT,
                    added_date TEXT
                )
            """)
            
            conn.commit()
            conn.close()
            logger.info("✅ Scam bytecode database initialized")
        except Exception as e:
            logger.error(f"Failed to initialize scam database: {e}")
    
    async def find_similar_contracts(
        self, 
        bytecode: str, 
        min_similarity: float = 0.85,
        top_k: int = 20
    ) -> List[Dict]:
        """
        Find contracts with similar bytecode
        
        Args:
            bytecode: Contract bytecode to check
            min_similarity: Minimum similarity threshold (0.0-1.0)
            top_k: Return top K matches
        
        Returns:
            List of similar contracts with similarity scores
        """
        
        if not bytecode or bytecode == "0x":
            return []
        
        try:
            logger.info(f"🔍 Searching for similar bytecode patterns...")
            
            # Calculate bytecode hash
            bytecode_hash = self._hash_bytecode(bytecode)
            
            # Get all known scam bytecodes
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT address, bytecode, bytecode_hash, trust_score, scam_type
                FROM scam_bytecodes
            """)
            
            scam_contracts = cursor.fetchall()
            conn.close()
            
            # Calculate similarities
            similarities = []
            
            for scam_address, scam_bytecode, scam_hash, trust_score, scam_type in scam_contracts:
                # Quick hash check
                if bytecode_hash == scam_hash:
                    similarities.append({
                        'address': scam_address,
                        'similarity': 1.0,
                        'trust_score': trust_score,
                        'scam_type': scam_type,
                        'match_type': 'exact'
                    })
                    continue
                
                # Sequence matching (slower but more accurate)
                similarity = self._calculate_similarity(bytecode, scam_bytecode)
                
                if similarity >= min_similarity:
                    similarities.append({
                        'address': scam_address,
                        'similarity': similarity,
                        'trust_score': trust_score,
                        'scam_type': scam_type,
                        'match_type': 'partial'
                    })
            
            # Sort by similarity
            similarities.sort(key=lambda x: x['similarity'], reverse=True)
            
            if similarities:
                logger.warning(
                    f"⚠️ Found {len(similarities)} similar scam contracts "
                    f"(top similarity: {similarities[0]['similarity']:.2%})"
                )
            
            return similarities[:top_k]
            
        except Exception as e:
            logger.error(f"Similarity matching failed: {e}")
            return []
    
    async def add_scam_contract(
        self, 
        address: str, 
        bytecode: str, 
        trust_score: int,
        scam_type: str
    ):
        """Add a known scam contract to database"""
        try:
            bytecode_hash = self._hash_bytecode(bytecode)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO scam_bytecodes
                (address, bytecode_hash, bytecode, trust_score, scam_type, added_date)
                VALUES (?, ?, ?, ?, ?, datetime('now'))
            """, (address, bytecode_hash, bytecode, trust_score, scam_type))
            
            conn.commit()
            conn.close()
            
            logger.info(f"✅ Added scam contract to database: {address}")
            
        except Exception as e:
            logger.error(f"Failed to add scam contract: {e}")
    
    def _hash_bytecode(self, bytecode: str) -> str:
        """Create hash of bytecode for quick comparison"""
        # Remove constructor arguments (last 64+ chars often vary)
        normalized = bytecode[:min(len(bytecode), 10000)]
        return hashlib.sha256(normalized.encode()).hexdigest()
    
    def _calculate_similarity(self, bytecode1: str, bytecode2: str) -> float:
        """
        Calculate similarity ratio between two bytecodes
        Uses optimized sequence matching
        """
        try:
            # Truncate to first 5000 chars for performance
            bc1 = bytecode1[:5000]
            bc2 = bytecode2[:5000]
            
            # Quick ratio check
            matcher = SequenceMatcher(None, bc1, bc2, autojunk=False)
            return matcher.ratio()
            
        except Exception as e:
            logger.error(f"Similarity calculation failed: {e}")
            return 0.0
    
    async def build_scam_database_from_exploits(self):
        """Populate database from known exploits"""
        logger.info("🔨 Building scam database from known exploits...")
        
        # Placeholder - would integrate with blockchain_service to fetch bytecode
        # For now, just log that the database is ready
        logger.info("✅ Scam database ready for population")

# Singleton instance
similarity_matcher = BytecodeSimilarityMatcher()
