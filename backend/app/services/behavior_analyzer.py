"""
On-chain behavior analysis for suspicious patterns.

Analyzes contract activity to detect:
- Sudden fund drains
- New/untested contracts
- Suspicious owner behavior
- Unusual transaction patterns
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from web3 import Web3

logger = logging.getLogger(__name__)


class BehaviorAnalyzer:
    """Detect suspicious on-chain behavior patterns"""
    
    def __init__(self, web3_provider=None):
        """
        Initialize behavior analyzer.
        
        Args:
            web3_provider: Web3 provider instance (optional for now)
        """
        self.w3 = web3_provider
        self.behavior_cache = {}
        self.cache_ttl = timedelta(hours=1)  # Cache for 1 hour
    
    async def analyze_contract_behavior(
        self, 
        address: str,
        chain: str = "ethereum",
        contract_age_days: Optional[int] = None
    ) -> Dict:
        """
        Analyze on-chain behavior for red flags.
        
        Args:
            address: Contract address
            chain: Blockchain network
            contract_age_days: Contract age if known (to avoid redundant checks)
            
        Returns:
            Dict with red_flags and behavior_risk_score
        """
        
        # Check cache
        cache_key = f"{chain}:{address.lower()}"
        if cache_key in self.behavior_cache:
            cached = self.behavior_cache[cache_key]
            if datetime.now() - cached['timestamp'] < self.cache_ttl:
                return cached['data']
        
        red_flags = []
        risk_score = 0
        
        try:
            # Check 1: Contract age (can be done without Web3)
            if contract_age_days is not None:
                age_flags, age_risk = self._check_contract_age(contract_age_days)
                red_flags.extend(age_flags)
                risk_score += age_risk
            
            # Check 2: Web3-based checks (if provider available)
            if self.w3 and self.w3.is_connected():
                # Check contract code exists
                code = self.w3.eth.get_code(Web3.to_checksum_address(address))
                if code == b'' or code == b'0x':
                    red_flags.append({
                        'type': 'no_code',
                        'severity': 'critical',
                        'description': 'No contract code found at address'
                    })
                    risk_score += 50
            
            # Future: Add more sophisticated checks when Web3 is fully integrated
            # - Recent transaction volume
            # - Fund movement patterns
            # - Owner/admin activity
            
        except Exception as e:
            logger.error(f"❌ Behavior analysis failed for {address}: {e}")
            # Don't fail the entire analysis, just log and continue
        
        result = {
            'red_flags': red_flags,
            'behavior_risk_score': min(risk_score, 50),  # Cap at 50
            'analysis_date': datetime.now().isoformat()
        }
        
        # Cache result
        self.behavior_cache[cache_key] = {
            'data': result,
            'timestamp': datetime.now()
        }
        
        return result
    
    def _check_contract_age(self, age_days: int) -> tuple[List[Dict], int]:
        """
        Check if contract is too new (higher risk).
        
        Returns:
            (red_flags, risk_score)
        """
        red_flags = []
        risk_score = 0
        
        if age_days < 7:
            red_flags.append({
                'type': 'very_new_contract',
                'severity': 'high',
                'description': f'Contract deployed only {age_days} days ago'
            })
            risk_score += 20
        elif age_days < 30:
            red_flags.append({
                'type': 'new_contract',
                'severity': 'medium',
                'description': f'Contract deployed {age_days} days ago (less than 1 month)'
            })
            risk_score += 10
        
        return red_flags, risk_score
    
    async def _detect_sudden_drain(self, transfers: List[Dict]) -> bool:
        """
        Detect if large percentage of funds left recently.
        
        This is a placeholder for when transaction history is available.
        """
        if not transfers:
            return False
        
        try:
            total_out = sum(t['value'] for t in transfers if t.get('direction') == 'out')
            total_in = sum(t['value'] for t in transfers if t.get('direction') == 'in')
            
            # Red flag: >80% of funds left in last week
            if total_in > 0:
                return total_out > (total_in * 0.8)
        except Exception as e:
            logger.debug(f"Drain detection failed: {e}")
        
        return False


# Singleton instance
behavior_analyzer = BehaviorAnalyzer()
