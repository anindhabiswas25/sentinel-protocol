"""
Transaction Pattern Analysis
Detects active scams through on-chain behavior
"""

import logging
from typing import Dict, List
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class TransactionPatternAnalyzer:
    """Analyze transaction patterns for scam detection"""
    
    def __init__(self):
        self.suspicious_patterns = [
            'pump_and_dump',
            'rug_pull',
            'wash_trading',
            'whale_manipulation'
        ]
    
    async def analyze_patterns(
        self, 
        address: str, 
        chain: str
    ) -> Dict:
        """
        Analyze transaction patterns for suspicious activity
        
        Returns:
            {
                'is_suspicious': bool,
                'risk_score': int,
                'patterns_detected': List[str],
                'indicators': Dict
            }
        """
        
        try:
            logger.info(f"📊 Analyzing transaction patterns for {address[:10]}...")
            
            # For now, return basic analysis (blockchain_service integration needed)
            # This would normally fetch transaction data via blockchain_service
            indicators = {
                'buy_sell_ratio': await self._calculate_buy_sell_ratio([]),
                'volume_spike': await self._detect_volume_spike([]),
                'whale_concentration': 0.0,  # Would calculate from holder data
                'rapid_ownership_changes': 0,  # Would check OwnershipTransferred events
                'suspicious_timing': 0.0  # Would analyze transaction timestamps
            }
            
            # Detect patterns
            patterns_detected = []
            risk_score = 0
            
            # Pattern 1: Pump and Dump
            if indicators['buy_sell_ratio'] > 10 and indicators['volume_spike'] > 500:
                patterns_detected.append('pump_and_dump')
                risk_score += 25
                logger.warning(f"🚨 Pump-and-dump pattern detected: {address[:10]}")
            
            # Pattern 2: Rug Pull Risk
            if indicators['whale_concentration'] > 0.8:
                patterns_detected.append('rug_pull_risk')
                risk_score += 30
                logger.warning(f"🚨 High whale concentration: {address[:10]}")
            
            # Pattern 3: Wash Trading
            if indicators['suspicious_timing'] > 0.7:
                patterns_detected.append('wash_trading')
                risk_score += 15
            
            # Pattern 4: Rapid Ownership Changes
            if indicators['rapid_ownership_changes'] >= 3:
                patterns_detected.append('ownership_instability')
                risk_score += 20
            
            is_suspicious = risk_score >= 25
            
            if is_suspicious:
                logger.warning(f"⚠️ Suspicious patterns detected: {patterns_detected}")
            
            return {
                'is_suspicious': is_suspicious,
                'risk_score': min(risk_score, 50),  # Cap at 50
                'patterns_detected': patterns_detected,
                'indicators': indicators,
                'confidence': 0.7  # Basic confidence
            }
            
        except Exception as e:
            logger.error(f"Transaction pattern analysis failed: {e}")
            return {'is_suspicious': False, 'risk_score': 0, 'patterns_detected': [], 'indicators': {}}
    
    async def _calculate_buy_sell_ratio(self, txs: List[Dict]) -> float:
        """Calculate buy to sell ratio"""
        try:
            if not txs:
                return 1.0
            
            buys = sum(1 for tx in txs if tx.get('type') == 'buy')
            sells = sum(1 for tx in txs if tx.get('type') == 'sell')
            
            if sells == 0:
                return float('inf') if buys > 0 else 1.0
            
            return buys / sells
        except:
            return 1.0
    
    async def _detect_volume_spike(self, txs: List[Dict]) -> float:
        """Detect volume spikes (% increase)"""
        try:
            if len(txs) < 20:
                return 0.0
            
            # Compare last 10 vs previous 10
            recent_volume = sum(float(tx.get('value', 0)) for tx in txs[:10])
            baseline_volume = sum(float(tx.get('value', 0)) for tx in txs[10:20])
            
            if baseline_volume == 0:
                return 0.0
            
            spike = ((recent_volume - baseline_volume) / baseline_volume) * 100
            return max(spike, 0.0)
        except:
            return 0.0

# Singleton instance
transaction_analyzer = TransactionPatternAnalyzer()
