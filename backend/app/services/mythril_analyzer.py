"""
Mythril Symbolic Execution for Bytecode Analysis
Detects vulnerabilities invisible to pattern matching
"""

import logging
from typing import Dict, List, Optional
import json

logger = logging.getLogger(__name__)

class MythrilBytecodeAnalyzer:
    """Symbolic execution analyzer for bytecode"""
    
    def __init__(self):
        self.mythril_available = False
        try:
            from mythril.mythril import MythrilDisassembler, MythrilConfig, MythrilAnalyzer
            from mythril.exceptions import CriticalError
            self.MythrilDisassembler = MythrilDisassembler
            self.MythrilConfig = MythrilConfig
            self.MythrilAnalyzer = MythrilAnalyzer
            self.CriticalError = CriticalError
            
            self.config = MythrilConfig()
            self.config.execution_timeout = 30  # 30 seconds max
            self.mythril_available = True
            logger.info("✅ Mythril analyzer initialized")
        except ImportError:
            logger.warning("⚠️ Mythril not available - install with 'pip install mythril==0.24.8'")
        except Exception as e:
            logger.warning(f"⚠️ Mythril initialization failed: {e}")
    
    async def analyze_bytecode(self, bytecode: str, address: str) -> Dict:
        """
        Run symbolic execution on bytecode
        
        Returns:
            {
                'is_dangerous': bool,
                'score_penalty': int,
                'vulnerabilities': List[Dict],
                'confidence': float
            }
        """
        
        if not self.mythril_available:
            logger.debug("Mythril not available, skipping symbolic execution")
            return {'is_dangerous': False, 'score_penalty': 0, 'vulnerabilities': []}
        
        if not bytecode or bytecode == "0x":
            return {'is_dangerous': False, 'score_penalty': 0, 'vulnerabilities': []}
        
        try:
            logger.info(f"🔬 Running Mythril symbolic execution on {address[:10]}...")
            
            # Initialize disassembler
            disassembler = self.MythrilDisassembler(
                eth=None,
                solc_version=None,
                solc_settings_json=None
            )
            
            # Load bytecode
            disassembler.load_from_bytecode(bytecode)
            
            # Create analyzer
            analyzer = self.MythrilAnalyzer(
                disassembler=disassembler,
                strategy="dfs",
                execution_timeout=30,
                max_depth=50,
                create_timeout=10
            )
            
            # Run analysis
            report = analyzer.fire_lasers()
            
            # Parse results
            vulnerabilities = self._parse_mythril_report(report)
            
            # Calculate risk
            critical_count = sum(1 for v in vulnerabilities if v['severity'] == 'High')
            medium_count = sum(1 for v in vulnerabilities if v['severity'] == 'Medium')
            
            is_dangerous = critical_count >= 2 or (critical_count >= 1 and medium_count >= 2)
            
            # Calculate penalty
            score_penalty = 0
            if critical_count >= 3:
                score_penalty = 40  # Extreme risk
            elif critical_count >= 2:
                score_penalty = 30  # High risk
            elif critical_count >= 1:
                score_penalty = 20  # Moderate risk
            elif medium_count >= 3:
                score_penalty = 15  # Low-moderate risk
            
            confidence = min(critical_count * 0.25 + medium_count * 0.15, 0.95)
            
            logger.info(f"✅ Mythril analysis complete: {len(vulnerabilities)} issues found")
            
            return {
                'is_dangerous': is_dangerous,
                'score_penalty': score_penalty,
                'vulnerabilities': vulnerabilities,
                'confidence': confidence,
                'critical_count': critical_count,
                'medium_count': medium_count
            }
            
        except self.CriticalError as e:
            logger.error(f"Mythril critical error: {e}")
            return {'is_dangerous': False, 'score_penalty': 0, 'vulnerabilities': []}
        except Exception as e:
            logger.error(f"Mythril analysis failed: {e}")
            return {'is_dangerous': False, 'score_penalty': 0, 'vulnerabilities': []}
    
    def _parse_mythril_report(self, report) -> List[Dict]:
        """Parse Mythril report into standardized format"""
        
        vulnerabilities = []
        
        try:
            # Mythril returns JSON report
            if hasattr(report, 'as_dict'):
                report_dict = report.as_dict()
            else:
                report_dict = json.loads(str(report))
            
            for issue in report_dict.get('issues', []):
                vulnerabilities.append({
                    'type': issue.get('title', 'Unknown'),
                    'severity': issue.get('severity', 'Medium'),
                    'description': issue.get('description', ''),
                    'swc_id': issue.get('swc-id', ''),
                    'location': issue.get('filename', 'Bytecode'),
                    'confidence': self._map_confidence(issue.get('severity'))
                })
        except Exception as e:
            logger.error(f"Error parsing Mythril report: {e}")
        
        return vulnerabilities
    
    def _map_confidence(self, severity: str) -> float:
        """Map Mythril severity to confidence score"""
        mapping = {
            'High': 0.9,
            'Medium': 0.7,
            'Low': 0.5
        }
        return mapping.get(severity, 0.6)

# Singleton instance
mythril_analyzer = MythrilBytecodeAnalyzer()
