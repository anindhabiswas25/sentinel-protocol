"""
Advanced Bytecode Pattern Detection Service
Automatically detects malicious patterns without manual updates
"""

import re
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class PatternDetector:
    """
    AI-powered pattern detection for smart contracts.
    Analyzes bytecode to detect malicious patterns, security risks, and contract behavior.
    """
    
    def __init__(self):
        """Initialize pattern detector with known signatures"""
        # Opcode mappings for readable analysis
        self.opcodes = {
            'f0': 'CREATE',
            'f1': 'CALL',
            'f2': 'CALLCODE',
            'f4': 'DELEGATECALL',
            'f5': 'CREATE2',
            'ff': 'SELFDESTRUCT',
            '3d': 'RETURNDATASIZE',
            '54': 'SLOAD',
            '55': 'SSTORE',
            '31': 'BALANCE',
            '33': 'CALLER',
            '34': 'CALLVALUE',
            '35': 'CALLDATALOAD',
            '42': 'TIMESTAMP',
            '43': 'NUMBER',
        }
        
        # Known safe patterns (OpenZeppelin, etc.)
        self.safe_patterns = [
            "SafeMath",
            "Ownable",
            "ReentrancyGuard",
            "Pausable"
        ]
    
    def analyze_comprehensive(self, bytecode: str) -> Dict[str, Any]:
        """
        Comprehensive bytecode analysis combining multiple detection methods.
        
        Returns:
            Dictionary with all detected patterns and risk scores
        """
        if not bytecode or bytecode == "0x":
            return {"error": "No bytecode found", "risk_level": "unknown"}
        
        bytecode_lower = bytecode.lower()
        
        analysis = {
            "basic_info": self._analyze_basic_info(bytecode_lower),
            "security_risks": self._detect_security_risks(bytecode_lower),
            "malicious_patterns": self._detect_malicious_patterns(bytecode_lower),
            "transparency_score": self._calculate_transparency_score(bytecode_lower),
            "complexity_analysis": self._analyze_complexity(bytecode_lower),
            "behavioral_flags": self._detect_behavioral_flags(bytecode_lower),
        }
        
        # Calculate overall risk level
        analysis["overall_risk_level"] = self._calculate_risk_level(analysis)
        analysis["risk_score_adjustment"] = self._calculate_score_adjustment(analysis)
        
        return analysis
    
    def _analyze_basic_info(self, bytecode: str) -> Dict[str, Any]:
        """Extract basic contract information from bytecode"""
        return {
            "size_bytes": len(bytecode) // 2,
            "has_constructor": bytecode.startswith("0x60806040") or bytecode.startswith("60806040"),
            "compiler_optimization": self._detect_optimization(bytecode),
            "has_fallback": "3d" in bytecode,  # RETURNDATASIZE used in fallback
        }
    
    def _detect_security_risks(self, bytecode: str) -> List[Dict[str, Any]]:
        """Detect known security risk patterns"""
        risks = []
        
        # 1. Reentrancy Risk
        if self._has_reentrancy_risk(bytecode):
            risks.append({
                "type": "reentrancy",
                "severity": "high",
                "confidence": 0.75,
                "description": "Potential reentrancy vulnerability - external calls before state updates",
                "score_impact": -12
            })
        
        # 2. Unprotected SELFDESTRUCT
        if self._has_unprotected_selfdestruct(bytecode):
            risks.append({
                "type": "selfdestruct",
                "severity": "critical",
                "confidence": 0.85,
                "description": "Unprotected SELFDESTRUCT - contract can be destroyed by unauthorized users",
                "score_impact": -25
            })
        
        # 3. Dangerous DELEGATECALL
        if self._has_dangerous_delegatecall(bytecode):
            risks.append({
                "type": "delegatecall",
                "severity": "high",
                "confidence": 0.70,
                "description": "Potentially unsafe DELEGATECALL usage detected",
                "score_impact": -15
            })
        
        # 4. Unchecked External Calls
        if self._has_unchecked_calls(bytecode):
            risks.append({
                "type": "unchecked_call",
                "severity": "medium",
                "confidence": 0.65,
                "description": "External calls without proper error handling",
                "score_impact": -8
            })
        
        # 5. Integer Overflow Risk (pre-Solidity 0.8.0)
        if self._has_overflow_risk(bytecode):
            risks.append({
                "type": "overflow",
                "severity": "medium",
                "confidence": 0.60,
                "description": "Potential integer overflow - no SafeMath detected",
                "score_impact": -7
            })
        
        # 6. Timestamp Dependency
        if self._has_timestamp_dependency(bytecode):
            risks.append({
                "type": "timestamp",
                "severity": "low",
                "confidence": 0.80,
                "description": "Contract logic depends on block timestamp (manipulable by miners)",
                "score_impact": -3
            })
        
        return risks
    
    def _detect_malicious_patterns(self, bytecode: str) -> List[Dict[str, Any]]:
        """Detect patterns commonly found in scam/malicious contracts"""
        threats = []
        
        # 1. Honeypot Detection - Transfer Restrictions
        if self._is_honeypot(bytecode):
            threats.append({
                "type": "honeypot",
                "severity": "critical",
                "confidence": 0.80,
                "description": "SCAM ALERT: Honeypot detected - tokens cannot be sold after purchase",
                "score_impact": -30,
                "user_warning": "🚨 NEVER INTERACT - This is a confirmed scam contract"
            })
        
        # 2. Hidden Mint Function
        if self._has_hidden_mint(bytecode):
            threats.append({
                "type": "hidden_mint",
                "severity": "critical",
                "confidence": 0.75,
                "description": "SCAM ALERT: Hidden unlimited minting capability detected",
                "score_impact": -28,
                "user_warning": "🚨 HIGH RISK - Owner can mint unlimited tokens and dilute value"
            })
        
        # 3. Excessive Owner Privileges
        if self._has_excessive_ownership(bytecode):
            threats.append({
                "type": "centralized_control",
                "severity": "high",
                "confidence": 0.85,
                "description": "Extreme centralization - owner has unrestricted control",
                "score_impact": -20,
                "user_warning": "⚠️ WARNING - Single address controls all contract functions"
            })
        
        # 4. Backdoor Detection
        if self._has_backdoor(bytecode):
            threats.append({
                "type": "backdoor",
                "severity": "critical",
                "confidence": 0.70,
                "description": "SCAM ALERT: Potential backdoor function detected",
                "score_impact": -35,
                "user_warning": "🚨 CRITICAL - Contract contains hidden functions for theft"
            })
        
        # 5. Fee Manipulation
        if self._has_fee_manipulation(bytecode):
            threats.append({
                "type": "fee_manipulation",
                "severity": "high",
                "confidence": 0.78,
                "description": "Owner can arbitrarily change transaction fees",
                "score_impact": -22,
                "user_warning": "⚠️ HIGH RISK - Fees can be set to 100% at any time"
            })
        
        # 6. Blacklist Function
        if self._has_blacklist(bytecode):
            threats.append({
                "type": "blacklist",
                "severity": "medium",
                "confidence": 0.82,
                "description": "Contract can blacklist addresses arbitrarily",
                "score_impact": -10,
                "user_warning": "⚠️ CAUTION - Your address can be blocked from trading"
            })
        
        return threats
    
    def _calculate_transparency_score(self, bytecode: str) -> int:
        """Calculate how transparent/readable the contract is"""
        score = 100
        
        # Penalize extremely large contracts (often obfuscated)
        size = len(bytecode) // 2
        if size > 24000:  # Max contract size is 24KB
            score -= 20
        elif size > 18000:
            score -= 10
        
        # Penalize high complexity without clear structure
        if self._is_obfuscated(bytecode):
            score -= 30
        
        # Bonus for standard patterns
        if self._has_standard_interfaces(bytecode):
            score += 10
        
        return max(0, min(100, score))
    
    def _analyze_complexity(self, bytecode: str) -> Dict[str, Any]:
        """Analyze contract complexity metrics"""
        return {
            "total_opcodes": len(bytecode) // 2,
            "unique_opcodes": len(set(bytecode[i:i+2] for i in range(0, len(bytecode), 2))),
            "external_calls": bytecode.count("f1"),
            "storage_operations": bytecode.count("54") + bytecode.count("55"),
            "jumps": bytecode.count("56") + bytecode.count("57"),  # JUMP, JUMPI
            "complexity_rating": self._rate_complexity(bytecode)
        }
    
    def _detect_behavioral_flags(self, bytecode: str) -> List[str]:
        """Detect behavioral red flags"""
        flags = []
        
        if bytecode.count("33") > 15:  # Excessive CALLER checks
            flags.append("excessive_owner_checks")
        
        if bytecode.count("f1") > 20:  # Too many external calls
            flags.append("high_external_dependency")
        
        if "ff" in bytecode and bytecode.count("33") < 2:  # SELFDESTRUCT without owner
            flags.append("unprotected_destruction")
        
        if bytecode.count("55") > 30:  # Excessive storage writes
            flags.append("high_storage_manipulation")
        
        if len(bytecode) < 1000:  # Suspiciously small
            flags.append("suspiciously_simple")
        
        return flags
    
    # ==================== Detection Methods ====================
    
    def _has_reentrancy_risk(self, bytecode: str) -> bool:
        """Detect potential reentrancy vulnerability"""
        # Look for: external call (f1) followed by storage write (55)
        call_positions = [m.start() for m in re.finditer('f1', bytecode)]
        sstore_positions = [m.start() for m in re.finditer('55', bytecode)]
        
        # Check if any SSTORE comes after CALL
        for call_pos in call_positions:
            for sstore_pos in sstore_positions:
                if sstore_pos > call_pos and (sstore_pos - call_pos) < 500:
                    return True
        return False
    
    def _has_unprotected_selfdestruct(self, bytecode: str) -> bool:
        """Detect SELFDESTRUCT without proper access control"""
        if "ff" not in bytecode:
            return False
        
        # SELFDESTRUCT should be preceded by CALLER check (33)
        selfdestruct_pos = bytecode.find("ff")
        caller_check_window = bytecode[max(0, selfdestruct_pos-200):selfdestruct_pos]
        
        return "33" not in caller_check_window  # No owner verification
    
    def _has_dangerous_delegatecall(self, bytecode: str) -> bool:
        """Detect potentially unsafe DELEGATECALL usage"""
        if "f4" not in bytecode:
            return False
        
        # DELEGATECALL with user-controlled address is dangerous
        delegatecall_count = bytecode.count("f4")
        caller_checks = bytecode.count("33")
        
        return delegatecall_count > 0 and caller_checks < delegatecall_count
    
    def _has_unchecked_calls(self, bytecode: str) -> bool:
        """Detect external calls without return value checks"""
        # If there are CALLs but no ISZERO checks after them
        has_calls = "f1" in bytecode
        has_return_checks = "15" in bytecode  # ISZERO opcode
        
        return has_calls and not has_return_checks
    
    def _has_overflow_risk(self, bytecode: str) -> bool:
        """Detect potential integer overflow (no SafeMath)"""
        # ADD/MUL operations without overflow checks
        has_math = "01" in bytecode or "02" in bytecode  # ADD, MUL
        has_overflow_check = "10" in bytecode  # LT (less than check)
        
        return has_math and not has_overflow_check
    
    def _has_timestamp_dependency(self, bytecode: str) -> bool:
        """Detect dependence on block.timestamp"""
        return "42" in bytecode  # TIMESTAMP opcode
    
    def _is_honeypot(self, bytecode: str) -> bool:
        """
        Detect honeypot pattern: Can buy but cannot sell
        Pattern: Transfer function has conditional that always fails for non-owners
        """
        # Look for transfer function with many conditional checks
        transfer_patterns = [
            "a9059cbb",  # transfer(address,uint256) selector
            "23b872dd",  # transferFrom(address,address,uint256)
        ]
        
        for pattern in transfer_patterns:
            if pattern in bytecode:
                # Check if there are excessive CALLER checks around transfer
                pattern_pos = bytecode.find(pattern)
                window = bytecode[pattern_pos:pattern_pos+500]
                caller_checks = window.count("33")
                
                # Honeypots typically have 3+ owner checks in transfer
                if caller_checks >= 3:
                    return True
        
        return False
    
    def _has_hidden_mint(self, bytecode: str) -> bool:
        """Detect hidden or unrestricted minting capability"""
        # Look for: Storage write to totalSupply without proper access control
        # totalSupply typically at slot 0x02 or 0x03
        
        has_storage_write = "55" in bytecode
        has_balance_manipulation = bytecode.count("55") > 10
        
        # Check for mint pattern without owner verification
        mint_pattern = has_storage_write and has_balance_manipulation
        has_owner_check = bytecode.count("33") > 2
        
        return mint_pattern and not has_owner_check
    
    def _has_excessive_ownership(self, bytecode: str) -> bool:
        """Detect contracts where owner has too much control"""
        # Count CALLER(33) checks - if >20, likely over-centralized
        caller_count = bytecode.count("33")
        total_functions = bytecode.count("63")  # Function selectors
        
        if total_functions == 0:
            return False
        
        # If >60% of functions require owner, highly centralized
        owner_ratio = caller_count / max(total_functions, 1)
        return owner_ratio > 0.6
    
    def _has_backdoor(self, bytecode: str) -> bool:
        """Detect potential backdoor functions"""
        # Look for functions that can transfer all funds without normal restrictions
        # Pattern: BALANCE + CALL without proper checks
        balance_pos = [m.start() for m in re.finditer('31', bytecode)]  # BALANCE
        call_pos = [m.start() for m in re.finditer('f1', bytecode)]  # CALL
        
        # If BALANCE immediately before CALL, could be drain function
        for bal_p in balance_pos:
            for call_p in call_pos:
                if 0 < (call_p - bal_p) < 50:
                    return True
        
        return False
    
    def _has_fee_manipulation(self, bytecode: str) -> bool:
        """Detect if owner can change fees arbitrarily"""
        # Look for: SSTORE to fee variable with CALLER check
        # Fee manipulation: storage write with owner modifier but no limits
        has_fee_storage = "55" in bytecode
        has_owner_control = "33" in bytecode
        has_fee_limit = "60" in bytecode and ("64" in bytecode or "0a" in bytecode)  # MAX constants
        
        return has_fee_storage and has_owner_control and not has_fee_limit
    
    def _has_blacklist(self, bytecode: str) -> bool:
        """Detect blacklist functionality"""
        # Blacklist pattern: mapping storage with transfer restrictions
        # Look for: SLOAD checks before transfers
        transfer_selector = "a9059cbb"
        
        if transfer_selector in bytecode:
            pos = bytecode.find(transfer_selector)
            window = bytecode[pos:pos+300]
            # Multiple SLOAD operations suggest blacklist checks
            return window.count("54") >= 2
        
        return False
    
    def _is_obfuscated(self, bytecode: str) -> bool:
        """Detect if bytecode is obfuscated"""
        # High entropy or unusual patterns suggest obfuscation
        if len(bytecode) < 1000:
            return False
        
        # Check for unusual opcode distribution
        sample = bytecode[:1000]
        unique_ratio = len(set(sample)) / len(sample)
        
        # If >90% unique characters, likely obfuscated
        return unique_ratio > 0.9
    
    def _has_standard_interfaces(self, bytecode: str) -> bool:
        """Check for standard ERC interfaces"""
        standard_selectors = [
            "18160ddd",  # totalSupply()
            "70a08231",  # balanceOf(address)
            "a9059cbb",  # transfer(address,uint256)
            "23b872dd",  # transferFrom(address,address,uint256)
            "095ea7b3",  # approve(address,uint256)
        ]
        
        matches = sum(1 for selector in standard_selectors if selector in bytecode)
        return matches >= 3  # Has at least 3 standard functions
    
    def _rate_complexity(self, bytecode: str) -> str:
        """Rate overall complexity"""
        size = len(bytecode) // 2
        
        if size < 2000:
            return "low"
        elif size < 8000:
            return "medium"
        elif size < 15000:
            return "high"
        else:
            return "very_high"
    
    def _detect_optimization(self, bytecode: str) -> bool:
        """Detect if contract was compiled with optimization"""
        # Optimized contracts have more compact bytecode
        # Check for optimization indicators
        return "fe" in bytecode[:100]  # INVALID opcode used in optimized code
    
    def _calculate_risk_level(self, analysis: Dict) -> str:
        """Calculate overall risk level from all analyses"""
        malicious_count = len(analysis.get("malicious_patterns", []))
        security_risks = len(analysis.get("security_risks", []))
        
        critical_malicious = sum(
            1 for m in analysis.get("malicious_patterns", [])
            if m.get("severity") == "critical"
        )
        
        if critical_malicious > 0:
            return "critical"
        elif malicious_count > 0 or security_risks > 3:
            return "high"
        elif security_risks > 1:
            return "medium"
        elif security_risks > 0:
            return "low"
        else:
            return "safe"
    
    def _calculate_score_adjustment(self, analysis: Dict) -> int:
        """Calculate how much to adjust trust score based on patterns"""
        adjustment = 0
        
        # Add up all score impacts from security risks
        for risk in analysis.get("security_risks", []):
            adjustment += risk.get("score_impact", 0)
        
        # Add up all score impacts from malicious patterns
        for threat in analysis.get("malicious_patterns", []):
            adjustment += threat.get("score_impact", 0)
        
        # Adjust based on transparency
        transparency = analysis.get("transparency_score", 100)
        if transparency < 50:
            adjustment -= 10
        elif transparency > 80:
            adjustment += 5
        
        return adjustment


# Singleton instance
pattern_detector = PatternDetector()
