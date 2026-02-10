"""
Trust score calculation service
"""

from typing import Dict, List, Any
from app.models.schemas import TrustScore, VulnerabilityDetail
from app.core.config import SEVERITY_LEVELS
import logging

logger = logging.getLogger(__name__)


class ScoringService:
    """
    Service for calculating trust scores for smart contracts.
    
    The trust score is a composite metric based on:
    1. Security Score - Based on vulnerability findings
    2. Code Quality Score - Based on code quality issues
    3. Verification Score - Whether source code is verified
    """
    
    # Weights for each component (must sum to 1.0)
    SECURITY_WEIGHT = 0.6
    CODE_QUALITY_WEIGHT = 0.2
    VERIFICATION_WEIGHT = 0.2
    
    # Severity impact on security score (deductions from 100)
    SEVERITY_DEDUCTIONS = {
        "critical": 25,
        "high": 15,
        "medium": 8,
        "low": 3,
        "informational": 1,
    }
    
    # Maximum deduction per severity to prevent single category domination
    MAX_SEVERITY_DEDUCTION = {
        "critical": 50,
        "high": 40,
        "medium": 30,
        "low": 15,
        "informational": 5,
    }
    
    def calculate_trust_score(
        self,
        vulnerabilities: List[Dict[str, Any]],
        code_quality_issues: List[Dict[str, Any]] = None,
        is_verified: bool = True,
        bytecode_analysis: Dict[str, Any] = None
    ) -> TrustScore:
        """
        Calculate comprehensive trust score for a contract.
        
        Args:
            vulnerabilities: List of vulnerability findings
            code_quality_issues: List of code quality issues
            is_verified: Whether source code is verified
            bytecode_analysis: Bytecode analysis results (for unverified)
        
        Returns:
            TrustScore with breakdown
        """
        # Calculate individual scores
        security_score = self._calculate_security_score(vulnerabilities)
        code_quality_score = self._calculate_code_quality_score(code_quality_issues or [])
        verification_score = 100.0 if is_verified else 30.0
        
        # Apply bytecode penalties for unverified contracts
        if not is_verified and bytecode_analysis:
            security_score = self._apply_bytecode_penalties(security_score, bytecode_analysis)
        
        # Calculate weighted overall score
        overall_score = (
            security_score * self.SECURITY_WEIGHT +
            code_quality_score * self.CODE_QUALITY_WEIGHT +
            verification_score * self.VERIFICATION_WEIGHT
        )
        
        # Determine risk level
        risk_level = self._determine_risk_level(overall_score, vulnerabilities)
        
        return TrustScore(
            overall_score=round(overall_score, 1),
            security_score=round(security_score, 1),
            code_quality_score=round(code_quality_score, 1),
            verification_score=round(verification_score, 1),
            risk_level=risk_level
        )
    
    def _calculate_security_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """
        Calculate security score based on vulnerabilities.
        Starts at 100 and deducts based on findings.
        """
        if not vulnerabilities:
            return 100.0
        
        score = 100.0
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        
        # Count vulnerabilities by severity
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "informational").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Apply deductions with caps
        for severity, count in severity_counts.items():
            if count > 0:
                deduction_per = self.SEVERITY_DEDUCTIONS.get(severity, 1)
                max_deduction = self.MAX_SEVERITY_DEDUCTION.get(severity, 10)
                
                total_deduction = min(count * deduction_per, max_deduction)
                score -= total_deduction
        
        # Critical vulnerabilities have extra impact
        if severity_counts["critical"] > 0:
            score = min(score, 40)  # Cap at 40 if any critical
        
        return max(0, score)
    
    def _calculate_code_quality_score(self, issues: List[Dict[str, Any]]) -> float:
        """Calculate code quality score based on issues found"""
        if not issues:
            return 100.0
        
        score = 100.0
        
        for issue in issues:
            severity = issue.get("severity", "informational").lower()
            if severity == "low":
                score -= 5
            else:
                score -= 2
        
        return max(0, score)
    
    def _apply_bytecode_penalties(
        self, 
        base_score: float, 
        bytecode_analysis: Dict[str, Any]
    ) -> float:
        """Apply additional penalties for concerning bytecode patterns"""
        score = base_score
        
        # Penalty for dangerous opcodes
        if bytecode_analysis.get("has_selfdestruct"):
            score -= 15
        
        if bytecode_analysis.get("has_delegatecall"):
            score -= 10
        
        # Penalty for unverified status
        score -= 10
        
        # Add penalties from pre-identified issues
        for issue in bytecode_analysis.get("potential_issues", []):
            severity = issue.get("severity", "low").lower()
            if severity == "high":
                score -= 10
            elif severity == "medium":
                score -= 5
        
        return max(0, score)
    
    def _determine_risk_level(
        self, 
        overall_score: float, 
        vulnerabilities: List[Dict[str, Any]]
    ) -> str:
        """Determine risk level based on score and critical findings"""
        # Check for critical vulnerabilities first
        has_critical = any(
            v.get("severity", "").lower() == "critical" 
            for v in vulnerabilities
        )
        
        if has_critical:
            return "Critical"
        
        # Check for multiple high severity
        high_count = sum(
            1 for v in vulnerabilities 
            if v.get("severity", "").lower() == "high"
        )
        
        if high_count >= 3:
            return "Critical"
        elif high_count >= 1:
            return "High"
        
        # Score-based risk level
        if overall_score >= 90:
            return "Safe"
        elif overall_score >= 75:
            return "Low"
        elif overall_score >= 50:
            return "Medium"
        elif overall_score >= 25:
            return "High"
        else:
            return "Critical"
    
    def get_severity_breakdown(
        self, 
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """Get count of vulnerabilities by severity"""
        breakdown = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "informational").lower()
            if severity in breakdown:
                breakdown[severity] += 1
        
        return breakdown
    
    def format_score_display(self, trust_score: TrustScore) -> Dict[str, Any]:
        """Format trust score for display with colors and icons"""
        # Determine color based on overall score
        if trust_score.overall_score >= 90:
            color = "#00CC00"  # Green
            icon = "✅"
        elif trust_score.overall_score >= 75:
            color = "#66CC00"  # Light green
            icon = "🟢"
        elif trust_score.overall_score >= 50:
            color = "#FFCC00"  # Yellow
            icon = "🟡"
        elif trust_score.overall_score >= 25:
            color = "#FF6600"  # Orange
            icon = "🟠"
        else:
            color = "#FF0000"  # Red
            icon = "🔴"
        
        return {
            "score": trust_score.overall_score,
            "color": color,
            "icon": icon,
            "label": f"{trust_score.risk_level} Risk",
            "breakdown": {
                "security": {
                    "score": trust_score.security_score,
                    "weight": f"{self.SECURITY_WEIGHT * 100:.0f}%"
                },
                "code_quality": {
                    "score": trust_score.code_quality_score,
                    "weight": f"{self.CODE_QUALITY_WEIGHT * 100:.0f}%"
                },
                "verification": {
                    "score": trust_score.verification_score,
                    "weight": f"{self.VERIFICATION_WEIGHT * 100:.0f}%"
                }
            }
        }


# Singleton instance
scoring_service = ScoringService()
