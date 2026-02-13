"""
Trust score calculation service with AI-powered dynamic scoring
"""

from typing import Dict, List, Any, Optional
from app.models.schemas import TrustScore, VulnerabilityDetail
from app.core.config import SEVERITY_LEVELS
import logging

# Import new AI services
from app.services.pattern_detector import pattern_detector
from app.services.similarity_search import similarity_service

# Import 4-layer exploit detection system
from app.services.exploit_detector import exploit_detector
from app.services.behavior_analyzer import behavior_analyzer
from app.services.community_reports import community_reports

# Try Gemini first, fall back to Cerebras
try:
    from app.services.gemini_service import gemini_service as llm_service
    LLM_PROVIDER = "Gemini Pro"
    logger = logging.getLogger(__name__)
    logger.info("✅ Using Gemini Pro for LLM analysis")
except Exception as e:
    from app.services.llm import llm_service
    LLM_PROVIDER = "Cerebras"
    logger = logging.getLogger(__name__)
    logger.warning(f"⚠️ Gemini not available, using Cerebras: {e}")


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
    
    # Removed hardcoded lists per user request to rely solely on AI analysis
    WELL_KNOWN_SAFE_CONTRACTS = set()
    KNOWN_EXPLOITED_CONTRACTS = {}
    
    
    # Severity impact on security score (deductions from 100)
    SEVERITY_DEDUCTIONS = {
        "critical": 30,      # Severe: direct exploit path
        "high": 12,          # Serious but not immediate
        "medium": 5,         # Moderate concern
        "low": 2,            # Minor best practice
        "informational": 0,  # No deduction for info
    }
    
    # Maximum deduction per severity to prevent single category domination
    MAX_SEVERITY_DEDUCTION = {
        "critical": 60,      # Max 2 criticals can reduce by 60
        "high": 35,          # Max ~3 highs can reduce by 35
        "medium": 20,        # Max 4 mediums can reduce by 20
        "low": 10,           # Max 5 lows can reduce by 10
        "informational": 0,  # No cap needed
    }
    
    def calculate_trust_score(
        self,
        vulnerabilities: List[Dict[str, Any]],
        code_quality_issues: List[Dict[str, Any]] = None,
        is_verified: bool = True,
        bytecode_analysis: Dict[str, Any] = None,
        contract_address: str = None,
        bytecode: str = None,
        use_ai_scoring: bool = True,
        chain: str = "ethereum",
        source_code: str = None
    ) -> TrustScore:
        """
        Calculate comprehensive trust score for a contract with AI-powered dynamic scoring.
        
        NEW: AI-Powered Features (use_ai_scoring=True):
        - Advanced bytecode pattern detection (honeypots, backdoors, scams)
        - Similarity learning from historical analyses
        - Dynamic scoring that improves over time
        - No manual whitelist updates needed!
        
        Score Ranges:
        - 75-95: Verified Safe (audited, minimal critical issues)
        - 50-74: Unverified Safe (safe patterns but no source)
        - 25-49: Verified Unsafe (source shows vulnerabilities)
        - 0-24: Unverified Unsafe (bytecode + red flags)
        
        Key: Each vulnerability's impact = severity_weight × confidence,
        so every contract gets a UNIQUE score based on its exact findings.
        """
        # ===== NEW: AI-Powered Dynamic Scoring =====
        if use_ai_scoring and bytecode:
            return self._calculate_ai_trust_score(
                vulnerabilities=vulnerabilities,
                code_quality_issues=code_quality_issues,
                is_verified=is_verified,
                bytecode=bytecode,
                contract_address=contract_address,
                chain=chain,
                source_code=source_code
            )
        # ===== END AI SCORING =====
        
        # Fallback: Traditional scoring (if AI disabled or no bytecode)
        # Start from 100 and deduct based on findings
        base_score = 100.0
        
        # Count vulnerabilities by severity
        critical_count = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "critical")
        high_count = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "high")
        medium_count = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "medium")
        low_count = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "low")
        
        # Apply vulnerability deductions (weighted by confidence)
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "informational").lower()
            confidence = vuln.get("confidence", 0.7)
            
            if severity == "critical":
                base_score -= 25 * confidence
            elif severity == "high":
                base_score -= 15 * confidence
            elif severity == "medium":
                base_score -= 8 * confidence
            elif severity == "low":
                base_score -= 3 * confidence
        
        # Apply code quality deductions
        if code_quality_issues:
            quality_impact = self._calculate_quality_impact(code_quality_issues)
            base_score -= quality_impact
        
        # Apply bytecode penalties for unverified contracts
        if not is_verified:
            # Base penalty for lack of verification
            base_score -= 20.0
            
            if bytecode_analysis:
                # Additional penalties for concerning patterns
                if bytecode_analysis.get("has_selfdestruct"):
                    base_score -= 10
                if bytecode_analysis.get("has_delegatecall"):
                    base_score -= 8
                
                suspicious = bytecode_analysis.get("suspicious_patterns", [])
                base_score -= len(suspicious) * 5
        
        # Map to category range with improved risk determination
        has_critical_risk = (
            critical_count >= 1 or  # Any critical = unsafe
            high_count >= 2 or      # 2+ high = unsafe
            (high_count >= 1 and medium_count >= 2) or  # 1 high + 2 medium = unsafe
            medium_count >= 5       # Many mediums = unsafe
        )
        
        is_unsafe = has_critical_risk or (
            not is_verified and 
            bytecode_analysis and 
            len(bytecode_analysis.get("suspicious_patterns", [])) > 2
        )
        
        # Log the categorization decision
        logger.info(f"📊 Traditional Scoring for {contract_address}:")
        logger.info(f"   Calculated base score: {base_score:.1f}")
        logger.info(f"   Verified: {is_verified}, Unsafe: {is_unsafe}")
        logger.info(f"   Vulnerabilities: C={critical_count}, H={high_count}, M={medium_count}")
        
        # Map calculated score to appropriate category range
        if is_verified:
            if is_unsafe:
                # Verified Unsafe: 25-49
                overall_score = 25 + (max(0, base_score) / 100.0) * 24
                overall_score = max(25, min(overall_score, 49))
                logger.info(f"   → Verified Unsafe: {overall_score:.1f}")
            else:
                # Verified Safe: 75-95
                overall_score = 75 + (max(0, base_score) / 100.0) * 20
                overall_score = max(75, min(overall_score, 95))
                logger.info(f"   → Verified Safe: {overall_score:.1f}")
        else:
            if is_unsafe:
                # Unverified Unsafe: 0-24
                overall_score = (max(0, base_score) / 100.0) * 24
                overall_score = max(0, min(overall_score, 24))
                logger.info(f"   → Unverified Unsafe: {overall_score:.1f}")
            else:
                # Unverified Safe: 50-74
                overall_score = 50 + (max(0, base_score) / 100.0) * 24
                overall_score = max(50, min(overall_score, 74))
                logger.info(f"   → Unverified Safe: {overall_score:.1f}")
        
        # Calculate component scores
        security_score = self._calculate_security_score(vulnerabilities)
        code_quality_score = self._calculate_code_quality_score(code_quality_issues or [])
        verification_score = 100.0 if is_verified else 30.0
        
        # Determine risk level from final score
        risk_level = self._determine_risk_level(overall_score, vulnerabilities)
        
        logger.info(f"Traditional scoring: {contract_address} - Score: {overall_score:.1f} ({risk_level})")
        
        return TrustScore(
            overall_score=round(overall_score, 1),
            security_score=round(security_score, 1),
            code_quality_score=round(code_quality_score, 1),
            verification_score=round(verification_score, 1),
            risk_level=risk_level
        )
    
    def _calculate_ai_trust_score(
        self,
        vulnerabilities: List[Dict[str, Any]],
        code_quality_issues: List[Dict[str, Any]],
        is_verified: bool,
        bytecode: str,
        contract_address: str,
        chain: str = "ethereum",
        source_code: str = None
    ) -> TrustScore:
        """
        🤖 AI-POWERED DYNAMIC TRUST SCORING
        
        Score Ranges (Continuous & Real-time):
        - 75-95: Verified Safe (audited, minimal issues)
        - 50-74: Unverified Safe (safe patterns, no source)
        - 25-49: Verified Unsafe (source shows vulnerabilities)
        - 0-24: Unverified Unsafe (bytecode + red flags)
        
        The system starts from 100 and deducts based on actual findings.
        """
        logger.info(f"🤖 AI Scoring: {contract_address} (Verified: {is_verified})")
        
        # Step 1: Start from 100 (perfect score)
        base_score = 100.0
        logger.debug(f"Starting score: {base_score}")
        
        # Step 2: Run comprehensive bytecode pattern analysis
        pattern_analysis = pattern_detector.analyze_comprehensive(bytecode)
        
        # Step 3: Count vulnerabilities by severity
        critical_count = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "critical")
        high_count = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "high")
        medium_count = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "medium")
        low_count = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "low")
        
        # Step 4: Apply LLM vulnerability deductions (weighted by confidence)
        llm_deduction = self._calculate_llm_vulnerability_impact(vulnerabilities)
        base_score -= llm_deduction
        logger.debug(f"After LLM vulnerabilities: {base_score:.1f} (deduction: -{llm_deduction:.1f})")
        
        # Step 5: Apply bytecode pattern adjustments (only for unverified)
        # Note: pattern_detector returns negative for risks, positive for good patterns
        if not is_verified:
            pattern_adjustment = pattern_analysis.get("risk_score_adjustment", 0)
            base_score += pattern_adjustment  # Add since negatives are already penalties
            logger.debug(f"After bytecode patterns: {base_score:.1f} (adjustment: {pattern_adjustment:+.1f})")
        
        # Step 6: Apply code quality deductions
        quality_deduction = self._calculate_quality_impact(code_quality_issues)
        base_score -= quality_deduction
        logger.debug(f"After code quality: {base_score:.1f} (deduction: -{quality_deduction:.1f})")
        
        # Step 7: Apply verification penalty (unverified contracts lose points for lack of transparency)
        if not is_verified:
            verification_penalty = 20.0  # Base penalty for not being verified
            base_score -= verification_penalty
            logger.debug(f"After verification penalty: {base_score:.1f} (deduction: -{verification_penalty:.1f})")
        
        # Step 8: 🧠 LEARNING COMPONENT - Find similar contracts
        similar_contracts = similarity_service.find_similar_contracts(
            bytecode=bytecode,
            top_k=10,
            min_similarity=0.70
        )
        
        if similar_contracts:
            learned_score, learning_explanation = similarity_service.calculate_learned_score_adjustment(
                similar_contracts=similar_contracts,
                base_score=base_score,
                learning_weight=0.15  # 15% weight to historical data
            )
            learning_adjustment = learned_score - base_score
            base_score = learned_score
            logger.info(f"🧠 {learning_explanation}")
            logger.debug(f"After learning: {base_score:.1f} (adjustment: {learning_adjustment:+.1f})")
        else:
            logger.debug("No similar contracts found for learning")
        
        # 🚨 Step 8.5: 4-LAYER EXPLOIT DETECTION SYSTEM 🚨
        # Layer 1: Known Exploit Database API
        # Layer 2: Semantic RAG Pattern Matching  
        # Layer 3: On-Chain Behavior Analysis
        # Layer 4: Community Reports
        logger.info("🔍 Running 4-layer exploit detection...")
        
        try:
            # Layer 1: Check external exploit databases
            import asyncio
            exploit_status = asyncio.run(exploit_detector.check_exploit_status(contract_address, chain))
            if exploit_status and exploit_status['is_exploited']:
                sources = [s['source'] for s in exploit_status['sources']]
                logger.warning(f"🚨 KNOWN EXPLOIT DETECTED! Sources: {', '.join(sources)}")
                logger.warning(f"   Confidence: {exploit_status['confidence']:.1%}, Severity: {exploit_status['severity']}")
                
                # Apply severe penalty based on confidence
                exploit_penalty = exploit_status['confidence'] * 35  # Up to 35 point penalty
                base_score -= exploit_penalty
                logger.warning(f"   Applied exploit penalty: -{exploit_penalty:.1f} points")
                
                # For high-confidence exploits, force into unsafe range
                if exploit_status['confidence'] >= 0.8:
                    base_score = min(base_score, 45 if is_verified else 20)
                    logger.warning(f"   High-confidence exploit - capping score at {base_score:.1f}")
            else:
                logger.debug("✅ No known exploits found in databases")
                
        except Exception as e:
            logger.error(f"❌ Layer 1 (Exploit DB) check failed: {e}")
        
        # Layer 2: Semantic RAG (already integrated in _map_to_category_range)
        # This checks for similar vulnerability patterns when LLM disagrees with patterns
        
        # Layer 3: On-chain behavior analysis
        try:
            # Calculate contract age if possible (placeholder for now)
            contract_age_days = None  # TODO: Get from blockchain data
            
            behavior = asyncio.run(behavior_analyzer.analyze_contract_behavior(
                address=contract_address,
                chain=chain,
                contract_age_days=contract_age_days
            ))
            
            if behavior['red_flags']:
                logger.warning(f"⚠️ Behavior red flags detected: {len(behavior['red_flags'])} issues")
                for flag in behavior['red_flags']:
                    logger.warning(f"   - [{flag['severity']}] {flag['description']}")
                
                behavior_penalty = behavior['behavior_risk_score']
                base_score -= behavior_penalty
                logger.warning(f"   Applied behavior penalty: -{behavior_penalty:.1f} points")
            else:
                logger.debug("✅ No suspicious behavior detected")
                
        except Exception as e:
            logger.error(f"❌ Layer 3 (Behavior Analysis) check failed: {e}")
        
        # Layer 4: Community reports
        try:
            community = asyncio.run(community_reports.get_report_score(contract_address, chain))
            
            if community['report_count'] > 0:
                logger.warning(f"📢 Community reports: {community['report_count']} reports found")
                logger.warning(f"   Average severity: {community['avg_severity']:.1f}/10")
                logger.warning(f"   Risk adjustment: -{community['risk_adjustment']:.1f} points")
                
                base_score -= community['risk_adjustment']
                
                # Show recent reports
                for report in community['recent_reports'][:2]:  # Show top 2
                    logger.warning(f"   - {report['category']}: {report['description'][:50]}...")
            else:
                logger.debug("✅ No community reports found")
                
        except Exception as e:
            logger.error(f"❌ Layer 4 (Community Reports) check failed: {e}")
        
        logger.info(f"After 4-layer detection: {base_score:.1f}")
        # 🚨 END 4-LAYER EXPLOIT DETECTION 🚨
        
        # Step 9: Apply intelligent category mapping (smooth, no hard boundaries)
        final_score = self._map_to_category_range(
            base_score, 
            is_verified, 
            critical_count,
            high_count,
            medium_count,
            pattern_analysis,
            vulnerabilities,  # Pass vulnerabilities for confidence-weighted risk calculation
            source_code  # Pass source_code for RAG tiebreaker
        )
        
        # Step 10: Calculate component scores
        security_score = self._calculate_security_score_ai(pattern_analysis, vulnerabilities)
        code_quality_score = self._calculate_code_quality_score(code_quality_issues)
        verification_score = 100.0 if is_verified else 30.0
        
        # Step 11: Determine risk level
        risk_level = self._determine_risk_level_ai(final_score, pattern_analysis)
        
        # Step 12: Store this analysis for future learning
        try:
            similarity_service.store_analysis(
                contract_address=contract_address,
                bytecode=bytecode,
                trust_score=final_score,
                is_verified=is_verified,
                vulnerabilities=vulnerabilities
            )
        except Exception as e:
            logger.error(f"Failed to store analysis for learning: {e}")
        
        logger.info(f"✅ Final AI Score: {final_score:.1f} ({risk_level})")
        
        return TrustScore(
            overall_score=round(final_score, 1),
            security_score=round(security_score, 1),
            code_quality_score=round(code_quality_score, 1),
            verification_score=round(verification_score, 1),
            risk_level=risk_level
        )
    
    def _calculate_llm_vulnerability_impact(self, vulnerabilities: List[Dict]) -> float:
        """
        Calculate score deduction from LLM-detected vulnerabilities.
        Returns a POSITIVE number representing the deduction amount.
        """
        deduction = 0.0
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "informational").lower()
            confidence = vuln.get("confidence", 0.7)
            
            # Weight by both severity and confidence
            # Returns positive deduction values
            if severity == "critical":
                deduction += 25 * confidence
            elif severity == "high":
                deduction += 15 * confidence
            elif severity == "medium":
                deduction += 8 * confidence
            elif severity == "low":
                deduction += 3 * confidence
        
        return deduction
    
    
    def _map_to_category_range(
        self,
        calculated_score: float,
        is_verified: bool,
        critical_count: int,
        high_count: int,
        medium_count: int,
        pattern_analysis: Dict,
        vulnerabilities: List[Dict] = None,
        source_code: str = None
    ) -> float:
        """
        Intelligently map calculated score to appropriate category range.
        
        Categories (based on actual risk):
        - 75-95: Verified Safe (audited, clean/minor issues)
        - 50-74: Unverified Safe (safe patterns, no verification)
        - 25-49: Verified Unsafe (verified but has vulnerabilities)
        - 0-24: Unverified Unsafe (unverified + red flags)
        
        Key: We determine the category based on verification + risk level,
        then map the calculated score within that category's range.
        
        Uses weighted risk scores (severity × confidence) rather than simple counts.
        """
        
        # Calculate weighted risk score (confidence-weighted severity)
        weighted_critical = 0.0
        weighted_high = 0.0
        weighted_medium = 0.0
        
        if vulnerabilities:
            for v in vulnerabilities:
                severity = v.get("severity", "informational").lower()
                confidence = v.get("confidence", 0.7)
                
                if severity == "critical":
                    weighted_critical += confidence
                elif severity == "high":
                    weighted_high += confidence
                elif severity == "medium":
                    weighted_medium += confidence
        
        # Determine if contract is "unsafe" using WEIGHTED thresholds
        # This prevents low-confidence findings from incorrectly categorizing contracts
        has_critical_risk = (
            weighted_critical >= 0.8 or  # High-confidence critical (e.g., 1 finding at 80%+)
            weighted_high >= 1.6 or      # Multiple/high-confidence highs (e.g., 2 at 80%)
            (weighted_high >= 0.75 and weighted_medium >= 1.5) or  # 1 confident high + 2 mediums
            weighted_medium >= 4.0       # Many confident mediums (e.g., 5 at 80%)
        )
        
        logger.debug(f"Weighted risk - Critical: {weighted_critical:.2f}, High: {weighted_high:.2f}, Medium: {weighted_medium:.2f}")
        logger.debug(f"Has critical risk: {has_critical_risk}")
        
        # Check for critical malicious patterns
        malicious_patterns = pattern_analysis.get("malicious_patterns", [])
        has_critical_patterns = any(
            p.get("severity") == "critical" for p in malicious_patterns
        )
        
        # Check for high-risk security patterns
        security_risks = pattern_analysis.get("security_risks", [])
        has_high_security_risks = any(
            r.get("severity") in ["critical", "high"] for r in security_risks
        )
        
        # Enhanced risk check - any of these conditions make it unsafe
        # BUT: If we have LLM analysis with 0 vulnerabilities, check for disagreement
        
        # Determine if pattern detector suggests risk
        pattern_suggests_risk = (
            has_critical_risk or 
            has_critical_patterns or
            (not is_verified and has_high_security_risks)
        )
        
        if vulnerabilities is not None and len(vulnerabilities) == 0:
            # LLM found NO vulnerabilities
            if pattern_suggests_risk:
                # DISAGREEMENT: LLM says safe, but patterns suggest risk
                # Use RAG as tiebreaker to check for known exploits
                logger.warning("⚠️ LLM/Pattern mismatch - consulting RAG database...")
                
                try:
                    from app.services.rag_semantic import SemanticRAGService
                    rag = SemanticRAGService(use_semantic=True)
                    
                    # Search for similar vulnerability patterns (limit to first 2000 chars)
                    source_snippet = source_code[:2000] if source_code and len(source_code) > 2000 else source_code
                    if source_snippet:
                        rag_results = rag.search_similar_vulnerabilities(
                            source_snippet,
                            n_results=3
                        )
                        
                        # Check if top match is high-severity with high confidence
                        if rag_results and len(rag_results) > 0:
                            top_match = rag_results[0]
                            severity = top_match.get('severity', 'low').lower()
                            relevance = top_match.get('relevance_score', 0)
                            vuln_name = top_match.get('name', 'Unknown')
                            
                            if severity in ['critical', 'high'] and relevance > 0.75:
                                logger.warning(f"🔍 RAG found similar exploit: {vuln_name} (relevance: {relevance:.2f}, severity: {severity})")
                                is_unsafe = True  # RAG confirms pattern detector's concerns
                            else:
                                logger.info(f"✅ RAG confirms safe: {vuln_name} (relevance: {relevance:.2f}, severity: {severity})")
                                is_unsafe = False  # Trust LLM - RAG doesn't show critical match
                        else:
                            # No RAG matches, trust LLM
                            logger.info("💡 No RAG matches found - trusting LLM (0 vulnerabilities)")
                            is_unsafe = False
                    else:
                        # No source code for RAG, trust LLM
                        logger.info("💡 No source code available for RAG - trusting LLM")
                        is_unsafe = False
                        
                except Exception as e:
                    logger.error(f"❌ RAG lookup failed: {e}")
                    # Fallback to pattern detector on RAG failure (conservative approach)
                    logger.warning("⚠️ Falling back to pattern detector due to RAG error")
                    is_unsafe = pattern_suggests_risk
            else:
                # LLM and patterns AGREE: contract is safe
                is_unsafe = False
                logger.info("💡 LLM found 0 vulnerabilities - pattern detector agrees")
        else:
            # LLM found vulnerabilities OR no LLM analysis available
            is_unsafe = pattern_suggests_risk
        
        # Ensure calculated_score is within valid range
        calculated_score = max(0, min(calculated_score, 100))
        
        # Map to appropriate category and scale within range
        if is_verified:
            if is_unsafe:
                # Verified Unsafe: 25-49 range
                # Map score from 0-100 to 25-49
                # Lower calculated scores → lower in range (closer to 25)
                # Higher calculated scores → higher in range (closer to 49)
                mapped_score = 25 + (calculated_score / 100.0) * 24  # Map 0-100 to 25-49
                final_score = max(25, min(mapped_score, 49))
                logger.info(f"📊 Verified Unsafe: calculated={calculated_score:.1f} → final={final_score:.1f} (range: 25-49)")
            else:
                # Verified Safe: 75-95 range
                # Map score from 0-100 to 75-95
                mapped_score = 75 + (calculated_score / 100.0) * 20  # Map 0-100 to 75-95
                final_score = max(75, min(mapped_score, 95))
                logger.info(f"📊 Verified Safe: calculated={calculated_score:.1f} → final={final_score:.1f} (range: 75-95)")
        else:
            if is_unsafe:
                # Unverified Unsafe: 0-24 range
                # Map score from 0-100 to 0-24
                mapped_score = (calculated_score / 100.0) * 24  # Map 0-100 to 0-24
                final_score = max(0, min(mapped_score, 24))
                logger.info(f"📊 Unverified Unsafe: calculated={calculated_score:.1f} → final={final_score:.1f} (range: 0-24)")
            else:
                # Unverified Safe: 50-74 range
                # Map score from 0-100 to 50-74
                mapped_score = 50 + (calculated_score / 100.0) * 24  # Map 0-100 to 50-74
                final_score = max(50, min(mapped_score, 74))
                logger.info(f"📊 Unverified Safe: calculated={calculated_score:.1f} → final={final_score:.1f} (range: 50-74)")
        
        return final_score
    
    def _apply_category_boundaries(
        self,
        score: float,
        is_verified: bool,
        pattern_analysis: Dict
    ) -> float:
        """
        DEPRECATED: Use _map_to_category_range instead.
        Kept for backward compatibility only.
        """
        # Just clamp to 0-100 without the buggy boundary logic
        return max(0, min(score, 100))

    
    def _calculate_security_score_ai(
        self,
        pattern_analysis: Dict,
        vulnerabilities: List[Dict]
    ) -> float:
        """Calculate security score from AI pattern analysis"""
        base_security = 100.0
        
        # Deduct for pattern-detected threats
        for threat in pattern_analysis.get("malicious_patterns", []):
            severity = threat.get("severity", "informational")
            if severity == "critical":
                base_security -= 25
            elif severity == "high":
                base_security -= 15
            elif severity == "medium":
                base_security -= 8
        
        # Deduct for security risks
        for risk in pattern_analysis.get("security_risks", []):
            severity = risk.get("severity", "informational")
            if severity == "critical":
                base_security -= 20
            elif severity == "high":
                base_security -= 12
            elif severity == "medium":
                base_security -= 6
        
        # Deduct for LLM vulnerabilities
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "informational").lower()
            confidence = vuln.get("confidence", 0.7)
            if severity == "critical":
                base_security -= 15 * confidence
            elif severity == "high":
                base_security -= 8 * confidence
        
        return max(0, min(100, base_security))
    
    def _determine_risk_level_ai(self, score: float, pattern_analysis: Dict) -> str:
        """Determine risk level from AI analysis - Score-based mapping
        
        Risk Level Mapping:
        - 75-100: Low risk (safe contracts)
        - 50-74: Medium risk (unverified safe)
        - 25-49: High risk (verified unsafe)
        - 0-24: Critical risk (unverified unsafe / exploited)
        """
        # Score-first approach (consistent with _determine_risk_level)
        if score >= 75:
            return "Low"
        elif score >= 50:
            return "Medium"
        elif score >= 25:
            return "High"
        else:
            return "Critical"
    
    # ================================================================
    # Category-specific scoring methods (continuous formulas)
    # Each uses severity × confidence for granular differentiation
    # ================================================================
    
    def _calculate_vuln_impact(self, vulnerabilities, weights):
        """
        Calculate continuous vulnerability impact using severity × confidence.
        This is the core formula that ensures every contract gets a unique score.
        
        Higher confidence = more certain the vulnerability exists = more impact.
        """
        impact = 0.0
        for v in vulnerabilities:
            sev = v.get("severity", "informational").lower()
            conf = max(min(v.get("confidence", 0.7), 1.0), 0.1)
            impact += weights.get(sev, 0.0) * conf
        return impact
    
    def _calculate_quality_impact(self, code_quality_issues, weight_per_issue=0.5):
        """Calculate code quality impact for micro-differentiation."""
        if not code_quality_issues:
            return 0.0
        impact = 0.0
        for issue in code_quality_issues:
            sev = issue.get("severity", "informational").lower()
            if sev == "low":
                impact += weight_per_issue
            elif sev == "medium":
                impact += weight_per_issue * 1.5
            else:
                impact += weight_per_issue * 0.5
        return impact
    
    def _calculate_bytecode_impact(self, bytecode_analysis, scale=1.0):
        """Calculate continuous bytecode complexity impact."""
        if not bytecode_analysis:
            return 0.0
        
        impact = 0.0
        if bytecode_analysis.get("has_selfdestruct"):
            impact += 5.0
        if bytecode_analysis.get("has_delegatecall"):
            impact += 3.0
        
        suspicious = bytecode_analysis.get("suspicious_patterns", [])
        impact += len(suspicious) * 2.0
        
        ext_calls = bytecode_analysis.get("external_calls", 0)
        if ext_calls > 5:
            impact += min((ext_calls - 5) * 0.3, 2.0)
        
        size = bytecode_analysis.get("size", 0)
        if size > 15000:
            impact += min((size - 15000) / 10000.0, 2.0)
        
        return impact * scale
    
    def _has_risky_bytecode(self, bytecode_analysis):
        """Check if bytecode contains suspicious patterns."""
        if not bytecode_analysis:
            return False
        return len(bytecode_analysis.get("suspicious_patterns", [])) > 0
    

    
    def _score_verified_safe(self, vulnerabilities, code_quality_issues):
        """
        Generic verified safe contracts: 75-95 range.
        
        Verified source with no critical/high vulnerabilities.
        Slightly stricter than well-known (no reputation bonus).
        """
        weights = {"critical": 12.0, "high": 7.0, "medium": 3.5, "low": 2.0, "informational": 0.5}
        vuln_impact = self._calculate_vuln_impact(vulnerabilities, weights)
        quality_impact = self._calculate_quality_impact(code_quality_issues, 0.5)
        score = 95.0 - vuln_impact - quality_impact
        return round(max(min(score, 95.0), 75.0), 1)
    
    def _score_verified_unsafe(self, vulnerabilities, code_quality_issues):
        """
        Generic verified unsafe contracts: 25-49 range.
        
        Verified source with critical/high vulnerabilities found.
        Uses enhanced vulnerability profiling to differentiate between:
        - 25-30: Extreme risk (3+ critical, dangerous combinations)
        - 31-37: High risk (2+ critical or reentrancy+delegatecall)
        - 38-44: Moderate risk (1-2 critical or multiple high)
        - 45-49: Low risk (deprecated, isolated issues)
        """
        # Analyze vulnerability profile for risk tier
        risk_profile = self._analyze_vulnerability_profile(vulnerabilities)
        
        # Start from tier-specific baseline
        if risk_profile["tier"] == "extreme":
            base_score = 27.5  # Will spread 25-30
            weights = {"critical": 0.5, "high": 0.3, "medium": 0.1, "low": 0.05}
        elif risk_profile["tier"] == "high":
            base_score = 34.0  # Will spread 31-37
            weights = {"critical": 0.8, "high": 0.4, "medium": 0.15, "low": 0.05}
        elif risk_profile["tier"] == "moderate":
            base_score = 41.0  # Will spread 38-44
            weights = {"critical": 1.0, "high": 0.5, "medium": 0.2, "low": 0.1}
        else:  # low risk tier
            base_score = 47.0  # Will spread 45-49
            weights = {"critical": 1.5, "high": 0.8, "medium": 0.3, "low": 0.1}
        
        # Apply micro-differentiation within tier
        vuln_impact = self._calculate_vuln_impact(vulnerabilities, weights)
        quality_impact = self._calculate_quality_impact(code_quality_issues, 0.2)
        
        score = base_score - vuln_impact - quality_impact
        
        # Clamp to overall unsafe range
        return round(max(min(score, 49.0), 25.0), 1)
    
    def _analyze_vulnerability_profile(self, vulnerabilities):
        """
        Analyze vulnerability profile to determine risk tier.
        
        Returns dict with:
        - tier: extreme/high/moderate/low
        - critical_count: number of critical vulnerabilities
        - has_dangerous_combo: reentrancy + delegatecall/selfdestruct
        - vuln_types: set of vulnerability types found
        """
        critical_count = 0
        high_count = 0
        vuln_types = set()
        
        for v in vulnerabilities:
            severity = v.get("severity", "").lower()
            if severity == "critical":
                critical_count += 1
            elif severity == "high":
                high_count += 1
            
            # Extract vulnerability type from title/description
            title = v.get("title", "").lower()
            desc = v.get("description", "").lower()
            text = title + " " + desc
            
            if "reentrancy" in text:
                vuln_types.add("reentrancy")
            if "delegatecall" in text or "delegate call" in text:
                vuln_types.add("delegatecall")
            if "selfdestruct" in text or "self destruct" in text:
                vuln_types.add("selfdestruct")
            if "flash loan" in text or "flashloan" in text:
                vuln_types.add("flashloan")
            if "unchecked" in text or "overflow" in text or "underflow" in text:
                vuln_types.add("arithmetic")
            if "access control" in text or "unauthorized" in text:
                vuln_types.add("access_control")
        
        # Detect dangerous combinations
        has_dangerous_combo = False
        if "reentrancy" in vuln_types and ("delegatecall" in vuln_types or "selfdestruct" in vuln_types):
            has_dangerous_combo = True
        if "delegatecall" in vuln_types and "access_control" in vuln_types:
            has_dangerous_combo = True
        if "flashloan" in vuln_types and "reentrancy" in vuln_types:
            has_dangerous_combo = True
        
        # Determine tier based on profile
        if critical_count >= 3 or (critical_count >= 2 and has_dangerous_combo):
            tier = "extreme"
        elif critical_count >= 2 or (critical_count >= 1 and has_dangerous_combo) or high_count >= 4:
            tier = "high"
        elif critical_count >= 1 or high_count >= 2:
            tier = "moderate"
        else:
            tier = "low"
        
        return {
            "tier": tier,
            "critical_count": critical_count,
            "high_count": high_count,
            "has_dangerous_combo": has_dangerous_combo,
            "vuln_types": vuln_types
        }
    
    def _score_unverified_safe(self, vulnerabilities, bytecode_analysis, code_quality_issues):
        """
        Unverified safe contracts: 50-74 range.
        
        No critical/high vulnerabilities found but source not verified.
        Uses bytecode metrics (size, external calls, patterns) for
        additional differentiation.
        """
        weights = {"high": 12.0, "medium": 5.0, "low": 2.5, "informational": 0.5}
        vuln_impact = self._calculate_vuln_impact(vulnerabilities, weights)
        bytecode_impact = self._calculate_bytecode_impact(bytecode_analysis, scale=1.0)
        quality_impact = self._calculate_quality_impact(code_quality_issues, 0.5)
        
        score = 74.0 - vuln_impact - bytecode_impact - quality_impact
        
        # Fallback for no data at all
        if not vulnerabilities and not bytecode_analysis:
            score = min(score, 60.0)  # Conservative for completely unknown
        
        return round(max(min(score, 74.0), 50.0), 1)
    
    def _score_unverified_unsafe(self, vulnerabilities, bytecode_analysis, code_quality_issues):
        """
        Unverified unsafe contracts: 0-24 range.
        
        Critical/high vulnerabilities AND no source verification = highest risk.
        Uses severity × confidence for continuous scoring within 0-24.
        """
        weights = {"critical": 5.0, "high": 3.0, "medium": 1.5, "low": 0.5, "informational": 0.0}
        vuln_impact = self._calculate_vuln_impact(vulnerabilities, weights)
        bytecode_impact = self._calculate_bytecode_impact(bytecode_analysis, scale=0.7)
        quality_impact = self._calculate_quality_impact(code_quality_issues, 0.3)
        
        score = 24.0 - vuln_impact - bytecode_impact - quality_impact
        return round(max(min(score, 24.0), 0.0), 1)
    
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
        
        # Multiple critical vulnerabilities have extra impact (but don't cap too low)
        if severity_counts["critical"] >= 2:
            score = min(score, 45)  # Cap at 45 if multiple criticals
        elif severity_counts["critical"] == 1:
            score = min(score, 60)  # Single critical caps at 60 (not 40)
        
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
        """Determine risk level based on FINAL SCORE (includes reputation boosts)
        
        Risk Level Mapping:
        - 75-100: Low risk (safe contracts)
        - 50-74: Medium risk (unverified safe)
        - 25-49: High risk (verified unsafe)
        - 0-24: Critical risk (unverified unsafe / exploited)
        """
        
        # SCORE-FIRST approach (accounts for reputation/well-known contract boosts)
        if overall_score >= 75:
            return "Low"
        elif overall_score >= 50:
            # Unverified safe OR verified with issues → Medium risk
            return "Medium"
        elif overall_score >= 25:
            # Verified unsafe OR unverified with issues → High risk  
            return "High"
        else:
            # Unverified unsafe (0-24) → Critical risk
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
