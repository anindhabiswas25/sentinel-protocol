"""
Main analyzer service - orchestrates the contract analysis pipeline
with LLM output validation and bytecode cross-validation.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
import logging
import uuid

from app.services.blockchain import blockchain_service
from app.services.rag_semantic import rag_service
from app.services.exploit_detector import ExploitDetector
from app.services.dynamic_exploit_detector import dynamic_exploit_detector  # NEW: Dynamic detector

# Try Gemini first, fall back to Cerebras
try:
    from app.services.gemini_service import gemini_service as llm_service
    logger = logging.getLogger(__name__)
    logger.info("🚀 Analyzer using Gemini Pro")
except ImportError as e:
    from app.services.llm import llm_service
    logger = logging.getLogger(__name__)
    logger.warning(f"⚠️ Gemini not available, using Cerebras: {e}")

from app.services.scoring import scoring_service
from app.services.llm_validator import llm_validator

# Initialize exploit detector (legacy - for fallback)
exploit_detector = ExploitDetector()
from app.models.schemas import (
    ContractAnalysisRequest,
    ContractAnalysisResponse,
    ContractMetadata,
    TrustScore,
    AnalysisSummary,
    VulnerabilityDetail,
    SeverityEnum,
)
from app.db.connection import get_db_context
from app.db import crud

logger = logging.getLogger(__name__)


class AnalyzerService:
    """
    Main analyzer service that orchestrates the full analysis pipeline.
    
    Pipeline:
    1. Validate contract address and network
    2. Check cache for existing analysis
    3. Fetch contract data (source or bytecode)
    4. Get RAG context for relevant vulnerabilities
    5. Run LLM analysis
    6. Calculate trust score
    7. Store results and return
    """
    
    async def analyze_contract(
        self, 
        request: ContractAnalysisRequest
    ) -> ContractAnalysisResponse:
        """
        Main entry point for contract analysis.
        
        Args:
            request: Analysis request with address and network
        
        Returns:
            Complete analysis response
        """
        address = request.contract_address.lower()
        network = request.network.value
        
        logger.info(f"Starting analysis of {address} on {network}")
        
        # Step 1: Validate address
        if not blockchain_service.is_valid_address(address):
            return self._create_error_response(
                address, network, "Invalid contract address format"
            )
        
        # Step 1.5: Dynamic Exploit Detection FIRST (HIGHEST PRIORITY)
        # This catches known exploited contracts from multiple external sources
        logger.info(f"🔍 Running dynamic exploit detection for {address}...")
        exploit_result = await dynamic_exploit_detector.check_exploit_status(address, network)
        
        if exploit_result and exploit_result.get('is_exploited'):
            logger.warning(f"🚨 EXPLOIT DETECTED (Dynamic) - Score Override: {exploit_result.get('score_override')}")
            return self._create_exploit_response(
                address=address,
                network=network,
                exploit_data=exploit_result
            )
        
        # Step 1.6: FALLBACK to Legacy Exploit Database (if dynamic fails)
        # Ensures known exploits are caught even if external APIs are down
        logger.info(f"🔍 Checking legacy exploit database for {address}...")
        legacy_exploit = await exploit_detector.check_exploit_status(address, network)
        
        if legacy_exploit and legacy_exploit.get('is_exploited'):
            logger.warning(f"🚨 EXPLOIT DETECTED (Legacy Database) - Score Override: {legacy_exploit.get('score_override')}")
            return self._create_exploit_response(
                address=address,
                network=network,
                exploit_data=legacy_exploit
            )
        
        # Step 2: Check if it's actually a contract on specified network
        is_contract_on_network = blockchain_service.is_contract(address, network)
        
        # Step 2a: If not found on specified network, try auto-detecting
        if not is_contract_on_network:
            logger.info(f"Contract not found on {network}, attempting auto-detection...")
            detected_networks = blockchain_service.detect_network(address)
            
            if detected_networks:
                # Contract found on a different network, use the first one
                detected_network = detected_networks[0]["network"]
                logger.info(f"Contract found on {detected_network}, switching network")
                network = detected_network
            else:
                # Contract doesn't exist on any supported network
                return self._create_error_response(
                    address, 
                    network, 
                    f"No contract found at this address on any supported network (Ethereum, Polygon, Arbitrum, Base). "
                    f"Please verify the address is correct and the contract is deployed."
                )
        
        # Step 3: Check cache (unless force refresh)
        if not request.force_refresh:
            cached_result = self._get_cached_analysis(address, network)
            if cached_result:
                logger.info(f"Returning cached analysis for {address}")
                return cached_result
        
        # Step 4: Fetch contract data
        is_verified, source_data = await blockchain_service.get_verified_source_code(
            address, network
        )
        
        # Step 5: Get bytecode for additional analysis
        bytecode = blockchain_service.get_bytecode(address, network)
        bytecode_analysis = blockchain_service.analyze_bytecode_patterns(bytecode) if bytecode else {}
        
        # Step 6: Check for proxy
        is_proxy = False
        implementation_address = None
        
        if source_data and source_data.get("proxy"):
            is_proxy = True
            implementation_address = source_data.get("implementation")
        elif bytecode:
            is_proxy, _ = blockchain_service.detect_proxy(bytecode)
            if is_proxy:
                implementation_address = await blockchain_service.get_implementation_address(
                    address, network
                )
        
        # Step 7: Run analysis
        if is_verified and source_data:
            analysis_result = await self._analyze_verified_contract(
                source_data, address, network
            )
        else:
            analysis_result = await self._analyze_unverified_contract(
                bytecode, bytecode_analysis, address, network
            )
        
        # Step 8: Build response
        response = self._build_response(
            address=address,
            network=network,
            is_verified=is_verified,
            source_data=source_data,
            analysis_result=analysis_result,
            bytecode_analysis=bytecode_analysis,
            bytecode=bytecode,  # Pass bytecode for AI scoring
            is_proxy=is_proxy,
            implementation_address=implementation_address,
        )
        
        # Step 9: Store in database
        self._store_analysis(address, network, response)
        
        logger.info(f"Completed analysis of {address} - Score: {response.trust_score.overall_score}")
        return response
    
    async def _analyze_verified_contract(
        self,
        source_data: dict,
        address: str,
        network: str,
        exploit_context: Optional[Dict] = None,  # NEW: Exploit context for Gemini
    ) -> dict:
        """Analyze a verified contract with source code + LLM validation."""
        source_code = source_data.get("source_code", "")
        contract_name = source_data.get("contract_name", "Unknown")
        
        # Get RAG context
        rag_context = rag_service.get_context_for_analysis(source_code)
        
        # Run LLM analysis with exploit context (if any)
        analysis = await llm_service.analyze_source_code(
            source_code=source_code,
            contract_name=contract_name,
            rag_context=rag_context,
            exploit_context=exploit_context,  # Pass exploit context to Gemini
        )
        
        # ---- Validate LLM output ----
        validation = llm_validator.validate_analysis(analysis)
        if validation["is_valid"]:
            analysis = validation["cleaned_output"]
            report = validation["validation_report"]
            if report.get("warnings"):
                logger.info(
                    f"Verified analysis validated with {len(report['warnings'])} warnings "
                    f"(quality={validation['quality_score']:.2f})"
                )
        else:
            logger.warning(
                f"Verified analysis validation FAILED for {address}: "
                f"{validation['validation_report']['issues']}"
            )
            analysis = validation["cleaned_output"]  # use cleaned fallback
        
        analysis["analysis_method"] = "verified_source"
        analysis["_validation_quality"] = validation["quality_score"]
        return analysis
    
    async def _analyze_unverified_contract(
        self,
        bytecode: str,
        bytecode_analysis: dict,
        address: str,
        network: str,
    ) -> dict:
        """
        Analyze an unverified contract using bytecode.
        
        Pipeline:
        1. Run LLM bytecode analysis
        2. Validate LLM output
        3. Cross-validate LLM findings with regex-based bytecode patterns
        4. Return merged & validated result
        """
        # Run LLM bytecode analysis
        analysis = await llm_service.analyze_bytecode(
            bytecode=bytecode,
            bytecode_analysis=bytecode_analysis,
            contract_address=address,
        )
        
        # ---- Validate LLM output ----
        validation = llm_validator.validate_analysis(analysis)
        if validation["is_valid"]:
            analysis = validation["cleaned_output"]
        else:
            logger.warning(
                f"Bytecode analysis validation FAILED for {address}: "
                f"{validation['validation_report']['issues']}"
            )
            analysis = validation["cleaned_output"]
        
        # ---- Cross-validate with bytecode pattern analysis ----
        if bytecode_analysis:
            analysis["vulnerabilities"] = self._cross_validate_findings(
                llm_vulns=analysis.get("vulnerabilities", []),
                bytecode_patterns=bytecode_analysis,
            )
        
        analysis["analysis_method"] = "bytecode_only"
        analysis["_validation_quality"] = validation["quality_score"]
        return analysis
    
    # ================================================================
    # Cross-validation: LLM findings ↔ regex bytecode patterns
    # ================================================================
    
    def _cross_validate_findings(
        self,
        llm_vulns: List[Dict[str, Any]],
        bytecode_patterns: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Cross-validate LLM-reported vulnerabilities with regex-based
        bytecode pattern analysis.
        
        Rules:
        1. If both LLM and regex flag the same issue → boost confidence
        2. If LLM flags something regex can't confirm → slight penalty
        3. If regex finds a pattern LLM missed → add it with moderate confidence
        
        Returns:
            Updated vulnerability list
        """
        # Map bytecode patterns to vulnerability types
        pattern_vuln_map = {
            "has_selfdestruct": {
                "name": "Selfdestruct Detected",
                "severity": "critical",
                "keywords": ["selfdestruct", "destroy", "kill"],
                "description": "Contract bytecode contains SELFDESTRUCT opcode, which can permanently destroy the contract.",
                "confidence": 0.80,
                "cwe_id": "CWE-749",
            },
            "has_delegatecall": {
                "name": "Delegatecall Detected",
                "severity": "high",
                "keywords": ["delegatecall", "proxy", "delegate"],
                "description": "Contract bytecode contains DELEGATECALL opcode, which executes external code in the contract's context.",
                "confidence": 0.75,
                "cwe_id": "CWE-829",
            },
            "has_create": {
                "name": "Dynamic Contract Creation",
                "severity": "medium",
                "keywords": ["create", "factory", "deploy"],
                "description": "Contract can create new contracts at runtime using CREATE opcode.",
                "confidence": 0.60,
                "cwe_id": "CWE-913",
            },
            "has_create2": {
                "name": "Deterministic Contract Creation",
                "severity": "medium",
                "keywords": ["create2", "deterministic", "factory"],
                "description": "Contract uses CREATE2 for deterministic address deployment.",
                "confidence": 0.55,
                "cwe_id": "CWE-913",
            },
        }
        
        # Track which bytecode patterns are corroborated by LLM
        corroborated = set()
        updated_vulns = []
        
        for vuln in llm_vulns:
            vuln_copy = dict(vuln)
            vuln_name_lower = vuln.get("name", "").lower()
            vuln_desc_lower = vuln.get("description", "").lower()
            matched = False
            
            for pattern_key, pattern_info in pattern_vuln_map.items():
                if not bytecode_patterns.get(pattern_key, False):
                    continue
                
                # Check if LLM vulnerability matches this bytecode pattern
                keywords = pattern_info["keywords"]
                if any(kw in vuln_name_lower or kw in vuln_desc_lower for kw in keywords):
                    # MATCH: both LLM and regex agree → boost confidence
                    old_conf = vuln_copy.get("confidence", 0.5)
                    boost = min(old_conf * 1.2, 0.95)
                    vuln_copy["confidence"] = round(boost, 2)
                    vuln_copy["_cross_validated"] = True
                    corroborated.add(pattern_key)
                    matched = True
                    logger.debug(
                        f"Cross-validated: '{vuln.get('name')}' confirmed by bytecode "
                        f"pattern '{pattern_key}' (confidence {old_conf:.2f} → {boost:.2f})"
                    )
                    break
            
            if not matched:
                # LLM flagged something regex can't confirm
                # Apply slight penalty for bytecode-specific claims
                bytecode_specific = any(
                    kw in vuln_name_lower or kw in vuln_desc_lower
                    for kw in ["selfdestruct", "delegatecall", "create2"]
                )
                if bytecode_specific:
                    old_conf = vuln_copy.get("confidence", 0.5)
                    penalty = max(old_conf * 0.85, 0.15)
                    vuln_copy["confidence"] = round(penalty, 2)
                    logger.debug(
                        f"Unconfirmed bytecode claim: '{vuln.get('name')}' "
                        f"(confidence {old_conf:.2f} → {penalty:.2f})"
                    )
            
            updated_vulns.append(vuln_copy)
        
        # Add bytecode patterns that LLM missed
        external_calls = bytecode_patterns.get("external_calls", 0)
        for pattern_key, pattern_info in pattern_vuln_map.items():
            if bytecode_patterns.get(pattern_key, False) and pattern_key not in corroborated:
                # Regex found it but LLM didn't → add with moderate confidence
                new_vuln = {
                    "id": f"bytecode-{pattern_key}",
                    "name": pattern_info["name"],
                    "severity": pattern_info["severity"],
                    "description": pattern_info["description"],
                    "location": "Bytecode analysis",
                    "recommendation": "Verify this finding by reviewing the contract source code if available.",
                    "confidence": round(pattern_info["confidence"] * 0.7, 2),  # lower confidence since LLM didn't flag it
                    "cwe_id": pattern_info["cwe_id"],
                    "_source": "bytecode_cross_validation",
                }
                updated_vulns.append(new_vuln)
                logger.info(
                    f"Added bytecode-only finding: '{pattern_info['name']}' "
                    f"(confidence {new_vuln['confidence']:.2f})"
                )
        
        # Add high external call count warning if extreme
        if external_calls > 10:
            # Check if any existing vuln already covers this
            has_call_warning = any(
                "external call" in v.get("name", "").lower()
                or "external call" in v.get("description", "").lower()
                for v in updated_vulns
            )
            if not has_call_warning:
                updated_vulns.append({
                    "id": "bytecode-high-external-calls",
                    "name": "High External Call Count",
                    "severity": "medium",
                    "description": f"Contract makes {external_calls} external calls, which increases attack surface.",
                    "location": "Bytecode analysis",
                    "recommendation": "Review all external calls for potential reentrancy or trust issues.",
                    "confidence": round(min(0.3 + (external_calls - 10) * 0.03, 0.75), 2),
                    "cwe_id": "CWE-841",
                    "_source": "bytecode_cross_validation",
                })
        
        return updated_vulns
    
    def _build_response(
        self,
        address: str,
        network: str,
        is_verified: bool,
        source_data: Optional[dict],
        analysis_result: dict,
        bytecode_analysis: dict,
        bytecode: Optional[str],  # Add bytecode parameter
        is_proxy: bool,
        implementation_address: Optional[str],
    ) -> ContractAnalysisResponse:
        """Build the complete analysis response"""
        
        # Check if analysis failed
        if "error" in analysis_result:
            error_msg = analysis_result.get("error", "Analysis failed")
            logger.error(f"Analysis failed for {address}: {error_msg}")
            return self._create_error_response(address, network, f"Analysis failed: {error_msg}")
        
        # Build metadata
        metadata = ContractMetadata(
            address=address,
            network=network,
            name=source_data.get("contract_name") if source_data else None,
            compiler_version=source_data.get("compiler_version") if source_data else None,
            is_verified=is_verified,
            is_proxy=is_proxy,
            implementation_address=implementation_address,
        )
        
        # Parse vulnerabilities
        vulnerabilities = self._parse_vulnerabilities(
            analysis_result.get("vulnerabilities", [])
        )
        
        # Calculate trust score with AI-powered dynamic scoring + 4-layer detection
        trust_score = scoring_service.calculate_trust_score(
            vulnerabilities=[v.model_dump() for v in vulnerabilities],
            code_quality_issues=analysis_result.get("code_quality_issues", []),
            is_verified=is_verified,
            bytecode_analysis=bytecode_analysis if not is_verified else None,
            contract_address=address,
            bytecode=bytecode,  # Enable AI scoring
            use_ai_scoring=True,  # Use new AI-powered scoring
            chain=network,  # Pass network for 4-layer detection
            source_code=source_data.get("source_code") if source_data else None  # For RAG tiebreaker
        )
        
        # Get severity breakdown
        severity_breakdown = scoring_service.get_severity_breakdown(
            [v.model_dump() for v in vulnerabilities]
        )
        
        # Build summary
        summary = AnalysisSummary(
            total_vulnerabilities=len(vulnerabilities),
            critical_count=severity_breakdown["critical"],
            high_count=severity_breakdown["high"],
            medium_count=severity_breakdown["medium"],
            low_count=severity_breakdown["low"],
            informational_count=severity_breakdown["informational"],
            analysis_method="verified_source" if is_verified else "bytecode_only",
            llm_insights=analysis_result.get("summary", "Analysis completed."),
        )
        
        # Build recommendations
        recommendations = analysis_result.get("recommendations", [])
        
        # Add verification warning for unverified contracts
        if not is_verified:
            recommendations.insert(
                0, 
                "⚠️ WARNING: This contract's source code is not verified. "
                "Exercise extreme caution when interacting with unverified contracts."
            )
        
        return ContractAnalysisResponse(
            success=True,
            metadata=metadata,
            trust_score=trust_score,
            summary=summary,
            vulnerabilities=vulnerabilities,
            recommendations=recommendations,
            analysis_timestamp=datetime.utcnow(),
            cached=False,
        )
    
    def _parse_vulnerabilities(
        self, 
        raw_vulnerabilities: list
    ) -> list[VulnerabilityDetail]:
        """Parse and validate vulnerability data from LLM response"""
        vulnerabilities = []
        
        for i, vuln in enumerate(raw_vulnerabilities):
            try:
                # Map severity string to enum
                severity_str = vuln.get("severity", "informational").lower()
                severity_map = {
                    "critical": SeverityEnum.CRITICAL,
                    "high": SeverityEnum.HIGH,
                    "medium": SeverityEnum.MEDIUM,
                    "low": SeverityEnum.LOW,
                    "informational": SeverityEnum.INFORMATIONAL,
                }
                severity = severity_map.get(severity_str, SeverityEnum.INFORMATIONAL)
                
                vulnerabilities.append(VulnerabilityDetail(
                    id=vuln.get("id", f"vuln-{i+1}"),
                    name=vuln.get("name", "Unknown Vulnerability"),
                    severity=severity,
                    description=vuln.get("description", "No description provided"),
                    location=vuln.get("location"),
                    recommendation=vuln.get("recommendation", "Review and address this issue"),
                    confidence=min(max(vuln.get("confidence", 0.5), 0), 1),
                    cwe_id=vuln.get("cwe_id"),
                ))
            except Exception as e:
                logger.warning(f"Failed to parse vulnerability: {e}")
                continue
        
        return vulnerabilities
    
    def _get_cached_analysis(
        self, 
        address: str, 
        network: str
    ) -> Optional[ContractAnalysisResponse]:
        """Check for cached analysis in database"""
        try:
            with get_db_context() as db:
                record = crud.get_analysis_by_address(db, address, network)
                if record:
                    result_dict = crud.get_analysis_response_from_record(record)
                    if result_dict:
                        # Reconstruct response from cached data
                        return ContractAnalysisResponse(**result_dict)
        except Exception as e:
            logger.warning(f"Cache lookup failed: {e}")
        
        return None
    
    def _store_analysis(
        self, 
        address: str, 
        network: str, 
        response: ContractAnalysisResponse
    ):
        """Store analysis result in database"""
        try:
            with get_db_context() as db:
                crud.create_analysis_record(db, address, network, response)
        except Exception as e:
            logger.error(f"Failed to store analysis: {e}")
    
    def _create_error_response(
        self, 
        address: str, 
        network: str, 
        error_message: str
    ) -> ContractAnalysisResponse:
        """Create an error response"""
        return ContractAnalysisResponse(
            success=False,
            metadata=ContractMetadata(
                address=address,
                network=network,
                is_verified=False,
            ),
            trust_score=TrustScore(
                overall_score=0,
                security_score=0,
                code_quality_score=0,
                verification_score=0,
                risk_level="Unknown",
            ),
            summary=AnalysisSummary(
                total_vulnerabilities=0,
                analysis_method="error",
                llm_insights=f"Analysis failed: {error_message}",
            ),
            vulnerabilities=[],
            recommendations=[f"Error: {error_message}"],
            analysis_timestamp=datetime.utcnow(),
            cached=False,
        )
    
    def _create_exploit_response(
        self, 
        address: str, 
        network: str, 
        exploit_data: Dict
    ) -> ContractAnalysisResponse:
        """Create a response for a known exploited contract"""
        details = exploit_data.get('details', {})
        score = exploit_data.get('score_override', 15)
        severity = exploit_data.get('severity', 'critical')
        sources = exploit_data.get('sources', [])
        confidence = exploit_data.get('confidence', 1.0)
        
        # Format source names
        source_names = [s.get('source', 'Unknown') for s in sources]
        
        # Create vulnerability entry for the exploit
        exploited_vuln = VulnerabilityDetail(
            id="exploit-001",
            name=f"🚨 KNOWN EXPLOIT: {details.get('name', 'Confirmed Exploit')}",
            severity=SeverityEnum.CRITICAL,
            description=f"""This contract has been CONFIRMED as exploited by {len(sources)} security database(s).

Exploit Details:
- Type: {details.get('exploit_type', 'Unknown')}
- Severity: {severity.upper()}
- Amount Lost: {details.get('amount_lost', 'Unknown')}
- Date: {details.get('exploit_date', 'Unknown')}

Description: {details.get('description', 'No additional details available.')}

Sources: {', '.join(source_names)}""",
            location="Contract-wide",
            recommendation="⛔ CRITICAL: DO NOT INTERACT WITH THIS CONTRACT. It has been confirmed as exploited by multiple security databases.",
            confidence=confidence,
            cwe_id="CWE-693",  # Protection Mechanism Failure
        )
        
        return ContractAnalysisResponse(
            success=True,
            metadata=ContractMetadata(
                address=address,
                network=network,
                is_verified=False,
                name=details.get('name', 'Exploited Contract'),
            ),
            trust_score=TrustScore(
                overall_score=score,
                security_score=0,
                code_quality_score=0,
                verification_score=0,
                risk_level="Critical" if score < 30 else "High",
            ),
            summary=AnalysisSummary(
                total_vulnerabilities=1,
                critical_count=1 if severity == 'critical' else 0,
                high_count=1 if severity == 'high' else 0,
                medium_count=1 if severity == 'medium' else 0,
                low_count=0,
                informational_count=0,
                analysis_method="dynamic-exploit-detection",
                llm_insights=f"""🚨 KNOWN EXPLOITED CONTRACT DETECTED

Exploit Information:
- Name: {details.get('name', 'Unknown')}
- Type: {details.get('exploit_type', 'Unknown')}
- Severity: {severity.upper()}
- Amount Lost: {details.get('amount_lost', 'Unknown')}
- Date: {details.get('exploit_date', 'Unknown')}

Detection Details:
- Confidence: {confidence * 100:.0f}%
- Sources: {len(sources)} database(s) flagged this contract
- Detected by: {', '.join(source_names)}

⚠️ WARNING: This contract has been confirmed as exploited by multiple security databases. DO NOT INTERACT under any circumstances.

{details.get('description', '')}""",
            ),
            vulnerabilities=[exploited_vuln],
            recommendations=[
                "⛔ CRITICAL: This contract has been exploited",
                f"💰 Estimated Loss: {details.get('amount_lost', 'Unknown')}",
                f"📅 Exploit Date: {details.get('exploit_date', 'Unknown')}",
                f"🔍 Detected by {len(sources)} source(s): {', '.join(source_names)}",
                "🚨 EXTREME RISK - Use alternative contracts only",
                "If you have approvals for this contract, revoke them immediately",
            ],
            analysis_timestamp=datetime.utcnow(),
            cached=False,
        )


# Singleton instance
analyzer_service = AnalyzerService()
