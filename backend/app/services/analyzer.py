"""
Main analyzer service - orchestrates the contract analysis pipeline
"""

from typing import Optional
from datetime import datetime
import logging
import uuid

from app.services.blockchain import blockchain_service
from app.services.rag import rag_service
from app.services.llm import llm_service
from app.services.scoring import scoring_service
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
        
        # Step 2: Check if it's actually a contract
        if not blockchain_service.is_contract(address, network):
            return self._create_error_response(
                address, network, "Address is not a smart contract (no code deployed)"
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
    ) -> dict:
        """Analyze a verified contract with source code"""
        source_code = source_data.get("source_code", "")
        contract_name = source_data.get("contract_name", "Unknown")
        
        # Get RAG context
        rag_context = rag_service.get_context_for_analysis(source_code)
        
        # Run LLM analysis
        analysis = await llm_service.analyze_source_code(
            source_code=source_code,
            contract_name=contract_name,
            rag_context=rag_context,
        )
        
        analysis["analysis_method"] = "verified_source"
        return analysis
    
    async def _analyze_unverified_contract(
        self,
        bytecode: str,
        bytecode_analysis: dict,
        address: str,
        network: str,
    ) -> dict:
        """Analyze an unverified contract using bytecode"""
        # Run LLM bytecode analysis
        analysis = await llm_service.analyze_bytecode(
            bytecode=bytecode,
            bytecode_analysis=bytecode_analysis,
            contract_address=address,
        )
        
        analysis["analysis_method"] = "bytecode_only"
        return analysis
    
    def _build_response(
        self,
        address: str,
        network: str,
        is_verified: bool,
        source_data: Optional[dict],
        analysis_result: dict,
        bytecode_analysis: dict,
        is_proxy: bool,
        implementation_address: Optional[str],
    ) -> ContractAnalysisResponse:
        """Build the complete analysis response"""
        
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
        
        # Calculate trust score
        trust_score = scoring_service.calculate_trust_score(
            vulnerabilities=[v.model_dump() for v in vulnerabilities],
            code_quality_issues=analysis_result.get("code_quality_issues", []),
            is_verified=is_verified,
            bytecode_analysis=bytecode_analysis if not is_verified else None,
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


# Singleton instance
analyzer_service = AnalyzerService()
