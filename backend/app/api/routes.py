"""
API routes for Sentinel Protocol
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import Optional
import logging

from app.models.schemas import (
    ContractAnalysisRequest,
    ContractAnalysisResponse,
    SourceCodeAnalysisRequest,
    HealthResponse,
    ErrorResponse,
    NetworkEnum,
)
from app.services.analyzer import analyzer_service
from app.services.blockchain import blockchain_service
from app.services.rag import rag_service, seed_default_patterns
from app.services.llm import llm_service
from app.services.scoring import scoring_service
from app.db.connection import get_db, check_db_connection
from app.db import crud
from app.core.config import get_settings, SUPPORTED_NETWORKS

logger = logging.getLogger(__name__)
settings = get_settings()

# Create router
router = APIRouter()


# ===== Health & Info Endpoints =====

@router.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """
    Health check endpoint to verify all services are operational.
    """
    return HealthResponse(
        status="healthy",
        version=settings.APP_VERSION,
        database="connected" if check_db_connection() else "disconnected",
        vector_db="connected" if rag_service.check_health() else "disconnected",
        blockchain="connected" if blockchain_service.check_connection() else "disconnected",
    )


@router.get("/info", tags=["Health"])
async def get_info():
    """
    Get API information and supported networks.
    """
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "supported_networks": list(SUPPORTED_NETWORKS.keys()),
        "vulnerability_patterns_count": rag_service.get_pattern_count(),
    }


# ===== Contract Analysis Endpoints =====

@router.post(
    "/analyze",
    response_model=ContractAnalysisResponse,
    responses={
        400: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
    tags=["Analysis"],
    summary="Analyze a smart contract",
    description="Analyze a deployed smart contract for security vulnerabilities and calculate trust score.",
)
async def analyze_contract(request: ContractAnalysisRequest):
    """
    Analyze a smart contract by address.
    
    This endpoint:
    1. Fetches contract data from the blockchain
    2. Attempts to retrieve verified source code
    3. Performs AI-powered security analysis
    4. Returns vulnerability findings and trust score
    
    For verified contracts, full source code analysis is performed.
    For unverified contracts, bytecode pattern analysis provides limited insights.
    """
    try:
        result = await analyzer_service.analyze_contract(request)
        return result
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get(
    "/analyze/{network}/{address}",
    response_model=ContractAnalysisResponse,
    tags=["Analysis"],
    summary="Analyze contract by URL params",
)
async def analyze_contract_by_params(
    network: NetworkEnum,
    address: str,
    force_refresh: bool = Query(False, description="Force re-analysis"),
):
    """
    Convenience endpoint for analyzing contracts via URL path parameters.
    """
    request = ContractAnalysisRequest(
        contract_address=address,
        network=network,
        force_refresh=force_refresh,
    )
    return await analyze_contract(request)


@router.post(
    "/analyze/source",
    response_model=ContractAnalysisResponse,
    tags=["Analysis"],
    summary="Analyze source code directly",
)
async def analyze_source_code(request: SourceCodeAnalysisRequest):
    """
    Analyze Solidity source code directly without a deployed contract.
    
    Useful for:
    - Pre-deployment audits
    - Analyzing code before deploying
    - Testing vulnerability detection
    """
    try:
        from app.services.rag import rag_service
        from app.services.llm import llm_service
        from app.services.scoring import scoring_service
        from app.models.schemas import (
            ContractMetadata, TrustScore, AnalysisSummary, VulnerabilityDetail, SeverityEnum
        )
        from datetime import datetime
        
        # Get RAG context
        rag_context = rag_service.get_context_for_analysis(request.source_code)
        
        # Run LLM analysis
        analysis = await llm_service.analyze_source_code(
            source_code=request.source_code,
            contract_name=request.contract_name or "DirectAnalysis",
            rag_context=rag_context,
        )
        
        # Parse vulnerabilities
        vulnerabilities = []
        for i, vuln in enumerate(analysis.get("vulnerabilities", [])):
            severity_str = vuln.get("severity", "informational").lower()
            severity_map = {
                "critical": SeverityEnum.CRITICAL,
                "high": SeverityEnum.HIGH,
                "medium": SeverityEnum.MEDIUM,
                "low": SeverityEnum.LOW,
                "informational": SeverityEnum.INFORMATIONAL,
            }
            vulnerabilities.append(VulnerabilityDetail(
                id=vuln.get("id", f"vuln-{i+1}"),
                name=vuln.get("name", "Unknown"),
                severity=severity_map.get(severity_str, SeverityEnum.INFORMATIONAL),
                description=vuln.get("description", ""),
                location=vuln.get("location"),
                recommendation=vuln.get("recommendation", ""),
                confidence=vuln.get("confidence", 0.5),
                cwe_id=vuln.get("cwe_id"),
            ))
        
        # Calculate trust score
        trust_score = scoring_service.calculate_trust_score(
            vulnerabilities=[v.model_dump() for v in vulnerabilities],
            code_quality_issues=analysis.get("code_quality_issues", []),
            is_verified=True,
        )
        
        # Get severity breakdown
        breakdown = scoring_service.get_severity_breakdown([v.model_dump() for v in vulnerabilities])
        
        return ContractAnalysisResponse(
            success=True,
            metadata=ContractMetadata(
                address="0x0000000000000000000000000000000000000000",
                network="none",
                name=request.contract_name,
                is_verified=True,
            ),
            trust_score=trust_score,
            summary=AnalysisSummary(
                total_vulnerabilities=len(vulnerabilities),
                critical_count=breakdown["critical"],
                high_count=breakdown["high"],
                medium_count=breakdown["medium"],
                low_count=breakdown["low"],
                informational_count=breakdown["informational"],
                analysis_method="direct_source",
                llm_insights=analysis.get("summary", "Analysis completed."),
            ),
            vulnerabilities=vulnerabilities,
            recommendations=analysis.get("recommendations", []),
            analysis_timestamp=datetime.utcnow(),
            cached=False,
        )
        
    except Exception as e:
        logger.error(f"Source analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ===== History & Stats Endpoints =====

@router.get("/history", tags=["History"])
async def get_analysis_history(
    limit: int = Query(10, ge=1, le=100),
    network: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """
    Get recent analysis history.
    """
    records = crud.get_recent_analyses(db, limit=limit, network=network)
    return {
        "count": len(records),
        "analyses": [
            {
                "id": r.id,
                "contract_address": r.contract_address,
                "network": r.network,
                "contract_name": r.contract_name,
                "is_verified": r.is_verified,
                "trust_score": r.trust_score,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in records
        ]
    }


@router.get("/stats", tags=["Stats"])
async def get_stats(db: Session = Depends(get_db)):
    """
    Get analysis statistics.
    """
    return crud.get_analysis_stats(db)


# ===== Utility Endpoints =====

@router.get("/networks", tags=["Utilities"])
async def get_supported_networks():
    """
    Get list of supported blockchain networks.
    """
    return {
        "networks": [
            {
                "id": network_id,
                "name": config["name"],
                "chain_id": config["chain_id"],
                "explorer": config["explorer"],
            }
            for network_id, config in SUPPORTED_NETWORKS.items()
        ]
    }


@router.get("/validate/{address}", tags=["Utilities"])
async def validate_address(
    address: str,
    network: NetworkEnum = Query(NetworkEnum.ETHEREUM),
):
    """
    Validate an address and check if it's a contract.
    """
    is_valid = blockchain_service.is_valid_address(address)
    is_contract = False
    
    if is_valid:
        is_contract = blockchain_service.is_contract(address, network.value)
    
    return {
        "address": address,
        "is_valid": is_valid,
        "is_contract": is_contract,
        "network": network.value,
    }


@router.post("/seed-patterns", tags=["Admin"])
async def seed_vulnerability_patterns():
    """
    Seed the vector database with default vulnerability patterns.
    This should be called once during initial setup.
    """
    try:
        count = seed_default_patterns()
        return {
            "success": True,
            "patterns_added": count,
            "total_patterns": rag_service.get_pattern_count(),
        }
    except Exception as e:
        logger.error(f"Failed to seed patterns: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/score-breakdown/{address}", tags=["Analysis"])
async def get_score_breakdown(
    address: str,
    network: NetworkEnum = Query(NetworkEnum.ETHEREUM),
    db: Session = Depends(get_db),
):
    """
    Get detailed trust score breakdown for a previously analyzed contract.
    """
    record = crud.get_analysis_by_address(db, address.lower(), network.value)
    
    if not record:
        raise HTTPException(status_code=404, detail="Analysis not found. Please analyze the contract first.")
    
    return {
        "contract_address": address,
        "network": network.value,
        "trust_score": record.trust_score,
        "security_score": record.security_score,
        "code_quality_score": record.code_quality_score,
        "is_verified": record.is_verified,
        "display": scoring_service.format_score_display(
            scoring_service.calculate_trust_score(
                vulnerabilities=[],  # Simplified for display
                is_verified=record.is_verified,
            )
        ),
    }
