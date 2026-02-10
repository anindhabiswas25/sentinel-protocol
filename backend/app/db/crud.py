"""
CRUD operations for database models
"""

from sqlalchemy.orm import Session
from sqlalchemy import and_
from typing import Optional, List
from datetime import datetime, timedelta
import json
import logging

from app.db.connection import AnalysisRecord, VulnerabilityPattern
from app.models.schemas import ContractAnalysisResponse

logger = logging.getLogger(__name__)


# ===== Analysis Records CRUD =====

def get_analysis_by_address(
    db: Session, 
    contract_address: str, 
    network: str,
    max_age_hours: int = 24
) -> Optional[AnalysisRecord]:
    """
    Get cached analysis for a contract if it exists and is not too old.
    
    Args:
        db: Database session
        contract_address: Contract address (lowercase)
        network: Network name
        max_age_hours: Maximum age of cached result in hours
    
    Returns:
        AnalysisRecord if found and fresh, None otherwise
    """
    cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
    
    return db.query(AnalysisRecord).filter(
        and_(
            AnalysisRecord.contract_address == contract_address.lower(),
            AnalysisRecord.network == network,
            AnalysisRecord.created_at >= cutoff_time
        )
    ).order_by(AnalysisRecord.created_at.desc()).first()


def create_analysis_record(
    db: Session,
    contract_address: str,
    network: str,
    analysis_response: ContractAnalysisResponse
) -> AnalysisRecord:
    """
    Create a new analysis record in the database.
    
    Args:
        db: Database session
        contract_address: Contract address
        network: Network name
        analysis_response: Full analysis response
    
    Returns:
        Created AnalysisRecord
    """
    # Convert vulnerabilities to JSON
    vulnerabilities_json = json.dumps([v.model_dump() for v in analysis_response.vulnerabilities], default=str)
    
    # Convert full response to JSON
    analysis_result_json = json.dumps(analysis_response.model_dump(), default=str)
    
    record = AnalysisRecord(
        contract_address=contract_address.lower(),
        network=network,
        contract_name=analysis_response.metadata.name,
        is_verified=analysis_response.metadata.is_verified,
        is_proxy=analysis_response.metadata.is_proxy,
        implementation_address=analysis_response.metadata.implementation_address,
        trust_score=analysis_response.trust_score.overall_score,
        security_score=analysis_response.trust_score.security_score,
        code_quality_score=analysis_response.trust_score.code_quality_score,
        vulnerabilities_json=vulnerabilities_json,
        analysis_result_json=analysis_result_json,
        compiler_version=analysis_response.metadata.compiler_version,
    )
    
    db.add(record)
    db.commit()
    db.refresh(record)
    
    logger.info(f"Created analysis record for {contract_address} on {network}")
    return record


def get_analysis_response_from_record(record: AnalysisRecord) -> Optional[dict]:
    """
    Reconstruct analysis response from database record.
    
    Args:
        record: Database record
    
    Returns:
        Analysis response dict if valid, None otherwise
    """
    if record and record.analysis_result_json:
        try:
            result = json.loads(record.analysis_result_json)
            result['cached'] = True
            return result
        except json.JSONDecodeError:
            logger.error(f"Failed to parse analysis JSON for record {record.id}")
    return None


def get_recent_analyses(
    db: Session,
    limit: int = 10,
    network: Optional[str] = None
) -> List[AnalysisRecord]:
    """
    Get recent analysis records.
    
    Args:
        db: Database session
        limit: Maximum number of records
        network: Optional network filter
    
    Returns:
        List of recent AnalysisRecords
    """
    query = db.query(AnalysisRecord)
    
    if network:
        query = query.filter(AnalysisRecord.network == network)
    
    return query.order_by(AnalysisRecord.created_at.desc()).limit(limit).all()


def get_analysis_stats(db: Session) -> dict:
    """
    Get statistics about analyses performed.
    
    Returns:
        Dictionary with analysis statistics
    """
    from sqlalchemy import func
    
    total = db.query(func.count(AnalysisRecord.id)).scalar()
    verified = db.query(func.count(AnalysisRecord.id)).filter(
        AnalysisRecord.is_verified == True
    ).scalar()
    avg_score = db.query(func.avg(AnalysisRecord.trust_score)).scalar()
    
    return {
        "total_analyses": total or 0,
        "verified_contracts": verified or 0,
        "unverified_contracts": (total or 0) - (verified or 0),
        "average_trust_score": round(avg_score or 0, 2),
    }


# ===== Vulnerability Patterns CRUD =====

def get_all_vulnerability_patterns(db: Session) -> List[VulnerabilityPattern]:
    """Get all vulnerability patterns"""
    return db.query(VulnerabilityPattern).all()


def get_vulnerability_pattern_by_id(db: Session, pattern_id: str) -> Optional[VulnerabilityPattern]:
    """Get vulnerability pattern by ID"""
    return db.query(VulnerabilityPattern).filter(
        VulnerabilityPattern.pattern_id == pattern_id
    ).first()


def create_vulnerability_pattern(
    db: Session,
    pattern_id: str,
    name: str,
    severity: str,
    description: str,
    recommendation: str,
    pattern_code: Optional[str] = None,
    cwe_id: Optional[str] = None
) -> VulnerabilityPattern:
    """Create a new vulnerability pattern"""
    pattern = VulnerabilityPattern(
        pattern_id=pattern_id,
        name=name,
        severity=severity,
        description=description,
        pattern_code=pattern_code,
        recommendation=recommendation,
        cwe_id=cwe_id,
    )
    
    db.add(pattern)
    db.commit()
    db.refresh(pattern)
    
    return pattern


def bulk_create_vulnerability_patterns(
    db: Session,
    patterns: List[dict]
) -> int:
    """
    Bulk create vulnerability patterns.
    
    Args:
        db: Database session
        patterns: List of pattern dictionaries
    
    Returns:
        Number of patterns created
    """
    count = 0
    for pattern_data in patterns:
        existing = get_vulnerability_pattern_by_id(db, pattern_data.get("pattern_id", ""))
        if not existing:
            pattern = VulnerabilityPattern(**pattern_data)
            db.add(pattern)
            count += 1
    
    db.commit()
    logger.info(f"Created {count} vulnerability patterns")
    return count
