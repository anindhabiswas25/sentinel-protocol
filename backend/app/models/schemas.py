"""
Pydantic schemas for API request/response models
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime


class NetworkEnum(str, Enum):
    """Supported blockchain networks"""
    ETHEREUM = "ethereum"
    POLYGON = "polygon"
    ARBITRUM = "arbitrum"
    BASE = "base"


class SeverityEnum(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


# ===== Request Schemas =====

class ContractAnalysisRequest(BaseModel):
    """Request model for contract analysis"""
    contract_address: str = Field(..., description="Contract address to analyze")
    network: NetworkEnum = Field(default=NetworkEnum.ETHEREUM, description="Blockchain network")
    force_refresh: bool = Field(default=False, description="Force re-analysis even if cached")


class SourceCodeAnalysisRequest(BaseModel):
    """Request model for direct source code analysis"""
    source_code: str = Field(..., description="Solidity source code to analyze")
    contract_name: Optional[str] = Field(default=None, description="Name of the contract")


# ===== Response Schemas =====

class VulnerabilityDetail(BaseModel):
    """Individual vulnerability details"""
    id: str = Field(..., description="Unique vulnerability identifier")
    name: str = Field(..., description="Vulnerability name")
    severity: SeverityEnum = Field(..., description="Severity level")
    description: str = Field(..., description="Detailed description")
    location: Optional[str] = Field(default=None, description="Code location if available")
    recommendation: str = Field(..., description="Remediation recommendation")
    confidence: float = Field(..., ge=0, le=1, description="Detection confidence score")
    cwe_id: Optional[str] = Field(default=None, description="CWE identifier if applicable")


class TrustScore(BaseModel):
    """Trust score breakdown"""
    overall_score: float = Field(..., ge=0, le=100, description="Overall trust score (0-100)")
    security_score: float = Field(..., ge=0, le=100, description="Security assessment score")
    code_quality_score: float = Field(..., ge=0, le=100, description="Code quality score")
    verification_score: float = Field(..., ge=0, le=100, description="Verification status score")
    risk_level: str = Field(..., description="Risk level classification")
    
    class Config:
        json_schema_extra = {
            "example": {
                "overall_score": 75.5,
                "security_score": 70.0,
                "code_quality_score": 80.0,
                "verification_score": 100.0,
                "risk_level": "Medium"
            }
        }


class ContractMetadata(BaseModel):
    """Contract metadata information"""
    address: str = Field(..., description="Contract address")
    network: str = Field(..., description="Blockchain network")
    name: Optional[str] = Field(default=None, description="Contract name")
    compiler_version: Optional[str] = Field(default=None, description="Solidity compiler version")
    is_verified: bool = Field(..., description="Whether source code is verified")
    creation_date: Optional[datetime] = Field(default=None, description="Contract creation date")
    creator_address: Optional[str] = Field(default=None, description="Contract creator address")
    is_proxy: bool = Field(default=False, description="Whether contract is a proxy")
    implementation_address: Optional[str] = Field(default=None, description="Implementation address if proxy")


class AnalysisSummary(BaseModel):
    """Summary of the analysis"""
    total_vulnerabilities: int = Field(..., description="Total vulnerabilities found")
    critical_count: int = Field(default=0, description="Critical severity count")
    high_count: int = Field(default=0, description="High severity count")
    medium_count: int = Field(default=0, description="Medium severity count")
    low_count: int = Field(default=0, description="Low severity count")
    informational_count: int = Field(default=0, description="Informational severity count")
    analysis_method: str = Field(..., description="Method used for analysis (verified/bytecode)")
    llm_insights: str = Field(..., description="AI-generated insights summary")


class ContractAnalysisResponse(BaseModel):
    """Full contract analysis response"""
    success: bool = Field(..., description="Whether analysis completed successfully")
    metadata: ContractMetadata = Field(..., description="Contract metadata")
    trust_score: TrustScore = Field(..., description="Trust score breakdown")
    summary: AnalysisSummary = Field(..., description="Analysis summary")
    vulnerabilities: List[VulnerabilityDetail] = Field(default=[], description="List of vulnerabilities")
    recommendations: List[str] = Field(default=[], description="General recommendations")
    analysis_timestamp: datetime = Field(..., description="When analysis was performed")
    cached: bool = Field(default=False, description="Whether result was from cache")
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "metadata": {
                    "address": "0x1234...",
                    "network": "ethereum",
                    "name": "MyToken",
                    "is_verified": True,
                    "is_proxy": False
                },
                "trust_score": {
                    "overall_score": 75.5,
                    "security_score": 70.0,
                    "code_quality_score": 80.0,
                    "verification_score": 100.0,
                    "risk_level": "Medium"
                },
                "summary": {
                    "total_vulnerabilities": 3,
                    "critical_count": 0,
                    "high_count": 1,
                    "medium_count": 2,
                    "low_count": 0,
                    "informational_count": 0,
                    "analysis_method": "verified_source",
                    "llm_insights": "The contract has some security concerns..."
                },
                "vulnerabilities": [],
                "recommendations": ["Consider implementing access controls"],
                "analysis_timestamp": "2024-01-15T10:30:00Z",
                "cached": False
            }
        }


class HealthResponse(BaseModel):
    """Health check response"""
    status: str = Field(..., description="Service status")
    version: str = Field(..., description="API version")
    database: str = Field(..., description="Database connection status")
    vector_db: str = Field(..., description="Vector database status")
    blockchain: str = Field(..., description="Blockchain connection status")


class ErrorResponse(BaseModel):
    """Error response model"""
    success: bool = Field(default=False)
    error: str = Field(..., description="Error message")
    error_code: Optional[str] = Field(default=None, description="Error code")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Additional error details")


# ===== Database Models (for SQLAlchemy) =====

class AnalysisRecordCreate(BaseModel):
    """Schema for creating analysis record in database"""
    contract_address: str
    network: str
    is_verified: bool
    trust_score: float
    vulnerabilities_json: str
    analysis_result_json: str


class AnalysisRecordResponse(BaseModel):
    """Schema for analysis record from database"""
    id: int
    contract_address: str
    network: str
    is_verified: bool
    trust_score: float
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True
