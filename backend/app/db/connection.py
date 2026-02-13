"""
Database connection and session management for Neon PostgreSQL
"""

from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.sql import func
from contextlib import contextmanager
from typing import Generator
import logging

from app.core.config import get_settings

logger = logging.getLogger(__name__)

# Get settings
settings = get_settings()

# Ensure the DATABASE_URL uses correct driver
database_url = settings.DATABASE_URL

# Configure engine based on database type
if database_url.startswith("sqlite"):
    # SQLite configuration
    engine = create_engine(
        database_url,
        echo=settings.DEBUG,
        connect_args={"check_same_thread": False}  # Allow multiple threads
    )
else:
    # PostgreSQL configuration
    if database_url.startswith("postgresql://"):
        database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    elif database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql+psycopg://", 1)
    
    # Create SQLAlchemy engine with connection pooling optimized for serverless
    engine = create_engine(
        database_url,
        pool_pre_ping=True,  # Verify connections before using
        pool_size=1,  # Reduced for serverless database
        max_overflow=2,  # Reduced for serverless database
        pool_recycle=60,  # Recycle connections after 1 minute
        echo=settings.DEBUG,
        connect_args={
            "connect_timeout": 10,
            "options": "-c timezone=utc"
        }
    )

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()


# ===== Database Models =====

class AnalysisRecord(Base):
    """Stores contract analysis results"""
    __tablename__ = "analysis_records"
    
    id = Column(Integer, primary_key=True, index=True)
    contract_address = Column(String(42), index=True, nullable=False)
    network = Column(String(50), index=True, nullable=False)
    contract_name = Column(String(255), nullable=True)
    is_verified = Column(Boolean, default=False)
    is_proxy = Column(Boolean, default=False)
    implementation_address = Column(String(42), nullable=True)
    
    # Scores
    trust_score = Column(Float, nullable=False)
    security_score = Column(Float, nullable=True)
    code_quality_score = Column(Float, nullable=True)
    
    # Analysis results (JSON stored as text)
    vulnerabilities_json = Column(Text, nullable=True)
    analysis_result_json = Column(Text, nullable=True)
    
    # Metadata
    compiler_version = Column(String(50), nullable=True)
    source_code_hash = Column(String(66), nullable=True)  # keccak256 hash
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class VulnerabilityPattern(Base):
    """Stores known vulnerability patterns for RAG"""
    __tablename__ = "vulnerability_patterns"
    
    id = Column(Integer, primary_key=True, index=True)
    pattern_id = Column(String(50), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False)
    description = Column(Text, nullable=False)
    pattern_code = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=False)
    cwe_id = Column(String(20), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


# ===== Database Session Management =====

def get_db() -> Generator[Session, None, None]:
    """
    Dependency for getting database sessions.
    Use with FastAPI's Depends().
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context() -> Generator[Session, None, None]:
    """
    Context manager for getting database sessions.
    Use in non-FastAPI contexts.
    Returns None if database is not available.
    """
    try:
        db = SessionLocal()
        yield db
        db.commit()
    except Exception as e:
        if 'db' in locals():
            db.rollback()
        logger.debug(f"Database operation skipped (database not available): {e}")
        # Don't raise - app can work without database
    finally:
        if 'db' in locals():
            db.close()


def init_db() -> None:
    """Initialize database tables (optional - app works without database)"""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.warning(f"Failed to create database tables (will continue without database): {e}")
        # Don't raise - app can work without database


def check_db_connection() -> bool:
    """Check if database connection is healthy"""
    try:
        from sqlalchemy import text
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Database connection check failed: {e}")
        return False
