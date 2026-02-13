"""
Sentinel Protocol - AI-Powered Smart Contract Auditor
Main FastAPI application entry point
"""

from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
import sys

from app.core.config import get_settings
from app.api.routes import router
from app.db.connection import init_db
from app.services.rag_semantic import rag_service
from app.services.exploit_cache_scheduler import exploit_cache_scheduler  # NEW: Cache scheduler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Get settings
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Handles startup and shutdown events.
    """
    # Startup
    logger.info("🚀 Starting Sentinel Protocol Backend...")
    
    # Initialize database (optional)
    try:
        init_db()
        if check_db_connection():
            logger.info("✅ Database connected and initialized")
        else:
            logger.warning("⚠️  Database not available - continuing without persistence")
    except Exception as e:
        logger.warning(f"⚠️  Database initialization failed - continuing without persistence: {e}")
    
    # Initialize semantic RAG patterns (auto-loaded on first use)
    try:
        pattern_count = rag_service.get_pattern_count()
        logger.info(f"✅ Semantic RAG ready with {pattern_count} patterns")
    except Exception as e:
        logger.error(f"❌ Semantic RAG initialization failed: {e}")
    
    # Start exploit cache scheduler
    try:
        exploit_cache_scheduler.start()
        logger.info("✅ Exploit cache scheduler started")
    except Exception as e:
        logger.error(f"❌ Exploit cache scheduler failed to start: {e}")
    
    logger.info("✅ Sentinel Protocol Backend is ready!")
    
    yield
    
    # Shutdown
    logger.info("👋 Shutting down Sentinel Protocol Backend...")
    
    # Stop exploit cache scheduler
    try:
        exploit_cache_scheduler.stop()
        logger.info("✅ Exploit cache scheduler stopped")
    except Exception as e:
        logger.error(f"❌ Exploit cache scheduler failed to stop: {e}")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    description="""
    ## 🛡️ Sentinel Protocol - AI-Powered Smart Contract Auditor
    
    Sentinel Protocol analyzes smart contracts for security vulnerabilities using 
    AI-powered analysis and provides trust scores to help users make informed decisions.
    
    ### Features:
    - **Verified Contract Analysis**: Full source code analysis for verified contracts
    - **Bytecode Analysis**: Pattern-based analysis for unverified contracts
    - **Multi-Chain Support**: Ethereum, Polygon, Arbitrum, and Base
    - **Trust Scoring**: Comprehensive security scoring system
    - **RAG-Enhanced**: Knowledge base of known vulnerabilities
    
    ### Analysis Pipeline:
    1. Fetch contract data from blockchain
    2. Retrieve verified source code (if available)
    3. Query vulnerability knowledge base
    4. AI-powered security analysis
    5. Calculate trust score
    6. Return detailed findings
    """,
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router, prefix="/api/v1")


# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    """
    Root endpoint - API welcome message.
    """
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "description": "AI-Powered Smart Contract Auditor",
        "docs": "/docs",
        "health": "/api/v1/health",
    }


# Error handlers
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}")
    return {
        "success": False,
        "error": "Internal server error",
        "detail": str(exc) if settings.DEBUG else "An unexpected error occurred",
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info",
    )
