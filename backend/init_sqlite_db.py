"""
Initialize SQLite database with required tables
"""

import sys
from pathlib import Path

# Add backend directory to path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

from app.db.connection import init_db, check_db_connection
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    """Initialize SQLite database"""
    logger.info("=" * 60)
    logger.info("🗄️  Initializing SQLite Database for Sentinel Protocol")
    logger.info("=" * 60)
    
    # Initialize database tables
    logger.info("\n📋 Creating database tables...")
    init_db()
    
    # Check connection
    logger.info("\n🔍 Checking database connection...")
    if check_db_connection():
        logger.info("✅ Database connection is healthy!")
    else:
        logger.error("❌ Database connection failed!")
        return 1
    
    logger.info("\n" + "=" * 60)
    logger.info("✅ SQLite database initialized successfully!")
    logger.info("=" * 60)
    logger.info(f"\n📍 Database location: {backend_dir / 'sentinel.db'}")
    logger.info("\n🎉 You can now start the backend server!")
    logger.info("   Run: python main.py")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
