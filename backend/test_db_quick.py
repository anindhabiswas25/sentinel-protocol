"""
Quick database connection test before starting the server
"""
import os
from dotenv import load_dotenv
from pathlib import Path

# Load .env file
env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path, override=True)

# Test database connection
from sqlalchemy import create_engine, text

db_url = os.getenv("DATABASE_URL")
if db_url:
    # Use psycopg driver
    db_url = db_url.replace("postgresql://", "postgresql+psycopg://")
    
    try:
        engine = create_engine(db_url, connect_args={"connect_timeout": 5})
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            print("✅ Database connection test passed!")
    except Exception as e:
        print(f"❌ Database connection test failed: {e}")
        print("⚠️ Server will start with in-memory storage only")
else:
    print("⚠️ No DATABASE_URL found in environment!")
