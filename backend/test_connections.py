"""
Test script to verify database connection and LLM functionality
"""

import sys
import os
from pathlib import Path
from dotenv import load_dotenv

# Get the directory of this script
script_dir = Path(__file__).parent

# Load environment variables from .env file in the same directory
env_path = script_dir / ".env"
print(f"Loading .env from: {env_path}")
print(f"File exists: {env_path.exists()}")
load_dotenv(dotenv_path=env_path, override=True)

print("=" * 60)
print("SENTINEL PROTOCOL - CONNECTION TESTS")
print("=" * 60)

# Test 1: Environment Variables
print("\n1️⃣ Testing Environment Variables...")
print("-" * 60)

openrouter_key = os.getenv("OPENROUTER_API_KEY")
alchemy_key = os.getenv("ALCHEMY_API_KEY")
database_url = os.getenv("DATABASE_URL")

print(f"✓ OPENROUTER_API_KEY: {'Set ✅' if openrouter_key else 'Missing ❌'}")
print(f"✓ ALCHEMY_API_KEY: {'Set ✅' if alchemy_key else 'Missing ❌'}")
print(f"✓ DATABASE_URL: {'Set ✅' if database_url else 'Missing ❌'}")

if openrouter_key:
    print(f"  - Key preview: {openrouter_key[:15]}...{openrouter_key[-10:]}")

# Test 2: Database Connection
print("\n2️⃣ Testing Database Connection...")
print("-" * 60)

try:
    from sqlalchemy import create_engine, text
    from sqlalchemy.pool import NullPool
    
    # Use psycopg (version 3) instead of psycopg2
    # Replace postgresql:// with postgresql+psycopg://
    db_url = database_url.replace("postgresql://", "postgresql+psycopg://")
    
    # Create engine with connection timeout
    engine = create_engine(
        db_url,
        poolclass=NullPool,
        connect_args={
            "connect_timeout": 10,
        }
    )
    
    # Test connection
    with engine.connect() as conn:
        result = conn.execute(text("SELECT version();"))
        version = result.fetchone()[0]
        print(f"✅ Database Connected Successfully!")
        print(f"   PostgreSQL Version: {version[:50]}...")
        
        # Test table creation permissions
        result = conn.execute(text("SELECT current_database(), current_user;"))
        db_info = result.fetchone()
        print(f"   Database: {db_info[0]}")
        print(f"   User: {db_info[1]}")
        
except Exception as e:
    print(f"❌ Database Connection Failed!")
    print(f"   Error: {str(e)[:200]}")
    print(f"\n   Troubleshooting:")
    print(f"   - Check if the password is correct")
    print(f"   - Verify the hostname includes '.c-4' component")
    print(f"   - Ensure Neon database is not suspended")

# Test 3: LLM Connection (OpenRouter)
print("\n3️⃣ Testing LLM Connection (OpenRouter)...")
print("-" * 60)

try:
    from openai import OpenAI
    
    client = OpenAI(
        api_key=openrouter_key,
        base_url="https://openrouter.ai/api/v1"
    )
    
    # Test with a simple prompt
    response = client.chat.completions.create(
        model="anthropic/claude-3.5-sonnet",
        messages=[
            {"role": "user", "content": "Say OK"}
        ],
        max_tokens=5
    )
    
    result = response.choices[0].message.content
    print(f"✅ LLM Connected Successfully!")
    print(f"   Model: anthropic/claude-3.5-sonnet")
    print(f"   Response: {result}")
    print(f"   Tokens used: {response.usage.total_tokens}")
    
except Exception as e:
    print(f"❌ LLM Connection Failed!")
    print(f"   Error: {str(e)[:200]}")
    print(f"\n   Troubleshooting:")
    print(f"   - Check if OpenRouter API key is valid")
    print(f"   - Verify you have credits in your OpenRouter account")
    print(f"   - Check internet connection")

# Test 4: Blockchain RPC (Alchemy)
print("\n4️⃣ Testing Blockchain RPC (Alchemy)...")
print("-" * 60)

try:
    from web3 import Web3
    
    # Test Ethereum mainnet
    eth_rpc = f"https://eth-mainnet.g.alchemy.com/v2/{alchemy_key}"
    w3 = Web3(Web3.HTTPProvider(eth_rpc))
    
    if w3.is_connected():
        block_number = w3.eth.block_number
        print(f"✅ Ethereum RPC Connected!")
        print(f"   Latest Block: {block_number}")
        print(f"   Chain ID: {w3.eth.chain_id}")
    else:
        print(f"❌ Ethereum RPC Connection Failed!")
        
except Exception as e:
    print(f"❌ Blockchain RPC Failed!")
    print(f"   Error: {str(e)[:200]}")

print("\n" + "=" * 60)
print("TEST SUMMARY")
print("=" * 60)
print("Review the results above to identify any connection issues.")
print("=" * 60)
