from pathlib import Path
import os
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / '.env'

print(f'BASE_DIR: {BASE_DIR}')
print(f'ENV_FILE: {ENV_FILE}')
print(f'Exists: {ENV_FILE.exists()}')

# Load .env file
load_dotenv(ENV_FILE)

print(f'\nEnvironment Variables:')
print(f'CEREBRAS_API_KEY: {os.getenv("CEREBRAS_API_KEY", "NOT_FOUND")}')
print(f'DATABASE_URL: {os.getenv("DATABASE_URL", "NOT_FOUND")[:50]}...')
print(f'ALCHEMY_API_KEY: {os.getenv("ALCHEMY_API_KEY", "NOT_FOUND")}')
