"""
Configuration settings for Sentinel Protocol Backend
"""

from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # API Settings
    APP_NAME: str = "Sentinel Protocol"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Server Settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Database (Neon PostgreSQL)
    DATABASE_URL: str
    
    # Vector Database (ChromaDB)
    CHROMA_PERSIST_DIR: str = "./data/chromadb"
    CHROMA_COLLECTION_NAME: str = "vulnerabilities"
    
    # Blockchain (Alchemy)
    ALCHEMY_API_KEY: str
    
    # Supported Networks
    ETHEREUM_RPC: str = ""
    POLYGON_RPC: str = ""
    ARBITRUM_RPC: str = ""
    BASE_RPC: str = ""
    
    # LLM (Groq)
    GROQ_API_KEY: str
    LLM_MODEL: str = "llama-3.3-70b-versatile"
    LLM_MAX_TOKENS: int = 4096
    LLM_TEMPERATURE: float = 0.1
    
    # Etherscan API Keys (optional, for verified contracts)
    ETHERSCAN_API_KEY: Optional[str] = None
    POLYGONSCAN_API_KEY: Optional[str] = None
    ARBISCAN_API_KEY: Optional[str] = None
    BASESCAN_API_KEY: Optional[str] = None
    
    # CORS Settings
    CORS_ORIGINS: list = ["*"]
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60  # seconds
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Build RPC URLs from Alchemy API key
        if self.ALCHEMY_API_KEY:
            self.ETHEREUM_RPC = f"https://eth-mainnet.g.alchemy.com/v2/{self.ALCHEMY_API_KEY}"
            self.POLYGON_RPC = f"https://polygon-mainnet.g.alchemy.com/v2/{self.ALCHEMY_API_KEY}"
            self.ARBITRUM_RPC = f"https://arb-mainnet.g.alchemy.com/v2/{self.ALCHEMY_API_KEY}"
            self.BASE_RPC = f"https://base-mainnet.g.alchemy.com/v2/{self.ALCHEMY_API_KEY}"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()


# Network configuration
SUPPORTED_NETWORKS = {
    "ethereum": {
        "name": "Ethereum Mainnet",
        "chain_id": 1,
        "explorer": "https://etherscan.io",
        "explorer_api": "https://api.etherscan.io/api",
    },
    "polygon": {
        "name": "Polygon Mainnet",
        "chain_id": 137,
        "explorer": "https://polygonscan.com",
        "explorer_api": "https://api.polygonscan.com/api",
    },
    "arbitrum": {
        "name": "Arbitrum One",
        "chain_id": 42161,
        "explorer": "https://arbiscan.io",
        "explorer_api": "https://api.arbiscan.io/api",
    },
    "base": {
        "name": "Base Mainnet",
        "chain_id": 8453,
        "explorer": "https://basescan.org",
        "explorer_api": "https://api.basescan.org/api",
    },
}

# Vulnerability severity levels
SEVERITY_LEVELS = {
    "critical": {"score": 10, "color": "#FF0000"},
    "high": {"score": 8, "color": "#FF6600"},
    "medium": {"score": 5, "color": "#FFCC00"},
    "low": {"score": 2, "color": "#00CC00"},
    "informational": {"score": 1, "color": "#0066FF"},
}
