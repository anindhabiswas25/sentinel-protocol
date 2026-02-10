"""
Blockchain service for interacting with smart contracts via Alchemy RPC
"""

from web3 import Web3
from web3.exceptions import ContractLogicError
import httpx
from typing import Optional, Dict, Any, Tuple
import logging
import re

from app.core.config import get_settings, SUPPORTED_NETWORKS

logger = logging.getLogger(__name__)
settings = get_settings()


class BlockchainService:
    """Service for blockchain interactions using Alchemy"""
    
    def __init__(self):
        self.networks = self._initialize_networks()
        self.etherscan_keys = {
            "ethereum": settings.ETHERSCAN_API_KEY,
            "polygon": settings.POLYGONSCAN_API_KEY,
            "arbitrum": settings.ARBISCAN_API_KEY,
            "base": settings.BASESCAN_API_KEY,
        }
    
    def _initialize_networks(self) -> Dict[str, Web3]:
        """Initialize Web3 connections for all supported networks"""
        networks = {}
        
        rpc_urls = {
            "ethereum": settings.ETHEREUM_RPC,
            "polygon": settings.POLYGON_RPC,
            "arbitrum": settings.ARBITRUM_RPC,
            "base": settings.BASE_RPC,
        }
        
        for network, rpc_url in rpc_urls.items():
            if rpc_url:
                try:
                    w3 = Web3(Web3.HTTPProvider(rpc_url))
                    if w3.is_connected():
                        networks[network] = w3
                        logger.info(f"Connected to {network}")
                    else:
                        logger.warning(f"Failed to connect to {network}")
                except Exception as e:
                    logger.error(f"Error connecting to {network}: {e}")
        
        return networks
    
    def get_web3(self, network: str) -> Optional[Web3]:
        """Get Web3 instance for a network"""
        return self.networks.get(network)
    
    def is_valid_address(self, address: str) -> bool:
        """Check if address is a valid Ethereum address"""
        return Web3.is_address(address)
    
    def is_contract(self, address: str, network: str = "ethereum") -> bool:
        """Check if address is a contract (has code)"""
        w3 = self.get_web3(network)
        if not w3:
            return False
        
        try:
            checksum_address = Web3.to_checksum_address(address)
            code = w3.eth.get_code(checksum_address)
            return len(code) > 2  # "0x" is returned for EOA
        except Exception as e:
            logger.error(f"Error checking if contract: {e}")
            return False
    
    def get_bytecode(self, address: str, network: str = "ethereum") -> Optional[str]:
        """Get deployed bytecode of a contract"""
        w3 = self.get_web3(network)
        if not w3:
            return None
        
        try:
            checksum_address = Web3.to_checksum_address(address)
            bytecode = w3.eth.get_code(checksum_address)
            return bytecode.hex() if bytecode else None
        except Exception as e:
            logger.error(f"Error getting bytecode: {e}")
            return None
    
    async def get_verified_source_code(
        self, 
        address: str, 
        network: str = "ethereum"
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Fetch verified source code from block explorer (Etherscan, etc.)
        
        Returns:
            Tuple of (is_verified, source_data)
        """
        network_config = SUPPORTED_NETWORKS.get(network)
        if not network_config:
            return False, None
        
        api_url = network_config["explorer_api"]
        api_key = self.etherscan_keys.get(network)
        
        # Build API request
        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
        }
        
        if api_key:
            params["apikey"] = api_key
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(api_url, params=params, timeout=30.0)
                data = response.json()
                
                if data.get("status") == "1" and data.get("result"):
                    result = data["result"][0]
                    
                    # Check if source code is available
                    source_code = result.get("SourceCode", "")
                    if source_code and source_code != "":
                        return True, {
                            "source_code": self._parse_source_code(source_code),
                            "contract_name": result.get("ContractName", "Unknown"),
                            "compiler_version": result.get("CompilerVersion", ""),
                            "optimization_used": result.get("OptimizationUsed", "0") == "1",
                            "runs": int(result.get("Runs", 200)),
                            "constructor_arguments": result.get("ConstructorArguments", ""),
                            "abi": result.get("ABI", "[]"),
                            "implementation": result.get("Implementation", ""),
                            "proxy": result.get("Proxy", "0") == "1",
                        }
                
                return False, None
                
        except Exception as e:
            logger.error(f"Error fetching verified source: {e}")
            return False, None
    
    def _parse_source_code(self, source_code: str) -> str:
        """Parse source code, handling multi-file contracts"""
        # Check if it's a JSON formatted multi-file source
        if source_code.startswith("{{"):
            try:
                import json
                # Remove extra braces
                json_str = source_code[1:-1]
                sources = json.loads(json_str)
                
                # Combine all source files
                combined = []
                if isinstance(sources, dict) and "sources" in sources:
                    for filename, content in sources["sources"].items():
                        combined.append(f"// File: {filename}")
                        combined.append(content.get("content", ""))
                else:
                    for filename, content in sources.items():
                        combined.append(f"// File: {filename}")
                        if isinstance(content, dict):
                            combined.append(content.get("content", ""))
                        else:
                            combined.append(str(content))
                
                return "\n\n".join(combined)
            except:
                pass
        
        return source_code
    
    def detect_proxy(self, bytecode: str) -> Tuple[bool, Optional[str]]:
        """
        Detect if contract is a proxy and try to find implementation address.
        
        Common proxy patterns:
        - EIP-1967: Implementation slot at 0x360894...
        - OpenZeppelin Transparent Proxy
        - UUPS Proxy
        """
        if not bytecode:
            return False, None
        
        # Common proxy patterns in bytecode
        proxy_patterns = [
            # DELEGATECALL pattern
            r"f4",  # DELEGATECALL opcode
            # EIP-1967 implementation slot
            r"360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
        ]
        
        for pattern in proxy_patterns:
            if pattern.lower() in bytecode.lower():
                # Try to extract implementation address
                # This is simplified - real implementation would need storage reading
                return True, None
        
        return False, None
    
    async def get_implementation_address(
        self, 
        proxy_address: str, 
        network: str = "ethereum"
    ) -> Optional[str]:
        """Get implementation address for a proxy contract"""
        w3 = self.get_web3(network)
        if not w3:
            return None
        
        try:
            checksum_address = Web3.to_checksum_address(proxy_address)
            
            # EIP-1967 implementation slot
            implementation_slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
            
            storage = w3.eth.get_storage_at(checksum_address, implementation_slot)
            
            if storage and storage != bytes(32):
                # Extract address from storage (last 20 bytes)
                impl_address = "0x" + storage.hex()[-40:]
                if self.is_valid_address(impl_address) and impl_address != "0x" + "0" * 40:
                    return Web3.to_checksum_address(impl_address)
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting implementation address: {e}")
            return None
    
    def analyze_bytecode_patterns(self, bytecode: str) -> Dict[str, Any]:
        """
        Analyze bytecode for common patterns and potential issues.
        This is used for non-verified contracts.
        """
        if not bytecode or bytecode == "0x":
            return {"error": "No bytecode found"}
        
        analysis = {
            "size": len(bytecode) // 2,  # Bytes
            "has_selfdestruct": False,
            "has_delegatecall": False,
            "has_create": False,
            "has_create2": False,
            "external_calls": 0,
            "potential_issues": [],
        }
        
        bytecode_lower = bytecode.lower()
        
        # Check for dangerous opcodes
        if "ff" in bytecode_lower:  # SELFDESTRUCT
            analysis["has_selfdestruct"] = True
            analysis["potential_issues"].append({
                "type": "selfdestruct",
                "severity": "high",
                "description": "Contract contains SELFDESTRUCT opcode"
            })
        
        if "f4" in bytecode_lower:  # DELEGATECALL
            analysis["has_delegatecall"] = True
            analysis["potential_issues"].append({
                "type": "delegatecall",
                "severity": "medium",
                "description": "Contract uses DELEGATECALL - verify it's intentional"
            })
        
        if "f0" in bytecode_lower:  # CREATE
            analysis["has_create"] = True
        
        if "f5" in bytecode_lower:  # CREATE2
            analysis["has_create2"] = True
        
        # Count external calls (CALL opcode = f1)
        analysis["external_calls"] = bytecode_lower.count("f1")
        
        return analysis
    
    def check_connection(self, network: str = "ethereum") -> bool:
        """Check if connection to network is healthy"""
        w3 = self.get_web3(network)
        if not w3:
            return False
        
        try:
            return w3.is_connected()
        except:
            return False

    def detect_network(self, address: str) -> list[dict]:
        """
        Check all connected networks to find which ones contain
        a contract at the given address.

        Returns a list of dicts: [{"network": "ethereum", "is_contract": True}, ...]
        Only networks where the address holds contract code are included.
        """
        if not self.is_valid_address(address):
            return []

        results: list[dict] = []
        checksum = Web3.to_checksum_address(address)

        for network, w3 in self.networks.items():
            try:
                code = w3.eth.get_code(checksum)
                if len(code) > 2:  # not just "0x"
                    results.append({"network": network, "is_contract": True})
            except Exception as e:
                logger.debug(f"detect_network: {network} lookup failed: {e}")

        return results


# Singleton instance
blockchain_service = BlockchainService()
