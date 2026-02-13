import sys
sys.path.insert(0, 'D:\\New folder\\sentinel-protocol\\backend')

from app.services.blockchain import blockchain_service

# Test with USDT contract
usdt_address = "0xdAC17F958D2ee523a2206206994597C13D831ec7"

print("Testing Blockchain Service:")
print("=" * 50)

# Test address validation
print(f"\n1. Is valid address: {blockchain_service.is_valid_address(usdt_address)}")

# Test network connections
print(f"\n2. Network connections:")
for network in ["ethereum", "polygon", "arbitrum", "base"]:
    connected = blockchain_service.check_connection(network)
    print(f"   {network}: {'✅ Connected' if connected else '❌ Not connected'}")

# Test contract detection on Ethereum
print(f"\n3. Is contract on Ethereum: {blockchain_service.is_contract(usdt_address, 'ethereum')}")

# Test get bytecode
bytecode = blockchain_service.get_bytecode(usdt_address, 'ethereum')
print(f"\n4. Bytecode length: {len(bytecode) if bytecode else 0} characters")

# Test detect network
print(f"\n5. Detect network:")
results = blockchain_service.detect_network(usdt_address)
print(f"   Found on networks: {[r['network'] for r in results]}")

# Test with placeholder address (from testcontract.md)
test_address = "0x6789012345678901234567890123456789012345"
print(f"\n6. Testing placeholder address: {test_address}")
print(f"   Is valid: {blockchain_service.is_valid_address(test_address)}")
print(f"   Is contract on Ethereum: {blockchain_service.is_contract(test_address, 'ethereum')}")
results2 = blockchain_service.detect_network(test_address)
print(f"   Found on networks: {[r['network'] for r in results2] if results2 else 'None'}")
