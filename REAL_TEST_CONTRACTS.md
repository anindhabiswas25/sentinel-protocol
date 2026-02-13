# ✅ Real Contract Addresses for Testing Sentinel Protocol

This file contains **actual deployed contracts** that you can test immediately. All addresses are verified and exist on the blockchain.

---

## 🟢 Safe Contracts to Test (High Trust Score Expected)

These are well-audited, trusted contracts from major protocols.

### Ethereum Mainnet

| Name | Address | Description |
|------|---------|-------------|
| **USDT (Tether)** | `0xdAC17F958D2ee523a2206206994597C13D831ec7` | Major stablecoin, widely used |
| **USDC (Circle)** | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` | USD stablecoin, regulated |
| **WETH (Wrapped Ether)** | `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2` | Wrapped ETH token |
| **DAI Stablecoin** | `0x6B175474E89094C44Da98b954EedeAC495271d0F` | MakerDAO stablecoin |
| **Uniswap V3 Router** | `0xE592427A0AEce92De3Edee1F18E0157C05861564` | DEX router |
| **Chainlink ETH/USD** | `0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419` | Price oracle |
| **LINK Token** | `0x514910771AF9Ca656af840dff83E8264EcF986CA` | Chainlink token |
| **Aave V3 Pool** | `0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2` | Lending protocol |

---

## 🟠 Known Vulnerable Contracts (Low Trust Score Expected)

These contracts have known issues or were exploited in the past.

### Ethereum Mainnet

| Name | Address | Known Issue |
|------|---------|-------------|
| **Akutars NFT** | `0xF42c318dbfBaab0EEE040279c6A2588Fa01a961d` | Funds locked due to bug |
| **Merge Token** | `0x4a57E687b9126435a9B19E4A802113e266AdeBde` | Reentrancy vulnerability |
| **PolyNetwork (Old)** | `0x250e76987d838a75310c34bf422ea9f1AC4Cc906` | Exploited in 2021 |

---

## 🧪 How to Test

### 1. Using the Frontend (http://localhost:3000)

1. Open http://localhost:3000 in your browser
2. Copy any address from above
3. Paste it into the "Contract Address" field
4. Select "Ethereum" as the network
5. Click "Analyze Contract"

### 2. Using the API

```bash
# Test USDT (should get high trust score ~85-90)
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "contract_address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
    "network": "ethereum"
  }'

# Test Akutars (should get lower trust score ~40-50)
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "contract_address": "0xF42c318dbfBaab0EEE040279c6A2588Fa01a961d",
    "network": "ethereum"
  }'
```

### 3. Auto-Detect Network

The system will automatically detect which network the contract is on:

```bash
# Works even if you don't specify the correct network
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "contract_address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
    "network": "polygon"
  }'
# System will detect it's actually on Ethereum and analyze it there
```

---

## ⚠️ Important Notes

### Real vs Placeholder Addresses

- ✅ **This file**: All addresses are REAL and can be tested immediately
- ⚠️ **testcontract.md**: Contracts #23-50 are placeholders and won't work
  - Only contracts #1-22 in testcontract.md are real addresses

### Network Detection

The system now automatically detects which network a contract is deployed on:
- If you specify the wrong network, it will find the correct one
- If the address doesn't exist anywhere, you'll get a clear error message

### Expected Results

**Safe Contracts (USDT, USDC, etc.)**
- Trust Score: 75-95 (Green)  
- Verified: Yes
- Vulnerabilities: None or Low severity
- Recommendation: Safe to use

**Vulnerable Contracts (Akutars, etc.)**
- Trust Score: 25-50 (Orange/Red)
- Verified: Yes or No
- Vulnerabilities: Multiple, High severity
- Recommendation: Avoid or use with extreme caution

---

## 🚀 Quick Start

**Fastest way to test:**

1. Start both servers (if not already running):
   ```powershell
   # Backend
   cd "d:\New folder\sentinel-protocol\backend"
   .\venv\Scripts\python.exe main.py
   
   # Frontend (new terminal)
   cd "d:\New folder\sentinel-protocol\frontend"
   npm run dev
   ```

2. Open http://localhost:3000

3. Copy this address: `0xdAC17F958D2ee523a2206206994597C13D831ec7`

4. Paste and analyze!

---

## 📊 Testing Checklist

Use this checklist to verify Sentinel Protocol is working correctly:

- [ ] Test USDT - Should get high trust score (80+)
- [ ] Test USDC - Should get high trust score (85+)  
- [ ] Test Akutars - Should detect vulnerability and get lower score (40-50)
- [ ] Test with wrong network - Should auto-detect correct network
- [ ] Test invalid address - Should get clear error message
- [ ] Test non-existent address - Should get "not found" message

---

## 🐛 Troubleshooting

### Error: "No contract found at this address"

**Cause**: The address doesn't exist on any blockchain network.

**Solution**: 
- Make sure you copied the FULL address (starts with `0x` and has 42 characters)
- Use addresses from this file (all tested and verified)
- Don't use placeholder addresses from testcontract.md (#23-50)

### Error: "Address is not a smart contract"

**Cause**: The address is a wallet/EOA, not a contract.

**Solution**:
- Verify you're using a contract address, not a personal wallet
- Use addresses from this file which are all verified contracts

### Analysis takes too long

**Cause**: First analysis fetches source code and runs AI analysis.

**Expected**:
- Verified contracts: 10-30 seconds
- Unverified contracts: 5-15 seconds
- Cached results: Instant

---

**Last Updated**: February 12, 2026  
**Network**: Ethereum Mainnet  
**Status**: All addresses verified working ✅
