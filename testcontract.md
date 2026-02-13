# Test Contract Addresses for Sentinel Protocol

This file contains 50 different Ethereum contract addresses across four categories for testing the LLM and vector database analyzer.

---

## 📋 Test Categories & Decision Matrix

| Score Range | Category | Verification | Safety | User Action |
|-------------|----------|--------------|--------|-------------|
| **75-95** 🟢 | Verified Safe | ✅ Verified | ✅ Secure | **SAFE TO USE** |
| **50-74** 🟡 | Unverified Safe | ❌ Unverified | ⚠️ Likely Safe | **USE WITH CAUTION** |
| **25-49** 🟠 | Verified Unsafe | ✅ Verified | ❌ Vulnerable | **AVOID - Known Issues** |
| **0-24** 🔴 | Unverified Unsafe | ❌ Unverified | ❌ Dangerous | **NEVER USE - High Risk** |

### Scoring Logic:
- **Verified Safe (75-95)**: Audited, trusted, minimal vulnerabilities
- **Unverified Safe (50-74)**: Safe patterns but -25 penalty for no verification
- **Verified Unsafe (25-49)**: Open source shows vulnerabilities - transparency is better than hidden risks
- **Unverified Unsafe (0-24)**: Combination of unverified + red flags = highest risk

---

## ✅ Category 1: Verified Safe Contracts (75-95) 🟢
**User Action: SAFE TO USE - Proceed with transaction**

These are well-audited, trusted contracts from major protocols.

| # | Name | Address | Network | Expected Score | Reason |
|---|------|---------|---------|----------------|--------|
| 1 | USDT (Tether) | `0xdAC17F958D2ee523a2206206994597C13D831ec7` | Ethereum | 82 | Major stablecoin, audited |
| 2 | USDC (Circle) | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` | Ethereum | 90 | Regulated, transparent |
| 3 | WETH (Wrapped Ether) | `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2` | Ethereum | 93 | Simple, battle-tested |
| 4 | DAI Stablecoin | `0x6B175474E89094C44Da98b954EedeAC495271d0F` | Ethereum | 88 | MakerDAO, audited |
| 5 | Uniswap V3 Router | `0xE592427A0AEce92De3Edee1F18E0157C05861564` | Ethereum | 87 | Multiple audits |
| 6 | Aave V3 Pool | `0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2` | Ethereum | 89 | Institutional grade |
| 7 | Chainlink ETH/USD | `0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419` | Ethereum | 94 | Oracle standard |
| 8 | LINK Token | `0x514910771AF9Ca656af840dff83E8264EcF986CA` | Ethereum | 86 | Established token |
| 9 | Compound cUSDC | `0x39AA39c021dfbaE8faC545936693aC917d5E7563` | Ethereum | 84 | Proven protocol |
| 10 | MakerDAO DSChief | `0x0a3f6849f78076aefaDf113F5BED87720274dDC0` | Ethereum | 80 | Gov contract, audited |
| 11 | Curve 3pool | `0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7` | Ethereum | 85 | High TVL, secure |
| 12 | Balancer Vault | `0xBA12222222228d8Ba445958a75a0704d566BF2C8` | Ethereum | 88 | Multiple audits |

---

## 🟠 Category 2: Verified Unsafe Contracts (25-49) 🟠
**User Action: AVOID - Known vulnerabilities, do NOT transact**

These are verified (source code visible) but contain known vulnerabilities. Verification score helps identify specific issues.

| # | Name | Address | Network | Expected Score | Known Issue |
|---|------|---------|---------|----------------|-------------|
| 13 | Merge Token (Reentrancy) | `0x4a57E687b9126435a9B19E4A802113e266AdeBde` | Ethereum | 35 | Reentrancy vulnerability |
| 14 | Old PolyNetwork (Hacked) | `0x250e76987d838a75310c34bf422ea9f1AC4Cc906` | Ethereum | 26 | Known exploit 2021 |
| 15 | BadgerDAO (Compromised) | `0x19D97D8fA813EE2f51aD4B4e04EA08bAf4DFfC28` | Ethereum | 30 | Front-running attack |
| 16 | Cream Finance (Exploited) | `0x2db0E83599a91b508Ac268a6197b8B14F5e72840` | Ethereum | 28 | Flash loan attack |
| 17 | Yearn v1 Vault (Deprecated) | `0x5dbcF33D8c2E976c6b560249878e6F1491Bca25c` | Ethereum | 42 | Deprecated, unsafe |
| 18 | DForce Vault (Hacked) | `0x02285AcaafEB533e03A7306C55EC031297df9224` | Ethereum | 33 | Reentrancy 2020 |
| 19 | Pickle Finance (Exploited) | `0x6949Bb624E8e8A90F87cD2058139fcd77D2F3F87` | Ethereum | 36 | Evil jar attack |
| 20 | Akutars NFT (Locked) | `0xF42c318dbfBaab0EEE040279c6A2588Fa01a961d` | Ethereum | 46 | Funds locked bug |
| 21 | Nomad Bridge (Hacked) | `0x5D94309E5a0090b165FA4181519701637B6DAEBA` | Ethereum | 25 | Bridge exploit 2022 |
| 22 | Tornado Cash Router | `0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b` | Ethereum | 48 | Sanctioned protocol |

---

## 🟡 Category 3: Unverified Safe Contracts (50-74) 🟡
**User Action: USE WITH CAUTION - Small transactions, test first, verify independently**

Not verified on Etherscan but show safe patterns in bytecode analysis. Always verify before large transactions.

| # | Name | Address | Network | Expected Score | Reason |
|---|------|---------|---------|----------------|--------|
| 23 | Small DEX Router | `0x1234567890123456789012345678901234567890` | Ethereum | 58 | Simple logic, no red flags |
| 24 | Private Multisig | `0x2345678901234567890123456789012345678901` | Ethereum | 65 | Standard multisig pattern |
| 25 | Token Vesting | `0x3456789012345678901234567890123456789012` | Ethereum | 62 | Time-locked, safe pattern |
| 26 | NFT Marketplace | `0x4567890123456789012345678901234567890123` | Ethereum | 54 | Basic NFT logic detected |
| 27 | DAO Treasury | `0x5678901234567890123456789012345678901234` | Ethereum | 70 | Treasury pattern, high usage |
| 28 | Staking Contract | `0x6789012345678901234567890123456789012345` | Ethereum | 57 | Simple staking rewards |
| 29 | Airdrop Distributor | `0x7890123456789012345678901234567890123456` | Ethereum | 68 | Merkle tree pattern |
| 30 | Token Locker | `0x8901234567890123456789012345678901234567` | Ethereum | 61 | Time-lock mechanism |
| 31 | Escrow Contract | `0x9012345678901234567890123456789012345678` | Ethereum | 63 | Standard escrow flow |
| 32 | Swap Aggregator | `0xA012345678901234567890123456789012345678` | Ethereum | 55 | Basic aggregator logic |
| 33 | Liquidity Pool | `0xB012345678901234567890123456789012345678` | Ethereum | 59 | AMM pool pattern |
| 34 | Governance Token | `0xC012345678901234567890123456789012345678` | Ethereum | 69 | Standard ERC20 patterns |

---

## 🔴 Category 4: Unverified Unsafe Contracts (0-24) 🔴
**User Action: NEVER USE - High risk, likely scam, avoid completely**

Unverified AND showing multiple red flags. Combination of hidden code + suspicious patterns = extremely dangerous.

| # | Name | Address | Network | Expected Score | Risk Factor |
|---|------|---------|---------|----------------|-------------|
| 35 | Honeypot Token | `0xD012345678901234567890123456789012345678` | Ethereum | 12 | Cannot sell tokens |
| 36 | Rug Pull Contract | `0xE012345678901234567890123456789012345678` | Ethereum | 8 | Owner can drain funds |
| 37 | Fake Airdrop | `0xF012345678901234567890123456789012345678` | Ethereum | 15 | Phishing contract |
| 38 | Scam Token | `0x1023456789012345678901234567890123456789` | Ethereum | 5 | Hidden mint function |
| 39 | Malicious Proxy | `0x1123456789012345678901234567890123456789` | Ethereum | 18 | Upgradeable to scam |
| 40 | Fake Uniswap | `0x1223456789012345678901234567890123456789` | Ethereum | 10 | Impersonation attack |
| 41 | Blacklist Token | `0x1323456789012345678901234567890123456789` | Ethereum | 22 | Arbitrary blacklisting |
| 42 | Pausable Scam | `0x1423456789012345678901234567890123456789` | Ethereum | 19 | Can pause anytime |
| 43 | Fee Manipulator | `0x1523456789012345678901234567890123456789` | Ethereum | 24 | Owner changes fees |
| 44 | Reflection Token Bug | `0x1623456789012345678901234567890123456789` | Ethereum | 20 | Math overflow bugs |
| 45 | Unaudited DeFi | `0x1723456789012345678901234567890123456789` | Ethereum | 23 | Complex + unverified |
| 46 | Anonymous Deployer | `0x1823456789012345678901234567890123456789` | Ethereum | 17 | Suspicious behavior |
| 47 | Hidden Backdoor | `0x1923456789012345678901234567890123456789` | Ethereum | 11 | Assembly backdoor |
| 48 | Tax Token Scam | `0x2023456789012345678901234567890123456789` | Ethereum | 14 | 99% sell tax trap |
| 49 | Liquidity Trap | `0x2123456789012345678901234567890123456789` | Ethereum | 16 | LP locked scam |
| 50 | Copycat Contract | `0x2223456789012345678901234567890123456789` | Ethereum | 21 | Malicious clone |

---

## 🧪 Testing Strategy

### Phase 1: Verified Safe (Baseline)
Test contracts 1-12 to ensure:
- ✅ High trust scores (80-95)
- ✅ Minimal vulnerabilities detected
- ✅ Correct identification of standard patterns

### Phase 2: Verified Unsafe (Known Issues)
Test contracts 13-22 to verify:
- 🟠 Low trust scores (25-49)
- 🟠 Specific vulnerabilities identified
- 🟠 Historical exploit detection

### Phase 3: Unverified Safe (Gray Area)
Test contracts 23-34 to check:
- 🟡 Medium trust scores (50-74)
- 🟡 Caution flags for unverified
- 🟡 Pattern recognition without source

### Phase 4: Unverified Unsafe (Red Flags)
Test contracts 35-50 to validate:
- 🔴 Very low trust scores (0-24)
- 🔴 Multiple risk factors detected
- 🔴 Proper warnings generated

---

## 📊 Expected Results Summary

| Category | Count | Score Range | User Decision | Detection Target |
|----------|-------|-------------|---------------|------------------|
| 🟢 Verified Safe | 12 | 75-95 | ✅ SAFE TO USE | 100% accurate |
| 🟡 Unverified Safe | 12 | 50-74 | ⚠️ USE WITH CAUTION | 70%+ accurate |
| 🟠 Verified Unsafe | 10 | 25-49 | ❌ AVOID | 90%+ detection |
| 🔴 Unverified Unsafe | 16 | 0-24 | 🚫 NEVER USE | 85%+ detection |

### Why This Scoring Makes Sense:

1. **No Overlap**: Each range is distinct, no ambiguity
2. **Verification Premium**: Safe verified contracts score higher than unverified
3. **Transparency Bonus**: Verified unsafe (25-49) scores higher than unverified unsafe (0-24) because you can see the exact vulnerabilities
4. **Clear Thresholds**: 
   - 75+ = Green light ✅
   - 50-74 = Proceed with caution ⚠️
   - 25-49 = Stop, known issues ⛔
   - 0-24 = Danger, never interact 🚫

---

## 🎯 Success Criteria

**Your Sentinel Protocol should:**

1. ✅ **Accuracy**: 85%+ correct score ranges
2. ✅ **Vulnerability Detection**: Identify known exploits
3. ✅ **Pattern Recognition**: Detect honeypots, scams
4. ✅ **Speed**: <5 seconds per analysis
5. ✅ **Consistency**: Similar scores for similar contracts

---

## 🚀 How to Test

### Using the API:
```bash
# Test a verified safe contract
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
    "network": "ethereum"
  }'

# Test an unsafe contract
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "address": "0x4a57E687b9126435a9B19E4A802113e266AdeBde",
    "network": "ethereum"
  }'
```

### Using the Frontend:
1. Go to http://localhost:3000
2. Paste contract address
3. Click "Analyze"
4. Compare results with expected scores

---

## 📝 Notes

- **Real Addresses**: Contracts 1-22 are real Ethereum addresses
- **Placeholder Addresses**: Contracts 23-50 are examples (use real ones for actual testing)
- **Expected Scores**: Based on typical security analysis patterns
- **Network**: All examples use Ethereum mainnet

---

## 🔄 Continuous Testing

Run these tests after:
- ✅ LLM model changes
- ✅ Vector database updates
- ✅ New vulnerability patterns added
- ✅ Scoring algorithm modifications

---

**Last Updated**: February 12, 2026
**Version**: 1.0
**Purpose**: Sentinel Protocol Testing & Validation
