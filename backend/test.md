# Dynamic Analyzer Test Suite - 30 Contract Types

## Overview
This file contains 30 different types of Ethereum contract addresses to comprehensively test the dynamic exploit detection analyzer.

**Test Categories:**
- 10 Verified Safe Contracts
- 8 Known Exploited Contracts  
- 5 Unverified Contracts
- 3 OFAC Sanctioned Addresses
- 2 Honeypot/Scam Tokens
- 2 Edge Cases

---

## Category 1: Verified Safe Contracts (Expected Score: 75-95, Risk: Low)

### Test 1: USDT (Tether)
- **Address**: `0xdAC17F958D2ee523a2206206994597C13D831ec7`
- **Name**: Tether USD
- **Type**: Stablecoin (ERC-20)
- **Market Cap**: $94B+
- **Expected Score**: 88-95
- **Expected Risk**: Low
- **Notes**: One of the oldest and most used stablecoins
- **Purpose**: Test detection of major safe stablecoin

### Test 2: USDC (Circle)
- **Address**: `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`
- **Name**: USD Coin
- **Type**: Stablecoin (ERC-20)
- **Market Cap**: $35B+
- **Expected Score**: 90-95
- **Expected Risk**: Low
- **Notes**: Regulated stablecoin by Circle
- **Purpose**: Test regulated stablecoin detection

### Test 3: WETH (Wrapped ETH)
- **Address**: `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`
- **Name**: Wrapped Ether
- **Type**: Wrapper Token (ERC-20)
- **Purpose**: Test canonical wrapped asset
- **Expected Score**: 93-95
- **Expected Risk**: Low

### Test 4: DAI (MakerDAO)
- **Address**: `0x6B175474E89094C44Da98b954EedeAC495271d0F`
- **Name**: Dai Stablecoin
- **Type**: Decentralized Stablecoin
- **Purpose**: Test decentralized stablecoin
- **Expected Score**: 85-92
- **Expected Risk**: Low

### Test 5: LINK (Chainlink)
- **Address**: `0x514910771AF9Ca656af840dff83E8264EcF986CA`
- **Name**: Chainlink Token
- **Type**: Utility Token
- **Expected Score**: 88-94
- **Expected Risk**: Low
- **Notes**: Core infrastructure token

### Test 6: AAVE (Aave Protocol Token)
- **Address**: `0x7Fc66500c84A76Ad7e9c93437E434122A1f9AcDd`
- **Name**: Aave Token
- **Type**: Governance Token
- **Expected Score**: 85-92
- **Expected Risk**: Low

### Test 7: SHIB (Shiba Inu)
- **Address**: `0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE`
- **Name**: Shiba Inu
- **Type**: Community Token
- **Expected Score**: 70-85
- **Expected Risk**: Low to Medium
- **Notes**: Popular meme coin, verified but less safety guarantees

### Test 8: CRV (Curve DAO)
- **Address**: `0xD533a949740bb3306d119CC777fa900bA034cd52`
- **Name**: Curve DAO Token
- **Type**: Governance Token
- **Expected Score**: 80-90
- **Expected Risk**: Low

### Test 9: UNI (Uniswap)
- **Address**: `0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984`
- **Name**: Uniswap Token
- **Type**: Governance Token
- **Expected Score**: 88-95
- **Expected Risk**: Low

### Test 10: MATIC (Polygon)
- **Address**: `0x7D1AfA7B718fb893dB30A3aBc0Cfc608AaCfeBB0`
- **Name**: Polygon Token
- **Type**: Layer 2 Native Token
- **Expected Score**: 85-92
- **Expected Risk**: Low

---

## Category 2: Known Exploited Contracts (Expected Score: 0-24, Risk: Critical)

### Test 11: BadgerDAO Exploit
- **Address**: `0x19D97D8fA813EE2f51aD4B4e04EA08bAf4DFfC28`
- **Name**: Badger DAO (Exploited)
- **Exploit Type**: Access Control Vulnerability
- **Amount Lost**: $120,000,000
- **Date**: 2021-12
- **Expected Score**: 20
- **Expected Risk**: Critical
- **Source**: Rekt.news, Security Databases
- **Details**: Compromised private key allowed unauthorized token transfers

### Test 12: Nomad Bridge Exploit
- **Address**: `0x5d94309e5a0090b165fa4181519701637b6daeba`
- **Name**: Nomad Bridge (Exploited)
- **Exploit Type**: Authentication Bypass
- **Amount Lost**: $190,000,000
- **Date**: 2022-08
- **Expected Score**: 20
- **Expected Risk**: Critical
- **Source**: Rekt.news, DeFiYield
- **Details**: Missing signature verification in cross-chain transfers

### Test 13: Old PolyNetwork Exploit
- **Address**: `0x250e76987d838a75310c34bf422ea9f1ac4cc906`
- **Name**: Poly Network (Exploited)
- **Exploit Type**: Cross-chain Bridge Vulnerability
- **Amount Lost**: $611,000,000
- **Date**: 2021-08
- **Expected Score**: 20
- **Expected Risk**: Critical
- **Source**: Rekt.news, Slowmist
- **Details**: Largest DeFi exploit - missing signature verification

### Test 14: Cream Finance Exploit
- **Address**: `0x2db0E83599a91b508Ac268a6197b8B14F5e72840`
- **Name**: Cream Finance (Exploited)
- **Exploit Type**: Reentrancy Vulnerability
- **Amount Lost**: $29,000,000
- **Date**: 2021-10
- **Expected Score**: 20
- **Expected Risk**: Critical
- **Details**: Reentrancy attack in lending pool

### Test 15: Merge Token Exploit
- **Address**: `0x4a57e355bed70f6804084d1416e8f6e3f1d88690`
- **Name**: Merge Token (Exploited)
- **Exploit Type**: Access Control Vulnerability
- **Amount Lost**: $3,000,000
- **Date**: 2022-11
- **Expected Score**: 20
- **Expected Risk**: Critical
- **Details**: Unauthorized token minting

### Test 16: Yearn V1 Vulnerability
- **Address**: `0x5dbcF33D8c2E976c6b560249878e6F1491Bca25c`
- **Name**: Yearn Finance V1 (Deprecated)
- **Exploit Type**: Multiple Vulnerabilities
- **Status**: Deprecated Protocol
- **Expected Score**: 25-40
- **Expected Risk**: High to Critical
- **Details**: Legacy version with known issues

### Test 17: DForce Reentrancy
- **Address**: `0x02285AcaafEB533e03A7306C55EC031297df9224`
- **Name**: DForce (Hit by Reentrancy)
- **Exploit Type**: Reentrancy Attack
- **Amount Lost**: ~$25,000,000
- **Date**: 2020-04
- **Expected Score**: 20
- **Expected Risk**: Critical

### Test 18: Tornado Cash (OFAC Sanctioned)
- **Address**: `0xd90e2f925da726b50c4ed8d0fb90ad053324f31b`
- **Name**: Tornado Cash Router
- **Exploitation Type**: OFAC Sanctioned
- **Date**: 2022-08
- **Expected Score**: 20
- **Expected Risk**: Critical
- **Source**: OFAC Official List
- **Details**: US Government sanctioned mixing service

---

## Category 3: Unverified Contracts (Expected Score: 50-74, Risk: Medium)

### Test 19: Random Unverified Contract 1
- **Address**: `0x1234567890123456789012345678901234567890`
- **Status**: No Source Code Available
- **Expected Score**: 45-65
- **Expected Risk**: Medium to High
- **Behavior**: Analyzer should flag as unverified

### Test 20: Random Unverified Contract 2
- **Address**: `0xabcdefabcdefabcdefabcdefabcdefabcdefabcd`
- **Status**: No Source Code Available
- **Expected Score**: 50-70
- **Expected Risk**: Medium
- **Behavior**: Should warn about lack of verification

### Test 21: Honeypot Token (Unverified)
- **Address**: `0x60e4d636d1343d9d622ee5e17b0abf1457e1be4d`
- **Status**: Unverified, Suspected Honeypot
- **Expected Score**: 0-30
- **Expected Risk**: Critical
- **Behavior**: Should detect honeypot patterns

### Test 22: Malicious Contract (Unverified)
- **Address**: `0x8888888888888888888888888888888888888888`
- **Status**: Suspicious Activity
- **Expected Score**: 10-40
- **Expected Risk**: High to Critical
- **Behavior**: Should flag suspicious behavior

### Test 23: Low Liquidity Token (Unverified)
- **Address**: `0xfffffffffffffffffffffffffffffffffffffff0`
- **Status**: Very Low Liquidity, Unverified
- **Expected Score**: 30-50
- **Expected Risk**: High
- **Behavior**: Should warn about liquidity risks

---

## Category 4: OFAC Sanctioned Addresses (Expected Score: 15-25, Risk: Critical)

### Test 24: Tornado Cash 0.1 ETH
- **Address**: `0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc`
- **Name**: Tornado Cash 0.1 ETH Pool
- **Status**: OFAC Sanctioned
- **Expected Score**: 20
- **Expected Risk**: Critical
- **Source**: OFAC SDN List

### Test 25: Tornado Cash 1 ETH
- **Address**: `0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936`
- **Name**: Tornado Cash 1 ETH Pool
- **Status**: OFAC Sanctioned
- **Expected Score**: 20
- **Expected Risk**: Critical
- **Source**: OFAC SDN List

### Test 26: Tornado Cash 10 ETH
- **Address**: `0x910cbd523d972eb0a6f4cae4618ad62622b39dbf`
- **Name**: Tornado Cash 10 ETH Pool
- **Status**: OFAC Sanctioned
- **Expected Score**: 20
- **Expected Risk**: Critical
- **Source**: OFAC SDN List

---

## Category 5: Honeypot/Scam Tokens (Expected Score: 0-20, Risk: Critical)

### Test 27: ClassicFloki (Known Honeypot)
- **Address**: `0xF42c318dbfBaab0EEE040279c6A2588Fa01a961d`
- **Name**: ClassicFloki (Honeypot)
- **Type**: Honeypot Token
- **Status**: Tokens cannot be sold
- **Expected Score**: 5-15
- **Expected Risk**: Critical
- **Behavior**: Should detect sell/buy tax anomaly

### Test 28: Pump & Dump Scheme
- **Address**: `0xaabbccddaabbccddaabbccddaabbccddaabbccdd`
- **Name**: Suspected P&D Scheme
- **Type**: Scam Token
- **Status**: Suspicious trading patterns
- **Expected Score**: 10-25
- **Expected Risk**: Critical

---

## Category 6: Edge Cases (Expected: Various)

### Test 29: Contract with Zero Supply
- **Address**: `0x0000000000000000000000000000000000000000`
- **Name**: Null Address / Zero Address
- **Status**: Special Edge Case
- **Expected Score**: 0
- **Expected Risk**: Unknown/Error
- **Behavior**: Should handle gracefully

### Test 30: Invalid Address Format
- **Address**: `0xINVALIDINVALIDINVALIDINVALIDINVALIDINVA`
- **Name**: Invalid Format Test
- **Status**: Malformed Address
- **Expected Score**: 0
- **Expected Risk**: Unknown/Error
- **Behavior**: Should validate address format

---

## Test Execution

### Run Full Test Suite

```bash
# Create test script
python test_all_30_contracts.py

# Or test individually
curl -X POST http://localhost:8001/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"contract_address":"0xdAC17F958D2ee523a2206206994597C13D831ec7","network":"ethereum"}'
```

### Expected Results Summary

| Category | Count | Expected Score | Expected Risk | Detection Method |
|----------|-------|-----------------|----------------|-----------------|
| Verified Safe | 10 | 75-95 | Low | verified_source |
| Exploited Contracts | 8 | 0-24 | Critical | dynamic-exploit-detection |
| Unverified Safe | 5 | 50-74 | Medium | bytecode_only |
| OFAC Sanctioned | 3 | 15-25 | Critical | dynamic-exploit-detection |
| Honeypot/Scam | 2 | 0-20 | Critical | dynamic-exploit-detection |
| Edge Cases | 2 | 0-50 | Variable | error/unknown |
| **TOTAL** | **30** | **Varies** | **Varies** | **Dynamic** |

---

## Success Criteria

✅ **All 10 Verified Safe contracts** should score 75-95 with Low risk
✅ **All 8 Exploited contracts** should score 0-24 with Critical risk  
✅ **All 5 Unverified contracts** should score 50-74 with Medium risk
✅ **All 3 OFAC addresses** should be detected as Critical
✅ **Both Honeypot tokens** should be detected as Critical
✅ **Edge cases** should be handled gracefully (no crashes)

### Overall Success Metrics

- **Detection Accuracy**: 95%+ of known exploits detected
- **False Positive Rate**: <5%
- **Response Time**: <5 seconds per contract
- **Zero Crashes**: All edge cases handled gracefully
- **Detection Methods Used**: Multiple (dynamic-exploit-detection, verified_source, bytecode_only)

---

## Advanced Test Metrics

### Performance Testing
- Record response times for each address
- Identify bottlenecks in detection pipeline
- Measure cache hit rates

### Accuracy Testing  
- Compare scores against historical data
- Validate risk level classifications
- Cross-check with external databases

### Robustness Testing
- Test invalid inputs
- Test network timeouts
- Test API failures
- Test cache refresh cycles

---

## Notes

1. **Dynamic Detection**: All exploits should be detected via the 6 external sources (Rekt.news, Slowmist, DeFiYield, OFAC, ChainAbuse, Honeypot.is)

2. **No Hardcoding**: Detection should come from seed database sourced from external APIs, not manual hardcoding

3. **Auto-Refresh**: System should update this list every 6 hours automatically

4. **Fallback Support**: If external APIs are blocked, seed database should still provide detection

5. **Confidence Scoring**: More sources detecting an exploit = higher confidence, lower score

---

**Last Updated**: 2026-02-13
**Test Suite Version**: 1.0
**Total Test Cases**: 30
**Status**: Ready for execution
