"""
Comprehensive test for ALL 4 scoring categories with UNIQUE profiles.

Every contract has a unique combination of:
- Vulnerability severities with DIFFERENT confidence values
- Bytecode analysis metrics (size, external_calls, patterns)
- Code quality issues

This ensures every contract gets a UNIQUE score for clear relative comparison.

Category 1: Verified Safe (75-95) - 12 contracts
Category 2: Verified Unsafe (25-49) - 10 contracts  
Category 3: Unverified Safe (50-74) - 12 contracts
Category 4: Unverified Unsafe (0-24) - 16 contracts
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from app.services.scoring import scoring_service


# ============================================================
# CATEGORY 1: Verified Safe Contracts (Expected: 75-95)
# Well-known contracts in the WELL_KNOWN_SAFE_CONTRACTS list
# Formula: 95 - sum(severity_weight × confidence) - quality_impact
# Weights: critical=10, high=6, medium=4, low=2.5, informational=0.5
# ============================================================
CATEGORY_1_TESTS = [
    {
        "name": "USDT (Tether)",
        "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        "expected_score": 82,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "medium", "confidence": 0.90, "description": "Centralized pause functionality allows freezing all transfers"},
            {"severity": "medium", "confidence": 0.85, "description": "Owner can blacklist any address and freeze their funds"},
            {"severity": "low", "confidence": 0.80, "description": "No SafeMath in Solidity 0.4.17 (mitigated by simple operations)"},
            {"severity": "low", "confidence": 0.70, "description": "Missing events on deprecation status change"},
            {"severity": "low", "confidence": 0.60, "description": "Upgradeable proxy adds complexity"},
        ],
        "code_quality_issues": [{"severity": "low", "issue": "Old Solidity version"}],
        "bytecode_analysis": None,
        "reason": "Major stablecoin - centralization is main concern"
    },
    {
        "name": "USDC (Circle)",
        "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "expected_score": 90,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "low", "confidence": 0.65, "description": "Centralized admin controls via proxy"},
            {"severity": "low", "confidence": 0.55, "description": "Regulatory freeze capability"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": None,
        "reason": "Regulated, transparent, well-structured"
    },
    {
        "name": "WETH (Wrapped Ether)",
        "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        "expected_score": 95,
        "is_verified": True,
        "vulnerabilities": [],
        "code_quality_issues": [],
        "bytecode_analysis": None,
        "reason": "Simplest contract, zero vulnerabilities"
    },
    {
        "name": "DAI Stablecoin",
        "address": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
        "expected_score": 89,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "medium", "confidence": 0.70, "description": "Complex governance dependency on MakerDAO system"},
            {"severity": "low", "confidence": 0.55, "description": "Permit function edge cases"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": None,
        "reason": "MakerDAO governance dependency lowers score slightly"
    },
    {
        "name": "Uniswap V3 Router",
        "address": "0xE592427A0AEce92De3Edee1F18E0157C05861564",
        "expected_score": 87,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "medium", "confidence": 0.75, "description": "Slippage risk in complex multi-hop swap paths"},
            {"severity": "low", "confidence": 0.65, "description": "Deadline parameter could be set too far in future"},
            {"severity": "low", "confidence": 0.50, "description": "Complex callback interaction patterns"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": None,
        "reason": "Complex routing logic adds moderate concerns"
    },
    {
        "name": "Aave V3 Pool",
        "address": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
        "expected_score": 90,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "low", "confidence": 0.60, "description": "Complex interest rate model edge cases"},
            {"severity": "low", "confidence": 0.45, "description": "Flash loan surface area"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": None,
        "reason": "Institutional grade, minor complexity concerns"
    },
    {
        "name": "Chainlink ETH/USD",
        "address": "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419",
        "expected_score": 95,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "informational", "confidence": 0.30, "description": "Aggregator proxy pattern adds indirection"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": None,
        "reason": "Oracle standard, essentially no concerns"
    },
    {
        "name": "LINK Token",
        "address": "0x514910771AF9Ca656af840dff83E8264EcF986CA",
        "expected_score": 87,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "medium", "confidence": 0.70, "description": "ERC677 non-standard extension may cause compatibility issues"},
            {"severity": "low", "confidence": 0.60, "description": "transferAndCall callback could be misused by receivers"},
        ],
        "code_quality_issues": [{"severity": "informational", "issue": "Non-standard ERC20"}],
        "bytecode_analysis": None,
        "reason": "Non-standard extension is moderate concern"
    },
    {
        "name": "Compound cUSDC",
        "address": "0x39AA39c021dfbaE8faC545936693aC917d5E7563",
        "expected_score": 84,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "medium", "confidence": 0.80, "description": "Interest rate model rounding can cause dust amount discrepancy"},
            {"severity": "low", "confidence": 0.70, "description": "Exchange rate manipulation in low-liquidity edge cases"},
            {"severity": "low", "confidence": 0.55, "description": "Comptroller dependency creates systemic risk"},
        ],
        "code_quality_issues": [{"severity": "low", "issue": "Complex cToken math"}],
        "bytecode_analysis": None,
        "reason": "Complex lending math with multiple concerns"
    },
    {
        "name": "MakerDAO DSChief",
        "address": "0x0a3f6849f78076aefaDf113F5BED87720274dDC0",
        "expected_score": 80,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "medium", "confidence": 0.85, "description": "Flash loan governance attack could manipulate voting"},
            {"severity": "medium", "confidence": 0.75, "description": "Voting power concentration risk via delegation"},
            {"severity": "low", "confidence": 0.70, "description": "Slate management complexity allows vote splitting"},
            {"severity": "low", "confidence": 0.65, "description": "Hat selection mechanism has edge cases"},
        ],
        "code_quality_issues": [{"severity": "low", "issue": "Complex slate logic"}, {"severity": "low", "issue": "Old Solidity patterns"}],
        "bytecode_analysis": None,
        "reason": "Governance contracts have inherent attack surface"
    },
    {
        "name": "Curve 3pool",
        "address": "0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7",
        "expected_score": 86,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "medium", "confidence": 0.75, "description": "Vyper reentrancy surface area in get_virtual_price"},
            {"severity": "low", "confidence": 0.65, "description": "Admin fee accumulation can affect pool pricing"},
        ],
        "code_quality_issues": [{"severity": "informational", "issue": "Vyper contract"}],
        "bytecode_analysis": None,
        "reason": "Vyper reentrancy concern but battle-tested"
    },
    {
        "name": "Balancer Vault",
        "address": "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
        "expected_score": 89,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "low", "confidence": 0.60, "description": "Internal balance accounting complexity"},
            {"severity": "low", "confidence": 0.50, "description": "Flash loan callback surface area"},
            {"severity": "informational", "confidence": 0.35, "description": "Large contract size increases audit surface"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": None,
        "reason": "Well-audited, minor complexity concerns"
    },
]


# ============================================================
# CATEGORY 2: Verified Unsafe Contracts (Expected: 25-49)
# Known exploited contracts in the KNOWN_EXPLOITED_CONTRACTS list
# Formula: 49 - sum(severity_weight × confidence) - quality_impact
# Weights: critical=7.5, high=3, medium=1.5, low=0.5
# ============================================================
CATEGORY_2_TESTS = [
    {
        "name": "Merge Token (Reentrancy)",
        "address": "0x4a57E687b9126435a9B19E4A802113e266AdeBde",
        "expected_score": 35,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.95, "description": "Reentrancy vulnerability in transfer function - state update after external call"},
            {"severity": "high", "confidence": 0.85, "description": "State changes after external call enable drain attack"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": None,
        "reason": "Classic reentrancy exploit"
    },
    {
        "name": "Old PolyNetwork (Hacked)",
        "address": "0x250e76987d838a75310c34bf422ea9f1AC4Cc906",
        "expected_score": 27,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.95, "description": "Access control bypass allows unauthorized cross-chain keeper changes"},
            {"severity": "critical", "confidence": 0.90, "description": "putCurEpochConPkBytes allows arbitrary keeper role replacement"},
            {"severity": "high", "confidence": 0.85, "description": "Missing signature verification in cross-chain message handling"},
            {"severity": "medium", "confidence": 0.70, "description": "Inadequate event logging for cross-chain transfers"},
        ],
        "code_quality_issues": [{"severity": "medium", "issue": "No access control tests"}],
        "bytecode_analysis": None,
        "reason": "$611M hack - critical access control bypass"
    },
    {
        "name": "BadgerDAO (Compromised)",
        "address": "0x19D97D8fA813EE2f51aD4b4e04EA08bAf4DFfC28",
        "expected_score": 32,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.90, "description": "Front-end injection allowed unlimited approval harvesting"},
            {"severity": "high", "confidence": 0.80, "description": "Unlimited token approval pattern exploitable via compromised front-end"},
            {"severity": "high", "confidence": 0.70, "description": "Missing approval amount validation allows max uint approvals"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": None,
        "reason": "Supply chain attack via approval abuse"
    },
    {
        "name": "Cream Finance (Exploited)",
        "address": "0x2db0E83599a91b508Ac268a6197b8B14F5e72840",
        "expected_score": 28,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.95, "description": "Flash loan attack vector exploiting price oracle manipulation"},
            {"severity": "high", "confidence": 0.90, "description": "Spot price oracle easily manipulable via flash loans"},
            {"severity": "high", "confidence": 0.80, "description": "Unchecked return value from collateral price feed"},
            {"severity": "medium", "confidence": 0.70, "description": "Insufficient collateral ratio validation"},
        ],
        "code_quality_issues": [{"severity": "low", "issue": "Complex oracle dependency"}],
        "bytecode_analysis": None,
        "reason": "Multiple flash loan exploits - $130M+ stolen"
    },
    {
        "name": "Yearn v1 Vault (Deprecated)",
        "address": "0x5dbcF33D8c2E976c6b560249878e6F1491Bca25c",
        "expected_score": 43,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "high", "confidence": 0.80, "description": "Deprecated vault strategy with known exploit path via flash loan"},
            {"severity": "medium", "confidence": 0.65, "description": "Strategy migration incomplete, residual funds at risk"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": None,
        "reason": "Deprecated but less severe than active exploits"
    },
    {
        "name": "DForce Vault (Hacked)",
        "address": "0x02285AcaafEB533e03A7306C55EC031297df9224",
        "expected_score": 33,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.90, "description": "Reentrancy via ERC777 tokensReceived callback during deposit"},
            {"severity": "high", "confidence": 0.85, "description": "Missing reentrancy guard on deposit/withdraw functions"},
            {"severity": "medium", "confidence": 0.65, "description": "Unprotected state modification during callback"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": None,
        "reason": "ERC777 reentrancy - $25M exploit"
    },
    {
        "name": "Pickle Finance (Exploited)",
        "address": "0x6949Bb624E8e8A90F87cD2058139fcd77D2F3F87",
        "expected_score": 37,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.85, "description": "Evil jar attack via swapExactJarForJar strategy manipulation"},
            {"severity": "high", "confidence": 0.75, "description": "Unauthorized strategy swap bypasses jar controller checks"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": None,
        "reason": "Strategy manipulation exploit"
    },
    {
        "name": "Akutars NFT (Locked)",
        "address": "0xF42c318dbfBaab0EEE040279c6A2588Fa01a961d",
        "expected_score": 45,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "high", "confidence": 0.75, "description": "Funds permanently locked - processRefunds reverts blocking all withdrawals"},
            {"severity": "medium", "confidence": 0.60, "description": "Refund mechanism has edge case causing permanent revert"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": None,
        "reason": "Logic bug locked $34M, not an active exploit"
    },
    {
        "name": "Nomad Bridge (Hacked)",
        "address": "0x5D94309E5a0090b165FA4181519701637B6DAEBA",
        "expected_score": 25,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.95, "description": "Replica process() allows arbitrary message execution after faulty upgrade"},
            {"severity": "critical", "confidence": 0.90, "description": "Missing Merkle root validation - zero root accepted as valid"},
            {"severity": "high", "confidence": 0.85, "description": "Bridge message replay attack after initialization flaw"},
            {"severity": "high", "confidence": 0.75, "description": "Cross-chain message forgery via prove-and-process bypass"},
        ],
        "code_quality_issues": [{"severity": "medium", "issue": "Upgrade process lacks validation"}],
        "bytecode_analysis": None,
        "reason": "Most critical - $190M exploit, multiple critical vulns"
    },
    {
        "name": "Tornado Cash Router",
        "address": "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b",
        "expected_score": 45,
        "is_verified": True,
        "vulnerabilities": [
            {"severity": "high", "confidence": 0.70, "description": "OFAC sanctioned protocol - legal compliance risk"},
            {"severity": "medium", "confidence": 0.55, "description": "Governance token manipulation risk via malicious proposal"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": None,
        "reason": "Sanctioned but technically competent code"
    },
]


# ============================================================
# CATEGORY 3: Unverified Safe Contracts (Expected: 50-74)
# Not verified but safe bytecode patterns
# Formula: 74 - vuln_impact - bytecode_impact - quality_impact
# Weights: high=12, medium=5, low=2.5, informational=0.5
# ============================================================
CATEGORY_3_TESTS = [
    {
        "name": "Small DEX Router",
        "expected_score": 58,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "medium", "confidence": 0.55, "description": "Complex external call pattern for token swaps"},
            {"severity": "low", "confidence": 0.50, "description": "No slippage protection detected in bytecode"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": True,
            "suspicious_patterns": [],
            "external_calls": 12, "size": 8500
        },
        "reason": "DEX router with delegatecall for routing"
    },
    {
        "name": "Private Multisig",
        "expected_score": 67,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "low", "confidence": 0.45, "description": "Multisig threshold not verifiable from bytecode"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": [],
            "external_calls": 4, "size": 6200
        },
        "reason": "Standard multisig, clean bytecode"
    },
    {
        "name": "Token Vesting",
        "expected_score": 64,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "low", "confidence": 0.60, "description": "Timestamp-based vesting schedule detectable"},
            {"severity": "low", "confidence": 0.40, "description": "No emergency withdrawal visible in bytecode"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": [],
            "external_calls": 3, "size": 5800
        },
        "reason": "Time-lock pattern detected, minor timestamp concern"
    },
    {
        "name": "NFT Marketplace",
        "expected_score": 67,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "medium", "confidence": 0.65, "description": "No ReentrancyGuard detected in bytecode"},
            {"severity": "low", "confidence": 0.55, "description": "Complex external calls for NFT transfers"},
            {"severity": "low", "confidence": 0.45, "description": "Royalty calculation not verifiable"},
        ],
        "code_quality_issues": [{"severity": "low", "issue": "Complex bytecode"}],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": [],
            "external_calls": 8, "size": 12500
        },
        "reason": "Complex marketplace logic with multiple concerns"
    },
    {
        "name": "DAO Treasury",
        "expected_score": 70,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "low", "confidence": 0.35, "description": "Multi-token handling detected"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": [],
            "external_calls": 2, "size": 4200
        },
        "reason": "Simple treasury, very clean bytecode"
    },
    {
        "name": "Staking Contract",
        "expected_score": 70,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "medium", "confidence": 0.50, "description": "Reward calculation may have rounding issues"},
            {"severity": "low", "confidence": 0.45, "description": "Timestamp dependency in staking rewards"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": [],
            "external_calls": 5, "size": 7800
        },
        "reason": "Staking with medium reward calculation concern"
    },
    {
        "name": "Airdrop Distributor",
        "expected_score": 69,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "low", "confidence": 0.40, "description": "Merkle proof verification pattern detected"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": [],
            "external_calls": 3, "size": 5500
        },
        "reason": "Secure Merkle tree pattern, very clean"
    },
    {
        "name": "Token Locker",
        "expected_score": 71,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "low", "confidence": 0.65, "description": "Lock duration not verifiable from bytecode"},
            {"severity": "low", "confidence": 0.50, "description": "Token withdrawal path complexity"},
        ],
        "code_quality_issues": [{"severity": "informational", "issue": "Lock mechanism"}],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": [],
            "external_calls": 4, "size": 6800
        },
        "reason": "Time-lock with some complexity"
    },
    {
        "name": "Escrow Contract",
        "expected_score": 66,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "low", "confidence": 0.50, "description": "Dispute resolution mechanism unclear from bytecode"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": [],
            "external_calls": 3, "size": 5200
        },
        "reason": "Standard escrow, minor dispute concern"
    },
    {
        "name": "Swap Aggregator",
        "expected_score": 63,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "medium", "confidence": 0.70, "description": "Complex external calls to multiple DEX routers"},
            {"severity": "low", "confidence": 0.55, "description": "Gas optimization patterns may mask behavior"},
        ],
        "code_quality_issues": [{"severity": "low", "issue": "Complex routing"}],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": True,
            "suspicious_patterns": [],
            "external_calls": 15, "size": 18000
        },
        "reason": "Complex aggregator with delegatecall and many external calls"
    },
    {
        "name": "Liquidity Pool",
        "expected_score": 71,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "low", "confidence": 0.65, "description": "Impermanent loss mechanism detected in bytecode"},
            {"severity": "low", "confidence": 0.45, "description": "Price oracle dependency pattern"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": [],
            "external_calls": 6, "size": 9200
        },
        "reason": "AMM pattern with price dependency"
    },
    {
        "name": "Governance Token",
        "expected_score": 71,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "informational", "confidence": 0.30, "description": "Standard ERC20 pattern with voting extension"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": [],
            "external_calls": 2, "size": 4800
        },
        "reason": "Clean ERC20 governance token, minimal concerns"
    },
]


# ============================================================
# CATEGORY 4: Unverified Unsafe Contracts (Expected: 0-24)
# Unverified with critical/high vulns and suspicious patterns
# Formula: 24 - vuln_impact - bytecode_impact × 0.7 - quality_impact
# Weights: critical=5, high=3, medium=1.5, low=0.5
# ============================================================
CATEGORY_4_TESTS = [
    {
        "name": "Honeypot Token",
        "expected_score": 12,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.90, "description": "Honeypot: transfer restriction blocks all selling"},
            {"severity": "high", "confidence": 0.80, "description": "Hidden transfer approval required from owner"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": ["honeypot", "hidden_transfer_restriction"],
            "external_calls": 3, "size": 5500
        },
        "reason": "Cannot sell tokens"
    },
    {
        "name": "Rug Pull Contract",
        "expected_score": 5,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.95, "description": "Owner has unlimited withdrawal rights to drain all funds"},
            {"severity": "critical", "confidence": 0.90, "description": "No timelock or governance controls on fund movement"},
            {"severity": "high", "confidence": 0.85, "description": "Centralized control with no multi-sig requirement"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": True, "has_delegatecall": False,
            "suspicious_patterns": ["owner_drain", "no_timelock"],
            "external_calls": 5, "size": 7000
        },
        "reason": "Owner can drain all funds"
    },
    {
        "name": "Fake Airdrop",
        "expected_score": 14,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.85, "description": "Phishing pattern harvests unlimited token approvals"},
            {"severity": "high", "confidence": 0.70, "description": "Approval harvesting drains approved tokens"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": True,
            "suspicious_patterns": ["phishing", "approval_harvesting"],
            "external_calls": 4, "size": 6000
        },
        "reason": "Phishing contract"
    },
    {
        "name": "Scam Token",
        "expected_score": 3,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.95, "description": "Hidden mint function accessible by owner only"},
            {"severity": "critical", "confidence": 0.90, "description": "Unlimited token inflation possible via internal function"},
            {"severity": "high", "confidence": 0.85, "description": "No maximum supply cap enforced"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": ["hidden_mint", "unlimited_supply"],
            "external_calls": 2, "size": 4500
        },
        "reason": "Hidden mint function"
    },
    {
        "name": "Malicious Proxy",
        "expected_score": 17,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.80, "description": "Upgradeable without timelock - can change to malicious code"},
            {"severity": "medium", "confidence": 0.65, "description": "No upgrade delay or governance requirement"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": True,
            "suspicious_patterns": ["malicious_upgrade_path", "no_timelock"],
            "external_calls": 3, "size": 5000
        },
        "reason": "Upgradeable to scam"
    },
    {
        "name": "Fake Uniswap",
        "expected_score": 8,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.90, "description": "Impersonation: fake router steals swap input tokens"},
            {"severity": "critical", "confidence": 0.85, "description": "Swap function sends tokens to attacker instead of expected output"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": ["impersonation", "fake_swap"],
            "external_calls": 6, "size": 9000
        },
        "reason": "Impersonation attack"
    },
    {
        "name": "Blacklist Token",
        "expected_score": 21,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "high", "confidence": 0.80, "description": "Owner can blacklist any address instantly"},
            {"severity": "high", "confidence": 0.70, "description": "Arbitrary transfer blocking without appeal"},
            {"severity": "medium", "confidence": 0.55, "description": "Centralized blacklisting with no governance"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": ["blacklist"],
            "external_calls": 3, "size": 5800
        },
        "reason": "Arbitrary blacklisting"
    },
    {
        "name": "Pausable Scam",
        "expected_score": 16,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.85, "description": "Pause function can permanently trap all user funds"},
            {"severity": "high", "confidence": 0.70, "description": "No guaranteed unpause mechanism exists"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": ["malicious_pause"],
            "external_calls": 2, "size": 4800
        },
        "reason": "Can pause permanently"
    },
    {
        "name": "Fee Manipulator",
        "expected_score": 20,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "high", "confidence": 0.85, "description": "Owner can set transfer fee to 100%"},
            {"severity": "high", "confidence": 0.75, "description": "Dynamic fee with no maximum cap in contract"},
            {"severity": "medium", "confidence": 0.60, "description": "Fee beneficiary is owner-controlled address"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": ["fee_manipulation"],
            "external_calls": 3, "size": 6200
        },
        "reason": "Dynamic fee manipulation"
    },
    {
        "name": "Reflection Token Bug",
        "expected_score": 14,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.85, "description": "Integer overflow in reflection calculation at high supply"},
            {"severity": "high", "confidence": 0.80, "description": "Balance returns incorrect values after overflow"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": ["overflow_risk"],
            "external_calls": 2, "size": 7500
        },
        "reason": "Math overflow bugs"
    },
    {
        "name": "Unaudited DeFi",
        "expected_score": 19,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "high", "confidence": 0.75, "description": "Unaudited lending logic with complex interest model"},
            {"severity": "high", "confidence": 0.65, "description": "Potential flash loan attack vector in price calculation"},
            {"severity": "medium", "confidence": 0.55, "description": "Missing access controls on liquidation function"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": True,
            "suspicious_patterns": [],
            "external_calls": 10, "size": 16000
        },
        "reason": "Complex unaudited DeFi"
    },
    {
        "name": "Anonymous Deployer",
        "expected_score": 14,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.80, "description": "Obfuscated bytecode hides contract true purpose"},
            {"severity": "high", "confidence": 0.70, "description": "Anonymous deployer with no identity verification"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": ["obfuscated_logic", "anonymous_deploy"],
            "external_calls": 4, "size": 8000
        },
        "reason": "Suspicious obfuscated behavior"
    },
    {
        "name": "Hidden Backdoor",
        "expected_score": 3,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.95, "description": "Assembly-level backdoor hidden in fallback function"},
            {"severity": "critical", "confidence": 0.92, "description": "Hidden function selector for direct fund extraction"},
            {"severity": "high", "confidence": 0.85, "description": "Obfuscated privileged function bypasses all checks"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": True, "has_delegatecall": False,
            "suspicious_patterns": ["assembly_backdoor", "hidden_function"],
            "external_calls": 5, "size": 9500
        },
        "reason": "Most dangerous - assembly backdoor"
    },
    {
        "name": "Tax Token Scam",
        "expected_score": 12,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.90, "description": "99% sell tax hidden in bytecode transfer logic"},
            {"severity": "high", "confidence": 0.75, "description": "Tax rate dynamically changeable by owner"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": ["hidden_tax", "variable_tax"],
            "external_calls": 3, "size": 6500
        },
        "reason": "99% sell tax trap"
    },
    {
        "name": "Liquidity Trap",
        "expected_score": 13,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "critical", "confidence": 0.85, "description": "LP tokens cannot be withdrawn after deposit"},
            {"severity": "high", "confidence": 0.80, "description": "Fake lock mechanism has owner bypass function"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": ["fake_lock", "lp_trap"],
            "external_calls": 4, "size": 7200
        },
        "reason": "LP locked scam"
    },
    {
        "name": "Copycat Contract",
        "expected_score": 19,
        "is_verified": False,
        "vulnerabilities": [
            {"severity": "high", "confidence": 0.80, "description": "Cloned code with hidden malicious modifications"},
            {"severity": "high", "confidence": 0.70, "description": "Backdoor added to otherwise legitimate code pattern"},
            {"severity": "medium", "confidence": 0.60, "description": "Malicious code injection in token transfer logic"},
        ],
        "code_quality_issues": [],
        "bytecode_analysis": {
            "has_selfdestruct": False, "has_delegatecall": False,
            "suspicious_patterns": ["malicious_clone"],
            "external_calls": 5, "size": 8500
        },
        "reason": "Malicious clone of legitimate contract"
    },
]


def run_category_tests(category_name, tests, expected_range, tolerance=8):
    """Run tests for a category and return results."""
    print(f"\n{'='*80}")
    print(f" {category_name}")
    print(f" Expected Range: {expected_range[0]}-{expected_range[1]} | Tolerance: +/-{tolerance}")
    print(f"{'='*80}")
    
    results = []
    passed = 0
    failed = 0
    scores = []
    
    for test in tests:
        score_result = scoring_service.calculate_trust_score(
            vulnerabilities=test["vulnerabilities"],
            code_quality_issues=test.get("code_quality_issues", []),
            is_verified=test["is_verified"],
            bytecode_analysis=test.get("bytecode_analysis"),
            contract_address=test.get("address"),
        )
        
        actual = score_result.overall_score
        expected = test["expected_score"]
        diff = abs(actual - expected)
        in_range = expected_range[0] <= actual <= expected_range[1]
        within_tolerance = diff <= tolerance
        
        status = "PASS" if (in_range and within_tolerance) else "FAIL"
        if status == "PASS":
            passed += 1
        else:
            failed += 1
        
        fail_reason = ""
        if not in_range:
            fail_reason = f"OUT OF RANGE [{expected_range[0]}-{expected_range[1]}]"
        elif not within_tolerance:
            fail_reason = f"BEYOND TOLERANCE (+/-{tolerance})"
        
        scores.append(actual)
        results.append({
            "name": test["name"],
            "expected": expected,
            "actual": actual,
            "diff": diff,
            "status": status,
            "fail_reason": fail_reason,
            "risk_level": score_result.risk_level,
        })
        
        icon = "PASS" if status == "PASS" else "FAIL"
        print(f"  [{icon}] {test['name']:<30} Expected: {expected:>4} | Actual: {actual:>6.1f} | Diff: {diff:>5.1f} | {status} {fail_reason}")
    
    # Check for score uniqueness (relativity)
    unique_scores = len(set(scores))
    total = len(scores)
    print(f"\n  Result: {passed}/{total} passed ({passed/total*100:.0f}%)")
    print(f"  Uniqueness: {unique_scores}/{total} unique scores ({unique_scores/total*100:.0f}%)")
    if unique_scores < total:
        from collections import Counter
        dupes = {s: c for s, c in Counter(scores).items() if c > 1}
        print(f"  WARNING: Duplicate scores: {dupes}")
    if failed > 0:
        print(f"  WARNING: {failed} FAILURES need attention")
    
    return results, passed, failed, unique_scores


def main():
    print("=" * 80)
    print("  SENTINEL PROTOCOL - COMPREHENSIVE SCORING TEST")
    print("  Testing ALL 4 Categories (50 contracts)")
    print("  Focus: Accuracy, Transparency, and RELATIVE Differentiation")
    print("=" * 80)
    
    all_results = {}
    total_passed = 0
    total_failed = 0
    total_unique = 0
    total_contracts = 0
    
    # Category 1: Verified Safe (75-95)
    r1, p1, f1, u1 = run_category_tests(
        "CATEGORY 1: Verified Safe (75-95)",
        CATEGORY_1_TESTS, (75, 95), tolerance=8
    )
    all_results["cat1"] = r1
    total_passed += p1; total_failed += f1; total_unique += u1; total_contracts += len(CATEGORY_1_TESTS)
    
    # Category 2: Verified Unsafe (25-49)
    r2, p2, f2, u2 = run_category_tests(
        "CATEGORY 2: Verified Unsafe (25-49)",
        CATEGORY_2_TESTS, (25, 49), tolerance=8
    )
    all_results["cat2"] = r2
    total_passed += p2; total_failed += f2; total_unique += u2; total_contracts += len(CATEGORY_2_TESTS)
    
    # Category 3: Unverified Safe (50-74)
    r3, p3, f3, u3 = run_category_tests(
        "CATEGORY 3: Unverified Safe (50-74)",
        CATEGORY_3_TESTS, (50, 74), tolerance=8
    )
    all_results["cat3"] = r3
    total_passed += p3; total_failed += f3; total_unique += u3; total_contracts += len(CATEGORY_3_TESTS)
    
    # Category 4: Unverified Unsafe (0-24)
    r4, p4, f4, u4 = run_category_tests(
        "CATEGORY 4: Unverified Unsafe (0-24)",
        CATEGORY_4_TESTS, (0, 24), tolerance=8
    )
    all_results["cat4"] = r4
    total_passed += p4; total_failed += f4; total_unique += u4; total_contracts += len(CATEGORY_4_TESTS)
    
    # Summary
    total = total_passed + total_failed
    print(f"\n{'='*80}")
    print(f"  FINAL SUMMARY")
    print(f"{'='*80}")
    print(f"  Category 1 (Verified Safe):     {p1:>2}/{len(CATEGORY_1_TESTS)} passed  |  {u1}/{len(CATEGORY_1_TESTS)} unique scores")
    print(f"  Category 2 (Verified Unsafe):   {p2:>2}/{len(CATEGORY_2_TESTS)} passed  |  {u2}/{len(CATEGORY_2_TESTS)} unique scores")
    print(f"  Category 3 (Unverified Safe):   {p3:>2}/{len(CATEGORY_3_TESTS)} passed  |  {u3}/{len(CATEGORY_3_TESTS)} unique scores")
    print(f"  Category 4 (Unverified Unsafe): {p4:>2}/{len(CATEGORY_4_TESTS)} passed  |  {u4}/{len(CATEGORY_4_TESTS)} unique scores")
    print(f"  {'='*60}")
    print(f"  TOTAL: {total_passed}/{total} passed ({total_passed/total*100:.0f}%)")
    print(f"  UNIQUE SCORES: {total_unique}/{total_contracts} ({total_unique/total_contracts*100:.0f}%)")
    
    if total_failed > 0:
        print(f"\n  {total_failed} tests FAILED - scoring needs adjustment")
        print(f"\n  FAILURES:")
        for cat_name, cat_results in [("Cat1", r1), ("Cat2", r2), ("Cat3", r3), ("Cat4", r4)]:
            for r in cat_results:
                if r["status"] == "FAIL":
                    print(f"    {cat_name}: {r['name']:<28} Expected: {r['expected']:>4} | Got: {r['actual']:>6.1f} | {r['fail_reason']}")
    else:
        print(f"\n  ALL TESTS PASSED! Scoring is properly calibrated with relative differentiation.")
    
    return total_failed


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
