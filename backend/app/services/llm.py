"""
LLM service for AI-powered smart contract analysis using Groq
"""

from openai import OpenAI
from typing import List, Dict, Any, Optional
import json
import logging
import re

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class LLMService:
    """
    LLM service for smart contract analysis using Groq's API.
    
    Uses Llama 3.1 70B via Groq for fast, high-quality security analysis.
    """
    
    def __init__(self):
        self.client = OpenAI(
            api_key=settings.CEREBRAS_API_KEY,
            base_url=settings.LLM_BASE_URL
        )
        self.model = settings.LLM_MODEL
        self.max_tokens = settings.LLM_MAX_TOKENS
        self.temperature = settings.LLM_TEMPERATURE
    
    async def analyze_source_code(
        self, 
        source_code: str,
        contract_name: str = "Unknown",
        rag_context: str = "",
    ) -> Dict[str, Any]:
        """
        Analyze verified source code for vulnerabilities.
        
        Args:
            source_code: Solidity source code
            contract_name: Name of the contract
            rag_context: Relevant vulnerability patterns from RAG
        
        Returns:
            Analysis results with vulnerabilities and recommendations
        """
        system_prompt = """You are an expert smart contract security auditor. Identify EXPLOITABLE vulnerabilities with PROOF OF CONCEPT.

⚠️  CRITICAL: Only report HIGH/CRITICAL if you can prove a REAL exploit path. Low-confidence guesses should be MEDIUM or LOW.

🔴 CRITICAL - Must have PROVEN exploit path:
- Reentrancy: ONLY if state changes AFTER external call AND attacker controls the call target
- Unprotected Self-Destruct: ONLY if selfdestruct is callable by anyone (not onlyOwner)
- Arbitrary External Call: ONLY if untrusted user input determines the target (not admin-controlled)
- Public Minting: ONLY if ANY user can mint unlimited tokens (not onlyOwner)

🟠 HIGH - Exploitable with specific conditions:
- Overflow in <0.8.0 WITHOUT SafeMath usage
- Access control bypass (not mitigations like require/onlyOwner)

🟡 MEDIUM - Design concerns, not exploits:
- Centralization (owner powers are by design, not vulnerabilities)
- Missing events

🟢 LOW - Non-security:
- Old compiler version (if code is otherwise secure)
- Gas optimizations

✅ **SAFE PATTERNS - DO NOT FLAG AS VULNERABILITIES:**
1. **ERC20 Standard Functions:**
   - `transfer`, `transferFrom`, `approve` → ALWAYS SAFE unless you find SPECIFIC exploit
   - These update balances ATOMICALLY and are NOT vulnerable to reentrancy
   
2. **Admin Functions (onlyOwner/onlyController):**
   - `deprecate`, `issue`, `redeem`, `setParams` when protected by `onlyOwner` → SAFE (admin privilege by design)
   - External calls in admin functions → SAFE (controlled by trusted party)
   
3. **SafeMath or Solidity >=0.8.0:**
   - ANY contract using SafeMath or v0.8+ → NO overflow vulnerabilities
   
4. **Proxy Patterns:**
   - `upgradeTo`, `upgradeToAndCall` with `onlyOwner` → SAFE (standard proxy pattern)

❌ **COMMON FALSE POSITIVES TO AVOID:**
1. ❌ "Reentrancy in transfer" → ERC20 transfers are SAFE (state updates first)
2. ❌ "Unprotected admin function" → If it HAS `onlyOwner`, it IS protected
3. ❌ "Arbitrary external call in deprecate" → If `onlyOwner`, it's SAFE (by design)
4. ❌ "Overflow possible" → If using SafeMath or >=0.8.0, NO overflows possible

🔍 **ANALYSIS PROCESS:**
1. Read the ENTIRE function first
2. Check for protective modifiers (`onlyOwner`, `require`)
3. Check SafeMath usage or Solidity version
4. Find the EXACT exploit path before flagging as HIGH/CRITICAL
5. If unsure, use LOWER severity (MEDIUM/LOW, not CRITICAL)

Return JSON with 'vulnerabilities' array. Each HIGH/CRITICAL vulnerability MUST include:
- Exact function name where exploit occurs
- Line of code that creates the vulnerability
- Step-by-step attack scenario showing HOW to exploit it
- Why existing protections FAIL to prevent the attack

If you cannot provide all of the above, downgrade severity to MEDIUM or LOW."""

        user_prompt = f"""Analyze this contract for EXPLOITABLE vulnerabilities with PROOF OF CONCEPT.

Contract: {contract_name}
Compiler: {source_code.split('pragma solidity')[1].split(';')[0] if 'pragma solidity' in source_code else 'Unknown'}

BEFORE marking HIGH/CRITICAL, CHECK:
1. Does contract use `using SafeMath for uint256`? → Overflows are PROTECTED
2. Do transfers update state AFTER external calls? → Reentrancy PROTECTED  
3. Are sensitive functions (mint/issue/transferOwnership) owner-only? → Access control PROTECTED

ONLY flag as HIGH/CRITICAL if protection is MISSING and exploit is POSSIBLE.

{rag_context}

Source Code:
```solidity
{source_code[:15000]}
```

For each HIGH/CRITICAL vulnerability, provide:
1. Exact function name + vulnerable line
2. Why existing protections fail (e.g., "no SafeMath", "external call before state update")
3. Step-by-step attack scenario

If all operations use SafeMath / proper access control→ DO NOT flag overflows/access issues.
If old Solidity but secure patterns → Mark compiler as LOW only.
{{
    "vulnerabilities": [
        {{
            "id": "vuln-1",
            "name": "Vulnerability Name",
            "severity": "critical|high|medium|low|informational",
            "description": "Detailed description of the vulnerability",
            "location": "Function or code location",
            "recommendation": "How to fix this issue",
            "confidence": 0.95,
            "cwe_id": "CWE-XXX if applicable"
        }}
    ],
    "code_quality_issues": [
        {{
            "issue": "Issue description",
            "severity": "low|informational",
            "recommendation": "Suggestion"
        }}
    ],
    "gas_optimizations": [
        {{
            "description": "Optimization opportunity",
            "potential_savings": "Estimated gas savings"
        }}
    ],
    "summary": "Brief overall assessment of the contract's security posture",
    "risk_level": "Critical|High|Medium|Low|Safe",
    "recommendations": ["List of general recommendations"]
}}"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature,
            )
            
            result_text = response.choices[0].message.content
            
            # Parse JSON from response
            analysis = self._parse_json_response(result_text)
            
            if analysis:
                # Post-process to filter false positives
                analysis = self._filter_false_positives(analysis, source_code)
                return analysis
            else:
                return self._create_error_response("Failed to parse LLM response")
                
        except Exception as e:
            logger.error(f"LLM analysis error: {e}")
            return self._create_error_response(str(e))
    
    def _filter_false_positives(self, analysis: dict, source_code: str) -> dict:
        """
        AGGRESSIVE FALSE POSITIVE FILTER
        
        Completely removes false positives instead of downgrading them.
        This is necessary because the LLM is overly cautious with older contracts.
        """
        vulnerabilities = analysis.get("vulnerabilities", [])
        filtered_vulns = []
        source_lower = source_code.lower()
        removed_count = 0
        
        logger.info(f"🔍 FILTER STARTING: Processing {len(vulnerabilities)} vulnerabilities")
        
        for vuln in vulnerabilities:
            name_lower = vuln.get("name", "").lower()
            desc_lower = vuln.get("description", "").lower()
            severity = vuln.get("severity", "").lower()
            location = vuln.get("location", "").lower()
            full_text = (name_lower + desc_lower + location).lower()
            
            should_remove = False
            removal_reason = ""
            
            # Filter 1: ERC20 standard functions are NEVER vulnerable to reentrancy
            if "reentrancy" in name_lower and severity in ["critical", "high"]:
                erc20_funcs = ["transfer", "transferfrom", "approve", "increaseallowance", "decreaseallowance"]
                if any(func in location for func in erc20_funcs):
                    should_remove = True
                    removal_reason = "ERC20 standard functions update state before external calls - NOT vulnerable to reentrancy"
            
            # Filter 2: Admin functions with access control are NOT vulnerabilities
            if severity in ["critical", "high"]:
                admin_keywords = ["unprotected", "arbitrary", "unrestricted"]
                admin_funcs = ["issue", "redeem", "deprecate", "setparams", "upgrade", "setstatus", "pause", "unpause", "migrate"]
                
                has_admin_keyword = any(kw in full_text for kw in admin_keywords)
                mentions_admin_func = any(func in full_text for func in admin_funcs)
                has_access_control = "onlyowner" in source_lower or "require(msg.sender == owner)" in source_lower
                
                if has_admin_keyword and mentions_admin_func and has_access_control:
                    should_remove = True
                    removal_reason = "Admin-only functions with access control are by design, not vulnerabilities"
            
            # Filter 3: Overflows when SafeMath is used
            if ("overflow" in name_lower or "underflow" in name_lower) and severity in ["critical", "high"]:
                if "using safemath" in source_lower or "safemath" in source_lower:
                    should_remove = True
                    removal_reason = "Contract uses SafeMath - overflows are mathematically impossible"
            
            # Filter 4: Centralization marked as critical/high - This is design, not vulnerability
            if ("centralization" in name_lower or "centralized" in name_lower) and severity in ["critical", "high"]:
                should_remove = True
                removal_reason = "Centralization is a design choice, not a security vulnerability (downgrade to informational if needed)"
            
            if should_remove:
                removed_count += 1
                logger.warning(f"🗑️  REMOVED FALSE POSITIVE [{severity.upper()}]: {vuln.get('name')} | Reason: {removal_reason}")
            else:
                filtered_vulns.append(vuln)
        
        analysis["vulnerabilities"] = filtered_vulns
        
        if removed_count > 0:
            logger.info(f"✅ Filtered out {removed_count} false positive vulnerability(ies)")
        
        return analysis
    
    async def analyze_bytecode(
        self, 
        bytecode: str,
        bytecode_analysis: Dict[str, Any],
        contract_address: str,
    ) -> Dict[str, Any]:
        """
        Analyze non-verified contract using bytecode patterns.
        
        This provides limited but useful analysis based on:
        - Opcode patterns
        - Known vulnerability signatures
        - Contract characteristics
        
        Args:
            bytecode: Contract bytecode
            bytecode_analysis: Pre-analyzed bytecode patterns
            contract_address: Contract address for context
        
        Returns:
            Analysis results
        """
        system_prompt = """You are an expert smart contract security analyst specializing in bytecode analysis. While source code is not available, you can identify potential security concerns based on bytecode patterns and characteristics.

Analyze the provided bytecode analysis and identify:
1. Potential security concerns based on opcode usage
2. Risk factors based on contract characteristics
3. Recommendations for users interacting with this contract

Be conservative with severity ratings since source code is not available.

CONFIDENCE SCORING RUBRIC (assign precise confidence for each finding):
- 0.85: Strong bytecode evidence (exact opcode pattern matches known exploit)
- 0.70: Moderate evidence (concerning opcode combinations)
- 0.55: Weak evidence (suspicious but inconclusive patterns)
- 0.40: Very weak (theoretical concern from bytecode characteristics)

IMPORTANT: Use DIFFERENT confidence values for each finding based on bytecode evidence strength.
Do NOT assign the same confidence to all findings.

Respond in valid JSON format only."""

        # Get RAG context for bytecode patterns
        from app.services.rag import rag_service
        bytecode_rag_context = ""
        if bytecode_analysis:
            # Build a query from bytecode characteristics for RAG lookup
            rag_query_parts = []
            if bytecode_analysis.get("has_selfdestruct"):
                rag_query_parts.append("selfdestruct opcode contract destruction")
            if bytecode_analysis.get("has_delegatecall"):
                rag_query_parts.append("delegatecall proxy storage corruption")
            if bytecode_analysis.get("has_create2"):
                rag_query_parts.append("create2 factory deployment")
            for pattern in bytecode_analysis.get("suspicious_patterns", []):
                rag_query_parts.append(pattern.replace("_", " "))
            if rag_query_parts:
                rag_query = " ".join(rag_query_parts)
                bytecode_rag_context = rag_service.get_context_for_analysis(rag_query)
        
        # Build context from bytecode analysis
        bytecode_context = f"""
Bytecode Analysis Results:
- Contract Size: {bytecode_analysis.get('size', 'Unknown')} bytes
- Contains SELFDESTRUCT: {bytecode_analysis.get('has_selfdestruct', False)}
- Contains DELEGATECALL: {bytecode_analysis.get('has_delegatecall', False)}
- Contains CREATE: {bytecode_analysis.get('has_create', False)}
- Contains CREATE2: {bytecode_analysis.get('has_create2', False)}
- External Calls Count: {bytecode_analysis.get('external_calls', 0)}

Pre-identified Issues:
{json.dumps(bytecode_analysis.get('potential_issues', []), indent=2)}
"""

        user_prompt = f"""Analyze this unverified smart contract at address {contract_address}.

{bytecode_context}

{bytecode_rag_context}

Since source code is not available, provide a cautious risk assessment based on the bytecode patterns.

Respond in JSON format:
{{
    "vulnerabilities": [
        {{
            "id": "bytecode-vuln-1",
            "name": "Potential Issue Name",
            "severity": "high|medium|low|informational",
            "description": "Description based on bytecode patterns",
            "location": "bytecode",
            "recommendation": "Recommendation for users",
            "confidence": 0.6,
            "cwe_id": null
        }}
    ],
    "bytecode_findings": {{
        "dangerous_opcodes": ["list of concerning opcodes found"],
        "risk_indicators": ["list of risk indicators"]
    }},
    "summary": "Assessment of unverified contract risk",
    "risk_level": "Critical|High|Medium|Low|Unknown",
    "recommendations": [
        "Recommendations for interacting with this unverified contract"
    ],
    "verification_warning": "Strong recommendation to interact only with verified contracts"
}}"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature,
            )
            
            result_text = response.choices[0].message.content
            analysis = self._parse_json_response(result_text)
            
            if analysis:
                # Add flag indicating bytecode-only analysis
                analysis["analysis_type"] = "bytecode_only"
                analysis["source_available"] = False
                return analysis
            else:
                logger.warning("LLMfailed to parse, returning minimal baseline analysis for unverified contract")
                return self._create_minimal_bytecode_analysis(bytecode_analysis)
                
        except Exception as e:
            logger.error(f"Bytecode analysis error: {e}, returning minimal baseline")
            return self._create_minimal_bytecode_analysis(bytecode_analysis)
    
    def _create_minimal_bytecode_analysis(self, bytecode_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Create minimal safe analysis for unverified contracts when LLM fails"""
        vulnerabilities = []
        
        # Only flag truly dangerous patterns found in bytecode
        if bytecode_analysis.get("has_selfdestruct"):
            vulnerabilities.append({
                "id": "bytecode-selfdestruct",
                "name": "SELFDESTRUCT opcode present",
                "severity": "high",
                "description": "Contract contains SELFDESTRUCT opcode which can destroy the contract",
                "location": "bytecode",
                "recommendation": "Verify contract purpose before interacting",
                "confidence": 0.8,
                "cwe_id": None
            })
        
        if bytecode_analysis.get("has_delegatecall"):
            vulnerabilities.append({
                "id": "bytecode-delegatecall",
                "name": "DELEGATECALL opcode present",
                "severity": "medium",
                "description": "Contract uses DELEGATECALL which can be risky if not properly controlled",
                "location": "bytecode",
                "recommendation": "Exercise caution with unverified contracts using delegatecall",
                "confidence": 0.7,
                "cwe_id": None
            })
        
        return {
            "vulnerabilities": vulnerabilities,
            "code_quality_issues": [],
            "gas_optimizations": [],
            "summary": "Limited analysis available for unverified contract. Bytecode patterns analyzed.",
            "risk_level": "Medium" if len(vulnerabilities) == 0 else "High",
            "recommendations": [
                "Source code not verified - consider requesting verification",
                "Exercise caution when interacting with unverified contracts",
                "Verify contract behavior through testing before use"
            ],
            "analysis_type": "bytecode_only",
            "source_available": False,
        }
    
    def _parse_json_response(self, text: str) -> Optional[Dict[str, Any]]:
        """Parse JSON from LLM response, handling common formatting issues"""
        try:
            # Try direct JSON parse
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        
        # Try to extract JSON from markdown code blocks
        json_patterns = [
            r"```json\s*([\s\S]*?)\s*```",
            r"```\s*([\s\S]*?)\s*```",
            r"\{[\s\S]*\}",
        ]
        
        for pattern in json_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                try:
                    return json.loads(match)
                except json.JSONDecodeError:
                    continue
        
        logger.warning(f"Could not parse JSON from response: {text[:200]}...")
        return None
    
    def _create_error_response(self, error_message: str) -> Dict[str, Any]:
        """Create a standardized error response"""
        return {
            "vulnerabilities": [],
            "code_quality_issues": [],
            "gas_optimizations": [],
            "summary": f"Analysis could not be completed: {error_message}",
            "risk_level": "Unknown",
            "recommendations": ["Unable to provide recommendations due to analysis error"],
            "error": error_message,
        }
    
    async def generate_insights_summary(
        self, 
        vulnerabilities: List[Dict[str, Any]],
        contract_name: str = "Unknown"
    ) -> str:
        """
        Generate a human-readable summary of findings.
        
        Args:
            vulnerabilities: List of found vulnerabilities
            contract_name: Contract name
        
        Returns:
            Human-readable summary string
        """
        if not vulnerabilities:
            return f"No significant security vulnerabilities were identified in {contract_name}. The contract appears to follow security best practices."
        
        # Count by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        prompt = f"""Based on these vulnerability findings for contract "{contract_name}":

Severity Distribution:
{json.dumps(severity_counts, indent=2)}

Vulnerabilities Found:
{json.dumps([{"name": v.get("name"), "severity": v.get("severity"), "description": v.get("description", "")[:100]} for v in vulnerabilities[:5]], indent=2)}

Write a concise 2-3 sentence summary of the security assessment suitable for non-technical users. Focus on the overall risk level and most critical concerns."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=200,
                temperature=0.3,
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            logger.error(f"Error generating summary: {e}")
            
            # Fallback summary
            total = len(vulnerabilities)
            critical = severity_counts.get("critical", 0)
            high = severity_counts.get("high", 0)
            
            if critical > 0:
                return f"⚠️ CRITICAL: {contract_name} has {critical} critical and {high} high severity vulnerabilities. Exercise extreme caution."
            elif high > 0:
                return f"⚠️ WARNING: {contract_name} has {high} high severity vulnerabilities that should be addressed before interaction."
            else:
                return f"ℹ️ {contract_name} has {total} findings of lower severity. Review recommended before interaction."
    
    def check_health(self) -> bool:
        """Check if LLM service is healthy"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "Reply with 'OK'"}],
                max_tokens=10,
            )
            return "ok" in response.choices[0].message.content.lower()
        except Exception as e:
            logger.error(f"LLM health check failed: {e}")
            return False


# Singleton instance
llm_service = LLMService()
