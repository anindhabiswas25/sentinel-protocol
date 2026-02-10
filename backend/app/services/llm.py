"""
LLM service for AI-powered smart contract analysis using Groq
"""

from groq import Groq
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
    
    Uses Llama 3.3 70B for fast, high-quality security analysis.
    """
    
    def __init__(self):
        self.client = Groq(api_key=settings.GROQ_API_KEY)
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
        system_prompt = """You are an expert smart contract security auditor with deep knowledge of Solidity, EVM, and blockchain security. Your task is to analyze smart contract code for security vulnerabilities, code quality issues, and best practice violations.

When analyzing code:
1. Identify specific vulnerabilities with exact locations (function names, line references if possible)
2. Assess the severity accurately (critical, high, medium, low, informational)
3. Provide actionable remediation recommendations
4. Consider both common vulnerabilities (reentrancy, access control, etc.) and context-specific issues
5. Evaluate code quality and gas optimization opportunities

You must respond in valid JSON format only."""

        user_prompt = f"""Analyze the following Solidity smart contract for security vulnerabilities and code quality issues.

Contract Name: {contract_name}

{rag_context}

Source Code:
```solidity
{source_code[:15000]}  // Truncated if too long
```

Provide your analysis in the following JSON format:
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
                return analysis
            else:
                return self._create_error_response("Failed to parse LLM response")
                
        except Exception as e:
            logger.error(f"LLM analysis error: {e}")
            return self._create_error_response(str(e))
    
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
Respond in valid JSON format only."""

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
                return self._create_error_response("Failed to parse LLM response")
                
        except Exception as e:
            logger.error(f"Bytecode analysis error: {e}")
            return self._create_error_response(str(e))
    
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
