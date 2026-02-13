"""
Gemini Pro LLM service for AI-powered smart contract analysis
"""

import google.generativeai as genai
from typing import Dict, Any, Optional
import json
import logging
import re

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class GeminiService:
    """
    Gemini Pro service for smart contract analysis.
    
    Uses Google's Gemini Pro for fast, accurate security analysis.
    """
    
    def __init__(self):
        """Initialize Gemini Pro API"""
        api_key = settings.GEMINI_API_KEY
        if not api_key:
            raise ValueError("GEMINI_API_KEY not configured")
        
        genai.configure(api_key=api_key)
        
        # Configure generation settings
        self.generation_config = {
            "temperature": 0.1,  # Low temperature for consistency
            "top_p": 0.95,
            "top_k": 40,
            "max_output_tokens": 2048,
        }
        
        # Safety settings (allow code analysis)
        self.safety_settings = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        ]
        
        self.model = genai.GenerativeModel(
            model_name='gemini-2.5-flash',  # Fast and accurate model
            generation_config=self.generation_config,
            safety_settings=self.safety_settings
        )
        
        logger.info("✅ Gemini Pro service initialized successfully")
    
    async def analyze_source_code(
        self, 
        source_code: str,
        contract_name: str = "Unknown",
        rag_context: str = "",
        exploit_context: Optional[Dict] = None  # NEW: Exploit context from dynamic detector
    ) -> Dict[str, Any]:
        """
        Analyze verified source code for vulnerabilities using Gemini Pro.
        
        Args:
            source_code: Solidity source code
            contract_name: Name of the contract
            rag_context: Relevant vulnerability patterns from RAG
            exploit_context: Known exploit information if contract is flagged
        
        Returns:
            Analysis results with vulnerabilities and recommendations
        """
        try:
            logger.info(f"🤖 Analyzing contract '{contract_name}' with Gemini Pro")
            
            # Create analysis prompt
            prompt = self._create_analysis_prompt(source_code, contract_name, rag_context, exploit_context)
            
            # Get analysis from Gemini
            response = self.model.generate_content(prompt)
            
            # Parse response
            analysis = self._parse_gemini_response(response.text)
            
            logger.info(f"✅ Gemini analysis complete: {len(analysis.get('vulnerabilities', []))} vulnerabilities found")
            
            return analysis
            
        except Exception as e:
            logger.error(f"❌ Gemini analysis failed: {e}")
            return self._create_error_response(str(e))
    
    def _create_analysis_prompt(self, source_code: str, contract_name: str, rag_context: str, exploit_context: Optional[Dict] = None) -> str:
        """Create detailed analysis prompt for Gemini Pro"""
        
        # Add exploit warning if contract is known to be exploited
        exploit_warning = ""
        if exploit_context and exploit_context.get('is_known_exploit'):
            exploit_warning = f"""

⚠️⚠️⚠️ CRITICAL CONTEXT - KNOWN EXPLOIT ⚠️⚠️⚠️

This contract has been CONFIRMED as EXPLOITED by multiple security databases:
- Type: {exploit_context.get('exploit_type', 'Unknown')}
- Severity: {exploit_context.get('severity', 'High').upper()}
- Details: {exploit_context.get('description', 'No details available')}

Your analysis MUST reflect this known exploit status.
Focus on finding:
1. The specific vulnerability type mentioned above
2. Related attack vectors that enabled the exploit
3. Other security issues present in the code

This is NOT a false positive - the exploit has been confirmed.
"""
        
        system_context = """You are an expert smart contract security auditor specializing in Ethereum/Solidity contracts.

**CRITICAL GUIDELINES - READ CAREFULLY:**

1. **Well-Known Contracts Are SAFE**: 
   - USDT, USDC, DAI, WETH, Uniswap, Aave, Compound = SAFE (unless you find ACTUAL exploitable vulnerability)
   - Audited contracts from major protocols = SAFE
   - Standard ERC20/ERC721 implementations = SAFE

2. **What IS a Vulnerability:**
   - Reentrancy WITHOUT proper guards (checks-effects-interactions violated)
   - Missing access control on critical functions (no onlyOwner, no require checks)
   - Integer overflow in Solidity <0.8.0 WITHOUT SafeMath
   - Unchecked external calls that can drain funds
   - Logic bugs that allow unauthorized token minting/burning

3. **What is NOT a Vulnerability:**
   - Standard ERC20 functions (transfer, transferFrom, approve) - These are SAFE by design
   - Functions with `onlyOwner` modifier - These are protected
   - Functions with proper `require(msg.sender == owner)` checks - Protected
   - Use of Solidity 0.4.x or 0.5.x - Old versions are NOT vulnerabilities
   - Centralization/admin control - This is a design choice, NOT a security bug
   - Gas optimizations - Not security issues
   - SafeMath usage - This PREVENTS vulnerabilities

4. **ERC20 Pattern Recognition:**
   - `transfer()` with balance updates BEFORE call = SAFE (follows checks-effects-interactions)
   - `approve()` + `transferFrom()` = Standard pattern, SAFE
   - Balance checks before transfers = SAFE

5. **Admin Function Pattern:**
   - If function has `onlyOwner` or `require(msg.sender == owner)` = NOT VULNERABLE
   - Admin-controlled upgrades/pauses = Design feature, NOT vulnerability

**RESPONSE FORMAT:** Return ONLY valid JSON with this structure:
{
    "vulnerabilities": [
        {
            "name": "Vulnerability Name",
            "severity": "Critical|High|Medium|Low",
            "confidence": 0.0-1.0,
            "description": "Detailed description with evidence",
            "location": "function name or line reference",
            "impact": "What can an attacker do",
            "recommendation": "How to fix it"
        }
    ],
    "summary": "Brief overall assessment",
    "risk_assessment": "Low|Medium|High|Critical"
}

**If contract is SAFE (no real vulnerabilities), return:**
{"vulnerabilities": [], "summary": "Contract follows secure patterns. No exploitable vulnerabilities found.", "risk_assessment": "Low"}
"""
        
        user_prompt = f"""{exploit_warning}

Contract Name: {contract_name}

{f"Known Vulnerability Patterns:{rag_context}" if rag_context else ""}

Solidity Source Code:
```solidity
{source_code[:6000]}
```

Analyze this contract carefully. Remember: Only flag REAL, EXPLOITABLE vulnerabilities. {'Focus on the known exploit type mentioned above.' if exploit_warning else ''} Return valid JSON only."""

        full_prompt = f"{system_context}\n\n{user_prompt}"
        return full_prompt
    
    def _parse_gemini_response(self, response_text: str) -> Dict[str, Any]:
        """Parse Gemini's JSON response"""
        
        try:
            # Clean response text
            json_text = response_text.strip()
            
            # Remove markdown code blocks if present
            if '```json' in json_text:
                json_text = json_text.split('```json')[1].split('```')[0].strip()
            elif '```' in json_text:
                json_text = json_text.split('```')[1].split('```')[0].strip()
            
            # Parse JSON
            data = json.loads(json_text)
            
            # Extract and normalize vulnerabilities
            vulnerabilities = []
            for vuln in data.get('vulnerabilities', []):
                vulnerabilities.append({
                    'name': vuln.get('name', 'Unknown Vulnerability'),
                    'severity': vuln.get('severity', 'Low'),
                    'confidence': float(vuln.get('confidence', 0.7)),
                    'description': vuln.get('description', ''),
                    'location': vuln.get('location', ''),
                    'impact': vuln.get('impact', ''),
                    'recommendation': vuln.get('recommendation', '')
                })
            
            logger.info(f"✅ Parsed {len(vulnerabilities)} vulnerabilities from Gemini")
            
            return {
                'vulnerabilities': vulnerabilities,
                'summary': data.get('summary', 'Analysis complete'),
                'risk_assessment': data.get('risk_assessment', 'Medium'),
                'recommendations': [v['recommendation'] for v in vulnerabilities if v.get('recommendation')]
            }
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Gemini response as JSON: {e}")
            logger.debug(f"Response text: {response_text[:500]}")
            
            # Fallback: try to extract vulnerabilities from text
            return self._fallback_text_parsing(response_text)
    
    def _fallback_text_parsing(self, text: str) -> Dict[str, Any]:
        """Fallback when JSON parsing fails - analyze text directly"""
        
        text_lower = text.lower()
        
        # Check for safety indicators
        safe_indicators = ['no vulnerabilities', 'secure', 'safe', 'no issues found', 'follows best practices']
        unsafe_indicators = ['critical', 'high risk', 'vulnerable', 'exploit', 'reentrancy', 'overflow']
        
        is_safe = any(indicator in text_lower for indicator in safe_indicators)
        is_unsafe = any(indicator in text_lower for indicator in unsafe_indicators)
        
        if is_safe and not is_unsafe:
            return {
                'vulnerabilities': [],
                'summary': 'Contract appears secure based on analysis',
                'risk_assessment': 'Low',
                'recommendations': []
            }
        elif is_unsafe:
            # Extract potential vulnerabilities from text
            vulnerabilities = []
            if 'reentrancy' in text_lower:
                vulnerabilities.append({
                    'name': 'Potential Reentrancy',
                    'severity': 'High',
                    'confidence': 0.6,
                    'description': 'Possible reentrancy pattern detected',
                    'location': 'Unknown',
                    'impact': 'Review for proper guards',
                    'recommendation': 'Implement checks-effects-interactions pattern'
                })
            
            return {
                'vulnerabilities': vulnerabilities,
                'summary': 'Potential issues detected',
                'risk_assessment': 'Medium',
                'recommendations': ['Manual review recommended']
            }
        else:
            return {
                'vulnerabilities': [],
                'summary': 'Analysis completed',
                'risk_assessment': 'Medium',
                'recommendations': []
            }
    
    def _create_error_response(self, error_message: str) -> Dict[str, Any]:
        """Create error response when analysis fails"""
        return {
            'vulnerabilities': [],
            'summary': f'Analysis failed: {error_message}',
            'risk_assessment': 'Unknown',
            'recommendations': ['Manual review required due to analysis error'],
            'error': error_message
        }
    
    def check_health(self) -> bool:
        """Check if Gemini service is healthy"""
        try:
            # Simple test prompt
            response = self.model.generate_content("Test")
            return bool(response.text)
        except Exception as e:
            logger.error(f"Gemini health check failed: {e}")
            return False


# Create singleton instance
gemini_service = GeminiService()
