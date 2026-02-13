"""
LLM Output Validator - validates and sanitizes all LLM analysis responses
before they are used in scoring.

Ensures:
1. Required fields exist and have correct types
2. Severity values are valid
3. Confidence scores are in range and diversified
4. Descriptions are meaningful (not vague/empty)
5. Vulnerability count is reasonable for contract complexity
6. Cross-validates severity vs. confidence consistency
"""

from typing import Dict, List, Any, Tuple
import logging
import re
from collections import Counter

logger = logging.getLogger(__name__)


# Valid severity values
VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}

# Minimum description length to be considered meaningful
MIN_DESCRIPTION_LENGTH = 15

# Maximum vulnerabilities expected from a single analysis
MAX_REASONABLE_VULNS = 30

# Confidence bounds
MIN_CONFIDENCE = 0.0
MAX_CONFIDENCE = 1.0
DEFAULT_CONFIDENCE = 0.5


class LLMValidator:
    """
    Validates and sanitizes LLM analysis output.
    
    Returns a validated result with:
    - is_valid: whether the output is usable
    - cleaned_output: sanitized version of the output
    - validation_report: details of issues found
    - quality_score: 0.0-1.0 quality rating
    """

    def validate_analysis(self, raw_output: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point: validate a full LLM analysis response.
        
        Returns:
            {
                "is_valid": bool,
                "cleaned_output": dict,      # sanitized output ready for use
                "validation_report": dict,    # detailed report of checks
                "quality_score": float,       # 0.0-1.0
            }
        """
        issues = []       # Hard failures
        warnings = []     # Soft issues (output still usable)
        fixes_applied = []  # Auto-corrections made
        
        # ---- 1. Check top-level structure ----
        if not isinstance(raw_output, dict):
            return self._fail("LLM output is not a dictionary")
        
        if "error" in raw_output:
            return self._fail(f"LLM returned an error: {raw_output['error']}")
        
        cleaned = dict(raw_output)  # shallow copy
        
        # ---- 2. Validate vulnerabilities array ----
        vulns = raw_output.get("vulnerabilities")
        if vulns is None:
            vulns = []
            fixes_applied.append("Added empty vulnerabilities array (was missing)")
        
        if not isinstance(vulns, list):
            issues.append("'vulnerabilities' is not a list")
            vulns = []
            fixes_applied.append("Reset vulnerabilities to empty list (invalid type)")
        
        if len(vulns) > MAX_REASONABLE_VULNS:
            warnings.append(
                f"Excessive vulnerabilities ({len(vulns)}), truncating to {MAX_REASONABLE_VULNS}"
            )
            vulns = vulns[:MAX_REASONABLE_VULNS]
            fixes_applied.append(f"Truncated to {MAX_REASONABLE_VULNS} vulnerabilities")
        
        # ---- 3. Validate each vulnerability ----
        cleaned_vulns = []
        for i, v in enumerate(vulns):
            vuln_result = self._validate_vulnerability(v, i)
            if vuln_result["usable"]:
                cleaned_vulns.append(vuln_result["cleaned"])
                warnings.extend(vuln_result["warnings"])
                fixes_applied.extend(vuln_result["fixes"])
            else:
                warnings.append(f"Vulnerability {i} dropped: {vuln_result['reason']}")
        
        cleaned["vulnerabilities"] = cleaned_vulns
        
        # ---- 4. Check confidence diversity ----
        diversity_result = self._check_confidence_diversity(cleaned_vulns)
        warnings.extend(diversity_result["warnings"])
        if diversity_result["needs_adjustment"]:
            cleaned["vulnerabilities"] = diversity_result["adjusted_vulns"]
            fixes_applied.append("Adjusted duplicate confidence values for differentiation")
        
        # ---- 5. Cross-validate severity vs confidence ----
        consistency_warnings = self._check_severity_confidence_consistency(
            cleaned["vulnerabilities"]
        )
        warnings.extend(consistency_warnings)
        
        # ---- 6. Validate summary & recommendations ----
        if not raw_output.get("summary") or not isinstance(raw_output.get("summary"), str):
            cleaned["summary"] = "Analysis completed."
            fixes_applied.append("Added default summary (was missing/invalid)")
        
        if not raw_output.get("recommendations") or not isinstance(
            raw_output.get("recommendations"), list
        ):
            cleaned["recommendations"] = []
            if cleaned_vulns:
                cleaned["recommendations"].append(
                    "Review identified vulnerabilities and apply recommended fixes."
                )
            fixes_applied.append("Reset recommendations to default")
        
        if not raw_output.get("risk_level") or raw_output.get("risk_level") not in {
            "Critical", "High", "Medium", "Low", "Safe", "Unknown"
        }:
            # Infer from vulnerabilities
            cleaned["risk_level"] = self._infer_risk_level(cleaned_vulns)
            fixes_applied.append(f"Inferred risk_level: {cleaned['risk_level']}")
        
        # ---- 7. Validate code_quality_issues ----
        cqi = raw_output.get("code_quality_issues")
        if cqi is not None and isinstance(cqi, list):
            cleaned["code_quality_issues"] = [
                q for q in cqi
                if isinstance(q, dict) and q.get("issue")
            ]
        else:
            cleaned["code_quality_issues"] = cleaned.get("code_quality_issues", [])
        
        # ---- 8. Calculate quality score ----
        quality_score = self._calculate_quality_score(
            issues, warnings, fixes_applied, cleaned_vulns
        )
        
        is_valid = len(issues) == 0
        
        report = {
            "is_valid": is_valid,
            "issues": issues,
            "warnings": warnings,
            "fixes_applied": fixes_applied,
            "vulnerability_count": len(cleaned_vulns),
            "quality_score": quality_score,
        }
        
        if not is_valid:
            logger.warning(f"LLM output validation FAILED: {issues}")
        elif warnings:
            logger.info(
                f"LLM output validated with {len(warnings)} warnings, "
                f"{len(fixes_applied)} auto-fixes. Quality: {quality_score:.2f}"
            )
        else:
            logger.info(f"LLM output validated cleanly. Quality: {quality_score:.2f}")
        
        return {
            "is_valid": is_valid,
            "cleaned_output": cleaned,
            "validation_report": report,
            "quality_score": quality_score,
        }

    # ================================================================
    # Per-vulnerability validation
    # ================================================================

    def _validate_vulnerability(
        self, vuln: Any, index: int
    ) -> Dict[str, Any]:
        """Validate a single vulnerability entry."""
        warnings = []
        fixes = []
        
        if not isinstance(vuln, dict):
            return {"usable": False, "reason": "not a dictionary", "warnings": [], "fixes": []}
        
        cleaned = dict(vuln)
        
        # -- severity --
        sev = str(vuln.get("severity", "")).lower().strip()
        if sev not in VALID_SEVERITIES:
            # Try fuzzy match
            sev = self._fuzzy_severity(sev)
            if sev:
                fixes.append(f"vuln-{index}: corrected severity to '{sev}'")
            else:
                sev = "informational"
                fixes.append(f"vuln-{index}: defaulted severity to 'informational'")
        cleaned["severity"] = sev
        
        # -- confidence --
        conf = vuln.get("confidence")
        if conf is None:
            conf = DEFAULT_CONFIDENCE
            fixes.append(f"vuln-{index}: defaulted confidence to {DEFAULT_CONFIDENCE}")
        else:
            try:
                conf = float(conf)
            except (TypeError, ValueError):
                conf = DEFAULT_CONFIDENCE
                fixes.append(f"vuln-{index}: invalid confidence, defaulted to {DEFAULT_CONFIDENCE}")
        
        conf = max(MIN_CONFIDENCE, min(MAX_CONFIDENCE, conf))
        cleaned["confidence"] = round(conf, 2)
        
        # -- description --
        desc = str(vuln.get("description", "")).strip()
        if len(desc) < MIN_DESCRIPTION_LENGTH:
            warnings.append(
                f"vuln-{index}: description too short ({len(desc)} chars): '{desc[:50]}'"
            )
        cleaned["description"] = desc if desc else "No description provided"
        
        # -- name --
        name = str(vuln.get("name", "")).strip()
        if not name:
            name = f"Unnamed Vulnerability {index + 1}"
            fixes.append(f"vuln-{index}: assigned default name")
        cleaned["name"] = name
        
        # -- id --
        if not vuln.get("id"):
            cleaned["id"] = f"vuln-{index + 1}"
        
        # -- location (optional) --
        if vuln.get("location"):
            cleaned["location"] = str(vuln["location"]).strip()
        
        # -- recommendation --
        rec = str(vuln.get("recommendation", "")).strip()
        if not rec:
            rec = "Review and remediate this finding."
            fixes.append(f"vuln-{index}: added default recommendation")
        cleaned["recommendation"] = rec
        
        return {
            "usable": True,
            "cleaned": cleaned,
            "warnings": warnings,
            "fixes": fixes,
            "reason": None,
        }

    # ================================================================
    # Confidence diversity check
    # ================================================================

    def _check_confidence_diversity(
        self, vulns: List[Dict]
    ) -> Dict[str, Any]:
        """
        Check that confidence values are diverse (not all the same).
        If all identical, jitter them slightly so scoring differentiates.
        """
        if len(vulns) < 2:
            return {"warnings": [], "needs_adjustment": False, "adjusted_vulns": vulns}
        
        confidences = [v["confidence"] for v in vulns]
        unique = set(confidences)
        
        warnings = []
        if len(unique) == 1 and len(vulns) > 1:
            warnings.append(
                f"All {len(vulns)} vulnerabilities have identical confidence "
                f"({confidences[0]}). Applying micro-jitter for differentiation."
            )
            adjusted = []
            for i, v in enumerate(vulns):
                v_copy = dict(v)
                # Spread by ±0.05 around original
                offset = (i - len(vulns) / 2) * 0.03
                v_copy["confidence"] = round(
                    max(0.1, min(0.99, v["confidence"] + offset)), 2
                )
                adjusted.append(v_copy)
            return {"warnings": warnings, "needs_adjustment": True, "adjusted_vulns": adjusted}
        
        # Check for too many duplicates (>60% same value)
        counts = Counter(confidences)
        most_common_val, most_common_count = counts.most_common(1)[0]
        if most_common_count / len(vulns) > 0.6 and len(vulns) >= 3:
            warnings.append(
                f"{most_common_count}/{len(vulns)} vulnerabilities share confidence "
                f"{most_common_val}. Consider more granular assessment."
            )
        
        return {"warnings": warnings, "needs_adjustment": False, "adjusted_vulns": vulns}

    # ================================================================
    # Severity-confidence consistency
    # ================================================================

    def _check_severity_confidence_consistency(
        self, vulns: List[Dict]
    ) -> List[str]:
        """
        Warn if severity and confidence are inconsistent.
        E.g., critical severity with very low confidence is suspicious.
        """
        warnings = []
        for v in vulns:
            sev = v.get("severity", "")
            conf = v.get("confidence", 0.5)
            
            if sev == "critical" and conf < 0.4:
                warnings.append(
                    f"'{v.get('name', '?')}': critical severity with low confidence "
                    f"({conf}). Consider downgrading severity or reviewing evidence."
                )
            if sev == "informational" and conf > 0.9:
                warnings.append(
                    f"'{v.get('name', '?')}': informational severity with very high "
                    f"confidence ({conf}). Consider upgrading severity if impactful."
                )
            if sev == "low" and conf > 0.95:
                warnings.append(
                    f"'{v.get('name', '?')}': low severity with confidence {conf} > 0.95. "
                    f"Verify this isn't under-categorized."
                )
        return warnings

    # ================================================================
    # Helpers
    # ================================================================

    def _fuzzy_severity(self, raw: str) -> str | None:
        """Try to match a garbled severity string."""
        raw = raw.lower().strip()
        for valid in VALID_SEVERITIES:
            if valid.startswith(raw) or raw.startswith(valid):
                return valid
        # Common LLM typos
        aliases = {
            "crit": "critical", "hi": "high", "med": "medium",
            "lo": "low", "info": "informational", "warning": "medium",
            "moderate": "medium", "severe": "high", "important": "high",
        }
        return aliases.get(raw)

    def _infer_risk_level(self, vulns: List[Dict]) -> str:
        """Infer risk level from vulnerability severities."""
        if not vulns:
            return "Safe"
        severities = [v.get("severity", "") for v in vulns]
        if "critical" in severities:
            return "Critical"
        if "high" in severities:
            return "High"
        if "medium" in severities:
            return "Medium"
        return "Low"

    def _calculate_quality_score(
        self,
        issues: List[str],
        warnings: List[str],
        fixes: List[str],
        vulns: List[Dict],
    ) -> float:
        """
        Calculate a quality score for the LLM output.
        1.0 = perfect output, 0.0 = unusable.
        """
        score = 1.0
        
        # Hard issues kill quality
        score -= len(issues) * 0.3
        
        # Warnings reduce quality slightly
        score -= len(warnings) * 0.05
        
        # Auto-fixes indicate moderate quality
        score -= len(fixes) * 0.03
        
        # Bonus: diverse confidence values
        if len(vulns) >= 2:
            confs = [v["confidence"] for v in vulns]
            unique_ratio = len(set(confs)) / len(confs)
            if unique_ratio >= 0.8:
                score += 0.05  # bonus for diverse confidence
        
        # Bonus: all vulns have descriptions > 30 chars
        if vulns and all(len(v.get("description", "")) > 30 for v in vulns):
            score += 0.05
        
        return round(max(0.0, min(1.0, score)), 2)

    def _fail(self, reason: str) -> Dict[str, Any]:
        """Return a hard failure result."""
        logger.error(f"LLM validation hard failure: {reason}")
        return {
            "is_valid": False,
            "cleaned_output": {
                "vulnerabilities": [],
                "code_quality_issues": [],
                "summary": f"Validation failed: {reason}",
                "risk_level": "Unknown",
                "recommendations": [],
            },
            "validation_report": {
                "is_valid": False,
                "issues": [reason],
                "warnings": [],
                "fixes_applied": [],
                "vulnerability_count": 0,
                "quality_score": 0.0,
            },
            "quality_score": 0.0,
        }


# Singleton
llm_validator = LLMValidator()
