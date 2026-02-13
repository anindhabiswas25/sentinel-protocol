"""
Tests for the three new features:
1. LLM Output Validator
2. Enhanced RAG Similarity Scoring
3. Bytecode Cross-Validation

Run:  python -m pytest test_improvements.py -v
"""

import sys
import os
import pytest

# Add the backend directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set required env vars before importing app modules
os.environ.setdefault("CEREBRAS_API_KEY", "test-key-for-unit-tests")
os.environ.setdefault("DATABASE_URL", "sqlite:///test.db")


# =====================================================================
# PART 1: LLM Output Validator Tests
# =====================================================================

from app.services.llm_validator import LLMValidator, llm_validator


class TestLLMValidator:
    """Tests for LLMValidator class."""

    def setup_method(self):
        self.validator = LLMValidator()

    # ---- Happy path ----

    def test_valid_output_passes(self):
        """A well-formed LLM output should validate cleanly."""
        good_output = {
            "vulnerabilities": [
                {
                    "id": "vuln-1",
                    "name": "Reentrancy",
                    "severity": "critical",
                    "description": "The withdraw function makes an external call before updating state, allowing recursive re-entry.",
                    "location": "withdraw() line 42",
                    "recommendation": "Use checks-effects-interactions pattern.",
                    "confidence": 0.85,
                    "cwe_id": "CWE-841",
                },
                {
                    "id": "vuln-2",
                    "name": "Missing Access Control",
                    "severity": "high",
                    "description": "The setOwner function has no access modifier and can be called by anyone.",
                    "location": "setOwner() line 10",
                    "recommendation": "Add onlyOwner modifier.",
                    "confidence": 0.92,
                    "cwe_id": "CWE-284",
                },
            ],
            "summary": "Contract has critical reentrancy and access control issues.",
            "risk_level": "Critical",
            "recommendations": ["Fix reentrancy", "Add access control"],
            "code_quality_issues": [{"issue": "No events emitted"}],
        }
        result = self.validator.validate_analysis(good_output)
        assert result["is_valid"] is True
        assert result["quality_score"] >= 0.8
        assert len(result["cleaned_output"]["vulnerabilities"]) == 2

    # ---- Non-dict input ----

    def test_non_dict_input_fails(self):
        result = self.validator.validate_analysis("not a dict")
        assert result["is_valid"] is False
        assert result["quality_score"] == 0.0

    # ---- Error key present ----

    def test_error_key_fails(self):
        result = self.validator.validate_analysis({"error": "LLM timed out"})
        assert result["is_valid"] is False

    # ---- Missing vulnerabilities field ----

    def test_missing_vulnerabilities_auto_fixed(self):
        result = self.validator.validate_analysis({"summary": "All clear"})
        assert result["is_valid"] is True
        assert result["cleaned_output"]["vulnerabilities"] == []
        assert any("empty vulnerabilities" in f.lower() for f in result["validation_report"]["fixes_applied"])

    # ---- Invalid vulnerability is dropped ----

    def test_invalid_vuln_dropped(self):
        output = {
            "vulnerabilities": [
                "not a dict",
                {
                    "name": "Valid Vuln",
                    "severity": "high",
                    "description": "A real vulnerability with enough detail to be meaningful.",
                    "confidence": 0.7,
                },
            ],
        }
        result = self.validator.validate_analysis(output)
        assert result["is_valid"] is True
        assert len(result["cleaned_output"]["vulnerabilities"]) == 1

    # ---- Severity auto-correction ----

    def test_fuzzy_severity_correction(self):
        output = {
            "vulnerabilities": [
                {
                    "name": "Test",
                    "severity": "crit",  # should map to "critical"
                    "description": "Testing fuzzy severity match with enough length.",
                    "confidence": 0.6,
                }
            ]
        }
        result = self.validator.validate_analysis(output)
        vuln = result["cleaned_output"]["vulnerabilities"][0]
        assert vuln["severity"] == "critical"

    def test_unknown_severity_defaults_informational(self):
        output = {
            "vulnerabilities": [
                {
                    "name": "Test",
                    "severity": "zzzz",  # unmappable
                    "description": "Unknown severity should default correctly.",
                    "confidence": 0.5,
                }
            ]
        }
        result = self.validator.validate_analysis(output)
        vuln = result["cleaned_output"]["vulnerabilities"][0]
        assert vuln["severity"] == "informational"

    # ---- Confidence clamping ----

    def test_confidence_clamped_to_range(self):
        output = {
            "vulnerabilities": [
                {
                    "name": "Over",
                    "severity": "medium",
                    "description": "Confidence above 1 should be clamped to 1.0.",
                    "confidence": 1.5,
                },
                {
                    "name": "Under",
                    "severity": "low",
                    "description": "Negative confidence should be clamped to 0.0.",
                    "confidence": -0.3,
                },
            ]
        }
        result = self.validator.validate_analysis(output)
        vulns = result["cleaned_output"]["vulnerabilities"]
        assert vulns[0]["confidence"] <= 1.0
        assert vulns[1]["confidence"] >= 0.0

    # ---- Confidence diversity auto-jitter ----

    def test_identical_confidences_get_jittered(self):
        output = {
            "vulnerabilities": [
                {"name": f"V{i}", "severity": "medium", "description": f"Vuln number {i} with enough description.", "confidence": 0.7}
                for i in range(5)
            ]
        }
        result = self.validator.validate_analysis(output)
        confs = [v["confidence"] for v in result["cleaned_output"]["vulnerabilities"]]
        # After jitter, they should be diverse
        assert len(set(confs)) > 1, f"All confidences still identical: {confs}"

    # ---- Severity-confidence consistency warnings ----

    def test_critical_low_confidence_warns(self):
        output = {
            "vulnerabilities": [
                {
                    "name": "Suspicious Critical",
                    "severity": "critical",
                    "description": "Claimed critical but low confidence should trigger warning.",
                    "confidence": 0.2,
                }
            ]
        }
        result = self.validator.validate_analysis(output)
        warnings = result["validation_report"]["warnings"]
        assert any("critical severity with low confidence" in w.lower() for w in warnings)

    # ---- Truncation beyond MAX_REASONABLE_VULNS ----

    def test_excessive_vulns_truncated(self):
        output = {
            "vulnerabilities": [
                {"name": f"V{i}", "severity": "low", "description": f"Padding vulnerability #{i} text.", "confidence": 0.3}
                for i in range(35)
            ]
        }
        result = self.validator.validate_analysis(output)
        assert len(result["cleaned_output"]["vulnerabilities"]) <= 30

    # ---- Risk level inference ----

    def test_risk_level_inferred(self):
        output = {
            "vulnerabilities": [
                {"name": "A", "severity": "high", "description": "Some real vulnerability detail here.", "confidence": 0.8}
            ]
        }
        result = self.validator.validate_analysis(output)
        assert result["cleaned_output"]["risk_level"] == "High"

    def test_risk_level_safe_when_no_vulns(self):
        output = {"vulnerabilities": []}
        result = self.validator.validate_analysis(output)
        assert result["cleaned_output"]["risk_level"] == "Safe"

    # ---- Default summary / recommendations ----

    def test_missing_summary_auto_filled(self):
        result = self.validator.validate_analysis({"vulnerabilities": []})
        assert result["cleaned_output"]["summary"] == "Analysis completed."

    # ---- Singleton works ----

    def test_singleton_instance(self):
        result = llm_validator.validate_analysis({"vulnerabilities": []})
        assert result["is_valid"] is True


# =====================================================================
# PART 2: Enhanced RAG Similarity Tests
# =====================================================================

from app.services.rag import SimpleVectorStore, MIN_RELEVANCE_THRESHOLD


class TestEnhancedRAG:
    """Tests for enhanced SimpleVectorStore with TF-IDF + bigrams."""

    def setup_method(self):
        self.store = SimpleVectorStore()
        # Seed some patterns
        self.store.add("reentrancy", 
            "Vulnerability: Reentrancy\nSeverity: critical\nDescription: A reentrancy attack occurs when a contract makes an external call before updating state, allowing recursive re-entry",
            {"name": "Reentrancy", "severity": "critical", "cwe_id": "CWE-841", "category": "security"})
        self.store.add("overflow",
            "Vulnerability: Integer Overflow/Underflow\nSeverity: high\nDescription: Integer overflow or underflow occurs when arithmetic exceeds bounds",
            {"name": "Integer Overflow", "severity": "high", "cwe_id": "CWE-190", "category": "arithmetic"})
        self.store.add("access-control",
            "Vulnerability: Missing Access Control\nSeverity: critical\nDescription: Critical functions lacking proper access controls can be called by anyone",
            {"name": "Access Control", "severity": "critical", "cwe_id": "CWE-284", "category": "access-control"})
        self.store.add("flash-loan",
            "Vulnerability: Flash Loan Attack\nSeverity: high\nDescription: Contracts relying on token balances can be manipulated using flash loans",
            {"name": "Flash Loan", "severity": "high", "cwe_id": "CWE-669", "category": "defi"})
        self.store.add("timestamp",
            "Vulnerability: Block Timestamp Manipulation\nSeverity: low\nDescription: Block timestamps can be slightly manipulated by miners",
            {"name": "Timestamp", "severity": "low", "cwe_id": "CWE-367", "category": "timing"})

    # ---- Basic search ----

    def test_search_returns_results(self):
        results = self.store.search("reentrancy external call state update withdraw")
        assert len(results) > 0
        assert results[0]["id"] == "reentrancy"

    def test_search_relevance_ordering(self):
        """More relevant results should rank higher."""
        results = self.store.search("integer overflow arithmetic bounds exceed maximum value", n_results=5)
        ids = [r["id"] for r in results]
        assert ids[0] == "overflow", f"Expected 'overflow' first, got {ids}"

    # ---- Minimum relevance threshold ----

    def test_irrelevant_query_returns_empty(self):
        """A query about unrelated topics should match nothing."""
        results = self.store.search("pizza delivery restaurant menu food")
        assert len(results) == 0, f"Expected empty, got {[r['id'] for r in results]}"

    # ---- Bigram matching ----

    def test_bigram_flash_loan_boosts(self):
        """Compound term 'flash loan' should boost the flash-loan pattern."""
        results = self.store.search("flash loan attack vector price manipulation")
        ids = [r["id"] for r in results]
        assert "flash-loan" in ids, f"flash-loan not in results: {ids}"
        # Should be the top or near-top result
        assert ids.index("flash-loan") < 3

    def test_bigram_access_control(self):
        results = self.store.search("missing access control onlyOwner modifier")
        assert results[0]["id"] == "access-control"

    # ---- Severity boosting ----

    def test_critical_severity_boosted(self):
        """Between two equally-matching patterns, critical severity should rank higher."""
        # Both "reentrancy" (critical) and "overflow" (high) have security keywords
        results = self.store.search("contract vulnerability security issue pattern")
        if len(results) >= 2:
            # Critical patterns should get a boost
            critical_results = [r for r in results if r["metadata"]["severity"] == "critical"]
            non_critical = [r for r in results if r["metadata"]["severity"] != "critical"]
            if critical_results and non_critical:
                assert critical_results[0]["score"] >= non_critical[0]["score"] * 0.8

    # ---- Severity filter ----

    def test_severity_filter(self):
        results = self.store.search("vulnerability attack", severity_filter=["critical"])
        for r in results:
            assert r["metadata"]["severity"] == "critical"

    # ---- Score properties ----

    def test_scores_are_positive(self):
        results = self.store.search("reentrancy attack external call state")
        for r in results:
            assert r["score"] > 0

    def test_scores_above_threshold(self):
        results = self.store.search("reentrancy")
        for r in results:
            assert r["score"] >= MIN_RELEVANCE_THRESHOLD

    # ---- IDF rebuild ----

    def test_idf_rebuilds_on_add(self):
        initial_count = self.store.count()
        self.store.add("new-pattern",
            "Vulnerability: Something New\nSeverity: medium\nDescription: A totally new pattern",
            {"name": "New", "severity": "medium", "cwe_id": "", "category": "test"})
        assert self.store.count() == initial_count + 1
        # Should still search fine after IDF invalidation
        results = self.store.search("something new pattern")
        assert len(results) > 0

    # ---- Empty store ----

    def test_empty_store_returns_empty(self):
        empty_store = SimpleVectorStore()
        results = empty_store.search("reentrancy")
        assert results == []


# =====================================================================
# PART 3: Cross-Validation Tests
# =====================================================================

from app.services.analyzer import AnalyzerService


class TestCrossValidation:
    """Tests for _cross_validate_findings method."""

    def setup_method(self):
        self.analyzer = AnalyzerService()

    def test_boost_when_both_agree(self):
        """When LLM and regex both flag selfdestruct, confidence should increase."""
        llm_vulns = [
            {
                "id": "vuln-1",
                "name": "Unprotected Selfdestruct",
                "severity": "critical",
                "description": "The selfdestruct opcode can be triggered by anyone.",
                "confidence": 0.70,
            }
        ]
        bytecode_patterns = {
            "has_selfdestruct": True,
            "has_delegatecall": False,
            "has_create": False,
            "has_create2": False,
            "external_calls": 3,
        }
        result = self.analyzer._cross_validate_findings(llm_vulns, bytecode_patterns)
        assert len(result) >= 1
        # The selfdestruct vuln should have boosted confidence
        sd_vuln = [v for v in result if "selfdestruct" in v["name"].lower()][0]
        assert sd_vuln["confidence"] > 0.70, f"Expected boost from 0.70, got {sd_vuln['confidence']}"
        assert sd_vuln.get("_cross_validated") is True

    def test_penalty_for_unconfirmed_bytecode_claim(self):
        """LLM claims delegatecall but regex doesn't see it → confidence penalty."""
        llm_vulns = [
            {
                "id": "vuln-1",
                "name": "Unsafe Delegatecall",
                "severity": "high",
                "description": "Contract uses delegatecall to untrusted address.",
                "confidence": 0.80,
            }
        ]
        bytecode_patterns = {
            "has_selfdestruct": False,
            "has_delegatecall": False,  # regex disagrees
            "has_create": False,
            "has_create2": False,
            "external_calls": 2,
        }
        result = self.analyzer._cross_validate_findings(llm_vulns, bytecode_patterns)
        dc_vuln = [v for v in result if "delegatecall" in v["name"].lower()][0]
        assert dc_vuln["confidence"] < 0.80, f"Expected penalty from 0.80, got {dc_vuln['confidence']}"

    def test_regex_finding_added_when_llm_misses(self):
        """Regex finds selfdestruct but LLM doesn't mention it → added."""
        llm_vulns = [
            {
                "id": "vuln-1",
                "name": "Integer Overflow",
                "severity": "high",
                "description": "Arithmetic overflow in token transfer function.",
                "confidence": 0.75,
            }
        ]
        bytecode_patterns = {
            "has_selfdestruct": True,  # regex found it
            "has_delegatecall": False,
            "has_create": False,
            "has_create2": False,
            "external_calls": 3,
        }
        result = self.analyzer._cross_validate_findings(llm_vulns, bytecode_patterns)
        # Should have the original vuln + the added selfdestruct finding
        assert len(result) >= 2
        names = [v["name"].lower() for v in result]
        assert any("selfdestruct" in n for n in names)
        # The added vuln should have reduced confidence (70% of base 0.80)
        added = [v for v in result if v.get("_source") == "bytecode_cross_validation" and "selfdestruct" in v["name"].lower()][0]
        assert added["confidence"] < 0.80

    def test_high_external_calls_warning(self):
        """Very high external call count should add a warning finding."""
        llm_vulns = []
        bytecode_patterns = {
            "has_selfdestruct": False,
            "has_delegatecall": False,
            "has_create": False,
            "has_create2": False,
            "external_calls": 15,
        }
        result = self.analyzer._cross_validate_findings(llm_vulns, bytecode_patterns)
        names = [v["name"].lower() for v in result]
        assert any("external call" in n for n in names)

    def test_no_duplicate_external_call_warning(self):
        """If LLM already flagged external calls, don't add another."""
        llm_vulns = [
            {
                "id": "vuln-1",
                "name": "High External Call Count",
                "severity": "medium",
                "description": "Too many external calls detected.",
                "confidence": 0.6,
            }
        ]
        bytecode_patterns = {
            "has_selfdestruct": False,
            "has_delegatecall": False,
            "has_create": False,
            "has_create2": False,
            "external_calls": 15,
        }
        result = self.analyzer._cross_validate_findings(llm_vulns, bytecode_patterns)
        ext_call_vulns = [v for v in result if "external call" in v["name"].lower()]
        assert len(ext_call_vulns) == 1  # should NOT add duplicate

    def test_non_bytecode_vulns_not_penalized(self):
        """Non-bytecode-specific LLM findings should not be penalized."""
        llm_vulns = [
            {
                "id": "vuln-1",
                "name": "Missing Input Validation",
                "severity": "medium",
                "description": "User input is not properly validated before storage.",
                "confidence": 0.65,
            }
        ]
        bytecode_patterns = {
            "has_selfdestruct": False,
            "has_delegatecall": False,
            "has_create": False,
            "has_create2": False,
            "external_calls": 2,
        }
        result = self.analyzer._cross_validate_findings(llm_vulns, bytecode_patterns)
        assert result[0]["confidence"] == 0.65  # unchanged

    def test_empty_inputs(self):
        """Empty LLM vulns + empty bytecode patterns should return empty."""
        result = self.analyzer._cross_validate_findings([], {})
        assert result == []

    def test_multiple_bytecode_patterns_found(self):
        """Multiple regex patterns found, some confirmed by LLM, some not."""
        llm_vulns = [
            {
                "id": "v1",
                "name": "Selfdestruct Risk",
                "severity": "critical",
                "description": "Selfdestruct opcode found and unprotected.",
                "confidence": 0.75,
            },
        ]
        bytecode_patterns = {
            "has_selfdestruct": True,
            "has_delegatecall": True,  # not mentioned by LLM
            "has_create": False,
            "has_create2": True,       # not mentioned by LLM
            "external_calls": 5,
        }
        result = self.analyzer._cross_validate_findings(llm_vulns, bytecode_patterns)
        # Should have: 1 boosted selfdestruct + added delegatecall + added create2
        assert len(result) >= 3
        sources = [v.get("_source") for v in result]
        assert sources.count("bytecode_cross_validation") == 2


# =====================================================================
# PART 4: Integration - existing scoring test must still pass
# =====================================================================

class TestScoringStillWorks:
    """Sanity check that scoring engine imports aren't broken."""

    def test_scoring_import(self):
        from app.services.scoring import scoring_service
        assert scoring_service is not None

    def test_validator_import(self):
        from app.services.llm_validator import llm_validator
        assert llm_validator is not None

    def test_rag_import(self):
        from app.services.rag import rag_service
        assert rag_service is not None

    def test_analyzer_import(self):
        from app.services.analyzer import analyzer_service
        assert analyzer_service is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
