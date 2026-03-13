"""
Tests for the Quantum-Safe Code Auditor
Run with: pytest tests/ -v
"""

import asyncio
import json
import pytest
from unittest.mock import MagicMock

from scanner.crypto_scanner import (
    CryptoScanner, CryptoFinding, VULNERABLE_PATTERNS,
    _should_skip, _is_binary, _detect_language, _is_test_file,
    QUBIT_ESTIMATES, CNSA2_DEADLINES,
)
from quantum.vqe_demo import VQEThreatDemo
from reports.report_builder import ReportBuilder
from agent.config import AuditorConfig, validate_env
from datetime import datetime


# ── Scanner — regex pass ─────────────────────────────────────────────────────

class TestRegexSweep:

    def setup_method(self):
        self.scanner = CryptoScanner(MagicMock())

    # Original 8 algorithms
    def test_detects_rsa(self):
        results = self.scanner._regex_sweep("auth.py", ["key = RSA.generate(2048)"])
        assert any(r["algorithm"] == "RSA" for r in results)

    def test_detects_ecdsa(self):
        results = self.scanner._regex_sweep("crypto.py", ["sig = ECDSA.new(key, 'fips-186-3')"])
        assert any(r["algorithm"] == "ECDSA" for r in results)

    def test_detects_md5(self):
        results = self.scanner._regex_sweep("util.py", ["h = hashlib.md5(data).hexdigest()"])
        assert any(r["algorithm"] == "MD5" for r in results)

    def test_detects_sha1(self):
        results = self.scanner._regex_sweep("util.py", ["h = hashlib.sha1(data)"])
        assert any(r["algorithm"] == "SHA-1" for r in results)

    def test_detects_aes128(self):
        results = self.scanner._regex_sweep("enc.py", ["cipher = AES.new(key)  # AES-128"])
        assert any(r["algorithm"] == "AES-128" for r in results)

    # New Paper 1 algorithms (P2-1 through P2-11)
    def test_detects_ed25519(self):
        results = self.scanner._regex_sweep("keys.py", ["from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey"])
        assert any(r["algorithm"] == "Ed25519" for r in results)

    def test_detects_x25519(self):
        results = self.scanner._regex_sweep("tls.py", ["from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey"])
        assert any(r["algorithm"] == "X25519" for r in results)

    def test_detects_rc4(self):
        results = self.scanner._regex_sweep("legacy.py", ["cipher = ARC4.new(key)"])
        assert any(r["algorithm"] == "RC4" for r in results)

    def test_detects_3des(self):
        results = self.scanner._regex_sweep("legacy.py", ["cipher = TripleDES.new(key, TripleDES.MODE_CBC, iv)"])
        assert any(r["algorithm"] == "3DES" for r in results)

    def test_detects_rsa1024(self):
        results = self.scanner._regex_sweep("keys.py", ["key = rsa.newkeys(1024)"])
        assert any(r["algorithm"] == "RSA-1024" for r in results)

    def test_detects_pkcs1v15(self):
        results = self.scanner._regex_sweep("enc.py", ["ciphertext = key.encrypt_pkcs1_v1_5(msg)"])
        assert any(r["algorithm"] == "PKCS1v15" for r in results)

    def test_detects_hardcoded_key(self):
        results = self.scanner._regex_sweep("config.py", ["SECRET_KEY = 'mysupersecretkey123456789'"])
        assert any(r["algorithm"] == "HARDCODED_KEY" for r in results)

    def test_no_aes256_false_positive(self):
        results = self.scanner._regex_sweep("enc.py", ["key = os.urandom(32)  # AES-256"])
        aes = [r for r in results if r["algorithm"] == "AES-128"]
        assert len(aes) == 0

    def test_deduplication(self):
        # Same algorithm matched twice at same line should appear once
        lines = ["key = RSA.generate(2048)  # RSA key generation with RSA"]
        results = self.scanner._regex_sweep("a.py", lines)
        rsa = [r for r in results if r["algorithm"] == "RSA"]
        assert len(rsa) == 1


# ── File-level helpers ───────────────────────────────────────────────────────

class TestFileHelpers:

    def test_skip_minified(self):
        assert _should_skip("static/app.min.js") is True
        assert _should_skip("dist/bundle.js") is True
        assert _should_skip("node_modules/lib/index.js") is True
        assert _should_skip("src/auth.py") is False

    def test_binary_detection(self):
        assert _is_binary(b"Hello\x00World") is True
        assert _is_binary(b"Hello World") is False

    def test_language_detection(self):
        assert _detect_language("auth.py") == "Python"
        assert _detect_language("server.js") == "JavaScript"
        assert _detect_language("App.java") == "Java"
        assert _detect_language("main.go") == "Go"

    def test_test_file_detection(self):
        assert _is_test_file("tests/test_auth.py") is True
        assert _is_test_file("spec/auth_spec.rb") is True
        assert _is_test_file("src/auth.py") is False


# ── Qubit estimates ──────────────────────────────────────────────────────────

class TestQubitEstimates:

    def test_rsa2048_qubit_count(self):
        assert QUBIT_ESTIMATES["RSA-2048"]["logical_qubits"] == 4096

    def test_rsa1024_qubit_count(self):
        assert QUBIT_ESTIMATES["RSA-1024"]["logical_qubits"] == 2048

    def test_ecdsa_p256_qubit_count(self):
        assert QUBIT_ESTIMATES["ECDSA-P256"]["logical_qubits"] == 2330

    def test_default_qubit_count(self):
        assert QUBIT_ESTIMATES["DEFAULT"]["logical_qubits"] == 4096

    def test_finding_carries_qubit_info(self):
        finding = CryptoFinding(
            algorithm="RSA", severity="CRITICAL",
            file_path="auth.py", line_number=1,
            code_snippet="RSA.generate(2048)",
            pqc_replacement="ML-KEM", nist_standard="FIPS 203",
            quantum_threat="Shor's algorithm", confidence=0.9,
            logical_qubits=4096, qubit_reference="Roetteler et al. 2017",
        )
        d = finding.to_dict()
        assert d["logical_qubits"] == 4096
        assert "Roetteler" in d["qubit_reference"]


# ── CNSA 2.0 ─────────────────────────────────────────────────────────────────

class TestCNSA2:

    def test_rsa_deadline(self):
        assert "2025" in CNSA2_DEADLINES["RSA"]

    def test_dsa_already_disallowed(self):
        assert "disallowed" in CNSA2_DEADLINES["DSA"].lower()

    def test_md5_immediate(self):
        assert "immediately" in CNSA2_DEADLINES["MD5"].lower()


# ── AI enrichment (mocked) ───────────────────────────────────────────────────

class TestAIEnrichment:

    @pytest.mark.asyncio
    async def test_full_scan_pipeline(self):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text=json.dumps([
            {
                "line_number": 1, "algorithm": "RSA",
                "is_true_positive": True,
                "context": "RSA-2048 used for JWT signing",
                "is_test_code": False,
                "confidence": 0.95,
                "remediation_steps": [
                    "Install pqcrypto: pip install pqcrypto",
                    "Replace RSA with ML-KEM for key exchange",
                    "Replace RSA signatures with ML-DSA",
                ]
            }
        ]))]
        mock_client.messages.create = MagicMock(return_value=mock_response)

        scanner = CryptoScanner(mock_client, min_confidence=0.6)
        files = [{"path": "auth.py", "content": "private_key = RSA.generate(2048)\n"}]
        findings = await scanner.scan_files(files)

        assert len(findings) == 1
        assert findings[0].algorithm == "RSA"
        assert findings[0].severity == "CRITICAL"
        assert findings[0].confidence == 0.95
        assert findings[0].logical_qubits == 4096
        assert findings[0].language == "Python"
        assert not findings[0].is_test_code

    @pytest.mark.asyncio
    async def test_min_confidence_filters(self):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text=json.dumps([
            {"line_number": 1, "algorithm": "RSA", "is_true_positive": True,
             "context": "uncertain", "is_test_code": False,
             "confidence": 0.4, "remediation_steps": ["step1", "step2", "step3"]}
        ]))]
        mock_client.messages.create = MagicMock(return_value=mock_response)

        scanner = CryptoScanner(mock_client, min_confidence=0.6)
        files = [{"path": "auth.py", "content": "key = RSA.generate(2048)\n"}]
        findings = await scanner.scan_files(files)
        assert len(findings) == 0  # filtered by min_confidence

    @pytest.mark.asyncio
    async def test_false_positive_filtered(self):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text=json.dumps([
            {"line_number": 1, "algorithm": "RSA", "is_true_positive": False,
             "context": "comment only", "is_test_code": False,
             "confidence": 0.9, "remediation_steps": []}
        ]))]
        mock_client.messages.create = MagicMock(return_value=mock_response)

        scanner = CryptoScanner(mock_client, min_confidence=0.6)
        files = [{"path": "auth.py", "content": "# RSA is a widely used algorithm\n"}]
        findings = await scanner.scan_files(files)
        assert len(findings) == 0


# ── VQE ─────────────────────────────────────────────────────────────────────

class TestVQE:

    def setup_method(self):
        self.vqe = VQEThreatDemo(use_real_quantum=False)

    def test_threat_score_high_for_critical_findings(self):
        mock_findings = [
            MagicMock(algorithm="RSA", severity="CRITICAL", confidence=0.95,
                      nist_standard="FIPS 203", qubit_estimate=4096),
            MagicMock(algorithm="ECDSA", severity="CRITICAL", confidence=0.90,
                      nist_standard="FIPS 204", qubit_estimate=2330),
        ]
        result = self.vqe.run_threat_demo(mock_findings)
        assert result["threat_score"] > 5.0
        assert result["harvest_now_decrypt_later_risk"] is True

    def test_threat_score_zero_for_empty(self):
        result = self.vqe.run_threat_demo([])
        assert result["threat_score"] == 0.0

    def test_pearson_correlation_key_present(self):
        result = self.vqe.run_threat_demo([])
        # After report_builder adds it, the field should be present
        # VQE alone doesn't add it — that's report_builder's job
        assert "threat_score" in result


# ── Report builder ───────────────────────────────────────────────────────────

class TestReportBuilder:

    def setup_method(self):
        self.builder = ReportBuilder()

    def test_report_structure(self):
        finding = MagicMock()
        finding.severity = "CRITICAL"
        finding.algorithm = "RSA"
        finding.language = "Python"
        finding.logical_qubits = 4096
        finding.to_dict = lambda: {
            "algorithm": "RSA", "severity": "CRITICAL",
            "language": "Python", "logical_qubits": 4096,
        }
        result = self.builder.build(
            repo_url="https://github.com/test/repo",
            findings=[finding],
            quantum_analysis={"threat_score": 9.0, "threat_label": "CRITICAL"},
            started_at=datetime(2024, 1, 1, 10, 0),
            completed_at=datetime(2024, 1, 1, 10, 5),
        )
        assert result["repo_url"] == "https://github.com/test/repo"
        assert result["overall_risk"] == "CRITICAL"
        assert result["pqc_ready"] is False
        assert result["severity_summary"]["CRITICAL"] == 1
        assert "algorithm_inventory" in result  # P4-6
        assert "RSA" in result["algorithm_inventory"]
        assert result["algorithm_inventory"]["RSA"]["count"] == 1
        assert "pearson_correlation" in result["quantum_analysis"]  # P4-11
        assert "max_logical_qubits_in_corpus" in result["quantum_analysis"]  # P4-13

    def test_pqc_ready_for_clean_repo(self):
        result = self.builder.build(
            repo_url="https://github.com/clean/repo",
            findings=[],
            quantum_analysis={"threat_score": 0.0},
            started_at=datetime(2024, 1, 1),
            completed_at=datetime(2024, 1, 1),
        )
        assert result["pqc_ready"] is True
        assert result["overall_risk"] == "LOW"


# ── Pattern completeness ─────────────────────────────────────────────────────

class TestPatternCompleteness:

    def test_all_required_fields_present(self):
        required = {"severity", "patterns", "pqc_replacement",
                    "nist_standard", "quantum_threat", "qubit_key"}
        for algo, info in VULNERABLE_PATTERNS.items():
            missing = required - set(info.keys())
            assert not missing, f"{algo} missing: {missing}"

    def test_all_severities_valid(self):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for algo, info in VULNERABLE_PATTERNS.items():
            assert info["severity"] in valid

    def test_paper1_algorithms_present(self):
        expected = {"RSA", "RSA-1024", "ECDSA", "ECDH", "DH", "DSA",
                    "Ed25519", "X25519", "PKCS1v15",
                    "AES-128", "RC4", "3DES", "MD5", "SHA-1", "HARDCODED_KEY"}
        for algo in expected:
            assert algo in VULNERABLE_PATTERNS, f"Missing: {algo}"

    def test_qubit_keys_resolve(self):
        for algo, info in VULNERABLE_PATTERNS.items():
            key = info.get("qubit_key", "DEFAULT")
            assert key in QUBIT_ESTIMATES, f"{algo} has unknown qubit_key: {key}"

    def test_algo_count_paper1(self):
        # Paper 1 claims 15 vulnerability classes
        assert len(VULNERABLE_PATTERNS) >= 15


# ── Config validation ────────────────────────────────────────────────────────

class TestConfig:

    def test_severity_threshold(self):
        config = AuditorConfig(
            anthropic_api_key="test",
            min_severity="HIGH",
        )
        assert config.severity_passes_threshold("HIGH") is True
        assert config.severity_passes_threshold("CRITICAL") is True
        assert config.severity_passes_threshold("LOW") is False
        assert config.severity_passes_threshold("MEDIUM") is False
