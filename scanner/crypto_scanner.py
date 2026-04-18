"""
CryptoScanner — Two-pass PQC vulnerability scanner.

"""

import os, re, json, asyncio, logging
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass, field
import anthropic

logger = logging.getLogger(__name__)
MIN_CONFIDENCE = float(os.getenv("MIN_CONFIDENCE", "0.6"))

# ── Qubit estimates (logical qubits via Shor's algorithm) ────────────────────
QUBIT_ESTIMATES: Dict[str, Dict] = {
    "RSA-1024":   {"logical_qubits": 2048,  "ref": "Beauregard 2003"},
    "RSA-2048":   {"logical_qubits": 4096,  "ref": "Roetteler et al. 2017"},
    "RSA-4096":   {"logical_qubits": 8192,  "ref": "Roetteler et al. 2017"},
    "ECDSA-P256": {"logical_qubits": 2330,  "ref": "Banegas et al. 2021"},
    "ECDSA-P384": {"logical_qubits": 3484,  "ref": "Banegas et al. 2021"},
    "DH-2048":    {"logical_qubits": 4096,  "ref": "Roetteler et al. 2017"},
    "DSA-2048":   {"logical_qubits": 4096,  "ref": "Roetteler et al. 2017"},
    "DEFAULT":    {"logical_qubits": 4096,  "ref": "Conservative estimate"},
}

# ── CNSA 2.0 compliance deadlines ────────────────────────────────────────────
CNSA2_DEADLINES: Dict[str, str] = {
    "RSA":          "New use: disallow by 2025; retire by 2030",
    "RSA-1024":     "Already non-compliant — immediate action required",
    "ECDSA":        "New use: disallow by 2025; retire by 2030",
    "ECDH":         "New use: disallow by 2025; retire by 2030",
    "DH":           "New use: disallow by 2026; retire by 2030",
    "DSA":          "Already disallowed under CNSA 2.0",
    "MD5":          "Already disallowed — replace immediately",
    "SHA-1":        "Already disallowed — replace with SHA-384+",
    "AES-128":      "Retire by 2030; upgrade to AES-256",
    "RC4":          "Already disallowed — replace immediately",
    "3DES":         "Already disallowed — replace immediately",
    "PKCS1v15":     "New use: disallow by 2025",
    "Ed25519":      "Quantum-vulnerable — target replacement by 2030",
    "X25519":       "Quantum-vulnerable — target replacement by 2030",
    "HARDCODED_KEY":"Immediate remediation required",
}

# ── Vulnerability pattern library ────────────────────────────────────────────
VULNERABLE_PATTERNS: Dict[str, Dict] = {
    "RSA": {
        "severity": "CRITICAL",
        "patterns": [
            r"\bRSA\b", r"rsa\.generate", r"RSA\.generate_private_key",
            r"Crypto\.PublicKey\.RSA", r"openssl_pkey_new.*rsa",
            r"new\s+RSAKey", r"KeyPairGenerator\.getInstance\(['\"]RSA",
            r"rsa\.newkeys\(", r"generateKeyPair.*RSA",
        ],
        "pqc_replacement": "ML-KEM (CRYSTALS-Kyber, FIPS 203) for encryption; ML-DSA (CRYSTALS-Dilithium, FIPS 204) for signatures",
        "nist_standard": "FIPS 203 / FIPS 204",
        "quantum_threat": "Shor's algorithm factors RSA moduli in polynomial time. RSA-2048 requires ~4,096 logical qubits.",
        "qubit_key": "RSA-2048",
    },
    "RSA-1024": {
        "severity": "CRITICAL",
        "patterns": [
            r"RSA.*1024", r"1024.*RSA", r"rsa.*1024",
            r"rsa\.newkeys\(1024", r"key_size=1024",
            r"bits=1024",
        ],
        "pqc_replacement": "ML-KEM (FIPS 203) — RSA-1024 is non-compliant classically and quantum-vulnerable",
        "nist_standard": "FIPS 203 / FIPS 204",
        "quantum_threat": "RSA-1024 requires only ~2,048 logical qubits — already weak classically.",
        "qubit_key": "RSA-1024",
    },
    "ECDSA": {
        "severity": "CRITICAL",
        "patterns": [
            r"\bECDSA\b", r"elliptic\.Sign", r"ecdsa\.SignASN1",
            r"EC\.generate_private_key", r"ECDSA\.new",
            r"Signature\.getInstance\(['\"].*ECDSA",
            r"secp256k1", r"secp384r1", r"prime256v1",
            r"\bP-256\b", r"\bP-384\b", r"\bP-521\b",
        ],
        "pqc_replacement": "ML-DSA (CRYSTALS-Dilithium, FIPS 204) or SLH-DSA (SPHINCS+, FIPS 205)",
        "nist_standard": "FIPS 204 / FIPS 205",
        "quantum_threat": "Shor's algorithm solves the elliptic curve discrete log problem. P-256 requires ~2,330 logical qubits.",
        "qubit_key": "ECDSA-P256",
    },
    "ECDH": {
        "severity": "CRITICAL",
        "patterns": [
            r"\bECDH\b", r"ECDHE", r"ecdh\.computeSecret",
            r"EC_KEY_generate_key", r"ECDH\.generate_key",
            r"crypto\.createECDH",
        ],
        "pqc_replacement": "ML-KEM (CRYSTALS-Kyber, FIPS 203)",
        "nist_standard": "FIPS 203",
        "quantum_threat": "ECDH is vulnerable to harvest-now-decrypt-later attacks.",
        "qubit_key": "ECDSA-P256",
    },
    "DH": {
        "severity": "HIGH",
        "patterns": [
            r"\bDiffieHellman\b", r"\bDHE\b", r"dh\.generate_parameters",
            r"KeyPairGenerator\.getInstance\(['\"]DH",
            r"crypto\.createDiffieHellman",
        ],
        "pqc_replacement": "ML-KEM (CRYSTALS-Kyber, FIPS 203)",
        "nist_standard": "FIPS 203",
        "quantum_threat": "Shor's algorithm breaks discrete logarithm. DH-2048 requires ~4,096 logical qubits.",
        "qubit_key": "DH-2048",
    },
    "DSA": {
        "severity": "CRITICAL",
        "patterns": [
            r"\bDSA\b", r"DSA\.new", r"dsa\.generate_private_key",
            r"KeyPairGenerator\.getInstance\(['\"]DSA",
            r"Signature\.getInstance\(['\"].*withDSA",
        ],
        "pqc_replacement": "ML-DSA (CRYSTALS-Dilithium, FIPS 204) or SLH-DSA (SPHINCS+, FIPS 205)",
        "nist_standard": "FIPS 204 / FIPS 205",
        "quantum_threat": "Shor's algorithm breaks DSA. Already disallowed under CNSA 2.0.",
        "qubit_key": "DSA-2048",
    },
    "Ed25519": {
        "severity": "CRITICAL",
        "patterns": [
            r"\bEd25519\b", r"\bed25519\b", r"\bEdDSA\b", r"\bEd448\b",
            r"Ed25519PrivateKey", r"Ed25519PublicKey",
            r"signing\.Ed25519", r"nacl.*sign",
        ],
        "pqc_replacement": "ML-DSA (CRYSTALS-Dilithium, FIPS 204) or SLH-DSA (SPHINCS+, FIPS 205)",
        "nist_standard": "FIPS 204 / FIPS 205",
        "quantum_threat": "Ed25519 is elliptic-curve based — Shor's algorithm applies despite classical security.",
        "qubit_key": "ECDSA-P256",
    },
    "X25519": {
        "severity": "CRITICAL",
        "patterns": [
            r"\bX25519\b", r"\bX448\b", r"\bx25519\b", r"\bx448\b",
            r"X25519PrivateKey", r"X25519PublicKey",
            r"\bcurve25519\b", r"\bCurve25519\b",
        ],
        "pqc_replacement": "ML-KEM (CRYSTALS-Kyber, FIPS 203) for key exchange",
        "nist_standard": "FIPS 203",
        "quantum_threat": "X25519 is DH on Curve25519 — broken by Shor's algorithm. Widely used in TLS 1.3.",
        "qubit_key": "ECDSA-P256",
    },
    "PKCS1v15": {
        "severity": "HIGH",
        "patterns": [
            r"PKCS1_v1_5", r"PKCS1v15", r"pkcs1_v1_5", r"pkcs1v15",
            r"RSA_PKCS1_PADDING", r"padding.*PKCS1",
            r"\.encrypt_pkcs1_v1_5\(", r"\.decrypt_pkcs1_v1_5\(",
        ],
        "pqc_replacement": "ML-KEM (FIPS 203) replaces RSA key transport entirely; upgrade to OAEP if RSA is required.",
        "nist_standard": "FIPS 203",
        "quantum_threat": "PKCS#1 v1.5 is classically weak (ROBOT/Bleichenbacher attacks) and inherits RSA's quantum vulnerability.",
        "qubit_key": "RSA-2048",
    },
    "AES-128": {
        "severity": "HIGH",
        "patterns": [
            r"AES-128", r"aes-128",
            r"AES\.new.*128",
            r"Cipher\.getInstance\(['\"]AES.*128",
            r"createCipheriv\(['\"]aes-128",
        ],
        "pqc_replacement": "AES-256 — Grover's algorithm halves effective key length (AES-128 → ~64-bit security)",
        "nist_standard": "NIST SP 800-38 series",
        "quantum_threat": "Grover's algorithm provides quadratic speedup — AES-128 drops to ~64-bit post-quantum.",
        "qubit_key": "DEFAULT",
    },
    "RC4": {
        "severity": "CRITICAL",
        "patterns": [
            r"\bRC4\b", r"\bARC4\b", r"\bARCFOUR\b",
            r"Cipher\.getInstance\(['\"]RC4",
            r"createCipheriv\(['\"]rc4",
            r"ARC4\.new\(",
        ],
        "pqc_replacement": "AES-256-GCM — RC4 is classically broken and disallowed under CNSA 2.0",
        "nist_standard": "NIST SP 800-38D",
        "quantum_threat": "RC4 is classically broken (biased keystream). No quantum computer needed to attack it.",
        "qubit_key": "DEFAULT",
    },
    "3DES": {
        "severity": "HIGH",
        "patterns": [
            r"\b3DES\b", r"\bTripleDES\b", r"\bDESede\b", r"\b3des\b",
            r"\bDES3\b", r"TripleDES\.new\(",
            r"Cipher\.getInstance\(['\"]DESede",
            r"createCipheriv\(['\"]des-ede",
        ],
        "pqc_replacement": "AES-256-GCM — 3DES is disallowed under CNSA 2.0 (Sweet32 attack)",
        "nist_standard": "NIST SP 800-38D",
        "quantum_threat": "3DES 112-bit key strength drops to ~56-bit under Grover's algorithm.",
        "qubit_key": "DEFAULT",
    },
    "MD5": {
        "severity": "HIGH",
        "patterns": [
            r"\bmd5\b", r"\bMD5\b", r"hashlib\.md5",
            r"MessageDigest\.getInstance\(['\"]MD5",
            r"crypto\.createHash\(['\"]md5",
            r"Digest::MD5",
        ],
        "pqc_replacement": "SHA-3-256 (FIPS 202) or SHA-256 minimum",
        "nist_standard": "FIPS 202",
        "quantum_threat": "MD5 is classically broken. Grover reduces preimage resistance to ~64-bit.",
        "qubit_key": "DEFAULT",
    },
    "SHA-1": {
        "severity": "HIGH",
        "patterns": [
            r"\bSHA-?1\b", r"\bsha1\b", r"hashlib\.sha1",
            r"MessageDigest\.getInstance\(['\"]SHA-1",
            r"crypto\.createHash\(['\"]sha1",
            r"Digest::SHA1",
        ],
        "pqc_replacement": "SHA-3-256 or SHA-384 — SHA-1 is disallowed under CNSA 2.0",
        "nist_standard": "FIPS 202",
        "quantum_threat": "Grover's algorithm reduces SHA-1 collision resistance from ~80 bits to ~40 bits.",
        "qubit_key": "DEFAULT",
    },
    "HARDCODED_KEY": {
        "severity": "CRITICAL",
        "patterns": [
            r"private_key\s*=\s*['\"]-----BEGIN",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            r"SECRET_KEY\s*=\s*['\"][^'\"]{16,}",
            r"PRIVATE_KEY\s*=\s*['\"][^'\"]{16,}",
            r"secret_key\s*=\s*['\"][A-Za-z0-9+/=]{32,}",
        ],
        "pqc_replacement": "Use a secrets manager (HashiCorp Vault, AWS Secrets Manager, or environment variables)",
        "nist_standard": "NIST SP 800-57 Part 1 Rev 5",
        "quantum_threat": "Hardcoded keys are extractable without any quantum computer — immediate action required.",
        "qubit_key": "DEFAULT",
    },
}

# ── File helpers ─────────────────────────────────────────────────────────────
SKIP_TOKENS = {".min.", "dist/", "build/", "vendor/", "node_modules/"}

def _should_skip(path: str) -> bool:
    p = path.lower().replace("\\", "/")
    return any(tok in p for tok in SKIP_TOKENS)

def _is_binary(content_bytes: bytes) -> bool:
    return b"\x00" in content_bytes[:8192]

def _detect_language(path: str) -> str:
    return {
        ".py":"Python",".js":"JavaScript",".ts":"TypeScript",
        ".java":"Java",".go":"Go",".rs":"Rust",
        ".c":"C",".cpp":"C++",".cs":"C#",
        ".rb":"Ruby",".php":"PHP",".swift":"Swift",
        ".kt":"Kotlin",".scala":"Scala",
    }.get(Path(path).suffix.lower(), "Unknown")

def _is_test_file(path: str) -> bool:
    p = path.lower()
    return any(t in p for t in ["test","spec","mock","fixture","__test__"])


# ── Dataclass ────────────────────────────────────────────────────────────────
@dataclass
class CryptoFinding:
    algorithm: str
    severity: str
    file_path: str
    line_number: int
    code_snippet: str
    pqc_replacement: str
    nist_standard: str
    quantum_threat: str
    confidence: float
    context: str = ""
    is_test_code: bool = False
    language: str = "Unknown"
    cnsa2_status: str = ""
    logical_qubits: int = 0
    qubit_reference: str = ""
    remediation_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "pqc_replacement": self.pqc_replacement,
            "nist_standard": self.nist_standard,
            "quantum_threat": self.quantum_threat,
            "confidence": self.confidence,
            "context": self.context,
            "is_test_code": self.is_test_code,
            "language": self.language,
            "cnsa2_status": self.cnsa2_status,
            "logical_qubits": self.logical_qubits,
            "qubit_reference": self.qubit_reference,
            "remediation_steps": self.remediation_steps,
        }


# ── Scanner ──────────────────────────────────────────────────────────────────
class CryptoScanner:
    def __init__(self, client: anthropic.Anthropic = None,
                 min_confidence: float = MIN_CONFIDENCE,
                 enricher=None):
        self.client = client
        self.enricher = enricher
        self.min_confidence = min_confidence
        self.compiled_patterns = {
            algo: [re.compile(p, re.IGNORECASE) for p in info["patterns"]]
            for algo, info in VULNERABLE_PATTERNS.items()
        }

    async def scan_files(self, files: List[Dict[str, Any]]) -> List[CryptoFinding]:
        total = len(files)
        all_findings: List[CryptoFinding] = []
        for i, f in enumerate(files, 1):
            logger.info(f"[{i}/{total}] Scanning: {f['path']}")
            try:
                result = await self._scan_file(f)
                if result:
                    logger.info(f"  -> {len(result)} finding(s)")
                all_findings.extend(result)
            except Exception as exc:
                logger.warning(f"  -> Scan error: {exc}")
        return self._deduplicate(all_findings)

    async def _scan_file(self, file_info: Dict[str, Any]) -> List[CryptoFinding]:
        path = file_info["path"]
        content = file_info["content"]
        raw_bytes = file_info.get("raw_bytes", b"")
        if _should_skip(path):
            return []
        if raw_bytes and _is_binary(raw_bytes):
            return []
        candidates = self._regex_sweep(path, content.splitlines())
        if not candidates:
            return []
        return await self._ai_enrich(path, content, candidates)

    def _regex_sweep(self, path: str, lines: List[str]) -> List[Dict]:
        candidates, seen = [], set()
        for line_num, line in enumerate(lines, start=1):
            for algo, patterns in self.compiled_patterns.items():
                if any(p.search(line) for p in patterns):
                    key = (algo, line_num)
                    if key not in seen:
                        seen.add(key)
                        info = VULNERABLE_PATTERNS[algo]
                        candidates.append({
                            "algorithm": algo,
                            "severity": info["severity"],
                            "line_number": line_num,
                            "code_snippet": line.strip()[:200],
                            "pqc_replacement": info["pqc_replacement"],
                            "nist_standard": info["nist_standard"],
                            "quantum_threat": info["quantum_threat"],
                            "qubit_key": info.get("qubit_key", "DEFAULT"),
                        })
        return candidates

    async def _ai_enrich(self, path: str, full_content: str,
                         candidates: List[Dict]) -> List[CryptoFinding]:
        language = _detect_language(path)
        is_test = _is_test_file(path)

        enrichments = []

        if self.enricher:
            # ── Pluggable enricher (Ollama / Claude via factory) ──────────────
            try:
                enrichments = await self.enricher.enrich(
                    path, full_content, candidates, language, is_test
                )
            except Exception as e:
                logger.warning(f"Enricher failed for {path}: {e}. Fallback to regex-only.")
                enrichments = [
                    {"line_number": c["line_number"], "algorithm": c["algorithm"],
                     "is_true_positive": True,
                     "context": "Regex match — enrichment unavailable",
                     "is_test_code": is_test, "confidence": 0.5,
                     "remediation_steps": [f"Replace {c['algorithm']} with {c['pqc_replacement']}"]}
                    for c in candidates
                ]
        else:
            # ── Legacy direct Claude client path (GitHub-API / orchestrator) ──
            # P0-1: safe truncation at last newline before 2500 chars
            truncated = full_content[:2500]
            last_nl = truncated.rfind("\n")
            if last_nl > 1000:
                truncated = truncated[:last_nl]

            candidate_summary = "\n".join(
                f"Line {c['line_number']}: [{c['algorithm']}] {c['code_snippet']}"
                for c in candidates
            )
            test_note = (
                "FILE TYPE: TEST/SPEC — mark test fixtures as is_test_code=true."
                if is_test else
                "FILE TYPE: PRODUCTION — apply full severity assessment."
            )

            prompt = f"""You are a Post-Quantum Cryptography (PQC) security expert auditing source code.

Language: {language}
File: {path}
{test_note}

Regex candidates:
{candidate_summary}

File content:
```{language.lower()}
{truncated}
```

For EACH candidate:
- is_true_positive: false if comment, string literal, dead code, or PQC documentation.
- context: one sentence describing exact usage.
- is_test_code: true if test/mock/fixture context.
- confidence: 0.0-1.0 (>0.8 = clear production use; <0.5 = likely false positive).
- remediation_steps: exactly 3 steps with {language} code examples.

Respond ONLY with a JSON array — no markdown, no preamble:
[
  {{
    "line_number": <int>,
    "algorithm": "<str>",
    "is_true_positive": <bool>,
    "context": "<str>",
    "is_test_code": <bool>,
    "confidence": <float>,
    "remediation_steps": ["<step1>", "<step2>", "<step3>"]
  }}
]"""

            try:
                response = self.client.messages.create(
                    model="claude-sonnet-4-6",
                    max_tokens=2000,
                    messages=[{"role": "user", "content": prompt}]
                )
                raw = response.content[0].text.strip()
                if raw.startswith("```"):
                    raw = raw.split("\n", 1)[1].rsplit("```", 1)[0].strip()
                enrichments = self._safe_parse(raw)
            except Exception as e:
                logger.warning(f"AI enrichment failed for {path}: {e}. Fallback to regex-only.")
                # Confidence 0.5: deliberately below the default MIN_CONFIDENCE=0.6 threshold
                # so regex-only findings are excluded from results unless the user explicitly
                # sets MIN_CONFIDENCE=0.5 in .env. This prevents FPs from leaked string literals,
                # error messages, and PQC algorithm names (ML-DSA etc.) matching legacy patterns.
                enrichments = [
                    {"line_number": c["line_number"], "algorithm": c["algorithm"],
                     "is_true_positive": True,
                     "context": "Regex match - AI enrichment unavailable",
                     "is_test_code": is_test, "confidence": 0.5,
                     "remediation_steps": [f"Replace {c['algorithm']} with {c['pqc_replacement']}"]}
                    for c in candidates
                ]

        enrich_map = {(e["line_number"], e["algorithm"]): e for e in enrichments}
        findings: List[CryptoFinding] = []
        for c in candidates:
            enrich = enrich_map.get((c["line_number"], c["algorithm"]), {})
            raw_conf = enrich.get("confidence", 0.7)
            try:
                confidence = float(raw_conf) if str(raw_conf).strip() != "" else 0.7
            except (TypeError, ValueError):
                confidence = 0.7
            if not enrich.get("is_true_positive", True):
                continue
            if confidence < self.min_confidence:
                continue
            qi = QUBIT_ESTIMATES.get(c.get("qubit_key", "DEFAULT"), QUBIT_ESTIMATES["DEFAULT"])
            findings.append(CryptoFinding(
                algorithm=c["algorithm"], severity=c["severity"],
                file_path=path, line_number=c["line_number"],
                code_snippet=c["code_snippet"],
                pqc_replacement=c["pqc_replacement"],
                nist_standard=c["nist_standard"],
                quantum_threat=c["quantum_threat"],
                confidence=confidence,
                context=enrich.get("context", ""),
                is_test_code=enrich.get("is_test_code", is_test),
                language=language,
                cnsa2_status=CNSA2_DEADLINES.get(c["algorithm"], "See CNSA 2.0 advisory"),
                logical_qubits=qi["logical_qubits"],
                qubit_reference=qi["ref"],
                remediation_steps=enrich.get("remediation_steps", []),
            ))
        return findings

    def _safe_parse(self, raw: str) -> List[Dict]:
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass
        try:
            from json_repair import repair_json
            return json.loads(repair_json(raw))
        except Exception:
            pass
        logger.warning("JSON parse failed even with json-repair.")
        return []

    def _deduplicate(self, findings: List[CryptoFinding]) -> List[CryptoFinding]:
        best: Dict[tuple, CryptoFinding] = {}
        for f in findings:
            key = (f.file_path, f.algorithm, f.line_number)
            if key not in best or f.confidence > best[key].confidence:
                best[key] = f
        return list(best.values())
