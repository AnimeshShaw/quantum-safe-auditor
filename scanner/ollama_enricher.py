"""
OllamaEnricher — LLM enrichment via local Ollama server.
Compatible with any Ollama-served model; tuned for qwen2.5-coder.
"""

import asyncio
import json
import logging
import os
import re
import time
from typing import List, Dict

import requests

logger = logging.getLogger(__name__)

OLLAMA_URL   = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
_MAX_RETRIES  = 3
_BACKOFF_BASE = 2.0
_BATCH_SIZE   = 5   # candidates per LLM call

# Deterministic remediation lookup — keeps LLM output small
_REMEDIATION: Dict[str, List[str]] = {
    "RSA":           ["Replace with ML-KEM (FIPS 203) for encryption",
                      "Replace with ML-DSA (FIPS 204) for signatures",
                      "Use liboqs or pqcrypto library"],
    "ECDSA":         ["Replace with ML-DSA (FIPS 204)",
                      "Use SLH-DSA (FIPS 205) as alternative",
                      "Use liboqs or pqcrypto library"],
    "ECDH":          ["Replace with ML-KEM (FIPS 203)",
                      "Use X-Wing hybrid KEM during transition",
                      "Use liboqs or pqcrypto library"],
    "DSA":           ["Replace with ML-DSA (FIPS 204)",
                      "Use SLH-DSA (FIPS 205) as alternative",
                      "Use liboqs or pqcrypto library"],
    "DH":            ["Replace with ML-KEM (FIPS 203)",
                      "Use X-Wing hybrid KEM during transition",
                      "Use liboqs or pqcrypto library"],
    "X25519":        ["Replace with ML-KEM (FIPS 203)",
                      "Use X-Wing hybrid KEM during transition",
                      "Use liboqs or pqcrypto library"],
    "Ed25519":       ["Replace with ML-DSA (FIPS 204)",
                      "Use SLH-DSA (FIPS 205) as alternative",
                      "Use liboqs or pqcrypto library"],
    "PKCS1v15":      ["Replace with ML-KEM + OAEP (FIPS 203)",
                      "Replace with ML-DSA for signing (FIPS 204)",
                      "Use liboqs or pqcrypto library"],
    "AES128":        ["Upgrade to AES-256 (doubles Grover cost)",
                      "Use AES-256-GCM for authenticated encryption",
                      "Audit key derivation for quantum safety"],
    "3DES":          ["Replace with AES-256-GCM",
                      "Use ChaCha20-Poly1305 as alternative",
                      "Remove legacy TLS cipher suites"],
    "RC4":           ["Replace with AES-256-GCM immediately",
                      "Use ChaCha20-Poly1305 as alternative",
                      "Disable RC4 in all TLS configurations"],
    "MD5":           ["Replace with SHA-256 or SHA-3",
                      "Use BLAKE3 for high-performance hashing",
                      "Audit all MAC usages for SHA-3 migration"],
    "SHA1":          ["Replace with SHA-256 or SHA-3",
                      "Use SHA-3-256 for new implementations",
                      "Audit certificate chains for SHA-1 usage"],
    "HARDCODED_KEY": ["Move key to a secrets manager (Vault, AWS KMS)",
                      "Rotate the exposed key immediately",
                      "Use environment variables with restricted access"],
    "RSA1024":       ["Upgrade to RSA-4096 as interim measure",
                      "Migrate to ML-KEM (FIPS 203) for long-term safety",
                      "Use liboqs or pqcrypto library"],
}
_DEFAULT_REMEDIATION = [
    "Replace with a NIST PQC standard (FIPS 203/204/205)",
    "Use liboqs or pqcrypto library",
    "Review NIST SP 800-131A for migration guidance",
]


class OllamaEnricher:
    """Enriches regex candidates using a local Ollama model."""

    def __init__(self):
        self.url   = OLLAMA_URL.rstrip("/") + "/api/chat"
        self.model = OLLAMA_MODEL

    async def enrich(
        self,
        path: str,
        full_content: str,
        candidates: List[Dict],
        language: str,
        is_test: bool,
    ) -> List[Dict]:
        loop    = asyncio.get_event_loop()
        results = []
        batches = [candidates[i:i + _BATCH_SIZE] for i in range(0, len(candidates), _BATCH_SIZE)]
        for batch in batches:
            prompt  = self._build_prompt(path, full_content, batch, language, is_test)
            raw     = await loop.run_in_executor(None, self._call_ollama, prompt)
            enriched = self._parse(raw, batch, is_test)
            for item in enriched:
                item.setdefault("remediation_steps", self._get_remediation(item.get("algorithm", "")))
            results.extend(enriched)
        return results

    # ── Prompt ────────────────────────────────────────────────────────────────

    def _build_prompt(self, path, full_content, candidates, language, is_test) -> str:
        candidate_lines = "\n".join(
            f"Line {c['line_number']}: [{c['algorithm']}] {c['code_snippet']}"
            for c in candidates
        )
        test_note = (
            "FILE TYPE: TEST/SPEC — mark test fixtures as is_test_code=true."
            if is_test else
            "FILE TYPE: PRODUCTION — apply full severity assessment."
        )

        return f"""Classify each cryptographic code finding for quantum vulnerability. Language: {language}. File: {path}. {test_note}

Findings:
{candidate_lines}

For each finding output one JSON object. Rules:
- is_true_positive=false if algorithm name is only in a comment/string/import with no active use
- is_test_code=true if in test/fixture/mock/example context
- confidence: 0.9=active production use, 0.5=test code, 0.1=comment only
- context: one short sentence describing the usage

Output ONLY a JSON array, no markdown:
[{{"line_number":<int>,"algorithm":"<str>","is_true_positive":<bool>,"context":"<str>","is_test_code":<bool>,"confidence":<float>}}]"""

    # ── HTTP call ─────────────────────────────────────────────────────────────

    def _call_ollama(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "think": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 512,
                "num_ctx": 2048,
            },
        }
        for attempt in range(_MAX_RETRIES):
            try:
                logger.info(f"  -> Calling Ollama ({self.model}) attempt {attempt + 1}…")
                resp = requests.post(self.url, json=payload, timeout=120)
                resp.raise_for_status()
                content = resp.json()["message"]["content"]
                logger.info(f"  -> Ollama responded ({len(content)} chars)")
                return content
            except Exception as exc:
                if attempt < _MAX_RETRIES - 1:
                    wait = _BACKOFF_BASE ** attempt
                    logger.warning(
                        f"  -> Ollama attempt {attempt + 1} failed: {exc}. Retrying in {wait:.0f}s…"
                    )
                    time.sleep(wait)
                else:
                    logger.error(f"  -> Ollama failed after {_MAX_RETRIES} attempts: {exc}")
                    raise

    # ── Parsing ───────────────────────────────────────────────────────────────

    def _parse(self, raw: str, candidates: List[Dict], is_test: bool) -> List[Dict]:
        raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()

        for attempt in (raw, self._extract_json_block(raw), self._extract_first_array(raw)):
            if not attempt:
                continue
            try:
                result = json.loads(attempt)
                if isinstance(result, list):
                    return result
            except json.JSONDecodeError:
                pass

        logger.warning(
            f"Ollama: JSON parse failed for model={self.model} — "
            f"raw (first 300 chars): {raw[:300]!r}"
        )
        return self._fallback(candidates, is_test)

    def _extract_json_block(self, text: str) -> str:
        m = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        return m.group(1).strip() if m else ""

    def _extract_first_array(self, text: str) -> str:
        start = text.find("[")
        if start == -1:
            return ""
        depth = 0
        for i, ch in enumerate(text[start:], start):
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    return text[start : i + 1]
        return ""

    def _get_remediation(self, algorithm: str) -> List[str]:
        for key, steps in _REMEDIATION.items():
            if key.lower() in algorithm.lower():
                return steps
        return _DEFAULT_REMEDIATION

    def _fallback(self, candidates: List[Dict], is_test: bool) -> List[Dict]:
        return [
            {
                "line_number":      c["line_number"],
                "algorithm":        c["algorithm"],
                "is_true_positive": True,
                "context":          "Regex match — LLM enrichment unavailable",
                "is_test_code":     is_test,
                "confidence":       0.5,
                "remediation_steps": self._get_remediation(c["algorithm"]),
            }
            for c in candidates
        ]
