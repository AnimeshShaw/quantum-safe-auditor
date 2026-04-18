"""
ClaudeEnricher — LLM enrichment via Anthropic Claude API.
Drop-in replacement for OllamaEnricher; identical interface.
"""

import json
import logging
import os
from typing import List, Dict

import anthropic

logger = logging.getLogger(__name__)


class ClaudeEnricher:
    """Wraps Anthropic Claude with the same interface as OllamaEnricher."""

    def __init__(self):
        self.client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.model  = os.getenv("LLM_MODEL", os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6"))

    async def enrich(
        self,
        path: str,
        full_content: str,
        candidates: List[Dict],
        language: str,
        is_test: bool,
    ) -> List[Dict]:
        truncated = full_content[:2500]
        last_nl   = truncated.rfind("\n")
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
                model=self.model,
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response.content[0].text.strip()
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[1].rsplit("```", 1)[0].strip()
            return json.loads(raw)
        except Exception as exc:
            logger.warning(f"Claude enrichment failed for {path}: {exc}")
            return [
                {
                    "line_number":       c["line_number"],
                    "algorithm":         c["algorithm"],
                    "is_true_positive":  True,
                    "context":           "Regex match — Claude enrichment unavailable",
                    "is_test_code":      is_test,
                    "confidence":        0.5,
                    "remediation_steps": [f"Replace {c['algorithm']} with PQC alternative"],
                }
                for c in candidates
            ]
