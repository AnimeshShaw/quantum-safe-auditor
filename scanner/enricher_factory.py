"""
enricher_factory.py — Returns the correct LLM enricher based on LLM_BACKEND env var.

LLM_BACKEND=ollama  (default) → OllamaEnricher  (Qwen3:30b via local Ollama)
LLM_BACKEND=claude             → ClaudeEnricher  (Anthropic API)
"""

import os


def get_enricher():
    backend = os.getenv("LLM_BACKEND", "ollama").lower().strip()
    if backend == "claude":
        from scanner.claude_enricher import ClaudeEnricher
        return ClaudeEnricher()
    from scanner.ollama_enricher import OllamaEnricher
    return OllamaEnricher()
