"""Quick Ollama inference speed test."""
import time
import requests
import os
from dotenv import load_dotenv
load_dotenv()

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")

PROMPT = """You are a security expert. Analyze this Python code snippet for quantum-vulnerable cryptography.

```python
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
```

Return JSON: [{"line_number": 2, "algorithm": "RSA", "is_true_positive": true, "context": "RSA key generation", "is_test_code": false, "confidence": 0.95, "remediation_steps": ["step1", "step2", "step3"]}]"""

print(f"Testing model : {MODEL}")
print(f"Ollama URL    : {OLLAMA_URL}")
print("Sending request...\n")

payload = {
    "model": MODEL,
    "messages": [{"role": "user", "content": PROMPT}],
    "stream": False,
    "think": False,
    "options": {"temperature": 0.1, "num_predict": 256, "num_ctx": 2048},
}

t0 = time.time()
resp = requests.post(OLLAMA_URL.rstrip("/") + "/api/chat", json=payload, timeout=120)
elapsed = time.time() - t0

data = resp.json()
content = data["message"]["content"]
eval_count = data.get("eval_count", 0)
eval_duration_ns = data.get("eval_duration", 1)
prompt_eval_count = data.get("prompt_eval_count", 0)
prompt_duration_ns = data.get("prompt_eval_duration", 1)

tok_per_sec = eval_count / (eval_duration_ns / 1e9) if eval_count else 0
prompt_tok_per_sec = prompt_count / (prompt_duration_ns / 1e9) if (prompt_count := prompt_eval_count) else 0

print(f"--- RESULTS ---")
print(f"Total time      : {elapsed:.1f}s")
print(f"Output tokens   : {eval_count}")
print(f"Prompt tokens   : {prompt_eval_count}")
print(f"Gen speed       : {tok_per_sec:.1f} tok/s")
print(f"Prompt speed    : {prompt_tok_per_sec:.1f} tok/s")
print(f"\nResponse preview:\n{content[:300]}")
