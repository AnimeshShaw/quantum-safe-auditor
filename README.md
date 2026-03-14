# 🔐 Quantum-Safe Code Auditor

> **An automated three-tier pipeline that scans codebases for quantum-vulnerable cryptography, eliminates false positives using LLM enrichment, ranks findings by quantum attack cost via VQE simulation, and generates actionable migration reports aligned to NIST FIPS 203/204/205.**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![Powered by Claude](https://img.shields.io/badge/AI-Claude%20Sonnet%204.6-orange.svg)](https://anthropic.com)
[![NIST PQC](https://img.shields.io/badge/NIST-FIPS%20203%2F204%2F205-green.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![Qiskit 2.x](https://img.shields.io/badge/Qiskit-2.x%20compatible-6929c4.svg)](https://qiskit.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Why This Exists

Quantum computers running **Shor's algorithm** will break RSA, ECDSA, ECDH, and Diffie-Hellman — the cryptographic foundations of almost every production system on the internet today. NIST finalized its first Post-Quantum Cryptography (PQC) standards in August 2024 (FIPS 203, 204, 205). Most production codebases have not been updated.

Meanwhile, adversaries are already collecting encrypted data to decrypt later — the **Harvest-Now, Decrypt-Later (HNDL)** attack. The migration window is open today. The CNSA 2.0 compliance deadline for new systems is 2025–2026.

**This tool finds every instance of quantum-vulnerable cryptography in a GitHub repository and gives development teams everything they need to prioritize and execute the migration — automatically, with AI-powered context analysis to eliminate the false positives that make regex-only scanners impractical.**

---

## Where This Fits in Your Migration

The Quantum-Safe Auditor operationalizes **Phase 2 (Discover) and Phase 3 (Prioritize)** of the PQC migration lifecycle:

```
Phase 1            Phase 2 ★           Phase 3 ★           Phase 4            Phase 5
Inventory    →   DISCOVER         →   PRIORITIZE      →   Remediate     →   Verify
(manual)       Quantum-Safe           VQE Threat           Developer         Re-audit
               Auditor                Scoring              migration         + certify
               - 15 algorithm         - Qubit-weighted     - FIPS 203/204    - Zero findings
                 classes detected       threat score         guidance          = compliant
               - AI false positive    - GitHub Issues       per finding     - CNSA 2.0
                 elimination           auto-created        - Notion report     audit trail
               - 12 languages
```

Tool output includes one GitHub Issue per algorithm family with line-level references and NIST replacement recommendations, enabling teams to track migration progress in their existing issue workflow.

---

## Research Results (Paper 1 — 5-Repository Corpus)

Evaluated on 5 widely-used open-source repositories (18,160 ⭐ node-jsonwebtoken, 2,624 ⭐ bc-java, 1,743 ⭐ python-jose, 971 ⭐ python-ecdsa, 492 ⭐ python-rsa):

| Metric | Value |
|---|---|
| **Precision** | **71.98%** |
| **Recall** | **100%** |
| **F1 Score** | **83.71%** |
| Total Findings | 5,775 across 5 repos |
| Labeled for Evaluation | 602 (stratified sample) |
| bc-java spot-check TP rate | 92% (46/50) |

> **Recall = 100%** means the tool found every true quantum-vulnerable instance in the labeled evaluation set — no false negatives.

### Per-Repository VQE Threat Scores

| Repository | Stars | Language | Files Scanned | Findings | VQE Threat Score |
|---|---|---|---|---|---|
| node-jsonwebtoken | 18,160 | JavaScript | ~20 | 8 | **7.00 (HIGH)** |
| python-rsa | 492 | Python | 16 | 120 | 6.53 |
| python-jose | 1,743 | Python | ~30 | 75 | 5.49 |
| bc-java | 2,624 | Java | 300 (sampled) | 5,247 | 4.20 |
| python-ecdsa | 971 | Python | ~40 | 325 | 3.54 |

> **Key insight:** bc-java has the most findings (5,247) but a lower threat score than node-jsonwebtoken (8 findings). Raw finding count is a poor proxy for quantum migration urgency — the VQE qubit-weighted score better reflects actual risk. Pearson r = −0.35 between finding density and threat score across repos.

### Per-Algorithm Precision

| Algorithm | Precision | F1 | Notes |
|---|---|---|---|
| AES-128, DH, DSA, PKCS#1v15, RC4, RSA-1024 | 1.000 | 1.000 | Perfect |
| X25519, Ed25519 | 0.815–0.833 | 0.898–0.909 | Strong |
| MD5 | 0.800 | 0.889 | Strong |
| ECDSA | 0.719 | 0.837 | Good |
| RSA | 0.705 | 0.827 | Good (comment-line FP in bc-java) |
| 3DES | 0.667 | 0.800 | Acceptable |
| ECDH, SHA-1 | 0.458–0.533 | 0.629–0.696 | Lower (test fixture FP — resolved by EXCLUDE_PATHS) |
| HARDCODED_KEY | 0.000 | 0.000 | All FP-Test; needs tighter context filter |

> **Note on FP-Test:** 188 of 414 FP findings are test fixture false positives from python-ecdsa, eliminated by setting `EXCLUDE_PATHS=tests/`. Reported separately for transparency. Excluding them yields adjusted precision of 74.1%.

---

## Features

| Feature | Details |
|---|---|
| 🤖 **Two-Pass AI Scanning** | Regex sweep → Claude context analysis eliminates false positives |
| 🔍 **15 Algorithm Classes** | RSA, ECDSA, ECDH, DSA, DH, Ed25519, X25519, PKCS#1 v1.5, RSA-1024, AES-128, MD5, SHA-1, RC4, 3DES, Hardcoded Keys |
| 🌐 **12 Languages** | Python, JavaScript, TypeScript, Java, Go, Rust, C/C++, C#, Ruby, PHP, Swift, Kotlin |
| ⚛️ **VQE Quantum Simulation** | Real Qiskit 2.x circuits with qubit-weighted threat scoring |
| 📋 **Notion Reports** | Rich structured audit pages via Notion API |
| 🐛 **GitHub Issues** | Automated issue creation per algorithm with remediation steps |
| 🏷️ **NIST Standard Mapping** | Every finding mapped to FIPS 203 / 204 / 205 replacement |
| 📊 **Quantum Readiness Score** | 0–100 score for executive reporting |
| 📁 **Large Repo Sampling** | MAX_FILES priority-weighted sampling for repos with thousands of files |
| 🔬 **Evaluation Framework** | Stratified precision/recall + Pearson correlation for research reproducibility |

---

## Algorithms Detected

| Algorithm | Severity | Quantum Attack | PQC Replacement | NIST Standard | CNSA 2.0 Deadline |
|---|---|---|---|---|---|
| RSA | 🔴 CRITICAL | Shor's | ML-KEM (CRYSTALS-Kyber) | FIPS 203 | 2025 new / 2030 legacy |
| RSA-1024 | 🔴 CRITICAL | Shor's | ML-KEM (CRYSTALS-Kyber) | FIPS 203 | Immediate |
| ECDSA | 🔴 CRITICAL | Shor's | ML-DSA (CRYSTALS-Dilithium) | FIPS 204 | 2025 new / 2030 legacy |
| ECDH | 🔴 CRITICAL | Shor's | ML-KEM (CRYSTALS-Kyber) | FIPS 203 | 2026 |
| Ed25519 / EdDSA | 🔴 CRITICAL | Shor's | ML-DSA (CRYSTALS-Dilithium) | FIPS 204 | 2025 new |
| X25519 / X448 | 🔴 CRITICAL | Shor's | ML-KEM (CRYSTALS-Kyber) | FIPS 203 | 2026 |
| DSA | 🔴 CRITICAL | Shor's | ML-DSA / SLH-DSA | FIPS 204/205 | 2025 |
| PKCS#1 v1.5 | 🔴 CRITICAL | Shor's | ML-KEM / OAEP interim | FIPS 203 | 2025 |
| Diffie-Hellman | 🟠 HIGH | Shor's | ML-KEM (CRYSTALS-Kyber) | FIPS 203 | 2026 |
| AES-128 | 🟠 HIGH | Grover's | AES-256 | SP 800-38 | 2030 |
| MD5 | 🟠 HIGH | Grover's | SHA-3 / SHAKE256 | FIPS 202 | Already disallowed |
| SHA-1 | 🟠 HIGH | Grover's | SHA-3-256 | FIPS 202 | 2030 |
| RC4 | 🟠 HIGH | Classical + Grover's | AES-256-GCM | SP 800-175B | Already prohibited |
| 3DES / DESede | 🟠 HIGH | Grover's | AES-256-GCM | SP 800-131A | Already disallowed |
| Hardcoded Keys | 🟠 HIGH | Harvest-Now-Decrypt-Later | Secrets Manager | SP 800-57 | Immediate |

---

## Architecture

```
+------------------------------------------------------------------+
|                  Quantum-Safe Auditor Pipeline                    |
|                   (Three-Tier Automated Analysis)                 |
+------------------------------+-----------------------------------+
                               |
          +--------------------+--------------------+
          v                    v                    v
   +-------------+  +----------------+  +---------------+
   |  GitHub MCP |  | CryptoScanner  |  |  Notion MCP   |
   |             |  |                |  |               |
   | - Repo tree |  | Pass 1: Regex  |  | - Rich pages  |
   | - File fetch|  | Pass 2: Claude |  | - Tables      |
   | - Issues    |  |   AI-enriched  |  | - Code blocks |
   | batch=3     |  |   vs Regex-    |  +---------------+
   | + backoff   |  |   only fallback|
   +-------------+  +-------+--------+
                     +------v-------+
                     |   VQE Demo   |
                     |  Qiskit 2.x  |
                     | Statevector  |
                     | Estimator V2 |
                     | Shor branch: |
                     |  qubit-wtd   |
                     | Grover branch|
                     |  flat 0.4   |
                     +--------------+
```

### Pipeline Stages

1. **Ingest** — GitHub API fetches full repo file tree and source contents in batches of 3 with exponential backoff retry. Binary files, minified JS, and vendor directories are skipped. For large repos, `MAX_FILES` applies priority-weighted crypto-path sampling.
2. **Scan (Pass 1)** — Pre-compiled regex sweep across all lines for 15 algorithm classes.
3. **Enrich (Pass 2)** — Claude analyzes each candidate file with language-aware, test-vs-production context detection. Findings tagged `AI-enriched` or `Regex-only`.
4. **Simulate** — VQE quantum circuit runs via Qiskit 2.x `StatevectorEstimator`. Threat score weighted by logical qubit requirement. Shor-breakable and Grover-weakened algorithms scored on separate branches.
5. **Report** — Structured JSON with algorithm inventory, severity breakdown, language breakdown, and Pearson correlation between finding density and threat score.
6. **Publish** — Notion API creates rich formatted report page.
7. **Issues** — GitHub API opens one labeled issue per algorithm family with line references and NIST replacement guidance.

---

## Quick Start

```bash
git clone https://github.com/AnimeshShaw/quantum-safe-auditor.git
cd quantum-safe-auditor/qsa
conda activate quantum-safe-auditor
python -m agent.orchestrator
```

See [SETUP.md](SETUP.md) for full installation, API key setup, and configuration reference.

---

## Configuration Reference

```env
# -- Required -----------------------------------------------
ANTHROPIC_API_KEY=sk-ant-...
GITHUB_TOKEN=ghp_...
TARGET_REPO=https://github.com/owner/repo

# -- Scan Tuning --------------------------------------------
# Minimum confidence to include a finding (default 0.6)
# Regex-only fallback findings have confidence 0.5 — excluded
# at default 0.6. Lower to 0.5 to include them.
MIN_CONFIDENCE=0.6

# Minimum severity to create a GitHub Issue
MIN_SEVERITY=LOW

# Path fragments to skip (comma-separated).
# Always set this — dramatically reduces test fixture FP rate.
EXCLUDE_PATHS=tests/

# Max files to scan (0 = unlimited).
# Uses priority-weighted sampling: crypto-relevant paths first.
# Set MAX_FILES=300 for large repos like bc-java.
MAX_FILES=0

# Claude model
CLAUDE_MODEL=claude-sonnet-4-6

# -- Optional: Notion ----------------------------------------
NOTION_TOKEN=secret_...
NOTION_PAGE_ID=your-32-char-page-id
```

### Recommended settings by repo type

| Repo type | EXCLUDE_PATHS | MAX_FILES |
|---|---|---|
| Python package | `tests/` | 0 |
| Node.js package | `test/` | 0 |
| Maven/Gradle (Java) | `/test/,src/test/` | 0 |
| Large Java repo (e.g. bc-java) | `/test/,src/test/` | 300 |

---

## VQE Quantum Threat Simulation

The threat score is computed from a real Qiskit 2.x variational quantum eigensolver (VQE) circuit. Each finding contributes a qubit-weighted score based on the estimated logical qubit cost of the corresponding quantum attack:

| Algorithm | Logical Qubits (Shor's) | Score Branch |
|---|---|---|
| RSA-2048 | ~4,096 | Qubit-weighted (Shor) |
| RSA-1024 | ~2,048 | Qubit-weighted (Shor) |
| ECDSA P-256 / Ed25519 / X25519 | ~2,330 | Qubit-weighted (Shor) |
| MD5, SHA-1, AES-128, RC4, 3DES | N/A | Flat 0.4 penalty (Grover) |
| HARDCODED_KEY | N/A | Flat 0.4 penalty (HNDL) |

Qiskit 2.x fully supported. Uses `StatevectorEstimator` + COBYLA. No `qiskit_algorithms` dependency (removed in Qiskit 2.x).

---

## Evaluation Corpus

| Repo | Stars (Mar 2026) | Language | Files | Findings | VQE Threat Score |
|---|---|---|---|---|---|
| python-rsa | 492 | Python | 16 | 120 | 6.53 |
| python-ecdsa | 971 | Python | ~40 | 325 | 3.54 |
| python-jose | 1,743 | Python | ~30 | 75 | 5.49 |
| node-jsonwebtoken | 18,160 | JavaScript | ~20 | 8 | 7.00 |
| bc-java | 2,624 | Java | 300 (sampled) | 5,247 | 4.20 |
| **Total** | | | | **5,775** | |

> bc-java scanned with `MAX_FILES=300` using priority-weighted sampling (~180 crypto-relevant files + ~120 random).

### Research Evaluation Workflow

```bash
# 1. Generate labeling samples
python evaluation/sample_for_labeling.py
# Creates: evaluation/bc_java_spot_check.csv (50 rows)
#          evaluation/labeling_sample.csv (~530 rows)

# 2. Label both files (see SETUP.md labeling guide)

# 3. Compute precision/recall/F1
python evaluation/evaluate.py \
  --ground-truth evaluation/labeling_sample_HandLabeled.csv \
  --results results/audit_result_*.json \
  --output evaluation/metrics.json
```

---

## File Structure

```
qsa/
├── agent/
│   ├── orchestrator.py          ← Entry point
│   └── config.py
├── scanner/
│   └── crypto_scanner.py        ← Two-pass scanner (regex + Claude)
├── mcp/
│   ├── github_client.py         ← GitHub API (batch=3, retry, MAX_FILES)
│   └── notion_client.py         ← Notion API
├── quantum/
│   └── vqe_demo.py              ← VQE + QFT (Qiskit 2.x, StatevectorEstimator)
├── reports/
│   └── report_builder.py        ← Audit result assembly
├── evaluation/
│   ├── evaluate.py              ← Precision/recall/F1 (metrics from labeled rows only)
│   ├── sample_for_labeling.py   ← Stratified labeling sample generator
│   └── ground_truth.csv         ← Full 5,775-row findings (all repos)
├── results/                     ← JSON audit results per repo (gitignored)
├── tests/
│   └── test_auditor.py
├── .env.example
├── requirements.txt
└── run_all_repos.ps1            ← PowerShell batch runner
```

---

## Running Tests

```bash
pytest tests/ -v
```

No API keys required — all external calls are mocked.

---

## Citing This Work

If you use this tool or its evaluation corpus in research, please cite:

```bibtex
@misc{shaw2026quantumsafe,
  author    = {Shaw, Animesh},
  title     = {Quantum-Safe Code Auditor: An LLM-Augmented Static Analysis Tool
               for Detecting and Prioritising Post-Quantum Cryptography Migration Risks},
  year      = {2026},
  publisher = {arXiv},
  note      = {arXiv preprint — DOI to be added upon submission},
  url       = {https://github.com/AnimeshShaw/quantum-safe-auditor}
}
```

---

## PQC Migration Resources

| Resource | Link |
|---|---|
| NIST PQC Project | https://csrc.nist.gov/projects/post-quantum-cryptography |
| FIPS 203 (ML-KEM) | https://csrc.nist.gov/pubs/fips/203/final |
| FIPS 204 (ML-DSA) | https://csrc.nist.gov/pubs/fips/204/final |
| FIPS 205 (SLH-DSA) | https://csrc.nist.gov/pubs/fips/205/final |
| NSA CNSA 2.0 | https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF |
| CISA PQC Migration Guide | https://www.cisa.gov/quantum |

---

## License

MIT

*Built by Animesh Shaw · Claude Sonnet 4.6 (Anthropic) · Qiskit 2.x · NIST FIPS 203/204/205*
