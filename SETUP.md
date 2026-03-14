# Quantum-Safe Code Auditor — Setup & Usage Guide

---

## What You Need

| Requirement | Where to get it | Required? |
|---|---|---|
| **Python 3.11+** | python.org | Yes |
| **Anthropic API Key** | console.anthropic.com | Yes |
| **GitHub Personal Access Token** | github.com/settings/tokens | Yes |
| **Notion Integration Token** | notion.so/my-integrations | Optional |
| **Conda or venv** | Anaconda / built into Python | Yes (one or other) |

**Minimum viable setup**: Anthropic API key + GitHub token. That gets you scanning, VQE simulation, and GitHub issue creation. Notion is optional.

---

## Step 1 — Check Python Version

```bash
python --version
```

You need 3.11 or higher.

---

## Step 2 — Get the Code

Clone from GitHub:

```bash
git clone https://github.com/AnimeshShaw/quantum-safe-auditor.git
cd quantum-safe-auditor
```

The `qsa/` directory is where all commands are run from:

```
qsa/
├── agent/         orchestrator.py, config.py
├── scanner/       crypto_scanner.py
├── quantum/       vqe_demo.py
├── mcp/           github_client.py, notion_client.py
├── reports/       report_builder.py
├── evaluation/    evaluate.py, sample_for_labeling.py
├── results/       (empty — audit JSON files go here)
├── tests/         test_auditor.py
├── .env.example
├── requirements.txt
└── run_all_repos.ps1
```

---

## Step 3 — Create and Activate Environment

All commands are run from inside the `qsa/` folder.

```bash
cd qsa
```

### Conda (recommended)

```bash
conda create -n quantum-safe-auditor python=3.11
conda activate quantum-safe-auditor
```

Run `conda activate quantum-safe-auditor` every time you open a new terminal.

### venv (alternative)

```bash
python -m venv venv
# Mac/Linux:
source venv/bin/activate
# Windows PowerShell:
venv\Scripts\Activate.ps1
```

---

## Step 4 — Install Dependencies

```bash
pip install -r requirements.txt
```

This installs the Anthropic SDK, httpx, python-dotenv, json-repair, pytest, and optionally Qiskit.

**About Qiskit**: Takes 2–5 minutes and ~1 GB disk space. The tool works without it (classical fallback runs instead). To install separately:

```bash
pip install qiskit qiskit-aer
```

Verify everything installed:

```bash
python -c "import anthropic; print('Anthropic OK')"
python -c "import qiskit; print('Qiskit OK')"
```

---

## Step 5 — Get Your API Keys

### Anthropic API Key

1. Go to console.anthropic.com
2. Click **API Keys** in the left sidebar
3. Click **Create Key** — name it `quantum-auditor`
4. Copy immediately (starts with `sk-ant-`)

**Cost estimate**: Scanning a 50-file repo costs roughly $0.05–$0.20. A large repo like bc-java (300 sampled files) may cost $1–3.

### GitHub Personal Access Token

1. Go to github.com/settings/tokens
2. Click **Generate new token (classic)**
3. Name it `quantum-safe-auditor`, set 90-day expiration
4. Select `repo` scope (read access is sufficient for scanning; write access needed for opening Issues)
5. Click **Generate token** and copy (starts with `ghp_`)

**Rate limit note**: The tool automatically batches GitHub API calls at 3 requests/second with exponential backoff retry. For bc-java (6,000+ files), set `MAX_FILES=300` to avoid triggering secondary rate limits.

### Notion (Optional)

1. Go to notion.so/my-integrations
2. Create integration named `Quantum Auditor`
3. Enable Read, Update, Insert capabilities
4. Copy the Internal Integration Token (starts with `secret_`)
5. On your Notion page: click `...` menu → **Connect to** → **Quantum Auditor**
6. Get Page ID from the URL (32 chars after the last dash)

---

## Step 6 — Configure .env

```bash
cp .env.example .env
```

Edit `.env`:

```env
# -- Required -------------------------------------------
ANTHROPIC_API_KEY=sk-ant-YOUR-KEY
GITHUB_TOKEN=ghp_YOUR-TOKEN
TARGET_REPO=https://github.com/OWNER/REPO

# -- Scan tuning (these are the defaults) ---------------
MIN_CONFIDENCE=0.6
MIN_SEVERITY=LOW
EXCLUDE_PATHS=tests/
MAX_FILES=0
CLAUDE_MODEL=claude-sonnet-4-6

# -- Notion (optional) ----------------------------------
NOTION_TOKEN=secret_YOUR-TOKEN
NOTION_PAGE_ID=YOUR-32-CHAR-ID
```

**Important env var notes:**

- `MIN_CONFIDENCE=0.6` — findings below this are excluded. Regex-only fallback findings have confidence 0.5, so they are excluded by default. Lower to 0.5 only if you want to see them.
- `MAX_FILES=0` means unlimited. Set to `300` for large repos to avoid hours of scanning.
- `EXCLUDE_PATHS` — always set this. Skipping test directories dramatically reduces false positives. **Never commit `.env` to GitHub.**

**Per-repo recommended settings:**

| Repo | EXCLUDE_PATHS | MAX_FILES |
|---|---|---|
| python-rsa | `tests/` | 0 (16 files total) |
| python-ecdsa | `docs/` | 0 |
| python-jose | `tests/,docs/` | 0 |
| node-jsonwebtoken | `test/` | 0 |
| bc-java | `/test/,src/test/` | 300 |

---

## Step 7 — Run the Auditor

Always from inside `qsa/` with your environment active:

```bash
python -m agent.orchestrator
```

Use `-m agent.orchestrator`, not `python agent/orchestrator.py`.

Output goes to `audit_result.json` in the `qsa/` directory. Rename immediately if running multiple repos:

```bash
mv audit_result.json results/audit_result_python_rsa.json
```

---

## Running All 5 Evaluation Repos (Batch Mode)

### Windows PowerShell

Make sure your conda environment is already active, then from inside `qsa/`:

```powershell
.\run_all_repos.ps1
```

The script runs all 5 repos in sequence, saves results to `results/`, and pauses 10 seconds between repos.

### Editing .env between repos

You can change `TARGET_REPO` and `EXCLUDE_PATHS` in `.env` between runs. For bc-java specifically, also add `MAX_FILES=300` to avoid scanning 6,000+ files.

---

## Running Tests

```bash
pytest tests/ -v
```

No API keys needed — all calls are mocked.

---

## Ground-Truth Evaluation (Research Reproducibility)

### Current evaluation status (March 2026)

All 5 repos have been scanned. Total: 5,775 findings across 5 repos.

| Repo | Findings | VQE Threat Score |
|---|---|---|
| bc-java | 5,247 | 4.20 |
| python-ecdsa | 325 | 3.54 |
| python-rsa | 120 | 6.53 |
| python-jose | 75 | 5.49 |
| node-jsonwebtoken | 8 | 7.00 |

**Evaluation results**: P=71.98%, R=100%, F1=83.71% (n=602 labeled findings).

---

### Step 1 — Generate labeling samples

You do NOT need to label all 5,775 rows. Run the sampler instead:

```bash
python evaluation/sample_for_labeling.py
```

This creates two files:

| File | Rows | Purpose |
|---|---|---|
| `evaluation/bc_java_spot_check.csv` | 50 | Validates bc-java TP rate |
| `evaluation/labeling_sample.csv` | ~530 | Main labeling set for paper |

Both files have an `enrichment_source` column:
- `AI-enriched` — Claude analyzed the file. Low FP rate.
- `Regex-only` — Claude never saw this file (rate limit during bc-java scan). Be more skeptical.

---

### Step 2 — Label bc_java_spot_check.csv first

Open in Excel. For each row, look at the `code_snippet` column. Set the `label` column to:

| Label | Meaning |
|---|---|
| `TP` | Real vulnerability in real security code |
| `FP-Context` | Comment, string literal, error message, OID constant, dead code |
| `FP-Test` | Test code the tool missed classifying |
| `FP-Safe` | Algorithm used in a non-security context (e.g. MD5 for a cache key) |

**bc-java patterns that are always FP-Context:**

```
"RSA modulus is not composite"          ← error message string
isAlgIdFromPrivate.add("ML-DSA")        ← PQC algorithm in a list
/** id-MLDSA65-ECDSA-P256-SHA512 */     ← OID comment in javadoc
"SLH-DSA", "HASH-ML-DSA"               ← PQC algorithm names containing "DSA"
```

If 45+ out of 50 rows are TP, you can bulk-label all bc-java findings as TP in the paper's methodology. (Our result: 46/50 TP, 92% TP rate.)

---

### Step 3 — Label labeling_sample.csv

Same process. This file has:
- All non-bc-java findings
- ~70 stratified bc-java rows for coverage

This is the file that goes into `evaluate.py`.

---

### Step 4 — Compute metrics

```bash
python evaluation/evaluate.py \
  --ground-truth evaluation/labeling_sample_HandLabeled.csv \
  --results results/audit_result_python_rsa.json \
           results/audit_result_python_ecdsa.json \
           results/audit_result_python_jose.json \
           results/audit_result_node_jwt.json \
           results/audit_result_bc_java.json \
  --output evaluation/metrics.json
```

The output contains:
- Overall precision, recall, F1
- FP breakdown: FP-Context, FP-Safe, FP-Test (separately)
- Per-algorithm precision/recall/F1
- AI-enriched vs Regex-only tier comparison
- Pearson correlation between finding density and VQE threat score

---

### Understanding the two-tier results

The AI-enriched vs Regex-only split is the paper's core quality claim:

| Tier | What it means |
|---|---|
| AI-enriched | Claude analyzed the file — lower FP rate |
| Regex-only | Claude fell back (rate limit) — higher FP rate |

**Important caveat on the two-tier comparison**: All 188 FP-Test findings fell into the AI-enriched tier (python-ecdsa test fixtures not filtered by `EXCLUDE_PATHS`). This makes AI-enriched appear artificially lower. Excluding FP-Test from both denominators gives the fair comparison. Report both in any paper.

**Important caveat on the overall metrics**: Metrics are computed over a stratified sample of 602 findings (10.4% of the full corpus). Full-corpus labeling is planned for future evaluations.

---

## Common Errors and Fixes

### ModuleNotFoundError: No module named 'agent'

You are in the wrong directory or missing the `-m` flag.
```bash
cd qsa
python -m agent.orchestrator
```

### NameError: name 'meets_min_severity' is not defined

Old version of `orchestrator.py`. Pull the latest from GitHub.

### VQE WARNING / AttributeError about qiskit_algorithms

You have Qiskit 2.x. The `qiskit_algorithms` package was removed. The current `vqe_demo.py` uses `StatevectorEstimator` directly. Pull the latest from GitHub.

### Threat score is very low (e.g. 2.72) despite many CRITICAL findings

Old version of `vqe_demo.py` with the `qubit_estimate` field name bug. Pull the latest — the field is now `logical_qubits`.

### HTTP 403 during bc-java scan (rate limit)

The current `github_client.py` handles this with retry logic and batch_size=3. Also set `MAX_FILES=300` in your `.env` for bc-java.

### PowerShell errors about encoding or unexpected characters

The current `run_all_repos.ps1` is pure ASCII. Pull the latest from GitHub.

### HTTP 401 Unauthorized (GitHub)

Your GitHub token is expired or missing `repo` scope. Generate a new one at github.com/settings/tokens.

### HTTP 410 Gone (GitHub Issues)

Issues are disabled on the target repo. Go to repo Settings → Features → enable Issues.

### Qiskit install fails

The tool works without Qiskit — a classical fallback runs instead. Skip Qiskit if the install is difficult.

### evaluate.py gives unexpected precision values

Make sure you are passing `labeling_sample_HandLabeled.csv` (the labeled version), not `labeling_sample.csv` (the unlabeled original). Also confirm the column names are `file_path` and `line` (not `file` and `line_number` — old column names from an earlier version).
