"""
sample_for_labeling.py
======================
Takes the full ground_truth.csv and produces two focused files:

1. evaluation/labeling_sample.csv  (~400-500 rows)
   Stratified sample covering every repo x algorithm combination.
   Has an extra column `enrichment_source` (AI-enriched / Regex-only)
   so you know which rows need extra scrutiny.

2. evaluation/bc_java_spot_check.csv  (50 rows)
   Random bc-java sample for a quick TP-rate validation.
   If >=90% are TP you can bulk-label bc-java in the paper.

IMPORTANT - Two quality tiers in your data:
  AI-enriched : Claude analysed the file. Context field is populated.
                Low false-positive rate (~5-15%). Label normally.
  Regex-only  : Claude enrichment failed (API rate limit during bc-java scan).
                Context = "Regex match - AI enrichment unavailable".
                HIGH false-positive rate. Be skeptical. Common FPs:
                  - String literals / error messages containing algorithm names
                  - PQC names (ML-DSA, SLH-DSA) triggering the DSA pattern
                  - OID constants and comments
                Label carefully. When in doubt -> FP-Context.

Label values:
  TP          Real vulnerability in production security code
  FP-Context  Comment, string literal, error message, OID constant, dead code
  FP-Safe     Algorithm present but not used for security (e.g. MD5 for cache)
  FP-Test     Test fixture the tool missed classifying

Usage:
    python evaluation/sample_for_labeling.py
"""

import csv
import math
import os
import random
import sys
from collections import defaultdict

RANDOM_SEED     = 42
INPUT_CSV       = os.path.join("evaluation", "paper1", "ground_truth.csv")
SAMPLE_CSV      = os.path.join("evaluation", "paper1", "labeling_sample.csv")
SPOTCHK_CSV     = os.path.join("evaluation", "paper1", "bc_java_spot_check.csv")

TARGET_TOTAL    = 400
BC_SPOT_CHECK   = 50
MIN_PER_STRATUM = 3

REGEX_SENTINEL  = "Regex match"


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fieldnames):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def tag_enrichment_source(rows):
    for row in rows:
        context = row.get("context", "") or ""
        row["enrichment_source"] = (
            "Regex-only" if REGEX_SENTINEL in context else "AI-enriched"
        )
    return rows


def stratified_sample(rows, target, min_per_stratum, seed):
    rng = random.Random(seed)
    strata = defaultdict(list)
    for row in rows:
        key = (
            row.get("repo", ""),
            row.get("algorithm", ""),
            row.get("enrichment_source", "AI-enriched"),
        )
        strata[key].append(row)

    guaranteed = {k: min(min_per_stratum, len(v)) for k, v in strata.items()}
    guaranteed_total = sum(guaranteed.values())

    remaining = max(0, target - guaranteed_total)
    total_rows = max(len(rows), 1)
    extra = {}
    for k, v in strata.items():
        prop = math.floor((len(v) / total_rows) * remaining)
        extra[k] = min(prop, len(v) - guaranteed[k])

    selected = []
    for k, v in strata.items():
        n = guaranteed[k] + extra[k]
        selected.extend(rng.sample(v, n))
    return selected


def print_breakdown(label, rows):
    by_repo   = defaultdict(int)
    by_algo   = defaultdict(int)
    by_source = defaultdict(int)
    for r in rows:
        by_repo[r.get("repo", "?")] += 1
        by_algo[r.get("algorithm", "?")] += 1
        by_source[r.get("enrichment_source", "?")] += 1

    total = sum(by_repo.values())
    print(f"\n  {label} ({total} rows)")
    print(f"    Enrichment source:")
    for src, n in sorted(by_source.items()):
        pct = 100 * n // max(total, 1)
        flag = "  <- needs careful labeling" if src == "Regex-only" else ""
        print(f"      {src:<15} {n:>4}  ({pct}%){flag}")
    print(f"    By repo:")
    for repo, n in sorted(by_repo.items(), key=lambda x: -x[1]):
        print(f"      {repo:<35} {n}")
    print(f"    By algorithm:")
    for algo, n in sorted(by_algo.items(), key=lambda x: -x[1]):
        print(f"      {algo:<20} {n}")


def main():
    if not os.path.exists(INPUT_CSV):
        print(f"ERROR: {INPUT_CSV} not found. Run prepare_gt_sheet.py first.")
        sys.exit(1)

    rows = read_csv(INPUT_CSV)
    if not rows:
        print("ERROR: ground_truth.csv is empty.")
        sys.exit(1)

    rows = tag_enrichment_source(rows)
    fieldnames = list(rows[0].keys())

    print(f"\n{'─'*65}")
    print(f"  Ground Truth Sampler")
    print(f"{'─'*65}")

    regex_only  = [r for r in rows if r["enrichment_source"] == "Regex-only"]
    ai_enriched = [r for r in rows if r["enrichment_source"] == "AI-enriched"]
    print(f"  Total rows   : {len(rows)}")
    print(f"  AI-enriched  : {len(ai_enriched)}  (reliable)")
    print(f"  Regex-only   : {len(regex_only)}  (high FP risk - Claude enrichment failed for these files)")

    bc_rows    = [r for r in rows if "bc-java" in r.get("repo", "")]
    other_rows = [r for r in rows if "bc-java" not in r.get("repo", "")]
    bc_regex   = sum(1 for r in bc_rows if r["enrichment_source"] == "Regex-only")
    print(f"\n  bc-java rows : {len(bc_rows)}  ({bc_regex} are Regex-only)")
    print(f"  Other rows   : {len(other_rows)}  (python-rsa, python-ecdsa, python-jose, node-jwt)")

    # bc-java spot-check: proportional AI vs Regex-only
    rng = random.Random(RANDOM_SEED)
    bc_ai  = [r for r in bc_rows if r["enrichment_source"] == "AI-enriched"]
    bc_reg = [r for r in bc_rows if r["enrichment_source"] == "Regex-only"]
    n_ai_spot  = min(round(BC_SPOT_CHECK * len(bc_ai)  / max(len(bc_rows), 1)), len(bc_ai))
    n_reg_spot = min(BC_SPOT_CHECK - n_ai_spot, len(bc_reg))
    spot_check = rng.sample(bc_ai, n_ai_spot) + rng.sample(bc_reg, n_reg_spot)
    rng.shuffle(spot_check)
    write_csv(SPOTCHK_CSV, spot_check, fieldnames)

    # Labeling sample: all non-bc-java + stratified bc-java
    other_sample = other_rows
    bc_budget    = max(0, TARGET_TOTAL - len(other_sample))
    bc_sample    = stratified_sample(bc_rows, bc_budget, MIN_PER_STRATUM, RANDOM_SEED)
    combined     = other_sample + bc_sample
    rng.shuffle(combined)
    write_csv(SAMPLE_CSV, combined, fieldnames)

    print_breakdown("bc-java spot-check  -> " + SPOTCHK_CSV, spot_check)
    print_breakdown("labeling_sample     -> " + SAMPLE_CSV,  combined)

    regex_in_sample = sum(1 for r in combined if r["enrichment_source"] == "Regex-only")
    ai_in_sample    = sum(1 for r in combined if r["enrichment_source"] == "AI-enriched")

    print(f"\n{'─'*65}")
    print(f"  LABELING PLAN")
    print(f"{'─'*65}")
    print(f"""
  Step 1 - bc_java_spot_check.csv ({len(spot_check)} rows, ~30 min)
    Open in Excel. For each row, check the code_snippet on GitHub.
    Expected: >90% TP (bc-java is a cryptography library by design).
    {n_reg_spot} of these are Regex-only - expect more FPs here.
    If >=45/50 are TP: bulk-label remaining bc-java as TP in paper.

  Step 2 - labeling_sample.csv ({len(combined)} rows, ~2-3 hrs)
    {len(other_sample)} rows from python-rsa/ecdsa/jose/node-jwt (label ALL)
    {len(bc_sample)} rows from bc-java (stratified for algorithm coverage)

    enrichment_source column tells you the quality tier:
      AI-enriched ({ai_in_sample} rows): reliable, Claude analysed each file
      Regex-only  ({regex_in_sample} rows): extra scrutiny needed

    Regex-only false positive patterns to watch for:
      "RSA modulus is not composite"  <- error message string  -> FP-Context
      isAlgIdFromPrivate.add("ML-DSA") <- adding a PQC algo   -> FP-Context
      /** id-MLDSA65-ECDSA-P256 */    <- OID comment          -> FP-Context
      "SLH-DSA", "HASH-ML-DSA"        <- PQC names with DSA   -> FP-Context

  Step 3 - Run evaluate.py
    python evaluation/evaluate.py \\
        --ground-truth evaluation/paper1/labeling_sample.csv \\
        --results results/paper1/audit_result_*.json \\
        --output evaluation/paper1/metrics.json

  Total labeling time estimate: ~3 hours
""")
    print(f"{'─'*65}\n")


if __name__ == "__main__":
    main()
