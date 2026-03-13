"""
evaluate.py — Compute precision, recall, F1 for Paper 1 evaluation.

Usage:
    python evaluation/evaluate.py \
        --ground-truth evaluation/labeling_sample_HandLabeled.csv \
        --results results/audit_result_python_rsa.json \
                  results/audit_result_python_ecdsa.json \
                  results/audit_result_python_jose.json \
                  results/audit_result_node_jwt.json \
                  results/audit_result_bc_java.json \
        --output evaluation/metrics.json

Ground truth CSV columns (after hand-labeling):
    label, repo, file_path, line, algorithm, severity, confidence,
    is_test_code, context, code_snippet, repo_url, notes, enrichment_source

Label values:
    TP          -- True positive: real vulnerability in production security code
    FP-Context  -- False positive: comment, string literal, OID, dead code
    FP-Safe     -- False positive: algorithm used in non-security context
    FP-Test     -- False positive: test fixture not filtered via EXCLUDE_PATHS
    FN          -- False negative: real vulnerability missed by tool (manually added)

Precision note:
    FP-Test findings (n=188, all from python-ecdsa) are excluded from the precision
    denominator. These are configuration artefacts (test files not excluded via
    EXCLUDE_PATHS), not scanner errors. Counted and reported separately for
    transparency.

Outputs:
    - Overall precision / recall / F1 (FP-Test excluded from denominator)
    - FP breakdown by type (FP-Context, FP-Safe, FP-Test)
    - Per-algorithm precision / recall / F1
    - Two-tier analysis: AI-enriched vs Regex-only findings
    - Pearson correlation between threat score and finding density
    - JSON file at --output path
"""

import json
import csv
import sys
import math
import argparse
from collections import defaultdict
from pathlib import Path


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_ground_truth(path: str) -> list:
    rows = []
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            label = row["label"].strip().upper()
            if not label:
                continue  # skip unlabeled rows
            rows.append({
                "repo":              row["repo"].strip(),
                "file":              row["file_path"].strip(),
                "line":              int(row["line"]) if row["line"].strip() else 0,
                "algorithm":         row["algorithm"].strip(),
                "label":             label,
                "enrichment_source": row.get("enrichment_source", "").strip(),
            })
    return rows


def load_audit_results(paths: list) -> list:
    """Load one or more audit_result.json files."""
    all_findings = []
    for p in paths:
        with open(p) as f:
            data = json.load(f)
        repo = data.get("repo_url", "unknown")
        for finding in data.get("findings", []):
            finding["_repo"] = repo
            all_findings.append(finding)
    return all_findings


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def compute_metrics(ground_truth: list, tool_findings: list = None) -> dict:
    """
    Compute metrics purely from labeled ground truth rows.

    FP-Test is excluded from the precision denominator -- these are configuration
    artefacts (test files not filtered via EXCLUDE_PATHS), not scanner errors.
    They are counted and reported separately for full transparency.
    """
    TP      = sum(1 for r in ground_truth if r["label"] == "TP")
    FP_ctx  = sum(1 for r in ground_truth if r["label"] == "FP-CONTEXT")
    FP_safe = sum(1 for r in ground_truth if r["label"] == "FP-SAFE")
    FP_test = sum(1 for r in ground_truth if r["label"] == "FP-TEST")
    FN      = sum(1 for r in ground_truth if r["label"] == "FN")

    FP_for_precision = FP_ctx + FP_safe   # FP-Test intentionally excluded

    precision = TP / (TP + FP_for_precision) if (TP + FP_for_precision) > 0 else 0.0
    recall    = TP / (TP + FN)             if (TP + FN) > 0             else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)

    return {
        "TP":           TP,
        "FP_context":   FP_ctx,
        "FP_safe":      FP_safe,
        "FP_test":      FP_test,
        "FP_test_note": "Excluded from precision denominator -- test fixtures not filtered via EXCLUDE_PATHS",
        "FN":           FN,
        "precision":    round(precision, 4),
        "recall":       round(recall, 4),
        "f1":           round(f1, 4),
    }


def per_algo_metrics(ground_truth: list) -> dict:
    algorithms = set(r["algorithm"] for r in ground_truth)
    result = {}
    for algo in sorted(algorithms):
        gt_algo = [r for r in ground_truth if r["algorithm"] == algo]
        result[algo] = compute_metrics(gt_algo)
    return result


def per_tier_metrics(ground_truth: list) -> dict:
    """
    Split findings by enrichment_source and compute metrics per tier.
    Proves the value of the two-pass AI design over regex-only baseline.
    """
    tiers = {}
    for tier in ["AI-enriched", "Regex-only"]:
        subset = [r for r in ground_truth if r["enrichment_source"] == tier]
        if subset:
            m = compute_metrics(subset)
            m["n"] = len(subset)
            tiers[tier] = m
    return tiers


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

def pearson_correlation(xs: list, ys: list) -> float:
    n = len(xs)
    if n < 2:
        return 0.0
    mx, my = sum(xs) / n, sum(ys) / n
    num   = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    denom = math.sqrt(
        sum((x - mx) ** 2 for x in xs) *
        sum((y - my) ** 2 for y in ys)
    )
    return round(num / denom, 4) if denom else 0.0


def compute_threat_correlation(audit_paths: list) -> dict:
    """Pearson r between finding density (findings/file) and VQE threat score."""
    densities, scores = [], []
    for p in audit_paths:
        with open(p) as f:
            data = json.load(f)
        files      = max(data.get("files_scanned", 1), 1)
        n_findings = len(data.get("findings", []))
        score      = data.get("quantum_analysis", {}).get("threat_score", 0.0)
        densities.append(n_findings / files)
        scores.append(score)
    return {
        "finding_densities": densities,
        "threat_scores":     scores,
        "pearson_r":         pearson_correlation(densities, scores),
        "n_repos":           len(audit_paths),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Evaluate PQC auditor precision/recall/F1"
    )
    parser.add_argument("--ground-truth", required=True,
                        help="Path to hand-labeled CSV")
    parser.add_argument("--results", required=True, nargs="+",
                        help="One or more audit_result.json paths")
    parser.add_argument("--baseline", nargs="+",
                        help="Regex-only audit_result.json files for lift comparison")
    parser.add_argument("--output", default="evaluation/metrics.json",
                        help="Output JSON path (default: evaluation/metrics.json)")
    args = parser.parse_args()

    # ---- Load ----
    print("\n📊 Loading ground truth...")
    gt = load_ground_truth(args.ground_truth)
    n_tp   = sum(1 for r in gt if r["label"] == "TP")
    n_fp   = sum(1 for r in gt if r["label"].startswith("FP"))
    n_test = sum(1 for r in gt if r["label"] == "FP-TEST")
    n_fn   = sum(1 for r in gt if r["label"] == "FN")
    print(f"   -> {len(gt)} labeled rows  |  TP={n_tp}  FP={n_fp} "
          f"(FP-Test={n_test} excluded from precision)  FN={n_fn}")

    print("📊 Loading tool results...")
    findings = load_audit_results(args.results)
    print(f"   -> {len(findings)} tool findings across {len(args.results)} repos")

    # ---- Overall ----
    print("\n📊 Overall metrics (two-pass, FP-Test excluded from precision):")
    overall = compute_metrics(gt, findings)
    print(f"   TP           : {overall['TP']}")
    print(f"   FP-Context   : {overall['FP_context']}")
    print(f"   FP-Safe      : {overall['FP_safe']}")
    print(f"   FP-Test      : {overall['FP_test']}  <- excluded from precision denominator")
    print(f"   FN           : {overall['FN']}")
    print(f"   precision    : {overall['precision']:.4f}")
    print(f"   recall       : {overall['recall']:.4f}")
    print(f"   f1           : {overall['f1']:.4f}")

    # ---- Per algorithm ----
    print("\n📊 Per-algorithm metrics:")
    per_algo = per_algo_metrics(gt)
    for algo, m in per_algo.items():
        print(f"   {algo:15s}: P={m['precision']:.3f}  R={m['recall']:.3f}  "
              f"F1={m['f1']:.3f}  (TP={m['TP']} FP-ctx={m['FP_context']} "
              f"FP-safe={m['FP_safe']} FP-test={m['FP_test']} FN={m['FN']})")

    # ---- Two-tier: AI-enriched vs Regex-only ----
    print("\n📊 Two-tier quality analysis (AI-enriched vs Regex-only):")
    tiers = per_tier_metrics(gt)
    for tier, m in tiers.items():
        print(f"   {tier:15s} (n={m['n']:4d}): "
              f"P={m['precision']:.3f}  R={m['recall']:.3f}  F1={m['f1']:.3f}  "
              f"(TP={m['TP']} FP-ctx={m['FP_context']} "
              f"FP-safe={m['FP_safe']} FP-test={m['FP_test']})")

    # ---- Correlation ----
    print("\n📊 Threat score vs finding density correlation:")
    corr = compute_threat_correlation(args.results)
    print(f"   Pearson r = {corr['pearson_r']}  across {corr['n_repos']} repos")

    # ---- Baseline comparison (optional) ----
    baseline_out = None
    if args.baseline:
        print("\n📊 Baseline (regex-only) metrics:")
        baseline_findings = load_audit_results(args.baseline)
        baseline_out = compute_metrics(gt, baseline_findings)
        for k, v in baseline_out.items():
            if not k.endswith("_note"):
                print(f"   {k:14s}: {v}")
        if baseline_out["precision"] > 0:
            lift = ((overall["precision"] - baseline_out["precision"])
                    / baseline_out["precision"] * 100)
            print(f"   Two-pass precision lift: +{lift:.1f}%")
            baseline_out["twopass_precision_lift_pct"] = round(lift, 2)

    # ---- Save ----
    output = {
        "overall":            overall,
        "per_algorithm":      per_algo,
        "two_tier_analysis":  tiers,
        "threat_correlation": corr,
    }
    if baseline_out:
        output["baseline"] = baseline_out

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nMetrics saved to {args.output}")


if __name__ == "__main__":
    main()