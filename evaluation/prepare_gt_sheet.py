"""
prepare_gt_sheet.py
====================
Run this AFTER you have all 5 audit_result_*.json files.

What it does:
  1. Reads all JSON result files from results/
  2. Creates evaluation/ground_truth.csv pre-populated with every
     finding the tool found — one row per finding
  3. Sets label="?" for every row — YOU fill these in manually
  4. Also creates evaluation/ground_truth_instructions.txt

Usage:
    python evaluation/prepare_gt_sheet.py
    python evaluation/prepare_gt_sheet.py --results-dir my_results/

Then open ground_truth.csv in Excel or VS Code and change each "?" to:
    TP          - True Positive  (real vulnerability in production code)
    FP-Context  - False Positive (comment / docstring / string literal / dead code)
    FP-Safe     - False Positive (real usage but non-security context e.g. MD5 for checksums)
    FP-Test     - False Positive (test fixture or test vector - tool missed it)
"""

import json, csv, argparse, os
from pathlib import Path


LABEL_OPTIONS = ["TP", "FP-Context", "FP-Safe", "FP-Test"]

INSTRUCTIONS = """
GROUND TRUTH LABELING INSTRUCTIONS
====================================

You have a CSV with one row per finding the tool detected.
Your job: open each file on GitHub at the given line number and
assign one of these four labels in the "label" column.

LABELS
------
TP          True Positive
            The tool correctly identified a real quantum-vulnerable
            algorithm being used in production security code.
            Example: rsa/key.py line 45 — RSA.generate(2048)
            This is genuine key generation in a production library.

FP-Context  False Positive — Wrong context
            The pattern matched but it's NOT real crypto usage:
            - A comment:   # RSA is vulnerable to Shor's algorithm
            - A docstring: \"\"\"Uses RSA for signing...\"\"\"
            - A string:    algo_name = "RSA"
            - Dead code:   code in an #if False block
            - Import only: from rsa import RSA (no actual usage)

FP-Safe     False Positive — Safe context
            The algorithm IS being used, but not for security.
            Example: MD5 used to hash filenames for a cache key
            (not for authentication or integrity checking)
            Example: SHA-1 used for a non-cryptographic checksum

FP-Test     False Positive — Test code (tool missed classification)
            Claude said is_test_code=false but it's clearly a test.
            Example: test_rsa.py line 12 generating a test keypair
            Note: if the tool already marked is_test_code=true,
            it's still a TP or FP based on context — just lower priority.

HOW TO LABEL EACH ROW
---------------------
1. Look at the "file_path" column — does the path suggest test code?
   Paths with /test/, /tests/, /spec/, _test., Test. in the name
   are likely test code even if the tool didn't catch it.

2. Open GitHub:
   https://github.com/AnimeshShaw/REPO_NAME/blob/main/FILE_PATH#LLINE_NUMBER

3. Read 5-10 lines around the flagged line.

4. Ask yourself:
   - Is this actually using the algorithm (not just mentioning it)?
   - Is this security-relevant code (key gen, signing, encryption)?
   - Is this production code or a test fixture?

5. Write TP, FP-Context, FP-Safe, or FP-Test in the label column.

ALSO: ADD MISSED FINDINGS (FN = False Negative)
------------------------------------------------
If while browsing the code you notice the tool MISSED a real
vulnerability (e.g., it didn't detect an RSA usage on line 67),
add a new row manually with label="FN".

This is important for calculating recall.
You don't need to be exhaustive — spot-check 2-3 files per repo.

TIPS
----
- The "context" column shows what Claude said about each finding.
  This is helpful but not authoritative — Claude makes mistakes.
- The "confidence" column: anything below 0.75 deserves extra scrutiny.
- The "is_test_code" column: if True, the finding is lower priority
  but still label it correctly.
- For bc-java: this is a crypto library, so almost everything in
  core/src/main/ is a TP. The test/ and src/test/ folders were
  excluded, so you shouldn't see many test findings.
"""


def load_results(results_dir: str) -> list:
    rows = []
    results_path = Path(results_dir)
    json_files = sorted(results_path.glob("audit_result_*.json"))

    if not json_files:
        print(f"ERROR: No audit_result_*.json files found in {results_dir}/")
        print("Run the tool on all 5 repos first.")
        raise SystemExit(1)

    print(f"Found {len(json_files)} result files:")
    for jf in json_files:
        with open(jf) as f:
            data = json.load(jf if False else f)

        repo_url = data.get("repo_url", "unknown")
        findings = data.get("findings", [])
        print(f"  {jf.name}: {len(findings)} findings  ({repo_url})")

        for finding in findings:
            rows.append({
                "repo":         repo_url.split("/")[-1],
                "repo_url":     repo_url,
                "file_path":    finding.get("file_path", ""),
                "line":         finding.get("line_number", ""),
                "algorithm":    finding.get("algorithm", ""),
                "severity":     finding.get("severity", ""),
                "confidence":   finding.get("confidence", ""),
                "is_test_code": finding.get("is_test_code", False),
                "context":      finding.get("context", "").replace("\n", " ")[:120],
                "code_snippet": finding.get("code_snippet", "").replace("\n", " ")[:100],
                "label":        "?",   # <-- YOU FILL THIS IN
                "notes":        "",    # optional notes for yourself
            })

    return rows


def write_csv(rows: list, output_path: str):
    fieldnames = [
        "label", "repo", "file_path", "line", "algorithm",
        "severity", "confidence", "is_test_code",
        "context", "code_snippet", "repo_url", "notes"
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nWrote {len(rows)} rows → {output_path}")


def print_summary(rows: list):
    from collections import Counter
    by_repo  = Counter(r["repo"] for r in rows)
    by_algo  = Counter(r["algorithm"] for r in rows)
    by_sev   = Counter(r["severity"] for r in rows)
    test_ct  = sum(1 for r in rows if str(r["is_test_code"]).lower() == "true")

    print("\n── Findings to label ──────────────────────────────────────")
    print(f"  Total rows : {len(rows)}")
    print(f"  Test code  : {test_ct} (already flagged by tool)")
    print(f"\n  By repo:")
    for repo, cnt in sorted(by_repo.items()):
        print(f"    {repo:30s}  {cnt}")
    print(f"\n  By algorithm:")
    for algo, cnt in sorted(by_algo.items(), key=lambda x: -x[1]):
        print(f"    {algo:20s}  {cnt}")
    print(f"\n  By severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in by_sev:
            print(f"    {sev:10s}  {by_sev[sev]}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Prepare ground truth CSV from audit results")
    parser.add_argument("--results-dir", default="results", help="Directory containing audit_result_*.json files")
    parser.add_argument("--output", default="evaluation/paper1/ground_truth.csv", help="Output CSV path")
    args = parser.parse_args()

    print("\n── Quantum-Safe Auditor: Ground Truth Sheet Generator ─────")
    rows = load_results(args.results_dir)
    print_summary(rows)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    # Don't overwrite existing labels if file already exists
    existing_labels = {}
    if Path(args.output).exists():
        print(f"  NOTE: {args.output} already exists.")
        print(f"        Preserving existing labels for matching rows...")
        with open(args.output, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                key = (row["repo"], row["file_path"], row["line"], row["algorithm"])
                if row["label"] not in ("?", ""):
                    existing_labels[key] = (row["label"], row.get("notes", ""))

    # Apply preserved labels
    preserved = 0
    for row in rows:
        key = (row["repo"], row["file_path"], str(row["line"]), row["algorithm"])
        if key in existing_labels:
            row["label"], row["notes"] = existing_labels[key]
            preserved += 1

    if preserved:
        print(f"  Preserved {preserved} existing labels.")

    write_csv(rows, args.output)

    # Write instructions file
    inst_path = "evaluation/paper1/ground_truth_instructions.txt"
    with open(inst_path, "w") as f:
        f.write(INSTRUCTIONS)
    print(f"Wrote instructions → {inst_path}")

    remaining = sum(1 for r in rows if r["label"] == "?")
    print(f"\n── Next steps ──────────────────────────────────────────────")
    print(f"  1. Open evaluation/paper1/ground_truth.csv in Excel or VS Code")
    print(f"  2. Read evaluation/paper1/ground_truth_instructions.txt")
    print(f"  3. Change each '?' in the label column to one of:")
    print(f"       TP / FP-Context / FP-Safe / FP-Test")
    print(f"  4. Add FN rows for any findings the tool missed")
    print(f"  5. Save the file")
    print(f"  {remaining} rows need labeling")
    print(f"\n  Then run:")
    print(f"    python evaluation/evaluate.py \\")
    print(f"      --ground-truth evaluation/paper1/ground_truth.csv \\")
    print(f"      --results results/audit_result_*.json")
    print()


if __name__ == "__main__":
    main()
