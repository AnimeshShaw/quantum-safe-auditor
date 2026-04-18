"""
run_local_scan.py — Single-repo local filesystem audit pipeline.

Usage:
    python run_local_scan.py --repo repos/python-rsa --name python-rsa
    python run_local_scan.py  # reads LOCAL_REPO_PATH / LOCAL_REPO_NAME from .env
"""

import asyncio
import json
import logging
import os
import argparse
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from scanner.enricher_factory import get_enricher
from scanner.crypto_scanner import CryptoScanner
from quantum.vqe_demo import VQEThreatDemo
from reports.report_builder import ReportBuilder
from local_scan.local_repo_scanner import LocalRepoScanner

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


async def run_local_audit(
    repo_path: str,
    repo_name: str,
    exclude_paths: list,
    max_files: int,
    min_confidence: float,
    output_dir: str,
) -> dict:
    logger.info(f"Starting local audit: {repo_name}  ({repo_path})")
    start_time = datetime.now(timezone.utc)

    # Stage 1 — read local files
    fs_scanner = LocalRepoScanner(
        repo_path=repo_path,
        exclude_paths=exclude_paths,
        max_files=max_files,
    )
    files = fs_scanner.get_files()
    logger.info(f"   {len(files)} files to scan")

    # Stage 2 — two-pass scan (regex + LLM)
    enricher      = get_enricher()
    crypto_scanner = CryptoScanner(enricher=enricher, min_confidence=min_confidence)
    findings      = await crypto_scanner.scan_files(files)
    logger.info(f"   {len(findings)} findings (confidence >= {min_confidence})")

    # Stage 3 — VQE threat scoring
    vqe              = VQEThreatDemo()
    quantum_analysis = vqe.run_threat_demo(findings)
    logger.info(
        f"   VQE threat score: {quantum_analysis['threat_score']:.2f}"
        f"  ({quantum_analysis['threat_label']})"
    )

    # Stage 4 — build report
    report_builder = ReportBuilder()
    audit_result   = report_builder.build(
        repo_url         = f"local://{repo_name}",
        findings         = findings,
        quantum_analysis = quantum_analysis,
        started_at       = start_time,
        completed_at     = datetime.now(timezone.utc),
        qiskit_version   = _qiskit_version(),
    )

    # Augment with local-scan metadata
    audit_result["repo_name"]      = repo_name
    audit_result["repo_path"]      = repo_path
    audit_result["files_scanned"]  = len(files)
    audit_result["llm_backend"]    = os.getenv("LLM_BACKEND", "ollama")
    audit_result["llm_model"]      = os.getenv("OLLAMA_MODEL", os.getenv("LLM_MODEL", "unknown"))
    audit_result["exclude_paths"]  = exclude_paths
    audit_result["min_confidence"] = min_confidence

    # Save JSON
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    ts       = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = Path(output_dir) / f"audit_{repo_name}_{ts}.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(audit_result, fh, indent=2, ensure_ascii=False, default=str)
    logger.info(f"   Saved: {out_path}")

    _print_summary(repo_name, audit_result)
    return audit_result


def _qiskit_version() -> str:
    try:
        import qiskit
        return qiskit.__version__
    except ImportError:
        return "not installed"


def _print_summary(repo_name: str, result: dict):
    qa  = result.get("quantum_analysis", {})
    sev = result.get("severity_summary", {})
    sep = "=" * 62
    print(f"\n{sep}")
    print(f"  QUANTUM-SAFE AUDIT -- {repo_name}")
    print(sep)
    print(f"  Files Scanned : {result.get('files_scanned', 0)}")
    print(f"  Findings      : {len(result.get('findings', []))}")
    print(f"  CRITICAL      : {sev.get('CRITICAL', 0)}")
    print(f"  HIGH          : {sev.get('HIGH', 0)}")
    print(f"  MEDIUM        : {sev.get('MEDIUM', 0)}")
    score = qa.get('threat_score', 0)
    label = qa.get('threat_label', 'N/A').encode('ascii', errors='replace').decode()
    print(f"  VQE Score     : {score:.2f}  ({label})")
    print(f"  LLM Backend   : {result.get('llm_backend')} / {result.get('llm_model')}")
    print(f"{sep}\n")


def main():
    parser = argparse.ArgumentParser(description="Local repo quantum-safe audit")
    parser.add_argument("--repo",
                        default=os.getenv("LOCAL_REPO_PATH"),
                        help="Path to cloned repo directory")
    parser.add_argument("--name",
                        default=os.getenv("LOCAL_REPO_NAME"),
                        help="Repo name used in output filename")
    parser.add_argument("--exclude",
                        default=os.getenv("EXCLUDE_PATHS", ""),
                        help="Comma-separated path fragments to exclude")
    parser.add_argument("--max-files",
                        type=int,
                        default=int(os.getenv("MAX_FILES", "0")),
                        help="Max files to scan (0 = unlimited)")
    parser.add_argument("--confidence",
                        type=float,
                        default=float(os.getenv("MIN_CONFIDENCE", "0.6")),
                        help="Minimum confidence threshold (default 0.6)")
    parser.add_argument("--output",
                        default=os.getenv("LOCAL_RESULTS_DIR", "results/local"),
                        help="Output directory for JSON results")
    args = parser.parse_args()

    if not args.repo:
        parser.error("--repo is required (or set LOCAL_REPO_PATH in .env)")
    if not args.name:
        args.name = Path(args.repo).name

    exclude = [p.strip() for p in args.exclude.split(",") if p.strip()]

    asyncio.run(run_local_audit(
        repo_path     = args.repo,
        repo_name     = args.name,
        exclude_paths = exclude,
        max_files     = args.max_files,
        min_confidence= args.confidence,
        output_dir    = args.output,
    ))


if __name__ == "__main__":
    main()
