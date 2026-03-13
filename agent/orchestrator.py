"""
Quantum-Safe Code Auditor — Main Orchestrator

6-stage agentic pipeline:
  Stage 1: Ingest repository files via GitHub MCP
  Stage 2: Two-pass cryptographic vulnerability scan
  Stage 3: VQE quantum threat simulation
  Stage 4: Build structured audit report
  Stage 5: Publish report to Notion (optional)
  Stage 6: Open GitHub Issues per vulnerability class
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Optional

import anthropic

from agent.config import AuditorConfig, startup_check
from mcp.github_client import GitHubMCPClient
from mcp.notion_client import NotionMCPClient
from scanner.crypto_scanner import CryptoScanner
from quantum.vqe_demo import VQEThreatDemo
from reports.report_builder import ReportBuilder

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Severity ordering used for MIN_SEVERITY threshold filtering
_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def meets_min_severity(finding: dict, min_severity: str = "LOW") -> bool:
    """Return True if the finding's severity is >= min_severity."""
    sev = finding.get("severity", "LOW").upper()
    min_sev = min_severity.upper()
    return _SEVERITY_ORDER.get(sev, 0) >= _SEVERITY_ORDER.get(min_sev, 1)


class QuantumSafeAuditorAgent:
    """
    End-to-end agentic pipeline for Post-Quantum Cryptography (PQC) auditing.
    Combines Claude AI, MCP tooling, and quantum simulation.
    """

    def __init__(self, config: AuditorConfig):
        self.config = config
        self.client = anthropic.Anthropic(api_key=config.anthropic_api_key)
        self.github = GitHubMCPClient(config.github_token,
                                       verbose_errors=config.github_verbose_errors)
        self.notion = NotionMCPClient(config.notion_token)
        self.scanner = CryptoScanner(self.client,
                                      min_confidence=config.min_confidence)
        self.vqe = VQEThreatDemo()
        self.report_builder = ReportBuilder()

    async def run(self, repo_url: str,
                  notion_page_id: Optional[str] = None) -> dict:
        """Execute the full audit pipeline. Returns the audit result dict."""
        logger.info(f"🔐 Starting Quantum-Safe Audit for: {repo_url}")
        start_time = datetime.utcnow()

        # ── Stage 1: Ingest repository ─────────────────────────────────────
        logger.info("📦 Stage 1: Ingesting repository via GitHub MCP...")
        owner, repo = self._parse_repo_url(repo_url)
        all_files = await self.github.get_repo_files(
            owner, repo, extensions=self.config.scan_extensions
        )

        # Apply EXCLUDE_PATHS filter (P3-7)
        files = self._filter_excluded(all_files)
        logger.info(f"   → {len(all_files)} files fetched; "
                    f"{len(files)} after exclude-path filtering")

        # ── Stage 2: Scan for vulnerable cryptography ──────────────────────
        logger.info("🔍 Stage 2: Scanning for non-PQC cryptographic algorithms...")
        findings = await self.scanner.scan_files(files)
        logger.info(f"   → {len(findings)} vulnerability instances found "
                    f"(deduplicated, confidence ≥ {self.config.min_confidence})")

        # ── Stage 3: VQE Quantum Threat Simulation ─────────────────────────
        logger.info("⚛️  Stage 3: Running VQE quantum threat simulation...")
        quantum_analysis = self.vqe.run_threat_demo(findings)
        logger.info(f"   → Quantum threat score: {quantum_analysis['threat_score']:.2f} "
                    f"({quantum_analysis['threat_label']})")

        # Capture Qiskit version (P0-3)
        try:
            import qiskit
            self.config.qiskit_version = qiskit.__version__
        except ImportError:
            self.config.qiskit_version = "not installed (classical fallback used)"

        # ── Stage 4: Build Structured Report ──────────────────────────────
        logger.info("📊 Stage 4: Generating structured audit report...")
        audit_result = self.report_builder.build(
            repo_url=repo_url,
            findings=findings,
            quantum_analysis=quantum_analysis,
            started_at=start_time,
            completed_at=datetime.utcnow(),
            qiskit_version=self.config.qiskit_version,
        )
        audit_result["files_scanned"] = len(files)          # P0-2

        # ── Stage 5: Publish to Notion (optional) ─────────────────────────
        if notion_page_id and self.config.notion_token:
            logger.info("📋 Stage 5: Publishing report to Notion MCP...")
            notion_url = await self.notion.create_audit_report(
                parent_page_id=notion_page_id,
                audit_result=audit_result
            )
            audit_result["notion_url"] = notion_url
            logger.info(f"   → Report published: {notion_url}")

        # ── Stage 6: Open GitHub Issues ───────────────────────────────────
        logger.info("🐛 Stage 6: Opening GitHub Issues for each finding class...")
        filtered_findings = [
            f for f in findings
            if meets_min_severity(f.to_dict(), self.config.min_severity)
        ]
        issue_urls = await self.github.create_vulnerability_issues(
            owner=owner, repo=repo, findings=filtered_findings,
        )
        audit_result["github_issues"] = issue_urls
        logger.info(f"   → Created {len(issue_urls)} GitHub issues")

        logger.info("✅ Quantum-Safe Audit Complete!")
        self._print_summary(audit_result)
        return audit_result

    # ── Helpers ────────────────────────────────────────────────────────────

    def _parse_repo_url(self, url: str):
        parts = url.rstrip("/").split("/")
        return parts[-2], parts[-1]

    def _filter_excluded(self, files):
        """Drop files matching EXCLUDE_PATHS patterns (P3-7)."""
        if not self.config.exclude_paths:
            return files
        filtered = []
        for f in files:
            path = f["path"].lower()
            if any(ex.lower() in path for ex in self.config.exclude_paths):
                logger.debug(f"Excluded by EXCLUDE_PATHS: {f['path']}")
            else:
                filtered.append(f)
        return filtered

    def _print_summary(self, result: dict):
        findings = result.get("findings", [])
        by_sev = result.get("severity_summary", {})
        qa = result.get("quantum_analysis", {})
        inv = result.get("algorithm_inventory", {})

        print("\n" + "═" * 65)
        print("  🔐 QUANTUM-SAFE AUDIT SUMMARY")
        print("═" * 65)
        print(f"  Repository      : {result['repo_url']}")
        print(f"  Audit ID        : {result['audit_id']}")
        print(f"  Files Scanned   : {result['files_scanned']}")
        print(f"  Unique Findings : {len(findings)}")
        print(f"  ├─ CRITICAL     : {by_sev.get('CRITICAL', 0)}")
        print(f"  ├─ HIGH         : {by_sev.get('HIGH', 0)}")
        print(f"  ├─ MEDIUM       : {by_sev.get('MEDIUM', 0)}")
        print(f"  └─ LOW          : {by_sev.get('LOW', 0)}")
        print(f"  Quantum Risk    : {qa.get('threat_label', 'N/A')} "
              f"(score {qa.get('threat_score', 0):.2f}/10)")
        print(f"  Threat Corr.    : {qa.get('pearson_correlation', 'N/A')}")
        print(f"  PQC Ready       : {'✅ Yes' if result.get('pqc_ready') else '❌ No'}")
        print(f"  HNDT Risk       : "
              f"{'⚠️  YES' if qa.get('harvest_now_decrypt_later_risk') else '✅ No'}")
        if inv:
            print(f"  Algorithms      : {', '.join(sorted(inv.keys()))}")
        if result.get("notion_url"):
            print(f"  Notion Report   : {result['notion_url']}")
        print(f"  GitHub Issues   : {len(result.get('github_issues', []))}")
        print(f"  Qiskit Version  : {result.get('qiskit_version', 'N/A')}")
        print("═" * 65 + "\n")


async def main():
    import os
    from dotenv import load_dotenv
    load_dotenv()

    # Validate env vars before doing anything (P0-5)
    startup_check()

    config = AuditorConfig(
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
        github_token=os.getenv("GITHUB_TOKEN"),
        notion_token=os.getenv("NOTION_TOKEN"),
        claude_model=os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6"),
    )

    agent = QuantumSafeAuditorAgent(config)
    repo_url = os.getenv("TARGET_REPO", "https://github.com/example/sample-crypto-app")
    notion_page_id = os.getenv("NOTION_PAGE_ID")

    result = await agent.run(repo_url=repo_url, notion_page_id=notion_page_id)

    with open("audit_result.json", "w") as f:
        json.dump(result, f, indent=2, default=str)

    print("Full results saved to audit_result.json")


if __name__ == "__main__":
    asyncio.run(main())