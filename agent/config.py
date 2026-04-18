"""Configuration for the Quantum-Safe Auditor Agent.
"""

import os
import sys
import logging
from dataclasses import dataclass, field
from typing import Optional, List

logger = logging.getLogger(__name__)

REQUIRED_VARS = ["GITHUB_TOKEN", "TARGET_REPO"]


def validate_env() -> List[str]:
    """Return list of missing required environment variables."""
    missing = [v for v in REQUIRED_VARS if not os.getenv(v)]
    return missing


def startup_check():
    """Abort with a clear message if required env vars are missing. (P0-5)"""
    missing = validate_env()
    if missing:
        print("\n❌ STARTUP CHECK FAILED — missing required environment variables:")
        for v in missing:
            print(f"   • {v}")
        print("\nPlease set these in your .env file or environment before running.")
        print("See .env.example for reference.\n")
        sys.exit(1)
    logger.info("✅ Startup validation passed — all required env vars present.")


@dataclass
class AuditorConfig:
    """All configuration needed to run the audit pipeline."""

    # MCP integrations (optional — agent works without them)
    github_token: Optional[str] = None
    notion_token: Optional[str] = None

    # Scanning behaviour
    max_file_size_kb: int = 512
    scan_extensions: List[str] = field(default_factory=lambda: [
        ".py", ".js", ".ts", ".go", ".java", ".rs",
        ".c", ".cpp", ".cs", ".rb", ".php", ".swift", ".kt", ".scala"
    ])
    exclude_paths: List[str] = field(default_factory=lambda: [
        p.strip() for p in os.getenv("EXCLUDE_PATHS", "").split(",") if p.strip()
    ])

    # Severity threshold — findings below this are not reported in CI (P3-6)
    min_severity: str = os.getenv("MIN_SEVERITY", "LOW")

    # Confidence threshold — passed to CryptoScanner
    min_confidence: float = float(os.getenv("MIN_CONFIDENCE", "0.6"))

    # GitHub Issues settings
    issue_label: str = "quantum-vulnerability"
    issue_assignees: List[str] = field(default_factory=list)
    github_verbose_errors: bool = True  # P0-4

    # Report settings
    report_title_prefix: str = "PQC Audit"
    include_vqe_demo: bool = True

    # Qiskit version (populated at runtime, P0-3)
    qiskit_version: str = ""

    # Severity weights for quantum threat score calculation
    severity_weights: dict = field(default_factory=lambda: {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 1,
    })

    def severity_passes_threshold(self, severity: str) -> bool:
        """Return True if severity meets or exceeds min_severity."""
        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        try:
            return order.index(severity) >= order.index(self.min_severity.upper())
        except ValueError:
            return True
