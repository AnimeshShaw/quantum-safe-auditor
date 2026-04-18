"""
LocalRepoScanner — walks a cloned repo on disk.
Returns the same file-dict structure expected by CryptoScanner.scan_files().
"""

import logging
import os
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

ALWAYS_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__",
    ".tox", ".venv", "venv", "env", "dist", "build",
    "target", ".gradle", ".idea", ".vscode", ".eggs",
    "htmlcov", ".mypy_cache", ".pytest_cache",
}

ALWAYS_SKIP_EXTENSIONS = {
    ".pyc", ".pyo", ".class", ".jar", ".war", ".ear",
    ".so", ".dll", ".dylib", ".exe", ".bin", ".obj",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".whl", ".lock",
}

ALWAYS_SKIP_SUFFIXES = (".min.js", ".min.css", ".bundle.js")

SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".java", ".go", ".rs",
    ".c", ".cpp", ".h", ".hpp", ".cs",
    ".rb", ".php", ".swift", ".kt", ".scala",
}


class LocalRepoScanner:
    """Walk a locally cloned repository and return scannable file dicts."""

    def __init__(
        self,
        repo_path: str,
        exclude_paths: Optional[List[str]] = None,
        max_files: int = 0,
    ):
        self.repo_root = Path(repo_path).resolve()
        self.exclude   = [p.lower().strip("/") for p in (exclude_paths or []) if p.strip()]
        self.max_files = max_files

    def get_files(self) -> List[Dict]:
        """Return list of file dicts compatible with CryptoScanner.scan_files()."""
        collected = []

        for abs_path in self._walk():
            rel_str = abs_path.relative_to(self.repo_root).as_posix()

            if self._is_excluded(rel_str):
                logger.debug(f"Excluded: {rel_str}")
                continue

            try:
                raw_bytes = abs_path.read_bytes()
            except OSError as exc:
                logger.warning(f"Cannot read {abs_path}: {exc}")
                continue

            if b"\x00" in raw_bytes[:8192]:
                logger.debug(f"Skipping binary: {rel_str}")
                continue

            content = raw_bytes.decode("utf-8", errors="replace")

            collected.append({
                "path":      rel_str,
                "abs_path":  str(abs_path),
                "content":   content,
                "raw_bytes": raw_bytes[:8192],
            })

            if self.max_files > 0 and len(collected) >= self.max_files:
                logger.info(f"MAX_FILES={self.max_files} reached — stopping")
                break

        logger.info(f"LocalRepoScanner: {len(collected)} files from {self.repo_root.name}")
        return collected

    # ── internals ─────────────────────────────────────────────────────────────

    def _walk(self):
        for dirpath, dirnames, filenames in os.walk(self.repo_root):
            # Prune skip-dirs in place so os.walk won't descend into them
            dirnames[:] = [
                d for d in dirnames
                if d not in ALWAYS_SKIP_DIRS and not d.startswith(".")
            ]
            for fname in filenames:
                p = Path(dirpath) / fname
                fname_lower = fname.lower()

                if any(fname_lower.endswith(s) for s in ALWAYS_SKIP_SUFFIXES):
                    continue
                if p.suffix.lower() in ALWAYS_SKIP_EXTENSIONS:
                    continue
                if p.suffix.lower() in SCAN_EXTENSIONS:
                    yield p

    def _is_excluded(self, rel_path: str) -> bool:
        rp = rel_path.lower()
        return any(ex in rp for ex in self.exclude)
