"""
GitHub MCP Client
=================
Integrates with the GitHub MCP server to:
- Read repository file trees
- Fetch file contents
- Create issues with vulnerability details
"""

import asyncio
import base64
import logging
import os
import random
from typing import List, Dict, Any, Optional

import httpx

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"

# File size limit (skip binary / huge files)
MAX_FILE_SIZE_BYTES = 512 * 1024  # 512 KB

# Hard cap on files fetched per repo (0 = unlimited).
# Set MAX_FILES=300 in .env for large repos like bc-java.
# Smart sampling: crypto-relevant files are always included first.
MAX_FILES = int(os.getenv("MAX_FILES", "0"))

# Path fragments that strongly suggest crypto-relevant code.
# These files are always prioritised when MAX_FILES is active.
_CRYPTO_KEYWORDS = {
    "crypto", "cipher", "encrypt", "decrypt", "sign", "verify",
    "key", "rsa", "ecdsa", "ecdh", "aes", "hmac", "hash",
    "digest", "pkcs", "tls", "ssl", "pem", "der", "asn1",
    "bouncy", "bouncycastle", "openssl", "x509", "cert",
    "secret", "token", "auth", "jwt", "oauth",
}

# Extensions to scan
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java",
    ".rs", ".c", ".cpp", ".cc", ".h", ".hpp", ".cs",
    ".rb", ".php", ".swift", ".kt", ".scala", ".gradle",
    ".yaml", ".yml", ".toml", ".cfg", ".ini", ".env",
}


def _crypto_score(path: str) -> int:
    """Return number of crypto keyword hits in a file path (higher = more relevant)."""
    p = path.lower()
    return sum(1 for kw in _CRYPTO_KEYWORDS if kw in p)


def _prioritised_sample(file_nodes: List[Dict], max_files: int) -> List[Dict]:
    """
    Return up to max_files nodes, crypto-relevant files first.
    Within each tier (crypto vs general) order is preserved.
    """
    if max_files <= 0 or len(file_nodes) <= max_files:
        return file_nodes

    crypto = [n for n in file_nodes if _crypto_score(n["path"]) > 0]
    general = [n for n in file_nodes if _crypto_score(n["path"]) == 0]

    # Sort crypto tier by score descending so most-relevant come first
    crypto.sort(key=lambda n: _crypto_score(n["path"]), reverse=True)

    selected = crypto[:max_files]
    remaining_slots = max_files - len(selected)
    if remaining_slots > 0:
        # Sample general files to fill remaining quota
        random.seed(42)   # reproducible
        selected += random.sample(general, min(remaining_slots, len(general)))

    logger.info(
        f"   MAX_FILES={max_files}: selected {len(crypto[:max_files])} crypto-relevant "
        f"+ {len(selected) - len(crypto[:max_files])} general files "
        f"(skipped {len(file_nodes) - len(selected)} files)"
    )
    return selected


class GitHubMCPClient:
    """
    Client for GitHub REST API.

    For production use with GitHub MCP server, replace the HTTP calls
    with MCP tool calls via the mcp-server-github package:
    https://github.com/modelcontextprotocol/servers/tree/main/src/github
    """

    def __init__(self, token: str, verbose_errors: bool = False,
                 batch_size: int = 3, batch_delay: float = 1.0):
        self.token = token
        self.verbose_errors = verbose_errors
        self.batch_size = batch_size      # concurrent requests per batch
        self.batch_delay = batch_delay    # seconds to sleep between batches
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def get_repo_files(
        self,
        owner: str,
        repo: str,
        extensions: Optional[List[str]] = None,
        branch: str = "main",
    ) -> List[Dict[str, Any]]:
        """
        Fetch all scannable source files from a repository.

        Returns list of {"path": str, "content": str} dicts.
        """
        exts = set(extensions or SCANNABLE_EXTENSIONS)

        async with httpx.AsyncClient(headers=self.headers, timeout=60) as client:
            # Get the full tree (recursive)
            tree = await self._get_tree(client, owner, repo, branch)

            # Filter to scannable files
            file_nodes = [
                node for node in tree
                if node["type"] == "blob"
                and any(node["path"].endswith(ext) for ext in exts)
                and node.get("size", 0) < MAX_FILE_SIZE_BYTES
            ]

            # Apply smart sampling if MAX_FILES is set (for very large repos)
            file_nodes = _prioritised_sample(file_nodes, MAX_FILES)

            logger.info(f"   Fetching {len(file_nodes)} files from {owner}/{repo}...")

            # Fetch in small batches with delay to avoid GitHub secondary rate limits.
            # 403 on contents = abuse detection (not auth); back off and retry.
            files = []
            total_batches = (len(file_nodes) + self.batch_size - 1) // self.batch_size
            for batch_num, batch in enumerate(self._batch(file_nodes, size=self.batch_size), 1):
                if batch_num > 1:
                    await asyncio.sleep(self.batch_delay)

                results = await asyncio.gather(*[
                    self._fetch_file_with_retry(client, owner, repo, node["path"])
                    for node in batch
                ], return_exceptions=True)

                ok = 0
                for node, result in zip(batch, results):
                    if isinstance(result, Exception):
                        logger.debug(f"   Skipping {node['path']}: {result}")
                    elif result:
                        files.append({"path": node["path"], "content": result})
                        ok += 1

                if batch_num % 20 == 0:
                    logger.info(f"   ... batch {batch_num}/{total_batches} "
                                f"({len(files)} files collected so far)")

        return files

    async def _get_tree(
        self, client: httpx.AsyncClient, owner: str, repo: str, branch: str
    ) -> List[Dict]:
        """Get the full file tree for a repo branch."""
        # First get the branch SHA
        resp = await client.get(f"{GITHUB_API}/repos/{owner}/{repo}/branches/{branch}")

        if resp.status_code == 404:
            # Try 'master' if 'main' not found
            resp = await client.get(f"{GITHUB_API}/repos/{owner}/{repo}/branches/master")

        resp.raise_for_status()
        sha = resp.json()["commit"]["commit"]["tree"]["sha"]

        # Get recursive tree
        resp = await client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{sha}",
            params={"recursive": "1"}
        )
        resp.raise_for_status()
        return resp.json().get("tree", [])

    async def _fetch_file_with_retry(
        self, client: httpx.AsyncClient, owner: str, repo: str, path: str,
        max_retries: int = 3,
    ) -> Optional[str]:
        """Fetch a file with exponential backoff on 403/429 (rate limit responses)."""
        for attempt in range(max_retries):
            resp = await client.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("encoding") == "base64":
                    return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
                return data.get("content", "")

            if resp.status_code in (403, 429):
                # Secondary rate limit — back off and retry
                wait = 2 ** (attempt + 2)   # 4s, 8s, 16s
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    wait = int(retry_after) + 1
                logger.warning(
                    f"   Rate limited ({resp.status_code}) on {path} — "
                    f"waiting {wait}s (attempt {attempt + 1}/{max_retries})"
                )
                await asyncio.sleep(wait)
                continue

            # Any other non-200 (404, 500, etc.) — skip file
            if self.verbose_errors:
                logger.debug(f"   HTTP {resp.status_code} for {path}")
            return None

        logger.warning(f"   Giving up on {path} after {max_retries} retries")
        return None

    async def _fetch_file(
        self, client: httpx.AsyncClient, owner: str, repo: str, path: str
    ) -> Optional[str]:
        """Fetch and decode a single file's contents (no retry)."""
        return await self._fetch_file_with_retry(client, owner, repo, path, max_retries=1)

    async def create_vulnerability_issues(
        self, owner: str, repo: str, findings: List[Any]
    ) -> List[str]:
        """
        Create a GitHub Issue for each vulnerability finding.

        Groups findings by algorithm to avoid duplicate issues.
        """
        if not findings:
            return []

        # Group by algorithm
        by_algo: Dict[str, List] = {}
        for f in findings:
            by_algo.setdefault(f.algorithm, []).append(f)

        issue_urls = []

        async with httpx.AsyncClient(headers=self.headers, timeout=30) as client:
            for algo, algo_findings in by_algo.items():
                url = await self._create_issue(client, owner, repo, algo, algo_findings)
                if url:
                    issue_urls.append(url)
                await asyncio.sleep(0.5)  # Respect rate limits

        return issue_urls

    async def _create_issue(
        self,
        client: httpx.AsyncClient,
        owner: str,
        repo: str,
        algorithm: str,
        findings: List[Any],
    ) -> Optional[str]:
        """Create a single GitHub issue for an algorithm's findings."""
        severity = findings[0].severity
        pqc_replacement = findings[0].pqc_replacement
        nist_standard = findings[0].nist_standard
        quantum_threat = findings[0].quantum_threat

        # Build file references
        file_list = "\n".join([
            f"- `{f.file_path}` (line {f.line_number}): `{f.code_snippet[:80]}`"
            for f in findings[:10]  # Cap at 10 per issue
        ])

        if len(findings) > 10:
            file_list += f"\n- ...and {len(findings) - 10} more occurrences"

        body = f"""## 🔐 Quantum Vulnerability: {algorithm}

**Severity**: `{severity}`
**Algorithm**: {algorithm}
**Quantum Threat**: {quantum_threat}

### Affected Files ({len(findings)} occurrence{'s' if len(findings) > 1 else ''})

{file_list}

### Why This Is Vulnerable

{algorithm} is vulnerable to quantum computers running **Shor's algorithm**, which can break the mathematical assumptions underlying this cryptography in polynomial time — compared to exponential time on classical computers.

> ⚠️ **Harvest Now, Decrypt Later**: Adversaries may already be collecting encrypted data to decrypt once sufficiently powerful quantum computers exist (estimated 2030–2035).

### Recommended Migration

Replace `{algorithm}` with **{pqc_replacement}**

**NIST Standard**: {nist_standard}

### Remediation Steps

{chr(10).join([f"{i+1}. {step}" for i, step in enumerate(findings[0].remediation_steps or [f'Replace all {algorithm} usages with {pqc_replacement}'])])}

### Resources

- [NIST Post-Quantum Cryptography Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CISA PQC Migration Guide](https://www.cisa.gov/quantum)
- [NIST FIPS 203 (ML-KEM / Kyber)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 (ML-DSA / Dilithium)](https://csrc.nist.gov/pubs/fips/204/final)

---
*This issue was automatically generated by the [Quantum-Safe Code Auditor](https://github.com/AnimeshShaw/quantum-safe-auditor) 🤖*
"""

        severity_labels = {
            "CRITICAL": ["quantum-vulnerability", "security", "critical"],
            "HIGH": ["quantum-vulnerability", "security", "high"],
            "MEDIUM": ["quantum-vulnerability", "security", "medium"],
            "LOW": ["quantum-vulnerability", "security", "low"],
        }

        payload = {
            "title": f"[PQC Audit] {severity}: Non-quantum-safe {algorithm} detected ({len(findings)} occurrence{'s' if len(findings) > 1 else ''})",
            "body": body,
            "labels": severity_labels.get(severity, ["quantum-vulnerability", "security"]),
        }

        resp = await client.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/issues",
            json=payload
        )

        if resp.status_code == 201:
            return resp.json()["html_url"]
        else:
            logger.warning(f"Failed to create issue for {algorithm}: {resp.status_code} {resp.text[:200]}")
            return None

    @staticmethod
    def _batch(lst: list, size: int):
        for i in range(0, len(lst), size):
            yield lst[i:i + size]