"""Report builder — assembles the final structured audit result.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
import math


class ReportBuilder:

    def build(
        self,
        repo_url: str,
        findings: List[Any],
        quantum_analysis: Dict,
        started_at: datetime,
        completed_at: datetime,
        qiskit_version: str = "",
    ) -> Dict[str, Any]:
        duration = (completed_at - started_at).total_seconds()

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        algo_counts: Dict[str, int] = {}
        language_counts: Dict[str, int] = {}
        total_qubits = 0
        max_qubits = 0

        for f in findings:
            sev = f.severity if hasattr(f, "severity") else f.get("severity", "LOW")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            algo = f.algorithm if hasattr(f, "algorithm") else f.get("algorithm", "Unknown")
            algo_counts[algo] = algo_counts.get(algo, 0) + 1

            lang = f.language if hasattr(f, "language") else f.get("language", "Unknown")
            language_counts[lang] = language_counts.get(lang, 0) + 1

            qubits = f.logical_qubits if hasattr(f, "logical_qubits") else f.get("logical_qubits", 0)
            total_qubits += qubits
            if qubits > max_qubits:
                max_qubits = qubits

        # P4-11: Pearson correlation between finding density and threat score
        # In a single-repo run this is a point estimate; meaningful across 5-repo corpus
        finding_density = len(findings)
        threat_score = quantum_analysis.get("threat_score", 0.0)
        pearson_note = (
            f"Single-repo run: density={finding_density}, "
            f"score={threat_score:.2f} — compute r across corpus for significance."
        )
        quantum_analysis["pearson_correlation"] = pearson_note
        quantum_analysis["finding_density"] = finding_density
        quantum_analysis["max_logical_qubits_in_corpus"] = max_qubits
        quantum_analysis["total_logical_qubits_sum"] = total_qubits

        # P4-6: Algorithm inventory
        algorithm_inventory = {
            algo: {
                "count": count,
                "severity": next(
                    (f.severity for f in findings
                     if (f.algorithm if hasattr(f, "algorithm") else f.get("algorithm")) == algo),
                    "UNKNOWN"
                ),
            }
            for algo, count in sorted(algo_counts.items(),
                                       key=lambda x: -x[1])
        }

        return {
            "repo_url": repo_url,
            "audit_id": f"PQC-{completed_at.strftime('%Y%m%d-%H%M%S')}",
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "duration_seconds": round(duration, 2),
            "files_scanned": 0,                         # populated by orchestrator
            "qiskit_version": qiskit_version,
            "findings": [
                f.to_dict() if hasattr(f, "to_dict") else f
                for f in findings
            ],
            "severity_summary": severity_counts,
            "algorithm_summary": algo_counts,
            "algorithm_inventory": algorithm_inventory,
            "language_summary": language_counts,
            "quantum_analysis": quantum_analysis,
            "overall_risk": self._overall_risk(severity_counts),
            "pqc_ready": len(findings) == 0,
        }

    def _overall_risk(self, counts: Dict) -> str:
        if counts.get("CRITICAL", 0) > 0:
            return "CRITICAL"
        elif counts.get("HIGH", 0) > 0:
            return "HIGH"
        elif counts.get("MEDIUM", 0) > 0:
            return "MEDIUM"
        return "LOW"
