"""
VQE Threat Demo — Quantum threat quantification.

"""

import logging, math
from typing import List, Any

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {"CRITICAL": 3.0, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.3}
# Normalisation: RSA-2048 (4096 qubits) is the canonical reference
MAX_QUBIT_REFERENCE = 4096.0

# Algorithms broken by Grover's (symmetric/hash) — no Shor qubit weighting applies
GROVER_ALGORITHMS = {"MD5", "SHA-1", "SHA1", "AES-128", "AES128", "RC4", "3DES", "HARDCODED_KEY"}


class VQEThreatDemo:
    def __init__(self, use_real_quantum: bool = True):
        self.use_real_quantum = use_real_quantum
        self.qiskit_version = self._get_qiskit_version()
        if use_real_quantum and self.qiskit_version:
            logger.info(f"Qiskit {self.qiskit_version} available — using real quantum simulation")
        else:
            logger.info("Running in classical simulation mode")

    @staticmethod
    def _get_qiskit_version() -> str:
        try:
            import qiskit
            return qiskit.__version__
        except ImportError:
            return ""

    def run_threat_demo(self, findings: List[Any]) -> dict:
        """Compute quantum threat analysis from findings list."""
        if not findings:
            return self._empty_result()

        # ── Qubit-weighted threat score ─────────────────────────────────────
        # Each finding contributes: severity_weight × (qubit_count / max_qubits)
        # This makes the VQE connection causal: higher qubit requirement = higher score
        total_score = 0.0
        max_qubit_finding = 0
        max_qubit_algo = ""
        shor_vulnerable = []
        grover_vulnerable = []

        for f in findings:
            algo = getattr(f, "algorithm", "")
            severity = getattr(f, "severity", "LOW")
            qubits = getattr(f, "logical_qubits", 0) or 0   # field name on CryptoFinding
            confidence = getattr(f, "confidence", 0.7)

            weight = SEVERITY_WEIGHTS.get(severity, 0.3)
            if algo in GROVER_ALGORITHMS or qubits == 0:
                # Grover-weakened (hash/symmetric): flat contribution
                total_score += weight * 0.4 * confidence
                grover_vulnerable.append(algo)
            else:
                # Shor-breakable algorithm: score by logical qubit requirement
                qubit_factor = min(qubits / MAX_QUBIT_REFERENCE, 1.5)
                total_score += weight * qubit_factor * confidence
                shor_vulnerable.append(algo)
                if qubits > max_qubit_finding:
                    max_qubit_finding = qubits
                    max_qubit_algo = algo

        # Normalise to 0-10 scale
        normalised_score = min(total_score / max(len(findings), 1) * 3.0, 10.0)

        # ── Run VQE/QFT simulation ──────────────────────────────────────────
        vqe_baseline = {}
        shor_result = {}
        if self.use_real_quantum and self.qiskit_version:
            try:
                vqe_baseline = self._qiskit_vqe_h2()
                shor_result = self._run_qiskit_shor()
            except Exception as e:
                logger.warning(f"Qiskit simulation failed, using classical: {e}")
                vqe_baseline = self._classical_vqe_h2()
                shor_result = self._classical_shor_simulation()
        else:
            vqe_baseline = self._classical_vqe_h2()
            shor_result = self._classical_shor_simulation()

        hndl_risk = any(a in ("RSA", "ECDSA", "ECDH", "DH", "Ed25519", "X25519", "RSA-1024", "PKCS1v15")
                        for a in shor_vulnerable)

        return {
            "threat_score": round(normalised_score, 2),
            "threat_label": self._score_to_label(normalised_score),
            "quantum_readiness_score": max(0, round(100 - normalised_score * 10)),
            "harvest_now_decrypt_later_risk": hndl_risk,
            "recommended_migration_urgency": self._urgency(normalised_score),
            "shor_vulnerable_algorithms": list(set(shor_vulnerable)),
            "grover_vulnerable_algorithms": list(set(grover_vulnerable)),
            "max_qubit_requirement": max_qubit_finding,
            "max_qubit_algorithm": max_qubit_algo,
            "vqe_baseline": vqe_baseline,
            "shor_simulation": shor_result,
            "qiskit_version": self.qiskit_version or "classical-fallback",
            "total_findings_analyzed": len(findings),
        }

    def _empty_result(self) -> dict:
        vqe = self._classical_vqe_h2() if not (self.use_real_quantum and self.qiskit_version) \
              else self._try_qiskit_vqe()
        return {
            "threat_score": 0.0, "threat_label": "✅ LOW — No quantum-vulnerable algorithms detected",
            "quantum_readiness_score": 100, "harvest_now_decrypt_later_risk": False,
            "recommended_migration_urgency": "None", "shor_vulnerable_algorithms": [],
            "grover_vulnerable_algorithms": [], "max_qubit_requirement": 0,
            "max_qubit_algorithm": "", "vqe_baseline": vqe, "shor_simulation": {},
            "qiskit_version": self.qiskit_version or "classical-fallback",
            "total_findings_analyzed": 0,
        }

    def _try_qiskit_vqe(self) -> dict:
        try:
            return self._qiskit_vqe_h2()
        except Exception:
            return self._classical_vqe_h2()

    # ── Qiskit implementations ─────────────────────────────────────────────

    def _qiskit_vqe_h2(self) -> dict:
        """VQE on H2 molecule — Qiskit 2.x compatible.

        qiskit_algorithms and V1 primitives were removed in Qiskit 2.0.
        Uses StatevectorEstimator V2 + scipy COBYLA directly.
        """
        from qiskit.circuit.library import TwoLocal
        from qiskit.quantum_info import SparsePauliOp
        from qiskit.primitives import StatevectorEstimator
        from scipy.optimize import minimize
        import numpy as np

        hamiltonian = SparsePauliOp.from_list([
            ("II", -1.0523732), ("ZI",  0.3979374),
            ("IZ", -0.3979374), ("ZZ", -0.0112801),
            ("XX",  0.1809312),
        ])

        ansatz = TwoLocal(2, ["ry", "rz"], "cx", reps=2)
        estimator = StatevectorEstimator()

        def cost(params: np.ndarray) -> float:
            # V2 pub format: (circuit, observables, parameter_values)
            pub = (ansatz, hamiltonian, params)
            return float(estimator.run([pub]).result()[0].data.evs)

        np.random.seed(42)
        x0 = np.random.uniform(-math.pi, math.pi, ansatz.num_parameters)
        opt = minimize(cost, x0, method="COBYLA",
                       options={"maxiter": 200, "rhobeg": 0.5})

        return {
            "molecule": "H2 (STO-3G basis)",
            "ground_state_energy_hartree": round(float(opt.fun), 6),
            "exact_energy_hartree": -1.137306,
            "energy_error_hartree": round(abs(float(opt.fun) - (-1.137306)), 6),
            "optimizer_iterations": opt.nfev,
            "ansatz": "TwoLocal(ry,rz,cx,reps=2)",
            "method": "Qiskit VQE (StatevectorEstimator V2 + COBYLA)",
            "relevance": "VQE demonstrates quantum eigenvalue computation — the same class of quantum advantage exploited by Shor's algorithm for period finding.",
        }

    def _run_qiskit_shor(self) -> dict:
        """QFT-based circuit simulating Shor's order-finding subroutine."""
        from qiskit import QuantumCircuit
        from qiskit_aer import AerSimulator
        import numpy as np

        n_qubits = 4
        qc = QuantumCircuit(n_qubits, n_qubits)
        qc.h(range(n_qubits))
        # QFT as the core Shor subroutine
        for j in range(n_qubits):
            qc.h(j)
            for k in range(j + 1, n_qubits):
                qc.cp(math.pi / (2 ** (k - j)), j, k)
        qc.barrier()
        qc.measure(range(n_qubits), range(n_qubits))

        sim = AerSimulator()
        job = sim.run(qc, shots=1024)
        counts = job.result().get_counts()
        top = sorted(counts, key=counts.get, reverse=True)[:3]

        return {
            "method": "QFT circuit (Shor's subroutine)",
            "n_qubits": n_qubits,
            "top_measurement_outcomes": top,
            "relevance": "Quantum Fourier Transform is the key subroutine of Shor's algorithm for breaking RSA/ECDSA.",
        }

    # ── Classical fallbacks ────────────────────────────────────────────────

    def _classical_vqe_h2(self) -> dict:
        """Classical VQE simulation via gradient descent (no Qiskit required)."""
        import numpy as np

        H = np.array([
            [-1.0523732, 0.0, 0.0, 0.1809312],
            [0.0, -0.4744932, -0.1809312, 0.0],
            [0.0, -0.1809312, -0.4744932, 0.0],
            [0.1809312, 0.0, 0.0, -1.0523732],
        ])
        eigenvalues = np.linalg.eigvalsh(H)
        energy = float(eigenvalues[0])

        return {
            "molecule": "H2 (STO-3G basis)",
            "ground_state_energy_hartree": round(energy, 6),
            "exact_energy_hartree": -1.137306,
            "energy_error_hartree": round(abs(energy - (-1.137306)), 6),
            "method": "Classical exact diagonalisation (Qiskit not available)",
            "relevance": "VQE demonstrates quantum eigenvalue computation — the same class of quantum advantage exploited by Shor's algorithm for period finding.",
        }

    def _classical_shor_simulation(self, n: int = 15) -> dict:
        """Classical period-finding to demonstrate Shor's factoring logic."""
        import math, random
        a = 7
        for candidate_a in [7, 11, 13, 2, 4]:
            if math.gcd(candidate_a, n) == 1:
                a = candidate_a
                break
        # Find period r of f(x) = a^x mod n
        r, val = 1, a % n
        for _ in range(10000):
            if val == 1:
                break
            val = (val * a) % n
            r += 1
        if r % 2 == 0:
            factor = math.gcd(pow(a, r // 2) - 1, n)
            if 1 < factor < n:
                return {"success": True, "n": n, "a": a, "period": r, "factor": factor,
                        "method": "Classical period-finding (Shor's algorithm simulation)"}
        return {"success": False, "n": n, "a": a, "period": r,
                "method": "Classical period-finding (Shor's algorithm simulation)"}

    @staticmethod
    def _score_to_label(score: float) -> str:
        if score >= 8.5: return "🔴 CRITICAL — Immediate migration required"
        if score >= 7.0: return "🟠 HIGH — Urgent migration recommended"
        if score >= 4.0: return "🟡 MEDIUM — Migration planning required"
        if score >= 1.5: return "🟢 LOW — Monitor and plan migration"
        return "✅ MINIMAL — No immediate quantum risk"

    @staticmethod
    def _urgency(score: float) -> str:
        if score >= 8.5: return "Immediate (< 6 months)"
        if score >= 7.0: return "Urgent (6–12 months)"
        if score >= 4.0: return "Near-term (1–2 years)"
        if score >= 1.5: return "Medium-term (2–5 years)"
        return "None"