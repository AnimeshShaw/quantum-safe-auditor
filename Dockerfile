# Quantum-Safe Code Auditor — Reproducible evaluation container (P5-14)
# Builds a deterministic environment for running the 5-repo evaluation
# and reproducing all Paper 1 results.
#
# Build:  docker build -t qsa-auditor .
# Run:    docker run --env-file .env qsa-auditor

FROM python:3.11-slim

# System dependencies for Qiskit (BLAS for VQE)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libopenblas-dev \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (cache layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Create directory for evaluation outputs
RUN mkdir -p /app/eval /app/outputs

# Default: run the auditor
CMD ["python", "-m", "agent.orchestrator"]
