# ============================================================
# Quantum-Safe Auditor - Run All 5 Evaluation Repos
# Run with: .\run_all_repos.ps1
# The conda env must already be activated before running.
# ============================================================

$ErrorActionPreference = "Stop"

# -- Config --------------------------------------------------
$RESULTS_DIR = ".\results"

$REPOS = @(
    @{ name = "python_rsa";   url = "https://github.com/AnimeshShaw/python-rsa";        exclude = "tests/" },
    @{ name = "python_ecdsa"; url = "https://github.com/AnimeshShaw/python-ecdsa";       exclude = "docs/" },
    @{ name = "python_jose";  url = "https://github.com/AnimeshShaw/python-jose";        exclude = "tests/,docs/" },
    @{ name = "node_jwt";     url = "https://github.com/AnimeshShaw/node-jsonwebtoken";  exclude = "test/" },
    @{ name = "bc_java";      url = "https://github.com/AnimeshShaw/bc-java";            exclude = "/test/,src/test/" }
)

# -- Header --------------------------------------------------
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Quantum-Safe Auditor - 5-Repo Evaluation Run"              -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# -- Verify Python is available ------------------------------
$pythonPath = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonPath) {
    Write-Host "ERROR: python not found in PATH." -ForegroundColor Red
    Write-Host "Make sure your conda env is activated: conda activate quantum-safe-auditor" -ForegroundColor Yellow
    exit 1
}
Write-Host "Python   : $pythonPath" -ForegroundColor Green

# Show which conda env is active (informational only)
if ($env:CONDA_PREFIX) {
    Write-Host "Conda env: $env:CONDA_PREFIX" -ForegroundColor Green
} else {
    Write-Host "WARNING: CONDA_PREFIX not set - make sure your env is activated" -ForegroundColor Yellow
}

# -- Load .env -----------------------------------------------
if (-not (Test-Path ".\.env")) {
    Write-Host "ERROR: .env file not found in current directory" -ForegroundColor Red
    exit 1
}

$envLines      = Get-Content ".\.env"
$ANTHROPIC_KEY = ($envLines | Where-Object { $_ -match "^ANTHROPIC_API_KEY=" }) -replace "^ANTHROPIC_API_KEY=", ""
$GITHUB_TOKEN  = ($envLines | Where-Object { $_ -match "^GITHUB_TOKEN=" })      -replace "^GITHUB_TOKEN=", ""

if (-not $ANTHROPIC_KEY -or -not $GITHUB_TOKEN) {
    Write-Host "ERROR: ANTHROPIC_API_KEY or GITHUB_TOKEN missing from .env" -ForegroundColor Red
    exit 1
}
Write-Host "API keys : loaded from .env" -ForegroundColor Green

# -- Create results dir --------------------------------------
if (-not (Test-Path $RESULTS_DIR)) {
    New-Item -ItemType Directory -Path $RESULTS_DIR | Out-Null
    Write-Host "Created  : $RESULTS_DIR" -ForegroundColor Green
}

# -- Run each repo -------------------------------------------
$successful = 0
$failed     = 0
$startAll   = Get-Date

for ($i = 0; $i -lt $REPOS.Count; $i++) {
    $repo    = $REPOS[$i]
    $repoNum = $i + 1
    $outFile = "$RESULTS_DIR\audit_result_$($repo.name).json"

    Write-Host ""
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [$repoNum/$($REPOS.Count)] $($repo.name)"                  -ForegroundColor White
    Write-Host "  URL    : $($repo.url)"                                      -ForegroundColor Gray
    Write-Host "  Exclude: $($repo.exclude)"                                  -ForegroundColor Gray
    Write-Host "  Output : $outFile"                                          -ForegroundColor Gray
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray

    if (Test-Path $outFile) {
        Write-Host "  SKIPPING - result already exists. Delete to re-run." -ForegroundColor Yellow
        $successful++
        continue
    }

    $env:ANTHROPIC_API_KEY = $ANTHROPIC_KEY
    $env:GITHUB_TOKEN      = $GITHUB_TOKEN
    $env:TARGET_REPO       = $repo.url
    $env:EXCLUDE_PATHS     = $repo.exclude
    $env:MIN_CONFIDENCE    = "0.6"
    $env:MIN_SEVERITY      = "LOW"
    $env:CLAUDE_MODEL      = "claude-sonnet-4-6"

    $repoStart = Get-Date

    try {
        python -m agent.orchestrator

        if (Test-Path ".\audit_result.json") {
            Move-Item ".\audit_result.json" $outFile -Force
            $elapsed = [math]::Round(((Get-Date) - $repoStart).TotalMinutes, 1)
            Write-Host "  DONE in $elapsed min -> $outFile" -ForegroundColor Green
            $successful++
        } else {
            Write-Host "  WARNING: audit_result.json was not produced" -ForegroundColor Red
            $failed++
        }
    } catch {
        Write-Host "  ERROR: $_" -ForegroundColor Red
        $failed++
    }

    if ($i -lt ($REPOS.Count - 1)) {
        Write-Host "  Pausing 10s before next repo..." -ForegroundColor DarkGray
        Start-Sleep -Seconds 10
    }
}

# -- Summary -------------------------------------------------
$totalElapsed = [math]::Round(((Get-Date) - $startAll).TotalMinutes, 1)
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  COMPLETE - $successful/$($REPOS.Count) repos in $totalElapsed min" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Get-ChildItem $RESULTS_DIR -Filter "*.json" | ForEach-Object {
    $kb = [math]::Round($_.Length / 1KB, 1)
    Write-Host "  $($_.Name)  ($kb KB)" -ForegroundColor Gray
}
Write-Host ""
Write-Host "  Next step: python evaluation\prepare_gt_sheet.py" -ForegroundColor Yellow
Write-Host ""