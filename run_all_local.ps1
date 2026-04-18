# run_all_local.ps1 — Run local scan for all 5 Paper 1 evaluation repos.
# Requires: ollama serve (running), repos/ cloned via clone_repos.ps1

$repos = @(
    @{
        path     = "repos/python-rsa"
        name     = "python-rsa"
        exclude  = "tests/,examples/,docs/"
        maxFiles = 0
    },
    @{
        path     = "repos/python-ecdsa"
        name     = "python-ecdsa"
        exclude  = "tests/,src/ecdsa/test_,examples/,docs/"
        maxFiles = 0
    },
    @{
        path     = "repos/python-jose"
        name     = "python-jose"
        exclude  = "tests/,examples/,docs/"
        maxFiles = 0
    },
    @{
        path     = "repos/node-jsonwebtoken"
        name     = "node-jsonwebtoken"
        exclude  = "test/,__tests__/,node_modules/"
        maxFiles = 0
    },
    @{
        path     = "repos/bc-java"
        name     = "bc-java"
        exclude  = "test/,src/test/,tls/src/test/,pkix/src/test/"
        maxFiles = 300
    }
)

$failed = @()

foreach ($r in $repos) {
    Write-Host "`n>> Scanning $($r.name)..." -ForegroundColor Cyan
    python run_local_scan.py `
        --repo      $r.path `
        --name      $r.name `
        --exclude   $r.exclude `
        --max-files $r.maxFiles `
        --output    results/local

    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR scanning $($r.name) (exit $LASTEXITCODE)" -ForegroundColor Red
        $failed += $r.name
    } else {
        Write-Host "OK: $($r.name)" -ForegroundColor Green
    }
}

Write-Host "`n=== All scans complete ===" -ForegroundColor Green
Write-Host "Results: results/local/" -ForegroundColor White

if ($failed.Count -gt 0) {
    Write-Host "Failed repos: $($failed -join ', ')" -ForegroundColor Red
}

Write-Host "`nTo compute metrics:" -ForegroundColor Yellow
Write-Host "  python evaluation/evaluate.py ``" -ForegroundColor Yellow
Write-Host "    --results (Get-ChildItem results/local/*.json | Select -ExpandProperty FullName) ``" -ForegroundColor Yellow
Write-Host "    --ground-truth evaluation/paper1/labeling_sample_HandLabeled.csv ``" -ForegroundColor Yellow
Write-Host "    --output evaluation/paper1/metrics_local_llm.json" -ForegroundColor Yellow
