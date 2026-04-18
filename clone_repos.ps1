# clone_repos.ps1 — Clone all 5 Paper 1 evaluation repos into repos/
# Run once from the qsa/ directory. Shallow clone (--depth=1) to save space.

$repos = @(
    @{ url = "https://github.com/sybrenstuvel/python-rsa.git";    dir = "repos/python-rsa" },
    @{ url = "https://github.com/tlsfuzzer/python-ecdsa.git";     dir = "repos/python-ecdsa" },
    @{ url = "https://github.com/mpdavis/python-jose.git";        dir = "repos/python-jose" },
    @{ url = "https://github.com/auth0/node-jsonwebtoken.git";    dir = "repos/node-jsonwebtoken" },
    @{ url = "https://github.com/bcgit/bc-java.git";              dir = "repos/bc-java" }
)

New-Item -ItemType Directory -Force -Path "repos" | Out-Null

foreach ($r in $repos) {
    if (Test-Path $r.dir) {
        Write-Host "Already exists: $($r.dir) — skipping" -ForegroundColor Yellow
    } else {
        Write-Host "Cloning $($r.url) -> $($r.dir)" -ForegroundColor Cyan
        git clone --depth=1 $r.url $r.dir
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR cloning $($r.url)" -ForegroundColor Red
        }
    }
}

Write-Host "`nDone. All repos available in repos/" -ForegroundColor Green
