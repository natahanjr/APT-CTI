# One-command launcher for the live-CTI thesis implementation.
#
#   powershell -ExecutionPolicy Bypass -File start.ps1           # bootstrap + open UI (runs the pipeline if results are missing)
#   powershell -ExecutionPolicy Bypass -File start.ps1 -Check    # validate the environment and exit
#   powershell -ExecutionPolicy Bypass -File start.ps1 -Run      # force a full pipeline run, then open the UI
#   powershell -ExecutionPolicy Bypass -File start.ps1 -Serve    # live mode: poll feeds, refresh, serve the UI
#
[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$Run,
    [switch]$Serve,
    [switch]$NoBrowser,
    [switch]$NoData,
    [int]$Port = 8747,
    [int]$Interval = 300
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$vdir = Join-Path $root '.venv'
$py   = Join-Path $vdir 'Scripts\python.exe'
$req  = Join-Path $root 'requirements.txt'

function Fail([string]$msg) {
    Write-Host "ERROR: $msg" -ForegroundColor Red
    exit 1
}
function Info([string]$msg) { Write-Host $msg -ForegroundColor Cyan }
function Warn([string]$msg) { Write-Host $msg -ForegroundColor Yellow }

# --- 1. Python interpreter -------------------------------------------------
function Get-BasePython {
    $candidates = @(
        @{ File = 'py';      Pre = @('-3') },
        @{ File = 'python';  Pre = @() },
        @{ File = 'python3'; Pre = @() }
    )
    foreach ($c in $candidates) {
        $cmd = Get-Command $c.File -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        $argList = $c.Pre + @('-c', 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)')
        try {
            & $cmd.Source @argList 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) { return @{ File = $cmd.Source; Pre = $c.Pre } }
        } catch { }
    }
    return $null
}

# --- 2. virtualenv + dependencies -----------------------------------------
if (-not (Test-Path $py)) {
    $base = Get-BasePython
    if (-not $base) {
        Fail "Python 3.11+ not found on PATH. Install it from https://www.python.org/downloads/ and re-run."
    }
    Info "[env] creating virtualenv (.venv) ..."
    $argList = $base.Pre + @('-m', 'venv', $vdir)
    & $base.File @argList
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $py)) { Fail "virtualenv creation failed" }
}

Info "[env] checking dependencies ..."
& $py -m pip install --quiet --disable-pip-version-check -r $req
if ($LASTEXITCODE -ne 0) { Fail "dependency installation failed (see output above)" }

function Get-EnvCheck {
    $raw = & $py (Join-Path $root 'scripts\env_check.py') 2>&1
    if ($LASTEXITCODE -ne 0) { Fail "environment check failed: $raw" }
    return (($raw | Out-String).Trim()) | ConvertFrom-Json
}

function Show-Status($e) {
    $dsLabel = @{
        'unsw_nb15'   = 'UNSW-NB15  '
        'cicids2017'  = 'CICIDS2017 '
    }
    Write-Host ""
    Write-Host "  python        $($e.python)  (venv ready)" -ForegroundColor Gray
    foreach ($k in @('unsw_nb15', 'cicids2017')) {
        $hasData = $e.datasets.$k
        $hasRes  = $e.results.$k
        $dataTxt = if ($hasData) { 'data ok' } else { 'DATA MISSING' }
        $resTxt  = if ($hasRes) { 'results ok' } else { 'not run yet' }
        $color   = if ($hasData) { 'Green' } else { 'Yellow' }
        Write-Host ("  {0}  {1,-12} {2,-12} {3}" -f $dsLabel[$k], $dataTxt, $resTxt, $e.dataset_paths.$k) -ForegroundColor $color
    }
    $ind = if ($e.ioc_store.stats) { '{0:n0} indicators' -f $e.ioc_store.stats.total } else { 'no IoC store yet' }
    Write-Host "  results       $($e.tables) tables, $($e.figures) figures, dashboard $($e.dashboard.kb) KB" -ForegroundColor Gray
    Write-Host "  ioc store     $ind" -ForegroundColor Gray
    Write-Host ""
}

$e = Get-EnvCheck
Show-Status $e

if ($Check) {
    $ok = $e.ready -and ($e.datasets.unsw_nb15 -or $e.datasets.cicids2017)
    if ($ok) { Write-Host "  OK - environment ready" -ForegroundColor Green }
    else     { Write-Host "  NOT READY - see above" -ForegroundColor Red }
    exit ($(if ($ok) { 0 } else { 1 }))
}

# --- 3. live mode ----------------------------------------------------------
if ($Serve) {
    Info "[serve] live mode on http://127.0.0.1:$Port (poll every $Interval s, Ctrl+C to stop)"
    $serveArgs = @((Join-Path $root 'serve.py'), '--port', $Port, '--interval', $Interval)
    if ($NoBrowser) { $serveArgs += '--no-browser' }
    & $py @serveArgs
    exit $LASTEXITCODE
}

# --- 4. datasets -----------------------------------------------------------
if (-not $NoData) {
    if (-not $e.datasets.cicids2017) {
        Warn "[data] CICIDS2017 CSVs missing - downloading (~285 MB, resumable) ..."
        & $py (Join-Path $root 'scripts\download_cicids2017.py')
        if ($LASTEXITCODE -ne 0) { Fail "CICIDS2017 download failed - re-run start.ps1 to resume" }
        $e = Get-EnvCheck
    }
    if (-not $e.datasets.unsw_nb15) {
        Warn "[data] UNSW-NB15 part files not found under $($e.dataset_paths.unsw_nb15)"
        Warn "        download UNSW-NB15_1..4.csv from https://research.unsw.edu.au/projects/unsw-nb15-dataset"
        Warn "        (continuing with CICIDS2017 only)"
    }
}

$datasets = @()
if ($e.datasets.unsw_nb15)   { $datasets += 'unsw_nb15' }
if ($e.datasets.cicids2017) { $datasets += 'cicids2017' }
if ($datasets.Count -eq 0) { Fail "no datasets available - nothing can run" }

$missing = @($datasets | Where-Object { -not $e.results.$_ })
$needRun = $Run -or $missing.Count -gt 0

# --- 5. pipeline -----------------------------------------------------------
if ($needRun) {
    if ($Run) { Info "[run] full pipeline requested (-Run)" }
    else      { Info "[run] results missing for: $($missing -join ', ') - running the pipeline" }
    Info "[run] logs -> logs\run_all.log  (Ctrl+C aborts)"
    & (Join-Path $root 'run_all.ps1') -Datasets $datasets
    if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
        Warn "[run] pipeline exited with code $LASTEXITCODE - check logs\run_all.log"
    }
    $e = Get-EnvCheck
} else {
    Info "[run] results up to date - skipping the pipeline (use -Run to force)"
}

# --- 6. open the dashboard -------------------------------------------------
$dash = Join-Path $root 'dashboard\index.html'
if (-not (Test-Path $dash)) { Fail "dashboard missing - run: $py scripts\build_dashboard.py" }

if (-not $NoBrowser) {
    Info "[ui] opening $dash"
    Start-Process $dash
} else {
    Info "[ui] $dash"
}
