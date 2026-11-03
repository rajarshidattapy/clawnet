<# Start standalone ClawForge and its optional local MCP server. #>
param(
    [switch]$ServersOnly,
    [switch]$NoMcp
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$Py = Join-Path $Root ".venv\Scripts\python.exe"

if (-not (Test-Path $Py)) {
    python -m venv .venv
}

& $Py -m pip install -r core/requirements.txt
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (-not $NoMcp) {
    Start-Process -FilePath $Py -ArgumentList "-m", "clawforge", "serve" -WorkingDirectory $Root -WindowStyle Hidden
    Write-Host "Started local MCP server at http://127.0.0.1:8765/mcp" -ForegroundColor Green
}

if (-not $ServersOnly) {
    & $Py -m clawforge
    exit $LASTEXITCODE
}
