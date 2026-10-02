<#
.SYNOPSIS
    Start the whole ClawForge stack: each server in its own terminal, then the console here.

.DESCRIPTION
        terminal "TrueForge"     python -m clawforge trueforge   (http://localhost:8790)
        terminal "ClawNet MCP"   python -m clawforge serve       (http://127.0.0.1:8765/mcp)
        terminal "Supermemory"   bash scripts/supermemory-local.sh   (only with -Supermemory)
        this terminal            python -m clawforge             (the TUI)

    Servers that are already running are reused, except an MCP server running
    older code than what is on disk, which is restarted. Once both servers answer,
    `python -m clawforge setup` (idempotent) registers the provider, connector and
    agent in TrueForge, so the console starts with every check green.

    New terminals open as Windows Terminal tabs when `wt` is available, otherwise
    as separate PowerShell windows. The TUI runs in *this* console because /watch
    reads keys straight from the Windows console.

.EXAMPLE
    .\start.ps1                 # everything + TUI
    .\start.ps1 -Supermemory    # also start Supermemory Local (WSL)
    .\start.ps1 -ServersOnly    # start servers, no TUI
    .\start.ps1 -Restart        # restart the MCP server even if it is current
#>
param(
    [switch]$Supermemory,
    [switch]$ServersOnly,
    [switch]$SkipSetup,
    [switch]$Restart,
    [switch]$NewWindows,        # separate windows instead of Windows Terminal tabs
    [int]$TrueForgeTimeout = 600  # first run installs TrueForge via npm
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
Set-Location $Root

function Info($msg) { Write-Host "  $msg" -ForegroundColor DarkGray }
function Ok($msg)   { Write-Host "  [ok] $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "  [!]  $msg" -ForegroundColor Yellow }
function Fail($msg) { Write-Host "  [x]  $msg" -ForegroundColor Red }

Write-Host ""
Write-Host "  ClawForge launcher" -ForegroundColor Cyan
Write-Host ""

# -- Python venv ---------------------------------------------------------------
$Py = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Py)) {
    $sysPy = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $sysPy) { Fail "Python 3.10+ not found on PATH."; exit 1 }
    Info "creating .venv and installing core/requirements.txt ..."
    & $sysPy -m venv (Join-Path $Root ".venv")
    & $Py -m pip install --disable-pip-version-check -q -r (Join-Path $Root "core\requirements.txt")
    if ($LASTEXITCODE -ne 0) { Fail "pip install failed."; exit 1 }
}
Ok "python   $Py"

# -- .env ----------------------------------------------------------------------
$EnvFile = Join-Path $Root ".env"
if (-not (Test-Path $EnvFile)) {
    Copy-Item (Join-Path $Root ".env.example") $EnvFile
    Warn ".env created from .env.example; set OPENAI_API_KEY in it, then re-run."
}
$Cfg = @{}
foreach ($line in Get-Content $EnvFile -Encoding UTF8) {
    $l = $line.Trim()
    if ($l -and -not $l.StartsWith("#") -and $l.Contains("=")) {
        $k, $v = $l.Split("=", 2)
        $Cfg[$k.Trim()] = $v.Trim()
    }
}
function Cfg($name, $default) {
    $fromProc = [Environment]::GetEnvironmentVariable($name)
    if ($fromProc) { return $fromProc }
    if ($Cfg[$name]) { return $Cfg[$name] }
    return $default
}
if (-not (Cfg "OPENAI_API_KEY" "")) { Warn "OPENAI_API_KEY is empty in .env; the agent cannot run without it." }

$TfUrl   = (Cfg "TRUEFORGE_BASE_URL" "http://localhost:8790").TrimEnd("/")
$McpHost = Cfg "CLAWFORGE_HOST" "127.0.0.1"
$McpPort = [int](Cfg "CLAWFORGE_PORT" "8765")
$TfUri   = [Uri]$TfUrl

# -- helpers -------------------------------------------------------------------
function Test-Port([string]$h, [int]$p) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $c.BeginConnect($h, $p, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne(500)) { return $false }
        $c.EndConnect($ar); return $true
    } catch { return $false } finally { $c.Close() }
}

function Test-TrueForge {
    try {
        $r = Invoke-WebRequest "$TfUrl/api/v1/agents?limit=1" -UseBasicParsing -TimeoutSec 3
        return $r.StatusCode -eq 200
    } catch { return $false }
}

function Wait-Until([scriptblock]$cond, [int]$seconds, [string]$what) {
    $deadline = (Get-Date).AddSeconds($seconds)
    $i = 0
    while ((Get-Date) -lt $deadline) {
        if (& $cond) { Write-Host ""; return $true }
        if ($i++ % 4 -eq 0) { Write-Host -NoNewline "." -ForegroundColor DarkGray }
        Start-Sleep -Milliseconds 500
    }
    Write-Host ""
    Fail "$what did not come up within $seconds s (check its terminal)."
    return $false
}

$UseWt = (-not $NewWindows) -and [bool](Get-Command wt.exe -ErrorAction SilentlyContinue)

function Start-Pane([string]$title, [string]$command) {
    # -NoExit keeps the terminal open so a crash stays readable.
    # -EncodedCommand: wt treats ';' as its own separator, and quotes get mangled
    # passing through wt / Start-Process; base64 survives both untouched.
    $ps = "`$Host.UI.RawUI.WindowTitle = '$title'; `$env:PYTHONIOENCODING = 'utf-8'; Set-Location '$Root'; $command"
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ps))
    if ($UseWt) {
        & wt.exe -w 0 new-tab --title $title --suppressApplicationTitle -d $Root `
            powershell.exe -NoExit -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc
    } else {
        Start-Process powershell.exe -WorkingDirectory $Root `
            -ArgumentList @("-NoExit", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $enc)
    }
}

function Get-McpStaleReason {
    # Mirrors clawforge.tui._server_is_stale: compare the server's stamp to the code on disk.
    $stampPath = Join-Path $HOME ".clawnet\clawforge_server.json"
    if (-not (Test-Path $stampPath)) { return @{ reason = "no server stamp"; pid = $null } }
    $stamp = Get-Content $stampPath -Raw | ConvertFrom-Json
    $newest = Get-ChildItem (Join-Path $Root "clawforge\*.py"), (Join-Path $Root "core\*.py") |
        ForEach-Object { ([DateTimeOffset]$_.LastWriteTimeUtc).ToUnixTimeMilliseconds() / 1000.0 } |
        Measure-Object -Maximum
    if ($newest.Maximum -gt ([double]$stamp.code_mtime + 1)) {
        return @{ reason = "code changed since it started"; pid = $stamp.pid }
    }
    return @{ reason = ""; pid = $stamp.pid }
}

function Stop-McpServer($stalePid) {
    $owners = @()
    try {
        # @(): a single owner would otherwise be a bare int, and += would add PIDs.
        $owners = @(Get-NetTCPConnection -LocalPort $McpPort -State Listen -ErrorAction Stop |
            Select-Object -ExpandProperty OwningProcess -Unique)
    } catch {}
    if ($stalePid) { $owners += [int]$stalePid }
    foreach ($procId in ($owners | Select-Object -Unique)) {
        $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if ($p -and $p.ProcessName -match "^python") {
            Info "stopping MCP server (pid $procId)"
            Stop-Process -Id $procId -Force
        }
    }
    $deadline = (Get-Date).AddSeconds(10)
    while ((Test-Port $McpHost $McpPort) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }
}

$PyQ = "& '$Py'"

# -- TrueForge -----------------------------------------------------------------
if (Test-TrueForge) {
    Ok "TrueForge already running at $TfUrl"
} else {
    if (-not ((Get-Command node -ErrorAction SilentlyContinue) -and (Get-Command npm -ErrorAction SilentlyContinue))) {
        Fail "Node.js 22.14+ (node + npm on PATH) is required for TrueForge."; exit 1
    }
    if (Test-Port $TfUri.Host $TfUri.Port) {
        Warn "port $($TfUri.Port) is open but TrueForge is not answering yet; waiting."
    } else {
        Info "starting TrueForge (first run installs it into .trueforge\, can take a few minutes)"
        Start-Pane "TrueForge" "$PyQ -m clawforge trueforge"
    }
    Write-Host -NoNewline "  waiting for TrueForge " -ForegroundColor DarkGray
    if (-not (Wait-Until { Test-TrueForge } $TrueForgeTimeout "TrueForge")) { exit 1 }
    Ok "TrueForge  $TfUrl"
}

# -- ClawNet MCP server --------------------------------------------------------
$startMcp = $true
if (Test-Port $McpHost $McpPort) {
    $stale = Get-McpStaleReason
    if ($Restart -or $stale.reason) {
        $why = if ($Restart) { "-Restart" } else { "running old code: $($stale.reason)" }
        Warn "restarting the MCP server ($why)."
        Stop-McpServer $stale.pid
        if (Test-Port $McpHost $McpPort) {
            Fail "port $McpPort is still in use by something else. Free it or set CLAWFORGE_PORT in .env."
            exit 1
        }
    } else {
        Ok "ClawNet MCP server already running at http://${McpHost}:$McpPort/mcp"
        $startMcp = $false
    }
}
if ($startMcp) {
    Info "starting ClawNet MCP server"
    Start-Pane "ClawNet MCP" "$PyQ -m clawforge serve"
    Write-Host -NoNewline "  waiting for MCP server " -ForegroundColor DarkGray
    if (-not (Wait-Until { Test-Port $McpHost $McpPort } 60 "ClawNet MCP server")) { exit 1 }
    Ok "ClawNet MCP server  http://${McpHost}:$McpPort/mcp"
}

# -- Supermemory (optional) ----------------------------------------------------
if ($Supermemory) {
    $smUri = [Uri](Cfg "SUPERMEMORY_API_URL" "http://localhost:6767")
    if (Test-Port $smUri.Host $smUri.Port) {
        Ok "Supermemory already running at $smUri"
    } elseif (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
        Warn "Supermemory needs WSL (Ubuntu); skipped."
    } else {
        Info "starting Supermemory Local in WSL"
        $key = Cfg "OPENAI_API_KEY" ""
        Start-Pane "Supermemory" ("`$env:OPENAI_API_KEY = '$key'; `$env:WSLENV = 'OPENAI_API_KEY/u'; " +
            "wsl.exe -d Ubuntu -- bash -lc 'export SUPERMEMORY_DATA_DIR=`$HOME/.supermemory; exec `$HOME/.bun/bin/bun x supermemory local'")
    }
}

# -- register agent + connector in TrueForge -----------------------------------
if (-not $SkipSetup -and (Cfg "OPENAI_API_KEY" "")) {
    Info "registering provider, connector and agent in TrueForge"
    & $Py -m clawforge setup
    if ($LASTEXITCODE -ne 0) { Warn "setup failed; run /setup from the console once the cause is fixed." }
}

if ($ServersOnly) {
    Write-Host ""
    Ok "servers are up. Console: .\start.ps1 or python -m clawforge"
    exit 0
}

# -- the console (TUI), in this terminal ---------------------------------------
Write-Host ""
$env:PYTHONIOENCODING = "utf-8"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
& $Py -m clawforge
exit $LASTEXITCODE
