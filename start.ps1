# Starts the Wazuh MCP server and puts a public HTTPS tunnel in front of it, then mints a
# bearer token and prints the connector URL + Authorization header to paste into an MCP
# client (Claude Desktop, Claude Code, etc). Both processes are started detached and keep
# running after this script exits; re-running it reuses a still-alive tunnel.
#
# Tunnel provider defaults to a Cloudflare quick tunnel (cloudflared), auto-downloaded on
# first run if not already present next to this script. It is substitutable: set
# $env:MCP_TUNNEL_CMD to any other command before running this script (use the literal
# token {URL} for the local server address) to use ngrok, localtunnel, ssh -R, etc.
# instead -- see the README's "Exposing it publicly" section.
#
# python -m wazuh_mcp_server does NOT load .env itself (see config.py) -- this script
# exports every .env entry into its own process environment before launching the server,
# so the child process inherits it. Without this step the server silently falls back to
# an auto-generated, read-only, throwaway API key and every WAZUH5_* tool stays disabled.

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$serverLog    = Join-Path $PSScriptRoot "server_launch.log"
$tunnelLog    = Join-Path $PSScriptRoot "tunnel_launch.log"
$stateFile    = Join-Path $PSScriptRoot ".mcp_tunnel_state.json"
$envFile      = Join-Path $PSScriptRoot ".env"
$cloudflaredExe = Join-Path $PSScriptRoot "cloudflared.exe"

function Import-DotEnv {
    param([string]$Path)
    Get-Content $Path | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#")) { return }
        $idx = $line.IndexOf("=")
        if ($idx -lt 1) { return }
        $key = $line.Substring(0, $idx).Trim()
        $val = $line.Substring($idx + 1).Trim().Trim('"').Trim("'")
        [System.Environment]::SetEnvironmentVariable($key, $val, "Process")
    }
}

function Test-ProcessAlive {
    param([int]$Id)
    if (-not $Id) { return $false }
    return [bool](Get-Process -Id $Id -ErrorAction SilentlyContinue)
}

function Stop-Port {
    param([int]$Port)
    $conns = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    foreach ($c in $conns) {
        Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
    }
}

# Downloads the official cloudflared Windows amd64 build from Cloudflare's own GitHub
# releases if it isn't already sitting next to this script. Only runs when the default
# tunnel provider is in use (MCP_TUNNEL_CMD unset) -- a substituted command is expected
# to bring its own binary.
function Ensure-Cloudflared {
    param([string]$Path)
    if (Test-Path $Path) { return $Path }
    Write-Host "cloudflared.exe not found -- downloading the official Windows amd64 build from Cloudflare's GitHub releases..."
    $url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
    Invoke-WebRequest -Uri $url -OutFile $Path -UseBasicParsing
    if (-not (Test-Path $Path)) { throw "Failed to download cloudflared.exe" }
    Write-Host "Downloaded cloudflared.exe."
    return $Path
}

if (-not (Test-Path $envFile)) {
    Write-Error ".env not found. Copy .env.example to .env and fill in your Wazuh settings first."
    exit 1
}
Import-DotEnv -Path $envFile

$port = [System.Environment]::GetEnvironmentVariable("MCP_PORT", "Process")
if (-not $port) { $port = "3000" }
$localUrl = "http://127.0.0.1:$port"

# Reuse a previous run's tunnel if it's still alive (the tunnel needs no per-launch config)
$prevState = $null
if (Test-Path $stateFile) {
    try { $prevState = Get-Content $stateFile -Raw | ConvertFrom-Json } catch {}
}

# --- 1. MCP server: always (re)start with the freshly-exported .env so the API key is correct ---
Write-Host "Starting MCP server..."
Stop-Port -Port ([int]$port)
Start-Sleep -Milliseconds 500
Remove-Item $serverLog, "$serverLog.err" -ErrorAction SilentlyContinue
$serverProc = Start-Process -FilePath "python" -ArgumentList "-m", "wazuh_mcp_server" `
    -RedirectStandardOutput $serverLog -RedirectStandardError "$serverLog.err" `
    -WindowStyle Hidden -PassThru
$serverPid = $serverProc.Id

$ok = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    $r = curl.exe -s "$localUrl/health" 2>$null
    if ($r) { $ok = $true; break }
}
if (-not $ok) {
    Write-Error "MCP server did not come up within 30s. Check $serverLog and $serverLog.err"
    exit 1
}
Write-Host "MCP server is up (PID $serverPid)."

# --- 2. Public HTTPS tunnel (Cloudflare quick tunnel by default, substitutable) ---
$tunnelUrl = $null
if ($prevState -and (Test-ProcessAlive $prevState.tunnel_pid) -and $prevState.tunnel_url) {
    Write-Host "Reusing existing tunnel (PID $($prevState.tunnel_pid)): $($prevState.tunnel_url)"
    $tunnelUrl = $prevState.tunnel_url
    $tunnelPid = $prevState.tunnel_pid
} else {
    $customCmd = [System.Environment]::GetEnvironmentVariable("MCP_TUNNEL_CMD", "Process")
    if ($customCmd) {
        Write-Host "Starting tunnel via MCP_TUNNEL_CMD..."
        $cmdLine = $customCmd.Replace("{URL}", $localUrl)
    } else {
        Ensure-Cloudflared -Path $cloudflaredExe | Out-Null
        Write-Host "Starting Cloudflare quick tunnel..."
        $cmdLine = "`"$cloudflaredExe`" tunnel --protocol quic --url $localUrl"
    }

    Remove-Item $tunnelLog, "$tunnelLog.err" -ErrorAction SilentlyContinue
    $tunnelProc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $cmdLine `
        -RedirectStandardOutput $tunnelLog -RedirectStandardError "$tunnelLog.err" `
        -WindowStyle Hidden -PassThru
    $tunnelPid = $tunnelProc.Id

    # MCP_TUNNEL_URL_REGEX lets a substituted provider (ngrok, localtunnel, ...) override
    # how the public URL is recognized in its own log output; defaults cover the common ones.
    $urlPattern = [System.Environment]::GetEnvironmentVariable("MCP_TUNNEL_URL_REGEX", "Process")
    if (-not $urlPattern) {
        $urlPattern = "https://[a-zA-Z0-9\-\.]+\.(trycloudflare\.com|ngrok-free\.app|ngrok\.io|loca\.lt)"
    }
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        foreach ($f in @($tunnelLog, "$tunnelLog.err")) {
            if (Test-Path $f) {
                $m = Select-String -Path $f -Pattern $urlPattern -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($m) { $tunnelUrl = $m.Matches[0].Value; break }
            }
        }
        if ($tunnelUrl) { break }
    }
    if (-not $tunnelUrl) {
        Write-Error "Could not find the public tunnel URL after 30s. Check $tunnelLog and $tunnelLog.err (or set MCP_TUNNEL_URL_REGEX if you're using a custom MCP_TUNNEL_CMD)."
        exit 1
    }
    Write-Host "Tunnel is up (PID $tunnelPid): $tunnelUrl"
}

# --- 3. Mint a bearer token ---
$apiKey = [System.Environment]::GetEnvironmentVariable("MCP_API_KEY", "Process")
if (-not $apiKey) {
    Write-Error "MCP_API_KEY not set in .env -- cannot mint a bearer token. Set it, or read the auto-generated key from $serverLog."
    exit 1
}
# Written to a temp file and passed via -d @file: PowerShell 5.1 re-escapes embedded
# quotes in an inline -d string when calling a native exe, which corrupts the JSON.
$bodyFile = Join-Path $PSScriptRoot ".auth_body.json.tmp"
@{ api_key = $apiKey } | ConvertTo-Json -Compress | Set-Content -Path $bodyFile -Encoding ASCII -NoNewline
$tokenJson = curl.exe -s -X POST "$localUrl/auth/token" -H "Content-Type: application/json" -d "@$bodyFile"
Remove-Item $bodyFile -ErrorAction SilentlyContinue
$token = $null
try { $token = ($tokenJson | ConvertFrom-Json).access_token } catch {}
if (-not $token) {
    Write-Error "Failed to obtain a bearer token. Raw response: $tokenJson"
    exit 1
}

# --- 4. Persist state + report ---
@{ server_pid = $serverPid; tunnel_pid = $tunnelPid; tunnel_url = $tunnelUrl } | ConvertTo-Json | Set-Content $stateFile

Write-Host ""
Write-Host "=================================================================="
Write-Host " MCP connector URL   : $tunnelUrl/mcp"
Write-Host " Authorization header: Bearer $token"
Write-Host "=================================================================="
Write-Host ""
Write-Host "Server PID: $serverPid   Tunnel PID: $tunnelPid   (state saved to $stateFile)"
Write-Host "To stop both: Stop-Process -Id $serverPid,$tunnelPid -ErrorAction SilentlyContinue"
