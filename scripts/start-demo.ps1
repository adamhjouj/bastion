# Start the full Bastion stack locally and open the live dashboard.
#   scripts\start-demo.cmd            start (or restart) the stack, open the dashboard
#   scripts\start-demo.cmd -Attack    also run the red-team agent, stopped after 25 seconds
#   scripts\start-demo.cmd -Attack -Seconds 40   same, with a different time box
#   scripts\start-demo.cmd -Stop      stop the stack (data volume is kept)
param([switch]$Attack, [int]$Seconds = 25, [switch]$Stop)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

function Fail($msg) { Write-Host "`n[!] $msg" -ForegroundColor Red; Read-Host "Press Enter to close"; exit 1 }
function Get-EnvValue($name) {
    $line = Get-Content .env | Where-Object { $_ -match "^$name=" } | Select-Object -First 1
    if ($line) { return ($line -replace "^$name=", "").Trim().Trim('"') } else { return "" }
}

docker info *> $null
if ($LASTEXITCODE -ne 0) { Fail "Docker is not running. Start Docker Desktop, wait for it to say 'Engine running', then try again." }

if ($Stop) { docker compose --profile red-team down; Write-Host "Stopped. Data is kept in the bastion-data volume."; exit 0 }

# First run: create .env with freshly generated management/actuator tokens.
if (-not (Test-Path .env)) {
    $content = Get-Content .env.example -Raw
    foreach ($name in "MANAGEMENT_TOKEN", "ACTUATOR_TOKEN") {
        $bytes = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $token = -join ($bytes | ForEach-Object { $_.ToString("x2") })
        $content = $content -replace "(?m)^$name=.*$", "$name=$token"
    }
    $content = $content -replace "(?m)^BASTION_MODE=.*$", "BASTION_MODE=agent"
    [IO.File]::WriteAllText((Join-Path (Get-Location) ".env"), $content.Replace("`r`n", "`n"))
    Write-Host "[*] Created .env with generated tokens."
}

$mode = Get-EnvValue "BASTION_MODE"; if (-not $mode) { $mode = "observe" }
$llm = (Get-EnvValue "ANTHROPIC_API_KEY") + (Get-EnvValue "DEEPSEEK_API_KEY")
$jev = Get-EnvValue "TYPESAFE_API_KEY"
$missing = @()
if (($mode -in "agent", "inline") -and -not $llm) { $missing += "ANTHROPIC_API_KEY (or DEEPSEEK_API_KEY)" }
if (($mode -in "agent", "inline", "classifier-contain") -and -not $jev) { $missing += "TYPESAFE_API_KEY" }
if ($missing.Count) {
    Start-Process notepad.exe (Resolve-Path .env)
    Fail ("Add these keys to .env (opened in Notepad), save, and run this again:`n    " + ($missing -join "`n    "))
}

Write-Host "[*] Building and starting the stack in '$mode' mode (first build takes a few minutes) ..."
docker compose up --build -d
if ($LASTEXITCODE -ne 0) { Fail "docker compose failed; see the output above." }

$token = Get-EnvValue "MANAGEMENT_TOKEN"
$auth = @{ Authorization = "Bearer $token" }
Write-Host -NoNewline "[*] Waiting for the proxy "
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    try { $h = Invoke-RestMethod http://localhost:8080/__health -Headers $auth -TimeoutSec 3; if ($h.ready) { $ready = $true; break } } catch {}
    Write-Host -NoNewline "."; Start-Sleep 2
}
Write-Host ""
if (-not $ready) { Fail "Proxy did not come up. Check: docker compose logs proxy blue" }

Set-Clipboard -Value $token
Write-Host ""
Write-Host "=== Bastion is live ===" -ForegroundColor Green
Write-Host "  API       : http://localhost:8080/__api/v1/overview"
Write-Host "  Login     : username 'admin', password = MANAGEMENT_TOKEN (already copied to your clipboard)"
Write-Host "  Target app: http://localhost:8080/   (browse it: your clicks show up as live requests)"
Write-Host "  Mode      : $mode"
Write-Host "  Logs      : docker compose logs -f proxy blue"
Write-Host "  Stop      : scripts\start-demo.cmd -Stop"

if ($Attack) {
    # Time-boxed: the red agent is stopped after $Seconds so a demo run cannot keep spending.
    $before = Invoke-RestMethod http://localhost:8080/__api/v1/overview -Headers $auth
    Write-Host "`n[*] Red-team attack for $Seconds seconds (watch the dashboard) ..."
    docker compose --profile red-team up --build -d red | Out-Null
    for ($s = $Seconds; $s -gt 0; $s--) { Write-Host -NoNewline "`r    $s s left  "; Start-Sleep 1 }
    docker compose --profile red-team stop -t 2 red | Out-Null
    Write-Host "`r[*] Attack stopped.          "
    Start-Sleep 3   # let Bastion record what it was doing
    $after = Invoke-RestMethod http://localhost:8080/__api/v1/overview -Headers $auth
    Write-Host ("    attacker requests: {0}   Jev checks: {1}   sent to Bastion: {2}   Bastion actions: {3}" -f `
        ($after.events_total - $before.events_total), ($after.funnel.evaluated - $before.funnel.evaluated),
        ($after.funnel.escalated - $before.funnel.escalated), ($after.funnel.actions - $before.funnel.actions))
    Write-Host "    Bastion finishes any case already in progress, then goes idle (no spend without traffic)."
}
