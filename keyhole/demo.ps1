<#
.SYNOPSIS
    One-command local launcher for the Keyhole CTF challenge.

.EXAMPLE
    .\demo.ps1            # build + start on http://localhost:1337
    .\demo.ps1 -Port 8080 # use another host port
    .\demo.ps1 -Stop      # stop and remove the container
    .\demo.ps1 -Rebuild   # force a fresh image build
#>
[CmdletBinding()]
param(
    [int]$Port = 1337,
    [switch]$Stop,
    [switch]$Rebuild
)

$Name      = "ctf-keyhole"
$Image     = "ctf-keyhole"
$Here      = $PSScriptRoot
$Handout   = Join-Path $Here "handout"

function Info($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "[-] $msg" -ForegroundColor Red; exit 1 }

# --- Docker checks --------------------------------------------------------
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Fail "Docker is not installed. Get Docker Desktop: https://www.docker.com/products/docker-desktop/"
}
docker info *> $null
if ($LASTEXITCODE -ne 0) { Fail "Docker is installed but not running. Start Docker Desktop and try again." }

# --- Stop -----------------------------------------------------------------
docker rm -f $Name *> $null
if ($Stop) { Ok "Keyhole stopped."; exit 0 }

# --- Build ----------------------------------------------------------------
docker image inspect $Image *> $null
if ($Rebuild -or $LASTEXITCODE -ne 0) {
    Info "Building image '$Image' (first run takes a minute)..."
    docker build -t $Image $Here
    if ($LASTEXITCODE -ne 0) { Fail "docker build failed." }
}

# --- Run ------------------------------------------------------------------
Info "Starting container on port $Port..."
docker run -d --name $Name -p "${Port}:1337" $Image *> $null
if ($LASTEXITCODE -ne 0) { Fail "Could not start the container. Is port $Port already in use? Try -Port 8080." }

# Inject a random local flag, the same way a CTF platform would.
$rand = -join ((1..8) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
$flag = "isfcr{l0c4l_k3yh0l3_$rand}"
docker exec -u root $Name sh -c "printf '%s' '$flag' > /flag.txt && chmod 644 /flag.txt" *> $null
if ($LASTEXITCODE -ne 0) { Fail "Could not write the flag into the container." }

# Drop the handout binary next to the script for convenience.
New-Item -ItemType Directory -Force $Handout | Out-Null
docker cp "${Name}:/app/keyhole" (Join-Path $Handout "keyhole") *> $null

Write-Host ""
Ok  "Keyhole is running."
Write-Host "    Service : http://localhost:$Port"
Write-Host "    Binary  : $(Join-Path $Handout 'keyhole')  (also at http://localhost:$Port/keyhole)"
Write-Host "    Brief   : challenge.md"
Write-Host "    Stop    : .\demo.ps1 -Stop"
Write-Host ""
