<#
.SYNOPSIS
    One-command local launcher for the Cipher-Clock Relay CTF challenge.

.EXAMPLE
    .\demo.ps1             # build + start on localhost:8338
    .\demo.ps1 -Port 9338  # use another host port
    .\demo.ps1 -Stop       # stop and remove the container
    .\demo.ps1 -Rebuild    # force a fresh image build
#>
[CmdletBinding()]
param(
    [int]$Port = 8338,
    [switch]$Stop,
    [switch]$Rebuild
)

$Name  = "ctf-cipher-clock-relay"
$Image = "ctf-cipher-clock-relay"
$Here  = $PSScriptRoot
$Pcap  = Join-Path $Here "relay_dump.pcap"

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
if ($Stop) { Ok "Cipher-Clock Relay stopped."; exit 0 }

# --- Build ----------------------------------------------------------------
docker image inspect $Image *> $null
if ($Rebuild -or $LASTEXITCODE -ne 0) {
    Info "Building image '$Image'..."
    docker build -t $Image $Here
    if ($LASTEXITCODE -ne 0) { Fail "docker build failed." }
}

# --- Run ------------------------------------------------------------------
Info "Starting relay on port $Port..."
docker run -d --name $Name -p "${Port}:8338" $Image *> $null
if ($LASTEXITCODE -ne 0) { Fail "Could not start the relay. Is port $Port already in use? Try -Port 9338." }

Write-Host ""
Ok  "Cipher-Clock Relay is running."
Write-Host "    Capture : $Pcap"
Write-Host "    Relay   : localhost:$Port  (raw TCP, e.g. 'ncat localhost $Port' or a Python socket)"
Write-Host "    Brief   : challenge.md"
Write-Host "    Stop    : .\demo.ps1 -Stop"
Write-Host ""
