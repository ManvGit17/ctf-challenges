<#
.SYNOPSIS
    One-command local launcher for the Impostor Resolver CTF challenge.

.EXAMPLE
    .\demo.ps1             # build + start on http://localhost:5000
    .\demo.ps1 -Port 5050  # use another host port
    .\demo.ps1 -Stop       # stop and remove the container
    .\demo.ps1 -Rebuild    # force a fresh image build
#>
[CmdletBinding()]
param(
    [int]$Port = 5000,
    [switch]$Stop,
    [switch]$Rebuild
)

$Name  = "ctf-impostor-resolver"
$Image = "ctf-impostor-resolver"
$Here  = $PSScriptRoot

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
if ($Stop) { Ok "Impostor Resolver stopped."; exit 0 }

# --- Build ----------------------------------------------------------------
docker image inspect $Image *> $null
if ($Rebuild -or $LASTEXITCODE -ne 0) {
    Info "Building image '$Image' (first run takes a minute)..."
    docker build -t $Image $Here
    if ($LASTEXITCODE -ne 0) { Fail "docker build failed." }
}

# --- Run ------------------------------------------------------------------
Info "Starting container on port $Port..."
docker run -d --name $Name -p "${Port}:5000" $Image *> $null
if ($LASTEXITCODE -ne 0) { Fail "Could not start the container. Is port $Port already in use? Try -Port 5050." }

Write-Host ""
Ok  "Impostor Resolver is running."
Write-Host "    Console : http://localhost:$Port   (open it in a browser)"
Write-Host "    Brief   : challenge.md"
Write-Host "    Stop    : .\demo.ps1 -Stop"
Write-Host ""
