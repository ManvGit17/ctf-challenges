<#
.SYNOPSIS
    One-command local launcher for the Pilgrim's Trace CTF challenge.

.DESCRIPTION
    1. Picks a random local flag (kept in .local/ so restarts reuse the same capture).
    2. Generates handout/pilgrims_trace.pcap for that flag.
    3. Starts the relay service on localhost:9000 with the same flag.

.EXAMPLE
    .\demo.ps1            # generate capture (first run) + start relay on port 9000
    .\demo.ps1 -Port 9100 # use another host port for the relay
    .\demo.ps1 -Fresh     # new flag + brand new capture
    .\demo.ps1 -Stop      # stop and remove the relay container
    .\demo.ps1 -Rebuild   # force fresh image builds
#>
[CmdletBinding()]
param(
    [int]$Port = 9000,
    [switch]$Stop,
    [switch]$Fresh,
    [switch]$Rebuild
)

$Name      = "ctf-pilgrim-relay"
$RelayImg  = "ctf-pilgrim-relay"
$GenImg    = "ctf-pilgrim-gen"
$Here      = $PSScriptRoot
$Handout   = Join-Path $Here "handout"
$LocalDir  = Join-Path $Here ".local"
$FlagFile  = Join-Path $LocalDir "flag.txt"
$Pcap      = Join-Path $Handout "pilgrims_trace.pcap"

function Info($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "[-] $msg" -ForegroundColor Red; exit 1 }

function Build-Image($tag, $context) {
    docker image inspect $tag *> $null
    if ($Rebuild -or $LASTEXITCODE -ne 0) {
        Info "Building image '$tag'..."
        docker build -t $tag $context
        if ($LASTEXITCODE -ne 0) { Fail "docker build failed for $tag." }
    }
}

# --- Docker checks --------------------------------------------------------
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Fail "Docker is not installed. Get Docker Desktop: https://www.docker.com/products/docker-desktop/"
}
docker info *> $null
if ($LASTEXITCODE -ne 0) { Fail "Docker is installed but not running. Start Docker Desktop and try again." }

# --- Stop -----------------------------------------------------------------
docker rm -f $Name *> $null
if ($Stop) { Ok "Pilgrim's Trace relay stopped."; exit 0 }

# --- Flag + capture -------------------------------------------------------
New-Item -ItemType Directory -Force $Handout, $LocalDir | Out-Null

if ($Fresh -or -not (Test-Path $FlagFile) -or -not (Test-Path $Pcap)) {
    $rand = -join ((1..10) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
    $flag = "isfcr{l0c4l_p1lgr1m_$rand}"
    [IO.File]::WriteAllText($FlagFile, $flag)

    Build-Image $GenImg (Join-Path $Here "generator")
    Info "Generating a fresh capture..."
    docker rm -f ctf-pilgrim-gen *> $null
    # Generator output includes the answer, so it is discarded on purpose.
    docker create --name ctf-pilgrim-gen $GenImg --flag $flag --file /out/pilgrims_trace.pcap *> $null
    docker start -a ctf-pilgrim-gen *> $null
    if ($LASTEXITCODE -ne 0) { docker rm -f ctf-pilgrim-gen *> $null; Fail "Capture generation failed." }
    docker cp "ctf-pilgrim-gen:/out/pilgrims_trace.pcap" $Pcap *> $null
    docker rm -f ctf-pilgrim-gen *> $null
    if (-not (Test-Path $Pcap)) { Fail "Could not copy the capture out of the generator." }
} else {
    Info "Reusing existing capture (run with -Fresh for a new one)."
    $flag = [IO.File]::ReadAllText($FlagFile).Trim()
}

# --- Relay ----------------------------------------------------------------
Build-Image $RelayImg (Join-Path $Here "relay_service")
Info "Starting relay on port $Port..."
docker run -d --name $Name -p "${Port}:9000" $RelayImg *> $null
if ($LASTEXITCODE -ne 0) { Fail "Could not start the relay. Is port $Port already in use? Try -Port 9100." }

docker exec $Name sh -c "printf '%s' '$flag' > /flag.txt" *> $null
if ($LASTEXITCODE -ne 0) { Fail "Could not write the flag into the relay container." }

Write-Host ""
Ok  "Pilgrim's Trace is ready."
Write-Host "    Capture : $Pcap"
Write-Host "    Relay   : localhost:$Port  (raw TCP, e.g. 'ncat localhost $Port' or a Python socket)"
Write-Host "    Brief   : challenge.md"
Write-Host "    Stop    : .\demo.ps1 -Stop"
Write-Host ""
