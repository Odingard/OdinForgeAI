# OdinForge Agent Installer for Windows
# Usage: 
#   $env:ODINFORGE_SERVER = "https://your-server.com"
#   $env:ODINFORGE_REGISTRATION_TOKEN = "your-token"
#   iex ((New-Object System.Net.WebClient).DownloadString("$env:ODINFORGE_SERVER/api/agents/install.ps1"))

$ErrorActionPreference = "Stop"

Write-Host "OdinForge Agent Installer" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Check for admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Error: This script must be run as Administrator" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Detect architecture
$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
$platform = "windows-${arch}"
$binaryName = "odinforge-agent-${platform}.exe"

Write-Host "Detected platform: $platform" -ForegroundColor Green

# Default server URL - automatically embedded when downloaded from server
# When served via the API, this is replaced with the actual server URL
$defaultServerUrl = "__SERVER_URL_PLACEHOLDER__"

# Get server URL - check environment variables, default, or prompt
$serverUrl = $env:ODINFORGE_SERVER
if (-not $serverUrl) { $serverUrl = $env:ODINFORGE_SERVER_URL }
if (-not $serverUrl) { $serverUrl = $env:SERVER_URL }
# Check if URL was embedded (starts with http)
if (-not $serverUrl -and $defaultServerUrl -and $defaultServerUrl -match "^https?://") {
    $serverUrl = $defaultServerUrl
    Write-Host "Using server: $serverUrl" -ForegroundColor Green
}
if (-not $serverUrl) {
    $serverUrl = Read-Host "Enter OdinForge server URL (e.g., https://odinforgeai.replit.app)"
}
$serverUrl = $serverUrl.TrimEnd('/')

# Get registration token - check multiple environment variable names
$token = $env:ODINFORGE_REGISTRATION_TOKEN
if (-not $token) { $token = $env:ODINFORGE_TOKEN }
if (-not $token) { $token = $env:TOKEN }
if (-not $token) {
    $token = Read-Host "Enter registration token"
}

Write-Host ""
Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Server: $serverUrl"
Write-Host "  Token: $($token.Substring(0, [Math]::Min(8, $token.Length)))..."
Write-Host ""

# Stop and remove existing service if present
Write-Host "Stopping existing OdinForge service..." -ForegroundColor Yellow
sc.exe stop odinforge-agent 2>$null | Out-Null
Start-Sleep -Seconds 1

Write-Host "Removing existing OdinForge service..." -ForegroundColor Yellow
sc.exe delete odinforge-agent 2>$null | Out-Null
Start-Sleep -Seconds 1

# Create installation directories
Write-Host "Creating installation directories..." -ForegroundColor Yellow
$installDir = "C:\ProgramData\OdinForge"
$dataDir = "$installDir\data"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

# Download the agent binary
Write-Host "Downloading OdinForge agent..." -ForegroundColor Yellow
$downloadUrl = "${serverUrl}/agents/${binaryName}"
$binaryPath = "$installDir\odinforge-agent.exe"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $webClient = New-Object System.Net.WebClient
    $webClient.DownloadFile($downloadUrl, $binaryPath)
    Write-Host "  Downloaded to: $binaryPath" -ForegroundColor Green
} catch {
    Write-Host "Error: Failed to download agent from ${downloadUrl}" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

# Run the self-installing binary with install subcommand and flags
Write-Host "Installing OdinForge agent as Windows service..." -ForegroundColor Yellow

# Build the install command arguments
$installArgs = "install --server-url `"$serverUrl`" --registration-token `"$token`" --tenant-id default --force"

Write-Host "  Running: odinforge-agent.exe $installArgs" -ForegroundColor Gray

# Run the install command
$process = Start-Process -FilePath $binaryPath -ArgumentList $installArgs -Wait -PassThru -NoNewWindow
$exitCode = $process.ExitCode

if ($exitCode -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "OdinForge agent installed successfully!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "The agent is now running as a Windows service." -ForegroundColor Cyan
    Write-Host "Check status: sc.exe query odinforge-agent" -ForegroundColor Cyan
    Write-Host "View logs: Get-EventLog -LogName Application -Source odinforge-agent" -ForegroundColor Cyan
} else {
    Write-Host ""
    Write-Host "Installation failed with exit code: $exitCode" -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. Ensure you're running as Administrator" -ForegroundColor Yellow
    Write-Host "  2. Check if the server URL is reachable: $serverUrl" -ForegroundColor Yellow
    Write-Host "  3. Verify the registration token is correct" -ForegroundColor Yellow
    exit $exitCode
}

Write-Host ""
