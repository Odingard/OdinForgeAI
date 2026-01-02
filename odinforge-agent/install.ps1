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

# Get server URL - check multiple environment variable names
$serverUrl = $env:ODINFORGE_SERVER
if (-not $serverUrl) { $serverUrl = $env:ODINFORGE_SERVER_URL }
if (-not $serverUrl) { $serverUrl = $env:SERVER_URL }
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
$downloadUrl = "${serverUrl}/api/agents/download/${platform}"
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

# Run the self-installing binary
Write-Host "Installing OdinForge agent..." -ForegroundColor Yellow

# Set environment variables for the installer
$env:ODINFORGE_SERVER_URL = $serverUrl
$env:ODINFORGE_REGISTRATION_TOKEN = $token
$env:ODINFORGE_TENANT_ID = "default"

# Run with --install flag
$process = Start-Process -FilePath $binaryPath -ArgumentList "--install" -Wait -PassThru -NoNewWindow
$exitCode = $process.ExitCode

if ($exitCode -eq 0) {
    Write-Host ""
    Write-Host "OdinForge agent installed successfully" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Installation completed with exit code: $exitCode" -ForegroundColor Yellow
}

Write-Host "Error $exitCode" -ForegroundColor Gray
Write-Host ""
