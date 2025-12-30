# OdinForge Agent Installer for Windows
# Usage: irm https://YOUR_SERVER/api/agents/install.ps1 | iex

$ErrorActionPreference = "Stop"

Write-Host "OdinForge Agent Installer" -ForegroundColor Green
Write-Host "================================"

# Check for admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Error: This script must be run as Administrator" -ForegroundColor Red
    exit 1
}

# Detect architecture
$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
$binaryName = "odinforge-agent-windows-${arch}.exe"

Write-Host "Detected platform: windows-${arch}" -ForegroundColor Green

# Get server URL
$serverUrl = $env:ODINFORGE_SERVER_URL
if (-not $serverUrl) {
    $serverUrl = $env:SERVER_URL
}
if (-not $serverUrl) {
    $serverUrl = Read-Host "Enter OdinForge server URL"
}
$serverUrl = $serverUrl.TrimEnd('/')

# Get registration token
$token = $env:ODINFORGE_TOKEN
if (-not $token) {
    $token = $env:TOKEN
}
if (-not $token) {
    $token = Read-Host "Enter registration token"
}

# Create installation directories
Write-Host "Creating installation directories..."
New-Item -ItemType Directory -Force -Path "C:\Program Files\OdinForge" | Out-Null
New-Item -ItemType Directory -Force -Path "C:\ProgramData\OdinForge" | Out-Null

# Download the agent binary
Write-Host "Downloading agent binary..."
$downloadUrl = "${serverUrl}/agents/${binaryName}"
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile "C:\Program Files\OdinForge\odinforge-agent.exe" -UseBasicParsing
} catch {
    Write-Host "Error: Failed to download agent from ${downloadUrl}" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

# Store the API key
Write-Host "Storing configuration..."
$token | Out-File -FilePath "C:\ProgramData\OdinForge\api_key" -Encoding ASCII -NoNewline

# Set environment variable
[Environment]::SetEnvironmentVariable("ODINFORGE_SERVER_URL", $serverUrl, "Machine")

# Install as Windows service
Write-Host "Installing Windows service..."

# Remove existing service if present
$existingService = Get-Service -Name "OdinForgeAgent" -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "Stopping existing service..."
    Stop-Service -Name "OdinForgeAgent" -Force -ErrorAction SilentlyContinue
    sc.exe delete OdinForgeAgent | Out-Null
    Start-Sleep -Seconds 2
}

# Create the service
sc.exe create OdinForgeAgent binPath= "C:\Program Files\OdinForge\odinforge-agent.exe" start= auto | Out-Null
sc.exe description OdinForgeAgent "OdinForge Security Agent - Endpoint telemetry and security monitoring" | Out-Null

# Start the service
Write-Host "Starting service..."
Start-Service -Name "OdinForgeAgent"

# Verify service is running
$service = Get-Service -Name "OdinForgeAgent"
if ($service.Status -eq "Running") {
    Write-Host ""
    Write-Host "Agent installed and started successfully!" -ForegroundColor Green
    Write-Host "Check status: Get-Service OdinForgeAgent"
} else {
    Write-Host "Warning: Service installed but may not be running. Check Event Viewer for errors." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Installation complete!" -ForegroundColor Green
