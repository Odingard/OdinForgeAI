# OdinForge Agent Installer for Windows
# Usage: irm https://YOUR_SERVER/api/agents/install.ps1 | iex
# Or with parameters saved to script: .\install.ps1 -ServerUrl "https://YOUR_SERVER" -RegistrationToken "YOUR_TOKEN"

param(
    [string]$ServerUrl = "",
    [string]$RegistrationToken = "",
    [string]$Token = "",
    [switch]$Help
)

$ErrorActionPreference = "Stop"

Write-Host "OdinForge Agent Installer" -ForegroundColor Green
Write-Host "================================"
Write-Host ""

if ($Help) {
    Write-Host @"
Usage: install.ps1 [OPTIONS]

Options:
  -ServerUrl URL              OdinForge server URL
  -RegistrationToken TOKEN    Registration token for auto-registration
  -Token TOKEN                Alias for -RegistrationToken
  -Help                       Show this help message
"@
    exit 0
}

# Check for Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Error: This script must be run as Administrator" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Detect architecture
$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
$binaryName = "odinforge-agent-windows-$arch.exe"
Write-Host "Detected platform: windows-$arch" -ForegroundColor Green

# Default server URL - automatically embedded when downloaded from server
$defaultServerUrl = "__SERVER_URL_PLACEHOLDER__"

# Get server URL from parameters, environment, default, or prompt
if ($ServerUrl) {
    $server = $ServerUrl
} elseif ($env:ODINFORGE_SERVER_URL) {
    $server = $env:ODINFORGE_SERVER_URL
} elseif ($env:SERVER_URL) {
    $server = $env:SERVER_URL
} elseif ($defaultServerUrl -match "^https?://") {
    $server = $defaultServerUrl
    Write-Host "Using server: $server" -ForegroundColor Green
} else {
    $server = Read-Host "Enter OdinForge server URL"
}
$server = $server.TrimEnd('/')

# Default registration token - can be embedded when downloaded with ?token=<value>
$defaultToken = "__REGISTRATION_TOKEN_PLACEHOLDER__"

# Get registration token from parameters, environment, embedded default, or prompt
if ($RegistrationToken) {
    $regToken = $RegistrationToken
} elseif ($Token) {
    $regToken = $Token
} elseif ($env:ODINFORGE_REGISTRATION_TOKEN) {
    $regToken = $env:ODINFORGE_REGISTRATION_TOKEN
} elseif ($env:ODINFORGE_TOKEN) {
    $regToken = $env:ODINFORGE_TOKEN
} elseif ($env:TOKEN) {
    $regToken = $env:TOKEN
} elseif ($defaultToken -notmatch "__REGISTRATION_TOKEN_PLACEHOLDER__" -and $defaultToken -ne "") {
    $regToken = $defaultToken
    Write-Host "Using embedded registration token" -ForegroundColor Green
} else {
    $regToken = Read-Host "Enter registration token"
}

Write-Host ""

# Create installation directories
Write-Host "Creating installation directories..." -ForegroundColor Yellow
$installDir = "C:\Program Files\OdinForge"
$dataDir = "C:\ProgramData\OdinForge"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

# Download the agent binary
Write-Host "Downloading agent binary..." -ForegroundColor Yellow
$downloadUrl = "$server/agents/$binaryName"
$binaryPath = "$installDir\odinforge-agent.exe"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $downloadUrl -OutFile $binaryPath -UseBasicParsing
    Write-Host "  Downloaded to: $binaryPath" -ForegroundColor Green
} catch {
    Write-Host "Error: Failed to download agent from $downloadUrl" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

# Store credentials in environment file (for reference/debugging)
$envFilePath = "$dataDir\agent.env"
@"
ODINFORGE_SERVER_URL=$server
ODINFORGE_REGISTRATION_TOKEN=$regToken
"@ | Out-File -FilePath $envFilePath -Encoding UTF8 -Force

# Set restrictive permissions on env file
$acl = Get-Acl $envFilePath
$acl.SetAccessRuleProtection($true, $false)
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")
$acl.SetAccessRule($adminRule)
$acl.SetAccessRule($systemRule)
Set-Acl -Path $envFilePath -AclObject $acl

# Stop and remove existing service if present
Write-Host "Checking for existing service..." -ForegroundColor Yellow
$existingService = Get-Service -Name "odinforge-agent" -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "  Stopping existing service..." -ForegroundColor Yellow
    Stop-Service -Name "odinforge-agent" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    sc.exe delete "odinforge-agent" | Out-Null
    Start-Sleep -Seconds 2
}

# Create the Windows service
Write-Host "Installing Windows Service..." -ForegroundColor Yellow
sc.exe create "odinforge-agent" binPath= "`"$binaryPath`"" start= auto DisplayName= "OdinForge Security Agent" | Out-Null
sc.exe description "odinforge-agent" "OdinForge Security Agent for endpoint monitoring and security assessments" | Out-Null

# Set environment variables for the service via registry
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\odinforge-agent"
New-ItemProperty -Path $regPath -Name "Environment" -PropertyType MultiString -Value @(
    "ODINFORGE_SERVER_URL=$server",
    "ODINFORGE_REGISTRATION_TOKEN=$regToken",
    "ODINFORGE_TENANT_ID=default"
) -Force | Out-Null

# Configure service recovery options (restart on failure)
sc.exe failure "odinforge-agent" reset= 86400 actions= restart/10000/restart/10000/restart/10000 | Out-Null

# Start the service
Write-Host "Starting service..." -ForegroundColor Yellow
Start-Service -Name "odinforge-agent"
Start-Sleep -Seconds 2

# Verify service is running
$service = Get-Service -Name "odinforge-agent" -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq "Running") {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Agent installed and started successfully!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Check status: sc.exe query odinforge-agent" -ForegroundColor Cyan
    Write-Host "Stop service: sc.exe stop odinforge-agent" -ForegroundColor Cyan
    Write-Host "Start service: sc.exe start odinforge-agent" -ForegroundColor Cyan
} else {
    Write-Host ""
    Write-Host "Warning: Service installed but may not be running" -ForegroundColor Yellow
    Write-Host "Check status: sc.exe query odinforge-agent" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Installation complete!" -ForegroundColor Green
