# OdinForge Agent Installer for Windows
# Usage: irm 'https://YOUR_SERVER/api/agents/install.ps1?token=abc' | iex
# Or with parameters: .\install.ps1 -ServerUrl "https://server" -ApiKey "key"

param(
    [Parameter(Position=0)]
    [ValidateSet("install", "uninstall", "status", "")]
    [string]$Command = "install",
    
    [string]$ServerUrl = "",
    [string]$ApiKey = "",
    [string]$RegistrationToken = "",
    [string]$Token = "",
    [string]$TenantId = "",
    [switch]$DryRun,
    [switch]$Force,
    [switch]$Help,
    [switch]$Version
)

$ErrorActionPreference = "Stop"
$ScriptVersion = "1.0.0"

# Default values - automatically embedded when downloaded from server
$DefaultServerUrl = "__SERVER_URL_PLACEHOLDER__"
$DefaultApiKey = "__API_KEY_PLACEHOLDER__"
$DefaultTenantId = "default"

function Write-Banner {
    Write-Host ""
    Write-Host "=============================================================" -ForegroundColor Blue
    Write-Host "          OdinForge Agent Installer v$ScriptVersion" -ForegroundColor Blue
    Write-Host "          Adversarial Exposure Validation" -ForegroundColor Blue
    Write-Host "=============================================================" -ForegroundColor Blue
    Write-Host ""
}

function Write-HelpText {
    Write-Host @"
OdinForge Agent Installer for Windows

Usage: install.ps1 [COMMAND] [OPTIONS]

Commands:
  install     Install the OdinForge agent (default)
  uninstall   Remove the OdinForge agent
  status      Check agent status

Options:
  -ServerUrl URL    OdinForge server URL (required for install)
  -ApiKey KEY       API key for agent authentication
  -TenantId ID      Tenant ID (default: 'default')
  -DryRun           Show what would be done without making changes
  -Force            Force reinstall even if already installed
  -Help             Show this help message
  -Version          Show version

Environment Variables:
  ODINFORGE_SERVER_URL    Server URL
  ODINFORGE_API_KEY       API key
  ODINFORGE_TENANT_ID     Tenant ID

Examples:
  # Install with embedded credentials (from server-generated command)
  irm 'https://server/api/agents/install.ps1?token=abc' | iex

  # Install with explicit arguments
  .\install.ps1 -ServerUrl https://odinforge.example.com -ApiKey mykey

  # Check status
  .\install.ps1 status

  # Uninstall
  .\install.ps1 uninstall
"@
}

function Test-IsPlaceholder {
    param([string]$Value)
    return ($Value -match "__.*PLACEHOLDER__" -or [string]::IsNullOrEmpty($Value))
}

function Test-IsUrl {
    param([string]$Value)
    return $Value -match "^https?://"
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsInstalled {
    return Test-Path "C:\Program Files\OdinForge\odinforge-agent.exe"
}

function Get-Configuration {
    # Server URL: Param > ENV > Embedded > Error
    $script:Server = $null
    if ($ServerUrl) {
        $script:Server = $ServerUrl
    } elseif ($env:ODINFORGE_SERVER_URL) {
        $script:Server = $env:ODINFORGE_SERVER_URL
    } elseif (-not (Test-IsPlaceholder $DefaultServerUrl) -and (Test-IsUrl $DefaultServerUrl)) {
        $script:Server = $DefaultServerUrl
    } else {
        Write-Host "Error: Server URL is required." -ForegroundColor Red
        Write-Host "Use -ServerUrl or set ODINFORGE_SERVER_URL environment variable."
        exit 1
    }
    $script:Server = $script:Server.TrimEnd('/')

    # API Key: Param > Token params > ENV > Embedded > Error
    $script:Key = $null
    if ($ApiKey) {
        $script:Key = $ApiKey
    } elseif ($RegistrationToken) {
        $script:Key = $RegistrationToken
    } elseif ($Token) {
        $script:Key = $Token
    } elseif ($env:ODINFORGE_API_KEY) {
        $script:Key = $env:ODINFORGE_API_KEY
    } elseif ($env:ODINFORGE_TOKEN) {
        $script:Key = $env:ODINFORGE_TOKEN
    } elseif (-not (Test-IsPlaceholder $DefaultApiKey)) {
        $script:Key = $DefaultApiKey
    } else {
        Write-Host "Error: API key is required." -ForegroundColor Red
        Write-Host "Use -ApiKey or set ODINFORGE_API_KEY environment variable."
        exit 1
    }

    # Tenant ID: Param > ENV > Default
    $script:Tenant = $null
    if ($TenantId) {
        $script:Tenant = $TenantId
    } elseif ($env:ODINFORGE_TENANT_ID) {
        $script:Tenant = $env:ODINFORGE_TENANT_ID
    } elseif (-not (Test-IsPlaceholder $DefaultTenantId)) {
        $script:Tenant = $DefaultTenantId
    } else {
        $script:Tenant = "default"
    }
}

function Get-Platform {
    $script:Arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
    $script:BinaryName = "odinforge-agent-windows-$script:Arch.exe"
    Write-Host "Platform: windows-$script:Arch" -ForegroundColor Green
}

function Install-Agent {
    Write-Host "`nInstalling OdinForge Agent..." -ForegroundColor Blue
    
    Get-Configuration
    Get-Platform

    if ((Test-IsInstalled) -and -not $Force) {
        Write-Host "Agent is already installed. Use -Force to reinstall." -ForegroundColor Yellow
        exit 0
    }

    Write-Host "Server: $script:Server" -ForegroundColor Green
    Write-Host "Tenant: $script:Tenant" -ForegroundColor Green
    Write-Host ""

    if ($DryRun) {
        Write-Host "[DRY RUN] Would perform the following actions:" -ForegroundColor Yellow
        Write-Host "  - Download agent binary from $script:Server/agents/$script:BinaryName"
        Write-Host "  - Install to C:\Program Files\OdinForge\odinforge-agent.exe"
        Write-Host "  - Create data directory C:\ProgramData\OdinForge"
        Write-Host "  - Install Windows Service"
        Write-Host "  - Start agent service"
        exit 0
    }

    # Create directories
    $installDir = "C:\Program Files\OdinForge"
    $dataDir = "C:\ProgramData\OdinForge"
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

    # Download binary
    Write-Host "Downloading agent binary..." -ForegroundColor Yellow
    $downloadUrl = "$script:Server/agents/$script:BinaryName"
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

    # Write config file
    Write-Host "Writing configuration..." -ForegroundColor Yellow
    $envFilePath = "$dataDir\agent.env"
    @"
ODINFORGE_SERVER_URL=$script:Server
ODINFORGE_API_KEY=$script:Key
ODINFORGE_TENANT_ID=$script:Tenant
"@ | Out-File -FilePath $envFilePath -Encoding UTF8 -Force

    # Set restrictive permissions
    $acl = Get-Acl $envFilePath
    $acl.SetAccessRuleProtection($true, $false)
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")
    $acl.SetAccessRule($adminRule)
    $acl.SetAccessRule($systemRule)
    Set-Acl -Path $envFilePath -AclObject $acl

    # Stop and remove existing service
    $existingService = Get-Service -Name "odinforge-agent" -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Host "Removing existing service..." -ForegroundColor Yellow
        Stop-Service -Name "odinforge-agent" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        sc.exe delete "odinforge-agent" | Out-Null
        Start-Sleep -Seconds 2
    }

    # Install Windows Service
    Write-Host "Installing Windows Service..." -ForegroundColor Yellow
    sc.exe create "odinforge-agent" binPath= "`"$binaryPath`"" start= auto DisplayName= "OdinForge Security Agent" | Out-Null
    sc.exe description "odinforge-agent" "OdinForge Security Agent for endpoint monitoring and security assessments" | Out-Null

    # Set environment variables via registry
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\odinforge-agent"
    New-ItemProperty -Path $regPath -Name "Environment" -PropertyType MultiString -Value @(
        "ODINFORGE_SERVER_URL=$script:Server",
        "ODINFORGE_API_KEY=$script:Key",
        "ODINFORGE_TENANT_ID=$script:Tenant"
    ) -Force | Out-Null

    # Configure recovery
    sc.exe failure "odinforge-agent" reset= 86400 actions= restart/10000/restart/10000/restart/10000 | Out-Null

    # Start service
    Write-Host "Starting service..." -ForegroundColor Yellow
    Start-Service -Name "odinforge-agent"
    Start-Sleep -Seconds 2

    # Verify
    $service = Get-Service -Name "odinforge-agent" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        Write-Host ""
        Write-Host "=============================================================" -ForegroundColor Green
        Write-Host "         Agent installed and started successfully!" -ForegroundColor Green
        Write-Host "=============================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Quick commands:" -ForegroundColor Cyan
        Write-Host "  Status:    .\install.ps1 status   OR   sc.exe query odinforge-agent"
        Write-Host "  Restart:   Restart-Service odinforge-agent"
        Write-Host "  Uninstall: .\install.ps1 uninstall"
    } else {
        Write-Host ""
        Write-Host "Warning: Service installed but may not be running" -ForegroundColor Yellow
        Write-Host "Check: sc.exe query odinforge-agent" -ForegroundColor Cyan
    }
}

function Uninstall-Agent {
    Write-Host "`nUninstalling OdinForge Agent..." -ForegroundColor Blue

    if ($DryRun) {
        Write-Host "[DRY RUN] Would perform the following actions:" -ForegroundColor Yellow
        Write-Host "  - Stop and delete odinforge-agent service"
        Write-Host "  - Remove C:\Program Files\OdinForge\"
        Write-Host "  - Remove C:\ProgramData\OdinForge\"
        exit 0
    }

    # Stop and remove service
    $service = Get-Service -Name "odinforge-agent" -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "Stopping service..." -ForegroundColor Yellow
        Stop-Service -Name "odinforge-agent" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        sc.exe delete "odinforge-agent" | Out-Null
    }

    # Remove files
    Write-Host "Removing files..." -ForegroundColor Yellow
    if (Test-Path "C:\Program Files\OdinForge") {
        Remove-Item -Path "C:\Program Files\OdinForge" -Recurse -Force
    }
    if (Test-Path "C:\ProgramData\OdinForge") {
        Remove-Item -Path "C:\ProgramData\OdinForge" -Recurse -Force
    }

    Write-Host ""
    Write-Host "Agent uninstalled successfully." -ForegroundColor Green
}

function Get-AgentStatus {
    Write-Host "`nOdinForge Agent Status" -ForegroundColor Blue
    Write-Host "========================"
    Write-Host ""

    if (-not (Test-IsInstalled)) {
        Write-Host "Binary: " -NoNewline
        Write-Host "Not installed" -ForegroundColor Red
        exit 1
    }

    Write-Host "Binary: " -NoNewline
    Write-Host "Installed" -ForegroundColor Green
    Write-Host "  Path: C:\Program Files\OdinForge\odinforge-agent.exe"

    $envPath = "C:\ProgramData\OdinForge\agent.env"
    if (Test-Path $envPath) {
        Write-Host "Config: " -NoNewline
        Write-Host "Present" -ForegroundColor Green
        
        $content = Get-Content $envPath
        foreach ($line in $content) {
            if ($line -match "^ODINFORGE_SERVER_URL=(.+)$") {
                Write-Host "Server: $($Matches[1])" -ForegroundColor Green
            }
            if ($line -match "^ODINFORGE_TENANT_ID=(.+)$") {
                Write-Host "Tenant: $($Matches[1])" -ForegroundColor Green
            }
        }
    } else {
        Write-Host "Config: " -NoNewline
        Write-Host "Missing" -ForegroundColor Yellow
    }

    Write-Host ""

    $service = Get-Service -Name "odinforge-agent" -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "Service: " -NoNewline
        switch ($service.Status) {
            "Running" { Write-Host "Running" -ForegroundColor Green }
            "Stopped" { Write-Host "Stopped" -ForegroundColor Yellow }
            default { Write-Host $service.Status -ForegroundColor Yellow }
        }
    } else {
        Write-Host "Service: " -NoNewline
        Write-Host "Not configured" -ForegroundColor Red
    }
}

# Main
if ($Help) {
    Write-HelpText
    exit 0
}

if ($Version) {
    Write-Host "OdinForge Agent Installer v$ScriptVersion"
    exit 0
}

if (-not (Test-IsAdmin)) {
    Write-Host "Error: This script must be run as Administrator" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

Write-Banner

switch ($Command) {
    "install" { Install-Agent }
    "uninstall" { Uninstall-Agent }
    "status" { Get-AgentStatus }
    default { Install-Agent }
}
