<#
.SYNOPSIS
    Driver Automation CLI - Command-line interface.
    
.DESCRIPTION
    This script provides a CLI wrapper for the Driver Automation CLI module,
    focusing on Lenovo systems and Configuration Manager integration.
    All ConfigMgr communication uses AdminService (HTTPS/443) with CIM/DCOM fallback.
    No WinRM or remote WMI ports are required.
    
.PARAMETER SiteServer
    The FQDN of the Configuration Manager Site Server.
    
.PARAMETER Model
    The specific Lenovo model to process (e.g., "ThinkPad X1 Carbon Gen 9").
    
.PARAMETER OS
    The operating system (e.g., "Windows 10" or "Windows 11").
    
.PARAMETER OSVersion
    The OS build version (e.g., "23H2", "22H2"). Extracted from -OS if not specified.
    
.PARAMETER Architecture
    The OS architecture (e.g., "x64").
    
.PARAMETER DownloadType
    The type of content to download ("Drivers", "BIOS", or "Both").
    
.PARAMETER SkipDistribution
    If specified, content will not be distributed to DP Groups after package creation.
    
.EXAMPLE
    .\DriverAutomationCLI.ps1 -SiteServer "SCCM01.contoso.com" -Model "ThinkPad X1 Carbon Gen 9" -DownloadType "Both"
    
.EXAMPLE
    .\DriverAutomationCLI.ps1 -Model "ThinkPad L14 Gen 3" -OS "Windows 11" -OSVersion "23H2" -DownloadType "Drivers" -SkipDistribution
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$SiteServer,

    [Parameter(Mandatory = $false)]
    [string]$Model,

    [Parameter(Mandatory = $false)]
    [string]$OS = "Windows 10",

    [Parameter(Mandatory = $false)]
    [string]$OSVersion,

    [Parameter(Mandatory = $false)]
    [string]$Architecture = "x64",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Drivers", "BIOS", "Both")]
    [string]$DownloadType = "Both",

    [Parameter(Mandatory = $false)]
    [string]$SettingsFile,

    [Parameter(Mandatory = $false)]
    [switch]$SkipDistribution
)

$ErrorActionPreference = "Stop"

# 1. Import Module
$ModulePath = Join-Path $PSScriptRoot -ChildPath "DriverAutomation.psm1"
if (Test-Path $ModulePath) {
    Import-Module $ModulePath -Force
}
else {
    Write-Error "DriverAutomation.psm1 module not found."
    exit 1
}

# 2. Get Settings (Defaults)
$Settings = Get-DASettings
if ($Settings) {
    Write-LogEntry -Value "Loaded default settings from DASettings.json" -Severity 1
}

# 3. Handle Parameter Overrides
# If user provided a SiteServer via CLI, override the global for this session
if ($SiteServer) { $global:SiteServer = $SiteServer }

# Derive OSVersion from OS string if not explicitly provided (e.g. "Windows 11 23H2" -> "23H2")
if (-not $OSVersion) {
    $OSParts = $OS.Split(" ")
    if ($OSParts.Count -ge 3) {
        $OSVersion = $OSParts[-1]
        $OS = ($OSParts[0..($OSParts.Count - 2)] -join " ")
    }
    else {
        Write-LogEntry -Value "[Warning] - OSVersion not specified and could not be derived from '$OS'. You may need to pass -OSVersion explicitly." -Severity 2
    }
}

# 4. Initialize Local Directories and Logging
Get-OEMLinks | Out-Null

# 5. Execute Core Workflow
if ($Model) {
    # Build parameters for the orchestration cmdlet
    $Params = @{
        Model        = $Model
        OSName       = $OS
        Architecture = $Architecture
        SiteServer   = $global:SiteServer
        PackagePath  = $global:PackagePath
    }

    if ($OSVersion) { $Params.OSVersion = $OSVersion }
    if ($SkipDistribution) { $Params.SkipDistribution = $true }
    if ($DownloadType -eq "Drivers") { $Params.SkipBIOS = $true }

    Get-LenovoDrivers @Params
}
else {
    Write-LogEntry -Value "No model specified. Use -Model parameter or run Get-LenovoDrivers directly." -Severity 2
    Write-Host "Tip: You can use Set-DASettings to configure your defaults (SiteServer, paths, etc.)" -ForegroundColor Yellow
    Write-Host "     All ConfigMgr communication uses AdminService REST API (HTTPS/443). No WinRM needed." -ForegroundColor Yellow
}

Write-LogEntry -Value "Driver Automation Tool CLI process finished." -Severity 1
