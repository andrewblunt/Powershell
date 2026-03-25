<#
.SYNOPSIS
    Driver Automation CLI - Interactive command-line interface.

.DESCRIPTION
    Launches an interactive menu for the Driver Automation Tool.
    Supports model discovery, driver downloads, and settings management
    across Lenovo, Dell, HP, Microsoft, and custom driver packages.

    Run without parameters to enter interactive mode.

.EXAMPLE
    .\DriverAutomationCLI.ps1
#>

[CmdletBinding()]
param ()

$ErrorActionPreference = "Stop"

# Import Module
$ModulePath = Join-Path $PSScriptRoot -ChildPath "DriverAutomation.psm1"
if (Test-Path $ModulePath) {
    Import-Module $ModulePath -Force
}
else {
    Write-Error "DriverAutomation.psm1 module not found."
    exit 1
}

# Launch Interactive CLI
Start-DriverAutomationCLI
