<#
.SYNOPSIS
    Removes Microsoft Visual C++ Redistributable packages by year.

.DESCRIPTION
    This script uninstalls Microsoft Visual C++ Redistributable packages for specified years.
    It removes both x86 and x64 variants of each specified version.

.PARAMETER Years
    Array of years to uninstall. Valid values: 2005, 2008, 2010, 2012, 2013, 2015, 2017, 2019, 2022
    Note: 2015-2022 are part of the same product line and will all be removed together.

.PARAMETER WhatIf
    Shows what would be uninstalled without actually removing anything.

.EXAMPLE
    .\Remove-VCRedist.ps1 -Years 2008, 2010
    Removes Visual C++ 2008 and 2010 Redistributables (both x86 and x64).

.EXAMPLE
    .\Remove-VCRedist.ps1 -Years 2015 -WhatIf
    Shows what 2015-2022 redistributables would be removed without actually uninstalling.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('2005', '2008', '2010', '2012', '2013', '2015', '2017', '2019', '2022')]
    [string[]]$Years
)

# Mapping of years to their display names in the registry
$yearPatterns = @{
    '2005' = 'Microsoft Visual C\+\+ 2005'
    '2008' = 'Microsoft Visual C\+\+ 2008'
    '2010' = 'Microsoft Visual C\+\+ 2010'
    '2012' = 'Microsoft Visual C\+\+ 2012'
    '2013' = 'Microsoft Visual C\+\+ 2013'
    '2015' = 'Microsoft Visual C\+\+ 2015-2022'  # 2015-2022 are merged
    '2017' = 'Microsoft Visual C\+\+ 2015-2022'
    '2019' = 'Microsoft Visual C\+\+ 2015-2022'
    '2022' = 'Microsoft Visual C\+\+ 2015-2022'
}

function Get-InstalledPrograms {
    <#
    .SYNOPSIS
        Retrieves installed programs from the registry.
    #>
    $registryPaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    
    $programs = foreach ($path in $registryPaths) {
        Get-ItemProperty $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, UninstallString, PSPath
    }
    
    return $programs
}

function Uninstall-VCRedist {
    <#
    .SYNOPSIS
        Uninstalls a Visual C++ Redistributable package.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Package
    )
    
    $displayName = $Package.DisplayName
    $uninstallString = $Package.UninstallString
    
    if ([string]::IsNullOrWhiteSpace($uninstallString)) {
        Write-Warning "No uninstall string found for: $displayName"
        return
    }
    
    # Parse the uninstall string
    if ($uninstallString -match '^"?(.+\.exe)"?\s*(.*)$') {
        $executable = $Matches[1]
        $arguments = $Matches[2]
        
        # Add silent uninstall flags for msiexec
        if ($executable -match 'msiexec') {
            if ($arguments -notmatch '/qn') {
                $arguments += ' /qn /norestart'
            }
        }
        # For vcredist executables, add silent flags
        elseif ($executable -match 'vcredist') {
            if ($arguments -notmatch '/quiet') {
                $arguments = '/uninstall /quiet /norestart ' + $arguments
            }
        }
        
        if ($PSCmdlet.ShouldProcess($displayName, "Uninstall")) {
            Write-Host "Uninstalling: $displayName" -ForegroundColor Cyan
            Write-Verbose "Command: $executable $arguments"
            
            try {
                $process = Start-Process -FilePath $executable -ArgumentList $arguments -Wait -PassThru -NoNewWindow
                
                if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
                    Write-Host "  Successfully uninstalled: $displayName" -ForegroundColor Green
                }
                else {
                    Write-Warning "  Uninstall completed with exit code $($process.ExitCode): $displayName"
                }
            }
            catch {
                Write-Error "  Failed to uninstall $displayName : $_"
            }
        }
        else {
            Write-Host "Would uninstall: $displayName" -ForegroundColor Yellow
        }
    }
    else {
        Write-Warning "Could not parse uninstall string for: $displayName"
    }
}

# Main script logic
Write-Host "Scanning for installed Visual C++ Redistributables..." -ForegroundColor Cyan

$installedPrograms = Get-InstalledPrograms

# Get unique patterns (in case user specified 2015, 2017, etc., we only want one pattern)
$uniquePatterns = $Years | ForEach-Object { $yearPatterns[$_] } | Select-Object -Unique

$packagesToRemove = @()

foreach ($pattern in $uniquePatterns) {
    $matches = $installedPrograms | Where-Object { $_.DisplayName -match $pattern }
    if ($matches) {
        $packagesToRemove += $matches
    }
}

if ($packagesToRemove.Count -eq 0) {
    Write-Host "No Visual C++ Redistributables found for the specified year(s): $($Years -join ', ')" -ForegroundColor Yellow
    exit 0
}

Write-Host "`nFound $($packagesToRemove.Count) package(s) to remove:" -ForegroundColor Cyan
$packagesToRemove | ForEach-Object { Write-Host "  - $($_.DisplayName)" }

Write-Host ""

# Uninstall each package
foreach ($package in $packagesToRemove) {
    Uninstall-VCRedist -Package $package
}

Write-Host "`nOperation completed." -ForegroundColor Green
