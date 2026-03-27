# // ==============================================================================
# // DATCLI.psm1
# // Driver Automation CLI - Modular headless driver automation for SCCM
# // Focus: Lenovo, Dell, HP & Configuration Manager
# // ==============================================================================

# Requires TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Script Build Information
$ScriptRelease = "2.2.1"
$ScriptBuildDate = "2026-03-26"

# Hash Tables
# $WindowsBuildHashTable = @{
#     'Win11-22H2' = "10.0.22621"
#     'Win11-21H2' = "10.0.22000"
#     '22H2'       = "10.0.19045.1"
#     '21H2'       = "10.0.19044.1"
#     '21H1'       = "10.0.19043.1"
#     '20H2'       = "10.0.19042.1"
#     '2009'       = "10.0.19042.1"
#     '2004'       = "10.0.19041.1"
#     '1909'       = "10.0.18363.1"
#     '1903'       = "10.0.18362.1"
#     '1809'       = "10.0.17763.1"
#     '1803'       = "10.0.17134.1"
#     '1709'       = "10.0.16299.15"
#     '1703'       = "10.0.15063.0"
#     '1607'       = "10.0.14393.0"
# }

# Proxy & Bits Options
$global:ProxySettingsSet = $false
$global:BitsOptions = @{
    RetryInterval = "60"
    RetryTimeout  = "180"
    Priority      = "Foreground"
    TransferType  = "Download"
}

# ConfigMgr Validation State
$global:ConfigMgrValidation = $false
$global:SCCMCimSession = $null       # Set by Connect-ConfigMgr when CIM/DCOM fallback is needed

$global:HPModelXMLLoadTime = [datetime]::MinValue

# Shared Locations
function Get-ScriptDirectory {
    [OutputType([string])]
    param ()
    if ($null -ne $hostinvocation) {
        Split-Path $hostinvocation.MyCommand.path
    }
    else {
        Split-Path $script:MyInvocation.MyCommand.Path
    }
}

$global:TempDirectory = Join-Path $(Get-ScriptDirectory) -ChildPath "Temp"
$global:LogDirectory = Join-Path $(Get-ScriptDirectory) -ChildPath "Logs"
$global:SettingsJSONPath = Join-Path $(Get-ScriptDirectory) -ChildPath "DASettings.json"

# Create Required Folders
foreach ($Folder in @($global:TempDirectory, $global:LogDirectory)) {
    if (-not (Test-Path $Folder)) {
        New-Item -Path $Folder -ItemType Directory -Force | Out-Null
    }
}

# // =================== SETTINGS MANAGEMENT ====================== //

function Get-DASettings {
    <#
    .SYNOPSIS
        Retrieves DATCLI settings from the JSON configuration file.
    .DESCRIPTION
        Loads configuration from DASettings.json. If the file does not exist, it creates a default one.
    .EXAMPLE
        $Settings = Get-DASettings
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-Path $global:SettingsJSONPath)) {
        Write-LogEntry -Value "Settings file not found. Creating default DASettings.json" -Severity 1
        $DefaultSettings = @{
            SiteServer                   = ""
            SiteCode                     = ""
            SCCMNamespace                = ""
            PackagePath                  = ""
            DownloadPath                 = $global:TempDirectory
            PackageFormat                = "Raw"
            CleanupDownloadPath          = $false
            DistributionPointGroups      = @()
            EnableBinaryDeltaReplication = $false
            DistributionPriority         = "Medium"
        }
        $DefaultSettings | ConvertTo-Json | Out-File $global:SettingsJSONPath -Encoding utf8
    }

    try {
        $Settings = Get-Content -Path $global:SettingsJSONPath -Raw | ConvertFrom-Json
        
        # Populate global variables for module-wide access
        $global:SiteServer = $Settings.SiteServer
        $global:SiteCode = $Settings.SiteCode
        $global:SCCMNamespace = $Settings.SCCMNamespace
        $global:PackagePath = $Settings.PackagePath

        $ResolvedDownloadPath = $Settings.DownloadPath
        if ($ResolvedDownloadPath -and -not [System.IO.Path]::IsPathRooted($ResolvedDownloadPath)) {
            $ResolvedDownloadPath = Join-Path (Get-ScriptDirectory) -ChildPath $ResolvedDownloadPath
        }
        if ($ResolvedDownloadPath) {
            try {
                $ResolvedDownloadPath = [System.IO.Path]::GetFullPath($ResolvedDownloadPath)
            }
            catch {
                # Leave as-is if normalization fails
            }
        }
        if ($ResolvedDownloadPath) {
            $global:TempDirectory = $ResolvedDownloadPath
            if (-not (Test-Path $global:TempDirectory)) {
                New-Item -Path $global:TempDirectory -ItemType Directory -Force | Out-Null
            }
        }

        $global:CleanupDownloadPath = $Settings.CleanupDownloadPath
        $global:DPGroups = $Settings.DistributionPointGroups

        return $Settings
    }
    catch {
        Write-LogEntry -Value "[Error] - Failed to load JSON settings: $($_.Exception.Message)" -Severity 3
        return $null
    }
}

function Convert-OSName {
    param([string]$OSName)
    if (-not $OSName) { return $null }
    if ($OSName -match "11") { return "Windows 11" }
    return "Windows 10"
}
function Set-DASettings {
    <#
    .SYNOPSIS
        Updates the DATCLI JSON configuration file.
    .DESCRIPTION
        Saves updated settings to DASettings.json to be used as defaults for future runs.
        ConfigMgr connectivity uses CIM/DCOM (no WinRM).
    .PARAMETER SiteServer
        The FQDN of the ConfigMgr Site Server.
    .PARAMETER SiteCode
        The ConfigMgr site code (auto-populated on connection).
    .PARAMETER SCCMNamespace
        Optional SCCM WMI namespace override (e.g. root\SMS\site_UN2).
    .PARAMETER PackagePath
        The UNC path for storing driver packages.
    .PARAMETER DownloadPath
        The path for staging downloads.
    .PARAMETER PackageFormat
        Package storage format: Raw, Zip, or WIM.
    .PARAMETER CleanupDownloadPath
        If set to Yes, delete downloaded files after a successful import.
    .PARAMETER DPGroups
        An array of Distribution Point Group names.
    .PARAMETER EnableBinaryDeltaReplication
        Whether to enable BDR on created packages.
    .PARAMETER DistributionPriority
        Package distribution priority (High, Medium, Low).
    .EXAMPLE
        Set-DASettings -SiteServer "SCCM01.contoso.com" -PackagePath "\\Server\Drivers"
    .EXAMPLE
        Set-DASettings -DPGroups @("Standard OSD Distribution") -EnableBinaryDeltaReplication $true
    #>
    [CmdletBinding()]
    param(
        [string]$SiteServer,
        [string]$SiteCode,
        [string]$SCCMNamespace,
        [string]$PackagePath,
        [string]$DownloadPath,
        [ValidateSet("Raw", "Zip", "WIM")]
        [string]$PackageFormat,
        [string]$CleanupDownloadPath,
        [string[]]$DPGroups,
        [bool]$EnableBinaryDeltaReplication,
        [string]$DistributionPriority
    )

    if ($PSBoundParameters.Count -eq 0) {
        $CurrentSettings = Get-DASettings

        $SiteServer = Read-Host "Site Server FQDN [$($CurrentSettings.SiteServer)]"
        if ($SiteServer) { $CurrentSettings.SiteServer = $SiteServer }

        $PackagePath = Read-Host "Package Path (UNC) [$($CurrentSettings.PackagePath)]"
        if ($PackagePath) { $CurrentSettings.PackagePath = $PackagePath }

        $DownloadPath = Read-Host "Download Path (e.g. .\\Temp) [$($CurrentSettings.DownloadPath)]"
        if ($DownloadPath) { $CurrentSettings.DownloadPath = $DownloadPath }

        Write-Host ""
        Write-Host "Package Format Selection:" -ForegroundColor Cyan
        Write-Host "[1] Raw  (Extracted drivers only)"
        Write-Host "[2] Zip  (Compressed archive)"
        Write-Host "[3] WIM  (Windows Imaging Format)"
        $FormatIn = Read-Host "Select format (1, 2, or 3) [$($CurrentSettings.PackageFormat)]"
        
        switch ($FormatIn) {
            "1" { $CurrentSettings.PackageFormat = "Raw" }
            "2" { $CurrentSettings.PackageFormat = "Zip" }
            "3" { $CurrentSettings.PackageFormat = "WIM" }
            { $_ -match "(?i)raw" } { $CurrentSettings.PackageFormat = "Raw" }
            { $_ -match "(?i)zip" } { $CurrentSettings.PackageFormat = "Zip" }
            { $_ -match "(?i)wim" } { $CurrentSettings.PackageFormat = "WIM" }
            # If blank, keep current
        }

        $CleanupDefault = if ($CurrentSettings.CleanupDownloadPath) { "Yes" } else { "No" }
        $CleanupDownloadPath = Read-Host "Cleanup Download Path? (Yes/No) [$CleanupDefault]"
        if ($CleanupDownloadPath) { $CurrentSettings.CleanupDownloadPath = ($CleanupDownloadPath -eq "Yes") }

        $BdrDefault = if ($CurrentSettings.EnableBinaryDeltaReplication) { "Yes" } else { "No" }
        $EnableBinaryDeltaReplication = Read-Host "Enable BDR? (Yes/No) [$BdrDefault]"
        if ($EnableBinaryDeltaReplication) { $CurrentSettings.EnableBinaryDeltaReplication = ($EnableBinaryDeltaReplication -eq "Yes") }

        $DistributionPriority = Read-Host "Distribution Priority (High/Medium/Low) [$($CurrentSettings.DistributionPriority)]"
        if ($DistributionPriority) { $CurrentSettings.DistributionPriority = $DistributionPriority }

        if ($CurrentSettings.SiteServer) {
            if (Initialize-SCCMConnection) {
                $Options = Get-DPOptions -SiteServer $CurrentSettings.SiteServer -SiteCode $global:SiteCode
                if ($Options -and $Options.DistributionPointGroups) {
                    $Groups = $Options.DistributionPointGroups
                    Write-Host "`nDP Groups (enter numbers, comma-separated):" -ForegroundColor Cyan
                    for ($i = 0; $i -lt $Groups.Count; $i++) {
                        Write-Host "[$($i + 1)] $($Groups[$i])"
                    }

                    $CurrentDefault = if ($CurrentSettings.DistributionPointGroups -and $CurrentSettings.DistributionPointGroups.Count -gt 0) {
                        ($CurrentSettings.DistributionPointGroups -join ", ")
                    }
                    else { "" }

                    $Prompt = if ($CurrentDefault) { "Selection [$CurrentDefault]" } else { "Selection" }
                    $Selection = Read-Host $Prompt
                    if ($Selection) {
                        $Indices = $Selection.Split(',') | ForEach-Object { [int]$_.Trim() - 1 }
                        $SelectedGroups = @()
                        foreach ($Index in $Indices) {
                            if ($Index -ge 0 -and $Index -lt $Groups.Count) {
                                $SelectedGroups += $Groups[$Index]
                            }
                        }
                        if ($SelectedGroups.Count -gt 0) {
                            $CurrentSettings.DistributionPointGroups = $SelectedGroups
                        }
                    }
                }
            }
        }

        try {
            $CurrentSettings | ConvertTo-Json | Out-File $global:SettingsJSONPath -Encoding utf8
            Write-LogEntry -Value "Successfully updated DASettings.json" -Severity 1
            Get-DASettings | Out-Null
        }
        catch {
            Write-LogEntry -Value "[Error] - Failed to save JSON settings: $($_.Exception.Message)" -Severity 3
        }
        return
    }

    $CurrentSettings = Get-DASettings

    if ($PSBoundParameters.ContainsKey('SiteServer')) { $CurrentSettings.SiteServer = $SiteServer }
    if ($PSBoundParameters.ContainsKey('SiteCode')) { $CurrentSettings.SiteCode = $SiteCode }
    if ($PSBoundParameters.ContainsKey('SCCMNamespace')) { $CurrentSettings.SCCMNamespace = $SCCMNamespace }
    if ($PSBoundParameters.ContainsKey('PackagePath')) { $CurrentSettings.PackagePath = $PackagePath }
    if ($PSBoundParameters.ContainsKey('DownloadPath')) { $CurrentSettings.DownloadPath = $DownloadPath }
    if ($PSBoundParameters.ContainsKey('PackageFormat')) { $CurrentSettings.PackageFormat = $PackageFormat }
    if ($PSBoundParameters.ContainsKey('CleanupDownloadPath')) {
        $CurrentSettings.CleanupDownloadPath = ($CleanupDownloadPath -eq "Yes")
    }
    if ($PSBoundParameters.ContainsKey('DPGroups')) { $CurrentSettings.DistributionPointGroups = $DPGroups }
    if ($PSBoundParameters.ContainsKey('EnableBinaryDeltaReplication')) { $CurrentSettings.EnableBinaryDeltaReplication = $EnableBinaryDeltaReplication }
    if ($PSBoundParameters.ContainsKey('DistributionPriority')) { $CurrentSettings.DistributionPriority = $DistributionPriority }

    try {
        $CurrentSettings | ConvertTo-Json | Out-File $global:SettingsJSONPath -Encoding utf8
        Write-LogEntry -Value "Successfully updated DASettings.json" -Severity 1
        
        # Refresh globals
        Get-DASettings | Out-Null
    }
    catch {
        Write-LogEntry -Value "[Error] - Failed to save JSON settings: $($_.Exception.Message)" -Severity 3
    }
}

function Test-DASettings {
    <#
    .SYNOPSIS
        Validates that all settings are configured.
    .DESCRIPTION
        Checks for blank/null values in the settings file. Returns $true if valid, $false otherwise.
    #>
    [CmdletBinding()]
    param()

    $Settings = Get-DASettings
    if (-not $Settings) { return $false }

    $MissingSettings = @()
    $Settings.PSObject.Properties | ForEach-Object {
        $Name = $_.Name
        $Value = $_.Value

        if ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value)) {
            $MissingSettings += $Name
        }
        elseif ($Value -is [System.Array] -and $Value.Count -eq 0) {
            $MissingSettings += $Name
        }
    }

    if ($MissingSettings.Count -gt 0) {
        Write-LogEntry -Value "[Error] - The following settings are missing or blank: $($MissingSettings -join ', '). Please run Set-DASettings to configure." -Severity 3
        return $false
    }

    return $true
}

# // =================== LOGGING FUNCTION ====================== //

function Write-LogEntry {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Value,
        [Parameter(Mandatory = $true)]
        [ValidateSet('1', '2', '3')]
        [string]$Severity,
        [string]$FileName = "DATCLI.log",
        [bool]$WriteOutput = $true
    )
    
    $LogFilePath = Join-Path -Path $global:LogDirectory -ChildPath $FileName
    
    # Construct timestamp (Bias check for legacy compat)
    $Bias = 0
    try {
        $Bias = (Get-CimInstance -ClassName Win32_TimeZone).Bias
    }
    catch {
        $Bias = 0
    }
    $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), " ", $Bias)
    $Date = (Get-Date -Format "MM-dd-yyyy")
    $Context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    
    # Construct CMTrace compatible log entry
    $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""DriverAutomationTool"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
    
    try {
        Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
    }
    catch {
        Write-Warning "Unable to append log entry to $FileName. Error: $($_.Exception.Message)"
    }
    
    if ($WriteOutput) {
        switch ($Severity) {
            '1' { Write-Host $Value -ForegroundColor Cyan }
            '2' { Write-Warning $Value }
            '3' { Write-Error $Value }
        }
    }
}

# // =================== SHARED PACK HELPERS ====================== //

function Select-DriverPackResults {
    <#
    Filters a candidate driver pack list by requested OS family and OS version.
    Expected common properties:
      - WindowsName (canonical "Windows 10"/"Windows 11") for OS family matching
      - version for version matching
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$PackResults,
        [string]$OSName,
        [string]$OSVersion,
        [string]$OsFamilyNameProperty = 'WindowsName',
        [string]$OsVersionProperty = 'version'
    )

    if (-not $PackResults) { return @() }

    $results = $PackResults

    if ($OSName) {
        $osToken = if ($OSName -match "11") { "11" } else { "10" }
        $results = $results | Where-Object { $_.$OsFamilyNameProperty -match $osToken }
    }

    if ($OSVersion) {
        $results = $results | Where-Object { $_.$OsVersionProperty -match $OSVersion }
    }

    return $results
}

function Merge-DriverPackDuplicates {
    <#
    De-duplicates identical pack rows and merges ModelTypes across duplicates.
    Expected common properties:
      - ModelName, WindowsName, version, date, DownloadUrl, Architecture, ModelTypes
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$PackResults,
        [scriptblock]$CompositeKeyExpression = {
            "$($_.ModelName)|$($_.WindowsName)|$($_.version)|$($_.date)|$($_.DownloadUrl)|$($_.Architecture)"
        }
    )

    if (-not $PackResults) { return @() }

    return ($PackResults |
        Group-Object -Property $CompositeKeyExpression |
        ForEach-Object {
            $first = $_.Group[0]
            $allTypes = $_.Group | ForEach-Object { $_.ModelTypes } | Where-Object { $_ } | ForEach-Object { $_ }
            if ($allTypes) {
                $first.ModelTypes = $allTypes | Sort-Object -Unique
            }
            $first
        })
}

function Select-DriverPack {
    <#
    Interactive selection helper for a driver pack list.
    Returns:
      - the chosen pack object
      - $null when selection is invalid (caller should return to abort workflow)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$PackResults,
        [Parameter(Mandatory = $true)]
        [scriptblock]$LineFormatter,
        [string]$SelectionPrompt = "Enter selection number"
    )

    if (-not $PackResults -or $PackResults.Count -eq 0) { return $null }

    if ($PackResults.Count -gt 1) {
        Write-Host ""
        Write-Host "Found $($PackResults.Count) matching driver pack(s). Select a number to continue:" -ForegroundColor Gray

        for ($i = 0; $i -lt $PackResults.Count; $i++) {
            $p = $PackResults[$i]
            # Call formatter with positional arguments: ($p, $i)
            $line = & $LineFormatter $p $i
            Write-Host $line
        }

        $selectionInput = Read-Host $SelectionPrompt
        if (-not ($selectionInput -as [int])) {
            Write-LogEntry -Value "[Warning] - Invalid selection. Exiting." -Severity 2
            return $null
        }

        $selectionIndex = [int]$selectionInput - 1
        if ($selectionIndex -lt 0 -or $selectionIndex -ge $PackResults.Count) {
            Write-LogEntry -Value "[Warning] - Selection out of range. Exiting." -Severity 2
            return $null
        }

        return $PackResults[$selectionIndex]
    }

    return $PackResults[0]
}

function Build-DriverPackageName {
    <#
    .SYNOPSIS
        Constructs a standardised SCCM driver package name.
    .DESCRIPTION
        Single source of truth for package naming conventions across all OEMs
        and the interactive CLI pre-check. Strip leading OEM prefix from Model
        when the caller passes the raw catalog name (e.g. "HP EliteBook 840 G7").
    .PARAMETER OEM
        The OEM brand: Lenovo, Dell, HP, Microsoft, or Custom.
    .PARAMETER Model
        The model name as returned by the catalog / supplied by the user.
    .PARAMETER OSName
        Normalised OS family string: "Windows 10" or "Windows 11".
    .PARAMETER OSVersion
        OS version token, e.g. "22H2" or "23H2". Optional.
    .PARAMETER Architecture
        Architecture string, e.g. "x64". Optional.
    .PARAMETER Manufacturer
        For Custom OEM: the manufacturer label to use instead of "Custom".
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Lenovo", "Dell", "HP", "Microsoft", "Custom")]
        [string]$OEM,

        [Parameter(Mandatory = $true)]
        [string]$Model,

        [Parameter(Mandatory = $true)]
        [string]$OSName,

        [string]$OSVersion,
        [string]$Architecture,
        [string]$Manufacturer
    )

    # Determine the label used in the package name
    $label = if ($OEM -eq "Custom" -and $Manufacturer) { $Manufacturer } else { $OEM }

    # Strip leading OEM prefix from the model string if present (e.g. "HP EliteBook" -> "EliteBook")
    $displayModel = switch ($OEM) {
        "Dell" { $Model -replace '^\s*Dell\s+', '' }
        "HP" { $Model -replace '^\s*HP\s+', '' }
        default { $Model }
    }

    $parts = @("Drivers", "-", "$label $displayModel", "-", $OSName)
    if ($OSVersion) { $parts += $OSVersion }
    if ($Architecture) { $parts += $Architecture }

    return ($parts -join ' ')
}

function Get-OSVersionSortKey {
    [CmdletBinding()]
    param (
        [string]$OSVersion
    )

    if (-not $OSVersion) { return 0 }
    if ($OSVersion -match '^(\d{2})H([12])$') {
        return ((2000 + [int]$Matches[1]) * 10) + [int]$Matches[2]
    }
    if ($OSVersion -match '^\d{4}$') {
        return [int]$OSVersion
    }
    return 0
}

function Resolve-DriverPackageCheckInput {
    <#
    .SYNOPSIS
        Normalizes a Find-*Model result row into package-name inputs.
    .DESCRIPTION
        Used by CLI pre-check logic so package naming stays in one place via
        Build-DriverPackageName instead of being reimplemented per OEM.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Lenovo", "Dell", "HP", "Microsoft")]
        [string]$OEM,

        [Parameter(Mandatory = $true)]
        [psobject]$SelectedModel
    )

    $modelName = [string]$SelectedModel.Name
    $productSku = [string]$SelectedModel.SKU
    $osRaw = [string]$SelectedModel.OS
    $modelForPackage = if ($OEM -eq "Microsoft" -and $productSku) { $productSku } else { $modelName }

    if ([string]::IsNullOrWhiteSpace($modelForPackage)) {
        return $null
    }

    $osName = $null
    $osVersion = $null
    $architecture = $null

    if ($osRaw) {
        if ($osRaw -match '(?i)(windows\s*11|win11)') {
            $osName = "Windows 11"
        }
        elseif ($osRaw -match '(?i)(windows\s*10|win10)') {
            $osName = "Windows 10"
        }
        elseif ($osRaw -match '(?<!\d)11(?!\d)') {
            $osName = "Windows 11"
        }
        elseif ($osRaw -match '(?<!\d)10(?!\d)') {
            $osName = "Windows 10"
        }

        if ($osRaw -match '(?i)(\d{2}H[12]|\d{4})') {
            $osVersion = $Matches[1].ToUpper()
        }

        if ($osRaw -match '(?i)(x64|64-bit|amd64)') {
            $architecture = "x64"
        }
        elseif ($osRaw -match '(?i)(x86|32-bit)') {
            $architecture = "x86"
        }
    }

    if (-not $osName) {
        return $null
    }
    if (-not $architecture) {
        $architecture = "x64"
    }

    $packageName = Build-DriverPackageName -OEM $OEM -Model $modelForPackage -OSName $osName -OSVersion $osVersion -Architecture $architecture
    return [pscustomobject]@{
        PackageName   = $packageName
        ModelName     = $modelName
        ProductSku    = $productSku
        ModelForCheck = $modelForPackage
        OSName        = $osName
        OSVersion     = $osVersion
        Architecture  = $architecture
    }
}

function Test-DriverPackageExists {
    <#
    .SYNOPSIS
        Checks whether a package already exists for a selected Find-*Model row.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteServer,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Lenovo", "Dell", "HP", "Microsoft")]
        [string]$OEM,

        [Parameter(Mandatory = $true)]
        [psobject]$SelectedModel,

        [int]$TimeoutSec = 10
    )

    $checkInput = Resolve-DriverPackageCheckInput -OEM $OEM -SelectedModel $SelectedModel
    if (-not $checkInput) {
        return [pscustomobject]@{
            CanCheck        = $false
            Reason          = "Unable to derive OS/package naming inputs from selected catalog row."
            PackageName     = $null
            ExistingPackage = $null
            CheckInput      = $null
        }
    }

    # Ensure we have an active ConfigMgr connection before querying packages.
    # If connection is unavailable, skip pre-check cleanly rather than emitting
    # a hard error from Get-CMPackageCim.
    if (-not $global:SCCMCimSession) {
        $connected = $false
        try {
            $connected = Initialize-SCCMConnection
        }
        catch {
            $connected = $false
        }

        if (-not $connected -or -not $global:SCCMCimSession) {
            return [pscustomobject]@{
                CanCheck        = $false
                Reason          = "No active ConfigMgr connection. Package pre-check skipped."
                PackageName     = $checkInput.PackageName
                ExistingPackage = $null
                CheckInput      = $checkInput
            }
        }
    }

    $existing = Get-CMPackage -SiteServer $SiteServer -Name $checkInput.PackageName -TimeoutSec $TimeoutSec | Select-Object -First 1
    $newerPackage = $null
    $relatedPackages = @()

    # Also detect a newer package in the same model/OS family/arch to avoid
    # accidental downgrades when the selected pack is older than what's already in SCCM.
    if ($checkInput.OSName -and $checkInput.Architecture) {
        $basePrefix = Build-DriverPackageName -OEM $OEM -Model $checkInput.ModelForCheck -OSName $checkInput.OSName
        $escapedPrefix = ConvertTo-WqlEscapedString "$basePrefix "
        $relatedPackages = @(Get-CMPackage -SiteServer $SiteServer -NameFilter "startswith(Name,'$escapedPrefix')" -TimeoutSec $TimeoutSec)
        $selectedKey = Get-OSVersionSortKey -OSVersion $checkInput.OSVersion

        # Only do "newer package exists" checks when the selected pack has a
        # parseable OS version token. Otherwise rely on exact-name existence.
        if ($selectedKey -gt 0 -and $relatedPackages.Count -gt 0) {
            $candidates = foreach ($pkg in $relatedPackages) {
                if (-not $pkg.Name) { continue }
                if ($pkg.Name -notmatch " - $([regex]::Escape($checkInput.OSName))\s+([0-9]{2}H[12]|[0-9]{4})\s+([A-Za-z0-9]+)$") { continue }
                $pkgOsVersion = $Matches[1]
                $pkgArch = $Matches[2]
                if ($pkgArch -ne $checkInput.Architecture) { continue }

                [pscustomobject]@{
                    Package    = $pkg
                    OSVersion  = $pkgOsVersion
                    VersionKey = Get-OSVersionSortKey -OSVersion $pkgOsVersion
                }
            }

            $newerPackage = $candidates |
                Where-Object { $_.VersionKey -gt $selectedKey } |
                Sort-Object VersionKey -Descending |
                Select-Object -First 1 |
                Select-Object -ExpandProperty Package
        }
    }

    return [pscustomobject]@{
        CanCheck        = $true
        Reason          = $null
        PackageName     = $checkInput.PackageName
        ExistingPackage = $existing
        NewerPackage    = $newerPackage
        RelatedPackages = $relatedPackages
        CheckInput      = $checkInput
    }
}

# // =================== LENOVO CORE logic ====================== //

# OEM Links Master File
function Get-OEMLinks {
    try {
        $OEMXMLPath = (Join-Path (Get-ScriptDirectory) -ChildPath "OEMLinks.xml")
        if ((Test-Path -Path $OEMXMLPath) -eq $false) {
            Write-LogEntry -Value "OEM Links: Downloading OEMLinks XML" -Severity 1
            (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ajn142attamu/DriverAutomationTool/master/Data/OEMLinks.xml" -UseBasicParsing).Content | Out-File -FilePath $OEMXMLPath
        }
        else {
            [version]$OEMCurrentVersion = ([XML]((Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ajn142attamu/DriverAutomationTool/master/Data/OEMLinks.xml" -UseBasicParsing).Content)).OEM.Version
            [version]$OEMDownloadedVersion = ([XML](Get-Content -Path $OEMXMLPath)).OEM.Version
            if ($OEMDownloadedVersion -lt $OEMCurrentVersion) {
                Write-LogEntry -Value "OEM Links: Downloading updated OEMLinks XML ($OEMCurrentVersion)" -Severity 1
                (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ajn142attamu/DriverAutomationTool/master/Data/OEMLinks.xml" -UseBasicParsing).Content | Out-File -FilePath $OEMXMLPath -Force
            }
        }
        Write-LogEntry -Value "OEM Links: Reading OEMLinks XML" -Severity 1
        return [xml](Get-Content -Path $OEMXMLPath)
    }
    catch {
        Write-LogEntry -Value "[Error] - Failed to handle OEM Links: $($_.Exception.Message)" -Severity 3
    }
}

$global:OEMLinks = Get-OEMLinks
Write-LogEntry -Value "DATCLI $ScriptRelease module loaded ($ScriptBuildDate)" -Severity 1

# Lenovo Variables
$LenovoXMLSource = ($global:OEMLinks.OEM.Manufacturer | Where-Object {
        $_.Name -match "Lenovo"
    }).Link | Where-Object {
    $_.Type -eq "XMLSource"
} | Select-Object -ExpandProperty URL

$global:LenovoXMLCabFile = $LenovoXMLSource | Split-Path -Leaf
$global:LenovoXMLFile = [string]($LenovoXMLSource | Split-Path -Leaf)

$global:LenovoModelDrivers = $null
$global:LenovoModelXML = $null

# Dell Variables
$DellXMLCabSource = ($global:OEMLinks.OEM.Manufacturer | Where-Object {
        $_.Name -match "Dell"
    }).Link | Where-Object {
    $_.Type -eq "XMLCabinetSource"
} | Select-Object -ExpandProperty URL

$DellDownloadBase = ($global:OEMLinks.OEM.Manufacturer | Where-Object {
        $_.Name -match "Dell"
    }).Link | Where-Object {
    $_.Type -eq "DownloadBase"
} | Select-Object -ExpandProperty URL

$global:DellXMLCabFile = if ($DellXMLCabSource) { $DellXMLCabSource | Split-Path -Leaf } else { "" }
$global:DellXMLFile = if ($global:DellXMLCabFile) { [System.IO.Path]::ChangeExtension($global:DellXMLCabFile, ".xml") } else { "" }
$global:DellModelDrivers = $null
$global:DellModelXML = $null

# HP Variables
$HPXMLCabSource = ($global:OEMLinks.OEM.Manufacturer | Where-Object {
        $_.Name -match "HP"
    }).Link | Where-Object {
    $_.Type -eq "XMLCabinetSource"
} | Select-Object -ExpandProperty URL

$global:HPXMLCabFile = if ($HPXMLCabSource) { $HPXMLCabSource | Split-Path -Leaf } else { "" }
$global:HPXMLFile = if ($global:HPXMLCabFile) { [System.IO.Path]::ChangeExtension($global:HPXMLCabFile, ".xml") } else { "" }
$global:HPModelXML = $null
$global:HPModelDrivers = $null
$global:HPSoftPaqList = $null
$global:SCCMNamespace = $null

# Microsoft Variables
$MicrosoftJSONSource = ($global:OEMLinks.OEM.Manufacturer | Where-Object {
        $_.Name -match "Microsoft"
    }).Link | Where-Object {
    $_.Type -eq "JSONSource"
} | Select-Object -ExpandProperty URL

$global:MicrosoftJSONFile = if ($MicrosoftJSONSource) { "build-driverpack.json" } else { "" }
$global:MicrosoftModelDrivers = $null

# // =================== CONFIGMGR LOGIC ====================== //

# // =================== SCCM CONNECTIVITY ====================== //
# Strategy: CIM over DCOM (RPC) for all ConfigMgr operations.
# WinRM (TCP 5985/5986) is NOT used — it's blocked by firewall policy.
#
# CIM/DCOM uses New-CimSession with -SessionOption (New-CimSessionOption -Protocol DCOM)
# which tunnels over RPC/DCOM rather than WS-Man. This avoids the WinRM requirement.

# Internal helper to ensure ConfigMgr connection before any SCCM operation
function Initialize-SCCMConnection {
    <#
    .SYNOPSIS
        Internal helper - ensures ConfigMgr connection is established.
    .DESCRIPTION
        Called automatically by user-facing cmdlets. Checks if already connected
        ($global:ConfigMgrValidation), and if not, calls Connect-ConfigMgr.
    #>
    if ($global:ConfigMgrValidation -and $global:SiteServer) {
        return $true # Already connected
    }

    $Settings = Get-DASettings
    if (-not $Settings.SiteServer) {
        Write-LogEntry -Value "[Error] - SiteServer not configured. Run Set-DASettings first." -Severity 3
        return $false
    }

    return Connect-ConfigMgr -SiteServer $Settings.SiteServer
}

function New-SCCMCimSession {
    <#
    .SYNOPSIS
        Creates a CIM session to the SCCM site server using DCOM protocol (not WinRM).
    .DESCRIPTION
        Establishes a CIM session using the DCOM protocol option, which uses RPC
        instead of WS-Management. WinRM ports are NOT required.
    .PARAMETER SiteServer
        The FQDN of the ConfigMgr site server.
    .EXAMPLE
        $Session = New-SCCMCimSession -SiteServer "SCCM01.contoso.com"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteServer
    )

    try {
        Write-LogEntry -Value "- Creating CIM session to $SiteServer (DCOM protocol, no WinRM)" -Severity 1 -WriteOutput $false
        $DcomOption = New-CimSessionOption -Protocol Dcom
        $Session = New-CimSession -ComputerName $SiteServer -SessionOption $DcomOption -ErrorAction Stop
        Write-LogEntry -Value "- CIM/DCOM session established to $SiteServer" -Severity 1 -WriteOutput $false
        return $Session
    }
    catch {
        Write-LogEntry -Value "[Warning] - Failed to create CIM/DCOM session to ${SiteServer}: $($_.Exception.Message)" -Severity 2
        return $null
    }
}

function Resolve-SCCMProviderServer {
    <#
    .SYNOPSIS
        Resolves the SMS Provider host for the site.
    .PARAMETER SiteServer
        The site server to query for provider location.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteServer
    )

    try {
        $Session = New-SCCMCimSession -SiteServer $SiteServer
        if (-not $Session) { return $SiteServer }

        # Try via root\SMS (if provider is local)
        try {
            $Provider = Get-CimInstance -CimSession $Session -Namespace "root\\SMS" `
                -ClassName "SMS_ProviderLocation" -ErrorAction Stop |
            Where-Object { $_.ProviderForLocalSite -eq $true } | Select-Object -First 1

            if ($Provider -and $Provider.Machine) {
                $Machine = $Provider.Machine.Trim()
                if ($Machine.StartsWith("\\\\")) {
                    $Machine = $Machine.TrimStart("\\")
                }
                return $Machine
            }
        }
        catch {
            # Ignore and try registry-based discovery below
        }

        $RegProvider = Resolve-SCCMProviderFromRegistry -Session $Session
        if ($RegProvider) { return $RegProvider }
    }
    catch {
        Write-LogEntry -Value "[Warning] - Failed to resolve SMS Provider: $($_.Exception.Message)" -Severity 2
    }

    return $SiteServer
}

function Resolve-SCCMProviderFromRegistry {
    <#
    .SYNOPSIS
        Attempts to read SMS Provider host from registry via StdRegProv.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [CimSession]$Session
    )

    $HKLM = 2147483650
    $Candidates = @(
        @{ Key = "SOFTWARE\\Microsoft\\SMS\\Setup"; ValuePattern = "Provider" },
        @{ Key = "SOFTWARE\\Microsoft\\SMS\\Setup"; ValuePattern = "SMS Provider" },
        @{ Key = "SOFTWARE\\Microsoft\\SMS\\Providers"; ValuePattern = "" }
    )

    foreach ($cand in $Candidates) {
        try {
            $enum = Invoke-CimMethod -CimSession $Session -Namespace "root\\default" -ClassName "StdRegProv" `
                -MethodName "EnumValues" -Arguments @{ hDefKey = $HKLM; sSubKeyName = $cand.Key } -ErrorAction Stop

            if (-not $enum -or -not $enum.sNames) { continue }

            $names = $enum.sNames
            foreach ($name in $names) {
                if ($cand.ValuePattern -and ($name -notmatch $cand.ValuePattern)) { continue }

                $str = Invoke-CimMethod -CimSession $Session -Namespace "root\\default" -ClassName "StdRegProv" `
                    -MethodName "GetStringValue" -Arguments @{ hDefKey = $HKLM; sSubKeyName = $cand.Key; sValueName = $name } `
                    -ErrorAction SilentlyContinue

                $value = $str.sValue
                if (-not $value) {
                    $ms = Invoke-CimMethod -CimSession $Session -Namespace "root\\default" -ClassName "StdRegProv" `
                        -MethodName "GetMultiStringValue" -Arguments @{ hDefKey = $HKLM; sSubKeyName = $cand.Key; sValueName = $name } `
                        -ErrorAction SilentlyContinue
                    if ($ms.sValue) { $value = ($ms.sValue -join ";") }
                }

                if ($value) {
                    # Try to extract server name
                    if ($value -match "\\\\\\\\([^\\\\]+)\\\\root\\\\SMS") { return $Matches[1] }
                    if ($value -match "\\\\\\\\([^\\\\]+)") { return $Matches[1] }
                    if ($value -match "^[A-Za-z0-9_.-]+$") { return $value }
                }
            }
        }
        catch {
            # ignore and continue
        }
    }

    return $null
}

function Resolve-SCCMNamespaceFromProvider {
    <#
    .SYNOPSIS
        Resolves the site namespace using SMS_ProviderLocation.NamespacePath.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [CimSession]$Session
    )

    try {
        $Provider = Get-CimInstance -CimSession $Session -Namespace "root\\SMS" `
            -ClassName "SMS_ProviderLocation" -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderForLocalSite -eq $true } | Select-Object -First 1

        if ($Provider -and $Provider.NamespacePath) {
            $Path = $Provider.NamespacePath.Trim()
            # NamespacePath is like \\SERVER\root\SMS\site_ABC
            if ($Path -match "root\\\\SMS\\\\site_.+$") {
                $Namespace = $Path -replace ".*\\\\root\\\\", "root\\"
                return $Namespace
            }
        }
    }
    catch {
        Write-LogEntry -Value "[Warning] - Failed to resolve namespace from provider: $($_.Exception.Message)" -Severity 2
    }

    return $null
}

function Invoke-SCCMCimQuery {
    <#
    .SYNOPSIS
        Runs a WQL query against SCCM via CIM/DCOM.
    .DESCRIPTION
        Uses the existing CIM/DCOM session ($global:SCCMCimSession) to query the SCCM
        WMI namespace.
    .PARAMETER Query
        The WQL query string.
    .PARAMETER Namespace
        The WMI namespace. Defaults to "root\SMS\site_$($global:SiteCode)".
    .EXAMPLE
        Invoke-SCCMCimQuery -Query "SELECT * FROM SMS_Package WHERE Name = 'Test'"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Query,

        [string]$Namespace,
        [int]$TimeoutSec = 60
    )

    if (-not $Namespace) {
        $Namespace = Get-SCCMNamespace
    }

    if (-not $global:SCCMCimSession) {
        Write-LogEntry -Value "[Error] - No CIM/DCOM session available. Run Connect-ConfigMgr first." -Severity 3
        return $null
    }

    try {
        $Results = Get-CimInstance -CimSession $global:SCCMCimSession -Namespace $Namespace -Query $Query -OperationTimeoutSec $TimeoutSec -ErrorAction Stop
        return $Results
    }
    catch {
        $Message = $_.Exception.Message
        if ($Message -match "timed out|timeout" -or $_.FullyQualifiedErrorId -match "TimedOut|OperationTimeout") {
            Write-LogEntry -Value "[Warning] - CIM query timed out after ${TimeoutSec}s: $Message" -Severity 2
            Write-LogEntry -Value "  Query: $Query" -Severity 2
            return $null
        }
        if ($Message -match "Invalid namespace" -and $Namespace -match "root\\\\SMS\\\\site_") {
            Write-LogEntry -Value "[Warning] - Invalid namespace '$Namespace' on server $($global:SiteServer). Attempting recovery." -Severity 2
            try {
                $ResolvedNs = Resolve-SCCMNamespaceFromProvider -Session $global:SCCMCimSession
                if ($ResolvedNs) {
                    $global:SCCMNamespace = $ResolvedNs
                    $Namespace = $global:SCCMNamespace
                    $Results = Get-CimInstance -CimSession $global:SCCMCimSession -Namespace $Namespace -Query $Query -OperationTimeoutSec $TimeoutSec -ErrorAction Stop
                    return $Results
                }

                $NsList = Get-CimInstance -CimSession $global:SCCMCimSession -Namespace "root\\SMS" -ClassName "__Namespace" -ErrorAction Stop
                $SiteNs = $NsList | Where-Object { $_.Name -like "site_*" }
                if ($SiteNs) {
                    $SiteNames = $SiteNs | Select-Object -ExpandProperty Name
                    Write-LogEntry -Value "[Warning] - Available site namespaces: $($SiteNames -join ', ')" -Severity 2
                    $Target = $SiteNs | Where-Object { $_.Name -ieq "site_$($global:SiteCode)" } | Select-Object -First 1
                    if (-not $Target) { $Target = $SiteNs | Select-Object -First 1 }
                    if ($Target) {
                        $global:SCCMNamespace = "root\\SMS\\$($Target.Name)"
                        if (-not $global:SiteCode -and $Target.Name -match "^site_(.+)$") {
                            $global:SiteCode = $Matches[1].Trim().ToUpper()
                        }
                        $Namespace = $global:SCCMNamespace
                        $Results = Get-CimInstance -CimSession $global:SCCMCimSession -Namespace $Namespace -Query $Query -OperationTimeoutSec $TimeoutSec -ErrorAction Stop
                        return $Results
                    }
                }
            }
            catch {
                Write-LogEntry -Value "[Warning] - CIM namespace recovery failed: $($_.Exception.Message)" -Severity 2
            }
        }
        Write-LogEntry -Value "[Error] - CIM query failed: $Message" -Severity 3
        Write-LogEntry -Value "  Query: $Query" -Severity 3
        return $null
    }
}

function Get-SCCMNamespace {
    if ($global:SCCMNamespace) {
        return $global:SCCMNamespace
    }
    if ($global:SiteCode) {
        return "root\\SMS\\site_$($global:SiteCode)"
    }
    return "root\\SMS"
}

function ConvertTo-WqlEscapedString {
    param([string]$Value)
    if ($null -eq $Value) { return $null }
    return ($Value -replace "'", "''")
}

 


function Connect-ConfigMgr {
    <#
    .SYNOPSIS
        Connects to a Configuration Manager site server.
    .DESCRIPTION
        Connects using CIM over DCOM (RPC).
        WinRM (TCP 5985/5986) is never used.
    .PARAMETER SiteServer
        The FQDN of the ConfigMgr Site Server.
    .PARAMETER SiteCode
        Optional site code. If not provided, it will be auto-detected.
    .EXAMPLE
        Connect-ConfigMgr -SiteServer "SCCM01.contoso.com"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Specify the ConfigMgr Site Server FQDN.")]
        [string]$SiteServer,

        [string]$SiteCode
    )
    
    Write-LogEntry -Value "======== Connecting to ConfigMgr ========" -Severity 1 -WriteOutput $false
    Write-LogEntry -Value "- Site Server: $SiteServer" -Severity 1 -WriteOutput $false

    # --- Get Site Code from Settings ---
    $Settings = Get-DASettings
    $SiteCode = $Settings.SiteCode
    if ($SiteCode) { $SiteCode = $SiteCode.Trim().ToUpper() }
    $NamespaceOverride = $Settings.SCCMNamespace
    
    if (-not $SiteCode) {
        Write-LogEntry -Value "[Error] - Site Code not configured in settings. Please run Set-DASettings first." -Severity 3
        return $false
    }
    
    Write-LogEntry -Value "- Site Code from Settings: $SiteCode" -Severity 1 -WriteOutput $false
    $global:SiteCode = $SiteCode
    $global:SiteServer = $SiteServer
    
    # CIM/DCOM only
    Write-LogEntry -Value "- Using CIM/DCOM only" -Severity 1 -WriteOutput $false

    # --- Attempt 2: CIM over DCOM (RPC, no WinRM) ---
    $ProviderServer = Resolve-SCCMProviderServer -SiteServer $SiteServer
    if ($ProviderServer -and $ProviderServer -ne $SiteServer) {
        Write-LogEntry -Value "- Using SMS Provider: $ProviderServer" -Severity 1 -WriteOutput $false
    }

    $global:SCCMCimSession = New-SCCMCimSession -SiteServer $ProviderServer
    if ($global:SCCMCimSession) {
        # Get site code via CIM
        if (-not $SiteCode) {
            try {
                $Provider = Get-CimInstance -CimSession $global:SCCMCimSession -Namespace "root\SMS" -ClassName "SMS_ProviderLocation" -ErrorAction Stop |
                Where-Object { $_.ProviderForLocalSite -eq $true } | Select-Object -First 1
                $SiteCode = $Provider.SiteCode
            }
            catch {
                Write-LogEntry -Value "[Warning] - Could not auto-detect site code via CIM: $($_.Exception.Message)" -Severity 2
            }
        }

        if ($SiteCode) {
            $global:SiteCode = $SiteCode
            $global:SiteServer = $ProviderServer
            $global:ConfigMgrValidation = $true
            try {
                if ($NamespaceOverride) {
                    $global:SCCMNamespace = $NamespaceOverride
                    Write-LogEntry -Value "- Using SCCM namespace override: $($global:SCCMNamespace)" -Severity 1 -WriteOutput $false
                }
                else {
                    $ResolvedNs = Resolve-SCCMNamespaceFromProvider -Session $global:SCCMCimSession
                    if ($ResolvedNs) {
                        $global:SCCMNamespace = $ResolvedNs
                        Write-LogEntry -Value "- Using SCCM namespace: $($global:SCCMNamespace)" -Severity 1 -WriteOutput $false
                    }
                    else {
                        $NsList = Get-CimInstance -CimSession $global:SCCMCimSession -Namespace "root\\SMS" -ClassName "__Namespace" -ErrorAction Stop
                        $SiteNs = $NsList | Where-Object { $_.Name -like "site_*" }
                        if ($SiteNs) {
                            $Target = $SiteNs | Where-Object { $_.Name -ieq "site_$SiteCode" } | Select-Object -First 1
                            if (-not $Target) { $Target = $SiteNs | Select-Object -First 1 }
                            if ($Target) {
                                $global:SCCMNamespace = "root\\SMS\\$($Target.Name)"
                                Write-LogEntry -Value "- Using SCCM namespace: $($global:SCCMNamespace)" -Severity 1 -WriteOutput $false
                            }
                        }
                    }
                }
            }
            catch {
                Write-LogEntry -Value "[Warning] - Could not resolve SCCM namespace list: $($_.Exception.Message)" -Severity 2
            }
            Write-LogEntry -Value "- Connected via CIM/DCOM (Site: $SiteCode)." -Severity 1 -WriteOutput $false
            return $true
        }
    }

    Write-LogEntry -Value "[Error] - Could not connect to ConfigMgr via CIM/DCOM." -Severity 3
    Write-LogEntry -Value "  Check: RPC/DCOM connectivity and permissions." -Severity 3
    return $false
}

# // =================== CONFIGMGR PACKAGE MANAGEMENT (CIM/DCOM) ====================== //

function Get-CMPackageCim {
    <#
    .SYNOPSIS
        Queries ConfigMgr packages via CIM/DCOM.
    .DESCRIPTION
        Replaces Get-CMPackage (which requires the CM PowerShell module and WinRM).
        Queries the SMS_Package WMI class via CIM/DCOM.
    .PARAMETER SiteServer
        The FQDN of the ConfigMgr site server.
    .PARAMETER Name
        Filter packages by exact name match.
    .PARAMETER NameFilter
        Filter packages using an OData 'contains' or 'startswith' expression on the Name field.
    .PARAMETER PackageID
        Look up a specific package by its PackageID.
    .EXAMPLE
        Get-CMPackageCim -SiteServer "SCCM01" -Name "Drivers - Lenovo ThinkPad X1 Carbon - Windows 10 x64"
    .EXAMPLE
        Get-CMPackageCim -SiteServer "SCCM01" -NameFilter "startswith(Name,'Drivers - Lenovo')"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteServer,

        [string]$Name,
        [string]$NameFilter,
        [string]$PackageID,
        [int]$TimeoutSec = 60
    )

    if (-not $global:SCCMCimSession) {
        Write-LogEntry -Value "[Error] - CIM session not available for package query." -Severity 3
        return $null
    }

    $Namespace = Get-SCCMNamespace
    $Where = $null

    if ($PackageID) {
        $Where = "PackageID = '$(ConvertTo-WqlEscapedString $PackageID)'"
    }
    elseif ($Name) {
        $Where = "Name = '$(ConvertTo-WqlEscapedString $Name)'"
    }
    elseif ($NameFilter) {
        # Flexible regex for startswith(Name, 'prefix')
        if ($NameFilter -match "(?i)startswith\s*\(\s*Name\s*,\s*['""]([^'""\)]*)['""]\s*\)") {
            $prefix = ConvertTo-WqlEscapedString $Matches[1]
            $Where = "Name LIKE '$prefix%'"
        }
        # Flexible regex for contains(Name, 'substring')
        elseif ($NameFilter -match "(?i)contains\s*\(\s*Name\s*,\s*['""]([^'""\)]*)['""]\s*\)") {
            $contains = ConvertTo-WqlEscapedString $Matches[1]
            $Where = "Name LIKE '%$contains%'"
        }
        else {
            Write-LogEntry -Value "[Warning] - Unsupported NameFilter format for CIM: $NameFilter" -Severity 2
        }
    }

    $Query = if ($Where) { "SELECT * FROM SMS_Package WHERE $Where" } else { "SELECT * FROM SMS_Package" }
    return Invoke-SCCMCimQuery -Namespace $Namespace -Query $Query -TimeoutSec $TimeoutSec
}

function New-CMPackageCim {
    <#
    .SYNOPSIS
        Creates a new ConfigMgr package via CIM/DCOM.
    .DESCRIPTION
        Replaces New-CMPackage (which requires the CM PowerShell module and WinRM).
        Creates an SMS_Package instance via CIM/DCOM.
    .PARAMETER SiteServer
        The FQDN of the ConfigMgr site server.
    .PARAMETER Name
        The name of the new package.
    .PARAMETER Description
        A description for the package.
    .PARAMETER Manufacturer
        The manufacturer name.
    .PARAMETER Version
        The package version string.
    .PARAMETER PkgSourcePath
        The UNC source path for the package content.
    .PARAMETER MifName
        The MIF name (model name) for the package.
    .PARAMETER MifVersion
        The MIF version (OS + Architecture) for the package.
    .PARAMETER EnableBinaryDeltaReplication
        Whether to enable BDR on the package. Default $false.
    .PARAMETER Priority
        The distribution priority (High, Medium, Low). Default "Medium".
    .EXAMPLE
        New-CMPackageCim -SiteServer "SCCM01" -Name "Drivers - Lenovo ThinkPad X1" -PkgSourcePath "\\server\share\drivers" -Manufacturer "Lenovo" -Version "1.0"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteServer,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [string]$Description = "",
        [string]$Manufacturer = "",
        [string]$Version = "",

        [Parameter(Mandatory = $true)]
        [string]$PkgSourcePath,

        [string]$MifName = "",
        [string]$MifVersion = "",
        [bool]$EnableBinaryDeltaReplication = $false,
        [string]$Priority = "Medium"
    )

    $CreateBody = @{
        Name          = $Name
        PkgSourcePath = $PkgSourcePath
    }
    if ($Manufacturer) { $CreateBody.Manufacturer = $Manufacturer }

    if (-not $global:SCCMCimSession) {
        Write-LogEntry -Value "[Error] - CIM session not available for package creation." -Severity 3
        return $null
    }

    Write-LogEntry -Value "- Creating SCCM package '$Name' via CIM/DCOM..." -Severity 1
    $Namespace = Get-SCCMNamespace

    try {
        $Result = New-CimInstance -CimSession $global:SCCMCimSession -Namespace $Namespace -ClassName "SMS_Package" -Property $CreateBody -ErrorAction Stop
        if ($Result) {
            $PkgID = if ($Result.PackageID) { $Result.PackageID } else { "Unknown" }
            Write-LogEntry -Value "- Package created successfully (PackageID: $PkgID)" -Severity 1

            # Apply optional fields after creation to avoid type-mismatch on create
            $UpdateProps = @{}
            if ($Description) { $UpdateProps.Description = $Description }
            if ($Version) { $UpdateProps.Version = [string]$Version }
            if ($MifName) { $UpdateProps.MIFName = $MifName }
            if ($MifVersion) { $UpdateProps.MIFVersion = $MifVersion }

            $PriorityMap = @{ "High" = 1; "Medium" = 2; "Low" = 3 }
            if ($PriorityMap.ContainsKey($Priority)) {
                $UpdateProps.Priority = [uint32]$PriorityMap[$Priority]
            }

            if ($EnableBinaryDeltaReplication) {
                $UpdateProps.PkgFlags = [uint32]67108864
            }

            if ($UpdateProps.Count -gt 0 -and $PkgID -ne "Unknown") {
                $Updated = Set-CMPackage -SiteServer $SiteServer -PackageID $PkgID -Properties $UpdateProps
                if (-not $Updated) {
                    Write-LogEntry -Value "[Warning] - Package created but optional fields failed to apply." -Severity 2
                }
            }

            return $Result
        }
        Write-LogEntry -Value "[Error] - Failed to create package '$Name' via CIM/DCOM." -Severity 3
        return $null
    }
    catch {
        Write-LogEntry -Value "[Error] - Failed to create package '$Name' via CIM/DCOM: $($_.Exception.Message)" -Severity 3
        return $null
    }
}

function Set-CMPackageCim {
    <#
    .SYNOPSIS
        Updates an existing ConfigMgr package via CIM/DCOM.
    .DESCRIPTION
        Replaces Set-CMPackage (which requires the CM PowerShell module and WinRM).
        Updates SMS_Package via CIM/DCOM.
    .PARAMETER SiteServer
        The FQDN of the ConfigMgr site server.
    .PARAMETER PackageID
        The PackageID of the package to update.
    .PARAMETER Properties
        A hashtable of property names and values to update.
    .EXAMPLE
        Set-CMPackageCim -SiteServer "SCCM01" -PackageID "UN200001" -Properties @{ Version = "2.0"; Description = "Updated" }
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteServer,

        [Parameter(Mandatory = $true)]
        [string]$PackageID,

        [Parameter(Mandatory = $true)]
        [hashtable]$Properties
    )

    if (-not $global:SCCMCimSession) {
        Write-LogEntry -Value "[Error] - CIM session not available for package update." -Severity 3
        return $false
    }

    Write-LogEntry -Value "- Updating SCCM package $PackageID via CIM/DCOM..." -Severity 1
    $Namespace = Get-SCCMNamespace

    try {
        $Package = Get-CimInstance -CimSession $global:SCCMCimSession -Namespace $Namespace `
            -ClassName "SMS_Package" -Filter "PackageID = '$PackageID'" -ErrorAction Stop | Select-Object -First 1
        if (-not $Package) {
            Write-LogEntry -Value "[Error] - Package $PackageID not found for update." -Severity 3
            return $false
        }
        $null = Set-CimInstance -CimSession $global:SCCMCimSession -InputObject $Package -Property $Properties -ErrorAction Stop
        Write-LogEntry -Value "- Package $PackageID updated successfully." -Severity 1
        return $true
    }
    catch {
        Write-LogEntry -Value "[Error] - Failed to update package $PackageID via CIM/DCOM: $($_.Exception.Message)" -Severity 3
        return $false
    }
}

function Get-CMPackage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteServer,

        [string]$Name,
        [string]$NameFilter,
        [string]$PackageID,
        [int]$TimeoutSec = 60
    )
    return Get-CMPackageCim -SiteServer $SiteServer -Name $Name -NameFilter $NameFilter -PackageID $PackageID -TimeoutSec $TimeoutSec
}

function New-CMPackage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteServer,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [string]$Description = "",
        [string]$Manufacturer = "",
        [string]$Version = "",

        [Parameter(Mandatory = $true)]
        [string]$PkgSourcePath,

        [string]$MifName = "",
        [string]$MifVersion = "",
        [bool]$EnableBinaryDeltaReplication = $false,
        [string]$Priority = "Medium"
    )
    return New-CMPackageCim -SiteServer $SiteServer -Name $Name -Description $Description -Manufacturer $Manufacturer `
        -Version $Version -PkgSourcePath $PkgSourcePath -MifName $MifName -MifVersion $MifVersion `
        -EnableBinaryDeltaReplication $EnableBinaryDeltaReplication -Priority $Priority
}

function Set-CMPackage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteServer,

        [Parameter(Mandatory = $true)]
        [string]$PackageID,

        [Parameter(Mandatory = $true)]
        [hashtable]$Properties
    )
    return Set-CMPackageCim -SiteServer $SiteServer -PackageID $PackageID -Properties $Properties
}

function Remove-CMPackage {
    <#
    .SYNOPSIS
        Removes a ConfigMgr package via CIM/DCOM.
    .PARAMETER SiteServer
        The FQDN of the ConfigMgr site server.
    .PARAMETER PackageID
        The package ID to remove.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteServer,
        [Parameter(Mandatory = $true)]
        [string]$PackageID
    )

    try {
        if ($global:SCCMCimSession -and $global:SiteCode) {
            $Namespace = Get-SCCMNamespace
            $Package = Get-CimInstance -CimSession $global:SCCMCimSession -Namespace $Namespace `
                -ClassName "SMS_Package" -Filter "PackageID = '$PackageID'" -ErrorAction Stop | Select-Object -First 1
            if ($Package) {
                Remove-CimInstance -InputObject $Package -ErrorAction Stop | Out-Null
                Write-LogEntry -Value "- Removed SCCM package $PackageID via CIM/DCOM" -Severity 1
                return $true
            }
            Write-LogEntry -Value "[Warning] - Package $PackageID not found via CIM/DCOM" -Severity 2
            return $false
        }

        Write-LogEntry -Value "[Warning] - Unable to remove package $PackageID (no CIM session)" -Severity 2
        return $false
    }
    catch {
        Write-LogEntry -Value "[Error] - Failed to remove package ${PackageID}: $($_.Exception.Message)" -Severity 3
        return $false
    }
}

function Resolve-CMFolderPath {
    <#
    .SYNOPSIS
        Ensures an SCCM console folder path exists (CIM/DCOM).
    .PARAMETER Path
        Folder path like "Driver Packages\Lenovo".
    .PARAMETER ObjectType
        Object type for folders (SMS_Package = 2).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [int]$ObjectType
    )

    if (-not $global:SCCMCimSession) {
        Write-LogEntry -Value "[Error] - CIM session not available for folder operations." -Severity 3
        return $null
    }

    $Namespace = Get-SCCMNamespace
    $ParentId = 0
    $Parts = $Path -split "\\\\" | Where-Object { $_ -and $_.Trim() }

    foreach ($Part in $Parts) {
        $EscPart = ConvertTo-WqlEscapedString $Part
        $Node = Get-CimInstance -CimSession $global:SCCMCimSession -Namespace $Namespace `
            -ClassName "SMS_ObjectContainerNode" `
            -Filter "Name = '$EscPart' AND ParentContainerNodeID = $ParentId AND ObjectType = $ObjectType" `
            -ErrorAction SilentlyContinue | Select-Object -First 1

        if (-not $Node) {
            $Node = New-CimInstance -CimSession $global:SCCMCimSession -Namespace $Namespace `
                -ClassName "SMS_ObjectContainerNode" `
                -Property @{
                Name                  = $Part
                ObjectType            = [uint32]$ObjectType
                ParentContainerNodeID = [uint32]$ParentId
            } -ErrorAction Stop
        }

        $ParentId = $Node.ContainerNodeID
    }

    return $ParentId
}

function Add-CMPackageToFolder {
    <#
    .SYNOPSIS
        Adds a package to a console folder (CIM/DCOM).
    .PARAMETER PackageID
        Package ID to place in the folder.
    .PARAMETER FolderNodeId
        Container node ID for the target folder.
    .PARAMETER ObjectType
        Object type for the item (SMS_Package = 2).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$PackageID,
        [Parameter(Mandatory = $true)]
        [int]$FolderNodeId,
        [Parameter(Mandatory = $true)]
        [int]$ObjectType
    )

    if (-not $global:SCCMCimSession) {
        Write-LogEntry -Value "[Error] - CIM session not available for folder assignment." -Severity 3
        return $false
    }

    $Namespace = Get-SCCMNamespace
    $Existing = Get-CimInstance -CimSession $global:SCCMCimSession -Namespace $Namespace `
        -ClassName "SMS_ObjectContainerItem" `
        -Filter "InstanceKey = '$PackageID' AND ContainerNodeID = $FolderNodeId AND ObjectType = $ObjectType" `
        -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($Existing) {
        return $true
    }

    New-CimInstance -CimSession $global:SCCMCimSession -Namespace $Namespace `
        -ClassName "SMS_ObjectContainerItem" `
        -Property @{
        InstanceKey     = [string]$PackageID
        ContainerNodeID = [uint32]$FolderNodeId
        ObjectType      = [uint32]$ObjectType
    } -ErrorAction Stop | Out-Null

    return $true
}

function Invoke-ContentDistribution {
    <#
    .SYNOPSIS
        Distributes a ConfigMgr package to Distribution Point Groups.
    .DESCRIPTION
        Distributes content using CIM/DCOM (SMS_DistributionPointGroup.AddPackages).
    .PARAMETER SiteServer
        The FQDN of the ConfigMgr site server.
    .PARAMETER PackageID
        The PackageID of the package to distribute.
    .PARAMETER DistributionPointGroupNames
        An array of Distribution Point Group names to distribute content to.
    .PARAMETER DistributionPointNames
        An array of individual Distribution Point server names to distribute content to.
    .EXAMPLE
        Invoke-ContentDistribution -SiteServer "SCCM01" -PackageID "UN200001" -DistributionPointGroupNames @("Standard OSD Distribution")
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteServer,

        [Parameter(Mandatory = $true)]
        [string]$PackageID,

        [string[]]$DistributionPointGroupNames,
        [string[]]$DistributionPointNames
    )

    Write-LogEntry -Value "======== Distributing Content for $PackageID ========" -Severity 1

    # Distribute to DP Groups
    if ($DistributionPointGroupNames) {
        foreach ($DPGName in $DistributionPointGroupNames) {
            Write-LogEntry -Value "- Distributing $PackageID to DP Group: $DPGName" -Severity 1
            $Distributed = $false

            # --- CIM/DCOM ---
            if ($global:SCCMCimSession) {
                Write-LogEntry -Value "- Distributing via CIM/DCOM to '$DPGName'" -Severity 1
                try {
                    $Namespace = Get-SCCMNamespace
                    $EscDPG = ConvertTo-WqlEscapedString $DPGName
                    $DPGroupObj = Get-CimInstance -CimSession $global:SCCMCimSession -Namespace $Namespace `
                        -ClassName "SMS_DistributionPointGroup" -Filter "Name = '$EscDPG'" -ErrorAction Stop

                    if ($DPGroupObj) {
                        $InvokeResult = Invoke-CimMethod -CimSession $global:SCCMCimSession -InputObject $DPGroupObj `
                            -MethodName "AddPackages" `
                            -Arguments @{ PackageIDs = @($PackageID) } `
                            -ErrorAction Stop

                        if ($InvokeResult.ReturnValue -eq 0) {
                            Write-LogEntry -Value "- Distribution initiated via CIM/DCOM to '$DPGName'" -Severity 1
                            $Distributed = $true
                        }
                        else {
                            Write-LogEntry -Value "[Warning] - CIM AddPackages returned code $($InvokeResult.ReturnValue)" -Severity 2
                        }
                    }
                }
                catch {
                    Write-LogEntry -Value "[Warning] - CIM/DCOM distribution failed for '$DPGName': $($_.Exception.Message)" -Severity 2
                }
            }

            if (-not $Distributed) {
                Write-LogEntry -Value "[Warning] - Could not distribute $PackageID to '$DPGName' via either method." -Severity 2
            }
        }
    }

    # Distribute to individual DPs
    if ($DistributionPointNames) {
        foreach ($DPName in $DistributionPointNames) {
            Write-LogEntry -Value "- Distributing $PackageID to DP: $DPName" -Severity 1
            $Distributed = $false

            if ($global:SCCMCimSession) {
                try {
                    $Namespace = Get-SCCMNamespace
                    $NALPath = "[`"Display=\\$DPName\`"]MSWNET:[`"SMS_SITE=$($global:SiteCode)`"]\\$DPName\"
                    New-CimInstance -CimSession $global:SCCMCimSession -Namespace $Namespace `
                        -ClassName "SMS_DistributionPoint" `
                        -Property @{ PackageID = $PackageID; ServerNALPath = $NALPath; SiteCode = $global:SiteCode } `
                        -ErrorAction Stop | Out-Null
                    Write-LogEntry -Value "- Distribution initiated via CIM/DCOM to $DPName" -Severity 1
                    $Distributed = $true
                }
                catch {
                    Write-LogEntry -Value "[Warning] - CIM/DCOM distribution to $DPName failed: $($_.Exception.Message)" -Severity 2
                }
            }

            if (-not $Distributed) {
                Write-LogEntry -Value "[Warning] - Could not distribute $PackageID to $DPName via either method." -Severity 2
            }
        }
    }

    Write-LogEntry -Value "- Content distribution processing complete for $PackageID" -Severity 1
}

function Invoke-PackageRefresh {
    <#
    .SYNOPSIS
        Refreshes (redistributes) an existing package on its current distribution points.
    .DESCRIPTION
        Calls RefreshPkgSource on SMS_Package via CIM/DCOM.
    .PARAMETER SiteServer
        The FQDN of the ConfigMgr site server.
    .PARAMETER PackageID
        The PackageID of the package to refresh.
    .EXAMPLE
        Invoke-PackageRefresh -SiteServer "SCCM01" -PackageID "UN200001"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteServer,

        [Parameter(Mandatory = $true)]
        [string]$PackageID
    )

    Write-LogEntry -Value "- Refreshing package source for $PackageID..." -Severity 1
    $Refreshed = $false

    # CIM/DCOM
    if ($global:SCCMCimSession) {
        Write-LogEntry -Value "- Using CIM/DCOM for package refresh..." -Severity 1
        try {
            $Namespace = Get-SCCMNamespace
            $Package = Get-CimInstance -CimSession $global:SCCMCimSession -Namespace $Namespace `
                -ClassName "SMS_Package" -Filter "PackageID = '$PackageID'" -ErrorAction Stop

            if ($Package) {
                Invoke-CimMethod -InputObject $Package -MethodName "RefreshPkgSource" -CimSession $global:SCCMCimSession -ErrorAction Stop | Out-Null
                Write-LogEntry -Value "- Package $PackageID source refresh initiated (CIM/DCOM)." -Severity 1
                $Refreshed = $true
            }
        }
        catch {
            Write-LogEntry -Value "[Warning] - CIM/DCOM package refresh failed: $($_.Exception.Message)" -Severity 2
        }
    }

    if (-not $Refreshed) {
        Write-LogEntry -Value "[Warning] - Package refresh may not have completed for $PackageID." -Severity 2
    }
    return $Refreshed
}

function Get-DPOptions {
    <#
    .SYNOPSIS
        Queries ConfigMgr for available Distribution Points and DP Groups via CIM/DCOM.
    .DESCRIPTION
        Retrieves all Distribution Points and Distribution Point Groups from ConfigMgr
        using CIM/DCOM. No WinRM required.
    .PARAMETER SiteServer
        The FQDN of the ConfigMgr site server.
    .PARAMETER SiteCode
        The ConfigMgr site code (used for context logging only).
    .EXAMPLE
        $Options = Get-DPOptions -SiteServer "SCCM01" -SiteCode "UN2"
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteServer,
        [Parameter(Mandatory = $true)]
        [string]$SiteCode
    )
    
    Write-LogEntry -Value "======== Querying ConfigMgr Distribution Options (CIM/DCOM) ========" -Severity 1 -WriteOutput $false
    
    if (-not $global:SCCMCimSession) {
        Write-LogEntry -Value "[Error] - CIM session not available for DP query." -Severity 3
        return $null
    }

    $Namespace = Get-SCCMNamespace

    # Query DP Groups
    $DPGroups = Get-CimInstance -CimSession $global:SCCMCimSession -Namespace $Namespace `
        -ClassName "SMS_DistributionPointGroup" -ErrorAction SilentlyContinue
    $DPGNames = if ($DPGroups) { $DPGroups | Select-Object -ExpandProperty Name | Sort-Object } else { @() }

    # Query DPs (Resource List)
    $DPs = Get-CimInstance -CimSession $global:SCCMCimSession -Namespace $Namespace `
        -ClassName "SMS_SystemResourceList" -Filter "RoleName = 'SMS Distribution Point'" -ErrorAction SilentlyContinue
    $DPNames = if ($DPs) { $DPs | Select-Object -ExpandProperty ServerName -Unique | Sort-Object } else { @() }

    Write-LogEntry -Value "- Found $($DPGNames.Count) DP Groups and $($DPNames.Count) Distribution Points" -Severity 1 -WriteOutput $false

    return @{
        DistributionPoints      = $DPNames
        DistributionPointGroups = $DPGNames
    }
}

# // =================== LENOVO LOGIC ====================== //

function Find-LenovoModel {
    <#
    .SYNOPSIS
        Looks up a Lenovo model in the XML catalog.
    .DESCRIPTION
        Downloads the Lenovo SCCM catalog if not present and searches for the model.
        Supports partial/wildcard matching (e.g. "ThinkPad X1" matches "ThinkPad X1 Carbon Gen 9").
        Returns objects with Name and SKU (machine type) properties.
    .PARAMETER Model
        The model name to search for (e.g. "ThinkPad X1 Carbon Gen 9").
    .EXAMPLE
        Find-LenovoModel -Model "ThinkPad X1 Carbon Gen 9"
    .EXAMPLE
        Find-LenovoModel -Model "ThinkPad X1"  # Returns all X1 variants
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, HelpMessage = "Specify the Lenovo model name.")]
        [string]$Model
    )
    
    Get-DASettings | Out-Null

    $lenovoXmlPath = Join-Path $global:TempDirectory -ChildPath $global:LenovoXMLFile
    $lenovoXmlSourceExt = [System.IO.Path]::GetExtension($LenovoXMLSource)
    $lenovoXmlSourceIsCab = $lenovoXmlSourceExt -and ($lenovoXmlSourceExt -ieq ".cab")

    $refreshNeeded = $false
    if (Test-Path -Path $lenovoXmlPath) {
        try {
            $AgeDays = (New-TimeSpan -Start (Get-Item $lenovoXmlPath).LastWriteTime -End (Get-Date)).TotalDays
            if ($AgeDays -ge 7) { $refreshNeeded = $true }
        }
        catch {
            $refreshNeeded = $true
        }
    }

    if (-not (Test-Path -Path $lenovoXmlPath) -or $refreshNeeded) {
        if ($refreshNeeded) {
            $global:LenovoModelXML = $null
            $global:LenovoModelDrivers = $null
        }
        Write-LogEntry -Value "======== Downloading Lenovo XML Catalog ========" -Severity 1
        try {
            if ($global:ProxySettingsSet) {
                Start-BitsTransfer -Source $LenovoXMLSource -Destination (Join-Path $global:TempDirectory -ChildPath $global:LenovoXMLCabFile) @global:BitsProxyOptions
            }
            else {
                Start-BitsTransfer -Source $LenovoXMLSource -Destination (Join-Path $global:TempDirectory -ChildPath $global:LenovoXMLCabFile) @global:BitsOptions
            }
            if ($lenovoXmlSourceIsCab) {
                # Expand using expand.exe (Win native) when source is a CAB
                & expand.exe "$global:TempDirectory\$global:LenovoXMLCabFile" "$global:TempDirectory" -F:* | Out-Null
                # If source was CAB, pick the newest XML in temp as the catalog
                if (-not (Test-Path -Path $lenovoXmlPath)) {
                    $latestXml = Get-ChildItem -Path $global:TempDirectory -Filter *.xml | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if ($latestXml) {
                        $lenovoXmlPath = $latestXml.FullName
                    }
                }
            }
            if (Test-Path -Path $lenovoXmlPath) {
                try { (Get-Item -Path $lenovoXmlPath).LastWriteTime = Get-Date } catch { }
            }
        }
        catch {
            Write-LogEntry -Value "[Error] - Failed to download/expand Lenovo XML: $($_.Exception.Message)" -Severity 3
            return $null
        }
    }

    if (Test-Path -Path $lenovoXmlPath) {
        if ($null -eq $global:LenovoModelXML) {
            Write-LogEntry -Value "- Reading Lenovo product XML file" -Severity 1
            [xml]$global:LenovoModelXML = Get-Content -Path $lenovoXmlPath -Raw
            $global:LenovoModelDrivers = $global:LenovoModelXML.ModelList.Model
        }
        
        # Search for SKU/Model in Lenovo XML (supports wildcards)
        if ([string]::IsNullOrWhiteSpace($Model)) {
            $Model = Read-Host "Enter Lenovo model search (e.g. ThinkPad X1)"
            if (-not $Model) {
                Write-LogEntry -Value "[Warning] - No model search provided. Exiting." -Severity 2
                return $null
            }
        }

        $modelPattern = if ($Model -match "[\\*\\?]") { $Model } else { "*$Model*" }
        $LenovoModelInfo = $global:LenovoModelDrivers | Where-Object {
            ($_.Name -like $modelPattern) -or
            ($_.Types.Type | Where-Object { $_ -like $modelPattern })
        }

        if ($LenovoModelInfo) {
            Write-LogEntry -Value "- Found $($LenovoModelInfo.Count) matching model(s)" -Severity 1
            # Return expanded rows per SCCM pack with Name, SKU, OS, FileName
            $Results = @()
            foreach ($item in $LenovoModelInfo) {
                $sku = if ($item.Types -and $item.Types.Type) { ($item.Types.Type -join ', ') } else { $null }
                $modelName = $item.name
                if ($item.SCCM) {
                    foreach ($s in $item.SCCM) {
                        $Results += [pscustomobject]@{
                            Name     = $modelName
                            SKU      = $sku
                            OS       = "$($s.os) $($s.version)"
                            FileName = ($s.'#text' | Split-Path -Leaf)
                        }
                    }
                }
                else {
                    $Results += [pscustomobject]@{
                        Name     = $modelName
                        SKU      = $sku
                        OS       = ""
                        FileName = ""
                    }
                }
            }
            return $Results | Sort-Object Name, OS
        }
        else {
            # Suppress noisy warnings when we're using a wildcard (e.g. "*" to just force-load the cache).
            # The catalog globals are still populated even if the product-name filter returns no matches.
            if (-not [string]::IsNullOrWhiteSpace($Model) -and ($Model -notmatch '^[\\*\\?]+$')) {
                Write-LogEntry -Value "[Warning] - No models found matching '$Model'" -Severity 2
            }
            return $null
        }
    }
}

function Find-DellModel {
    <#
    .SYNOPSIS
        Looks up a Dell model in the XML catalog.
    .DESCRIPTION
        Downloads the Dell DriverPack catalog if not present and searches for the model.
        Supports partial/wildcard matching (e.g. "Latitude 7" matches "Latitude 7420").
        Returns objects with Name and SKU (system ID) properties.
    .PARAMETER Model
        The model name to search for (e.g. "Latitude 7420").
    .EXAMPLE
        Find-DellModel -Model "Latitude 7420"
    .EXAMPLE
        Find-DellModel -Model "Latitude"  # Returns all Latitude variants
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, HelpMessage = "Specify the Dell model name.")]
        [string]$Model
    )

    Get-DASettings | Out-Null

    if ([string]::IsNullOrWhiteSpace($Model)) {
        $Model = Read-Host "Enter Dell model search (e.g. Latitude 7420)"
        if (-not $Model) {
            Write-LogEntry -Value "[Warning] - No model search provided. Exiting." -Severity 2
            return $null
        }
    }

    if (-not $DellXMLCabSource) {
        Write-LogEntry -Value "[Error] - Dell XML source not found in OEMLinks.xml." -Severity 3
        return $null
    }

    $dellXmlPath = if ($global:DellXMLFile) { Join-Path $global:TempDirectory -ChildPath $global:DellXMLFile } else { "" }
    if (-not $dellXmlPath) {
        Write-LogEntry -Value "[Error] - Dell XML filename not resolved." -Severity 3
        return $null
    }

    $refreshNeeded = $false
    if (Test-Path -Path $dellXmlPath) {
        try {
            $AgeDays = (New-TimeSpan -Start (Get-Item $dellXmlPath).LastWriteTime -End (Get-Date)).TotalDays
            if ($AgeDays -ge 7) { $refreshNeeded = $true }
        }
        catch {
            $refreshNeeded = $true
        }
    }

    if ((-not (Test-Path -Path $dellXmlPath)) -and (Test-Path -Path (Join-Path $global:TempDirectory $global:DellXMLCabFile))) {
        $DellXmlDest = Join-Path $global:TempDirectory -ChildPath $global:DellXMLFile
        try {
            & expand.exe -F:$global:DellXMLFile (Join-Path $global:TempDirectory $global:DellXMLCabFile) $DellXmlDest | Out-Null
            if (Test-Path -Path $DellXmlDest) {
                $dellXmlPath = $DellXmlDest
            }
        }
        catch {
            Write-LogEntry -Value "[Warning] - Failed to expand existing Dell CAB: $($_.Exception.Message)" -Severity 2
        }
    }

    if (-not (Test-Path -Path $dellXmlPath) -or $refreshNeeded) {
        if ($refreshNeeded) {
            $global:DellModelXML = $null
            $global:DellModelDrivers = $null
        }
        Write-LogEntry -Value "======== Downloading Dell DriverPack Catalog ========" -Severity 1
        try {
            if ($global:ProxySettingsSet) {
                Start-BitsTransfer -Source $DellXMLCabSource -Destination (Join-Path $global:TempDirectory -ChildPath $global:DellXMLCabFile) @global:BitsProxyOptions
            }
            else {
                Start-BitsTransfer -Source $DellXMLCabSource -Destination (Join-Path $global:TempDirectory -ChildPath $global:DellXMLCabFile) @global:BitsOptions
            }

            $DellXmlDest = Join-Path $global:TempDirectory -ChildPath $global:DellXMLFile
            & expand.exe -F:$global:DellXMLFile "$global:TempDirectory\$global:DellXMLCabFile" "$DellXmlDest" | Out-Null
            if (Test-Path -Path $DellXmlDest) { $dellXmlPath = $DellXmlDest }

            if (-not (Test-Path -Path $dellXmlPath)) {
                $latestXml = Get-ChildItem -Path $global:TempDirectory -Filter "DriverPackCatalog*.xml" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($latestXml) {
                    $dellXmlPath = $latestXml.FullName
                }
            }

            if (Test-Path -Path $dellXmlPath) {
                try { (Get-Item -Path $dellXmlPath).LastWriteTime = Get-Date } catch { }
            }
            else {
                Write-LogEntry -Value "[Error] - Dell XML was not created from CAB. Check CAB contents." -Severity 3
                return $null
            }
        }
        catch {
            Write-LogEntry -Value "[Error] - Failed to download/expand Dell XML: $($_.Exception.Message)" -Severity 3
            return $null
        }
    }

    if (Test-Path -Path $dellXmlPath) {
        if ($null -eq $global:DellModelXML) {
            Write-LogEntry -Value "- Reading Dell product XML file" -Severity 1
            [xml]$global:DellModelXML = Get-Content -Path $dellXmlPath -Raw
            $global:DellModelDrivers = $global:DellModelXML.driverpackmanifest.driverpackage
        }

        $modelPattern = if ($Model -match "[\\*\\?]") { $Model } else { "*$Model*" }
        $Results = foreach ($pkg in $global:DellModelDrivers) {
            foreach ($m in $pkg.SupportedSystems.Brand.Model) {
                if (($m.name -like $modelPattern) -or ($m.systemID -like $modelPattern)) {
                    [pscustomobject]@{
                        Name     = $m.name
                        SKU      = $m.systemID
                        OS       = if ($pkg.SupportedOperatingSystems) { ($pkg.SupportedOperatingSystems.OperatingSystem | Select-Object -First 1).osCode } else { "" }
                        FileName = ($pkg.path | Split-Path -Leaf)
                    }
                }
            }
        }
        $Results = $Results | Sort-Object -Property Name, SKU, OS -Unique

        if ($Results -and $Results.Count -gt 0) {
            Write-LogEntry -Value "- Found $($Results.Count) matching model(s)" -Severity 1
            return $Results
        }
        else {
            # Suppress noisy warnings when we're using a wildcard (e.g. "*" to just force-load the cache).
            # The catalog globals are still populated even if the product-name filter returns no matches.
            if (-not [string]::IsNullOrWhiteSpace($Model) -and ($Model -notmatch '^[\\*\\?]+$')) {
                Write-LogEntry -Value "[Warning] - No models found matching '$Model'" -Severity 2
            }
            return $null
        }
    }
}

function Find-HPModel {
    <#
    .SYNOPSIS
        Looks up an HP model in the XML catalog.
    .DESCRIPTION
        Downloads the HP Client Driver Pack catalog if not present and searches for the model.
        Supports partial/wildcard matching (e.g. "EliteBook 8" matches "EliteBook 840 G7").
        Returns objects with Name and SKU (system ID) properties.
    .PARAMETER Model
        The model name to search for (e.g. "EliteBook 840 G7").
    .EXAMPLE
        Find-HPModel -Model "EliteBook 840 G7"
    .EXAMPLE
        Find-HPModel -Model "EliteBook"  # Returns all EliteBook variants
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, HelpMessage = "Specify the HP model name.")]
        [string]$Model
    )

    Get-DASettings | Out-Null

    if ([string]::IsNullOrWhiteSpace($Model)) {
        $Model = Read-Host "Enter HP model search (e.g. EliteBook 840)"
        if (-not $Model) {
            Write-LogEntry -Value "[Warning] - No model search provided. Exiting." -Severity 2
            return $null
        }
    }

    if (-not $HPXMLCabSource) {
        Write-LogEntry -Value "[Error] - HP XML source not found in OEMLinks.xml." -Severity 3
        return $null
    }

    $hpXmlPath = if ($global:HPXMLFile) { Join-Path $global:TempDirectory -ChildPath $global:HPXMLFile } else { "" }
    if (-not $hpXmlPath) {
        Write-LogEntry -Value "[Error] - HP XML filename not resolved." -Severity 3
        return $null
    }

    $refreshNeeded = $false
    if (Test-Path -Path $hpXmlPath) {
        try {
            $AgeDays = (New-TimeSpan -Start (Get-Item $hpXmlPath).LastWriteTime -End (Get-Date)).TotalDays
            if ($AgeDays -ge 7) { $refreshNeeded = $true }
        }
        catch {
            $refreshNeeded = $true
        }
    }

    if ((-not (Test-Path -Path $hpXmlPath)) -and (Test-Path -Path (Join-Path $global:TempDirectory $global:HPXMLCabFile))) {
        $HpXmlDest = Join-Path $global:TempDirectory -ChildPath $global:HPXMLFile
        try {
            & expand.exe -F:$global:HPXMLFile (Join-Path $global:TempDirectory $global:HPXMLCabFile) $HpXmlDest | Out-Null
            if (Test-Path -Path $HpXmlDest) {
                $hpXmlPath = $HpXmlDest
            }
        }
        catch {
            Write-LogEntry -Value "[Warning] - Failed to expand existing HP CAB: $($_.Exception.Message)" -Severity 2
        }
    }

    if (-not (Test-Path -Path $hpXmlPath) -or $refreshNeeded) {
        if ($refreshNeeded) {
            $global:HPModelXML = $null
            $global:HPModelDrivers = $null
            $global:HPSoftPaqList = $null
        }
        Write-LogEntry -Value "======== Downloading HP Driver Pack Catalog ========" -Severity 1
        try {
            if ($global:ProxySettingsSet) {
                Start-BitsTransfer -Source $HPXMLCabSource -Destination (Join-Path $global:TempDirectory -ChildPath $global:HPXMLCabFile) @global:BitsProxyOptions
            }
            else {
                Start-BitsTransfer -Source $HPXMLCabSource -Destination (Join-Path $global:TempDirectory -ChildPath $global:HPXMLCabFile) @global:BitsOptions
            }

            $HpXmlDest = Join-Path $global:TempDirectory -ChildPath $global:HPXMLFile
            & expand.exe -F:$global:HPXMLFile "$global:TempDirectory\$global:HPXMLCabFile" "$HpXmlDest" | Out-Null
            if (Test-Path -Path $HpXmlDest) { $hpXmlPath = $HpXmlDest }

            if (-not (Test-Path -Path $hpXmlPath)) {
                $latestXml = Get-ChildItem -Path $global:TempDirectory -Filter "HPClientDriverPackCatalog*.xml" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($latestXml) {
                    $hpXmlPath = $latestXml.FullName
                }
            }

            if (Test-Path -Path $hpXmlPath) {
                try { (Get-Item -Path $hpXmlPath).LastWriteTime = Get-Date } catch { }
            }
            else {
                Write-LogEntry -Value "[Error] - HP XML was not created from CAB. Check CAB contents." -Severity 3
                return $null
            }
        }
        catch {
            Write-LogEntry -Value "[Error] - Failed to download/expand HP XML: $($_.Exception.Message)" -Severity 3
            return $null
        }
    }

    if (Test-Path -Path $hpXmlPath) {
        $xmlLastWrite = (Get-Item $hpXmlPath).LastWriteTime
        if ($null -eq $global:HPModelXML -or $global:HPModelXMLLoadTime -lt $xmlLastWrite) {
            Write-LogEntry -Value "- Reading HP product XML file" -Severity 1
            [xml]$global:HPModelXML = Get-Content -Path $hpXmlPath -Raw
            $global:HPModelDrivers = $global:HPModelXML.NewDataSet.HPClientDriverPackCatalog.ProductOSDriverPackList.ProductOSDriverPack
            $global:HPSoftPaqList = $global:HPModelXML.NewDataSet.HPClientDriverPackCatalog.SoftPaqList.SoftPaq
            $global:HPModelXMLLoadTime = $xmlLastWrite
        }
        $modelPattern = if ($Model -match "[\\*\\?]") { $Model } else { "*$Model*" }
        $Results = foreach ($pkg in $global:HPModelDrivers) {
            if (($pkg.SystemName -like $modelPattern) -or ($pkg.SystemId -like $modelPattern)) {
                [pscustomobject]@{
                    Name     = $pkg.SystemName
                    SKU      = $pkg.SystemId
                    OS       = $pkg.OSName
                    FileName = "SoftPaq $($pkg.SoftPaqId)"
                }
            }
        }
        $Results = $Results | Sort-Object -Property Name, SKU, OS -Unique

        if ($Results -and $Results.Count -gt 0) {
            Write-LogEntry -Value "- Found $($Results.Count) matching model(s)" -Severity 1
            return $Results
        }
        else {
            # Suppress noisy warnings when we're using a wildcard (e.g. "*" to just force-load the cache).
            # The catalog globals are still populated even if the product-name filter returns no matches.
            if (-not [string]::IsNullOrWhiteSpace($Model) -and ($Model -notmatch '^[\\*\\?]+$')) {
                Write-LogEntry -Value "[Warning] - No models found matching '$Model'" -Severity 2
            }
            return $null
        }
    }
}

function Invoke-BitsJobMonitor {
    param (
        [Parameter(Mandatory = $true)]
        [string]$BitsJobName,
        [Parameter(Mandatory = $true)]
        [string]$DownloadSource,
        [System.Diagnostics.Stopwatch]$Timer
    )
    
    try {
        $BitsJob = Get-BitsTransfer | Where-Object { $_.DisplayName -eq $BitsJobName } | Select-Object -First 1
        
        if (-not $BitsJob) {
            return
        }

        if ($BitsJob.JobState -eq "Connecting") {
            Write-LogEntry -Value "- BitsTransfer: Connecting to $DownloadSource..." -Severity 1
            return
        }
        
        if ($BitsJob.JobState -eq "Transferring") {
            if ($BitsJob.BytesTotal -gt 0) {
                $PercentComplete = [int](($BitsJob.BytesTransferred * 100) / $BitsJob.BytesTotal)
                $DownloadedMB = [Math]::Round($BitsJob.BytesTransferred / 1MB, 2)
                $TotalMB = [Math]::Round($BitsJob.BytesTotal / 1MB, 2)

                $speedInfo = ""
                if ($Timer -and $Timer.Elapsed.TotalSeconds -gt 0) {
                    $SpeedMBps = [Math]::Round(($BitsJob.BytesTransferred / 1MB) / $Timer.Elapsed.TotalSeconds, 1)
                    $RemainingBytes = $BitsJob.BytesTotal - $BitsJob.BytesTransferred
                    if ($SpeedMBps -gt 0) {
                        $ETAsec = ($RemainingBytes / 1MB) / $SpeedMBps
                        $ETA = [TimeSpan]::FromSeconds($ETAsec).ToString("m\:ss")
                        $speedInfo = " | $SpeedMBps MB/s | ETA: $ETA"
                    }
                    else {
                        $speedInfo = " | $SpeedMBps MB/s"
                    }
                }
                Write-LogEntry -Value "- BitsTransfer: Downloaded $DownloadedMB MB of $TotalMB MB ($PercentComplete%)$speedInfo" -Severity 1
            }
            else {
                Write-LogEntry -Value "- BitsTransfer: Transferring (initializing byte count...)" -Severity 1
            }
            return
        }

        if ($BitsJob.JobState -match "TransientError") {
            Write-LogEntry -Value "- [Warning] - BITS reporting transient error. Attempting to resume..." -Severity 2
            $BitsJob | Resume-BitsTransfer -Asynchronous | Out-Null
            return
        }

        if ($BitsJob.JobState -eq "Error") {
            $err = $BitsJob.Error
            $errMsg = if ($err) { "0x$($err.Code.ToString('X8')): $($err.Description)" } else { "Unknown BITS error" }
            Write-LogEntry -Value "- [Error] - BITS job failed: $errMsg" -Severity 3
        }
    }
    catch {
        if ($_.Exception.Message -notmatch "Cannot find") {
            Write-LogEntry -Value "[Warning] - Issue monitoring BITS job: $($_.Exception.Message)" -Severity 2
        }
    }
}


function Invoke-ContentDownload {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DownloadURL,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,
        [Parameter(Mandatory = $true)]
        [string]$ModelName
    )
    
    function Test-DownloadFile {
        param([string]$Path)
        if (-not (Test-Path -Path $Path)) { return $false }
        try {
            $item = Get-Item -Path $Path -ErrorAction Stop
            return ($item.Length -gt 0)
        }
        catch {
            return $false
        }
    }

    # Use a descriptive yet unique job name
    $Cleaned = ($ModelName -replace '[^a-zA-Z0-9-]', '')
    $LimitLength = [Math]::Min($Cleaned.Length, 20)
    $CleanModel = $Cleaned.Substring(0, $LimitLength)
    $JobName = "DA-$CleanModel-$([guid]::NewGuid().ToString().Substring(0,8))"
    
    Write-LogEntry -Value "- Attempting to download content for $ModelName" -Severity 1
    Write-LogEntry -Value "- Source: $DownloadURL" -Severity 1
    Write-LogEntry -Value "- Destination: $DestinationPath" -Severity 1

    $DestinationDir = Split-Path -Parent $DestinationPath
    if (-not (Test-Path -Path $DestinationDir)) {
        New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
    }

    # Proactively clean up any existing stalled BITS jobs for this model
    try {
        $Stalled = Get-BitsTransfer | Where-Object { $_.DisplayName -like "DA-$CleanModel*" -or $_.DisplayName -like "*$ModelName-Download*" }
        foreach ($s in $Stalled) { $s | Remove-BitsTransfer -ErrorAction SilentlyContinue }
    }
    catch {}

    if (Test-DownloadFile -Path $DestinationPath) {
        Write-LogEntry -Value "- Download skipped: file already exists at $DestinationPath" -Severity 1
        return $true
    }
    
    # Ensure any partially downloaded file/tmp file is gone to prevent 0x80070002 move errors
    if (Test-Path -Path $DestinationPath) { try { Remove-Item -Path $DestinationPath -Force -ErrorAction SilentlyContinue } catch {} }

    try {
        $StartOptions = if ($global:ProxySettingsSet) { $global:BitsProxyOptions } else { $global:BitsOptions }
        
        # Start the transfer
        Write-LogEntry -Value "- Starting BITS transfer job: $JobName" -Severity 1
        $BitsJob = Start-BitsTransfer -DisplayName $JobName -Source $DownloadURL -Destination $DestinationPath -Asynchronous @StartOptions
        
        $Timer = [System.Diagnostics.Stopwatch]::StartNew()
        $LastLogTime = [datetime]::MinValue

        while ($BitsJob -and ($BitsJob.JobState -notmatch "Transferred|Suspended|Error")) {
            # Log progress every 30 seconds
            if ((Get-Date) -gt $LastLogTime.AddSeconds(30)) {
                Invoke-BitsJobMonitor -BitsJobName $JobName -DownloadSource $DownloadURL -Timer $Timer
                $LastLogTime = Get-Date
            }
            Start-Sleep -Seconds 2
            $BitsJob = Get-BitsTransfer | Where-Object { $_.DisplayName -eq $JobName } | Select-Object -First 1
        }
        
        if (-not $BitsJob) {
            if (Test-DownloadFile -Path $DestinationPath) { return $true }
            Write-LogEntry -Value "[Error] - Download job vanished and file not found." -Severity 3
            return $false
        }

        if ($BitsJob.JobState -eq "Transferred") {
            Write-LogEntry -Value "- Completing BITS transfer..." -Severity 1
            Complete-BitsTransfer -BitsJob $BitsJob
            if (Test-DownloadFile -Path $DestinationPath) {
                Write-LogEntry -Value "- Download successful: $DestinationPath" -Severity 1
                return $true
            }
        }
        
        # If we got here, it failed or is suspended
        $State = $BitsJob.JobState
        $err = $BitsJob.Error
        $BitsError = if ($err -and $err.Code) { "0x$($err.Code.ToString('X8')): $($err.Description)" } elseif ($err) { "$($err | Out-String)" } else { "None (connection or SSL issue likely)" }
        Write-LogEntry -Value "[Error] - BITS download failed. State: $State | BITS Error: $BitsError" -Severity 3
        Write-LogEntry -Value "- Bytes transferred: $($BitsJob.BytesTransferred) / $($BitsJob.BytesTotal)" -Severity 2

        $BitsJob | Remove-BitsTransfer -ErrorAction SilentlyContinue

        # Fallback: try Invoke-WebRequest (better redirect handling than BITS)
        Write-LogEntry -Value "- Attempting fallback download via Invoke-WebRequest..." -Severity 1
        try {
            $ProgressPreference = 'SilentlyContinue'
            $iwrParams = @{ Uri = $DownloadURL; OutFile = $DestinationPath; UseBasicParsing = $true; ErrorAction = 'Stop' }
            if ($global:ProxySettingsSet) { $iwrParams.Proxy = [System.Net.WebRequest]::DefaultWebProxy.ProxyAddress }
            Invoke-WebRequest @iwrParams
            $ProgressPreference = 'Continue'
            if (Test-DownloadFile -Path $DestinationPath) {
                Write-LogEntry -Value "- Fallback download successful: $DestinationPath" -Severity 1
                return $true
            }
            else {
                Write-LogEntry -Value "[Error] - Fallback download completed but file verification failed." -Severity 3
            }
        }
        catch {
            $statusCode = ""
            if ($_.Exception.Response) {
                $statusCode = "HTTP $([int]$_.Exception.Response.StatusCode) - $($_.Exception.Response.StatusCode)"
            }
            Write-LogEntry -Value "[Error] - Fallback download failed: $($_.Exception.Message)" -Severity 3
            if ($statusCode) { Write-LogEntry -Value "- HTTP Status: $statusCode" -Severity 3 }
            Write-LogEntry -Value "- The download URL may be expired or unavailable. Try downloading manually: $DownloadURL" -Severity 2
        }
        return $false
    }
    catch {
        Write-LogEntry -Value "[Error] - Exception during download: $($_.Exception.Message)" -Severity 3
        return $false
    }
}

function Invoke-ContentExtraction {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SourceFile,
        [Parameter(Mandatory = $true)]
        [string]$DestinationFolder,
        [string]$Make = "Lenovo"
    )
    
    Write-LogEntry -Value "======== Starting Content Extraction ========" -Severity 1
    Write-LogEntry -Value "- Source: $SourceFile" -Severity 1
    Write-LogEntry -Value "- Destination: $DestinationFolder" -Severity 1
    
    if (-not (Test-Path -Path $SourceFile)) {
        Write-LogEntry -Value "[Error] - Source file not found: $SourceFile" -Severity 3
        return $false
    }

    if (-not (Test-Path -Path $DestinationFolder)) {
        New-Item -ItemType Directory -Path $DestinationFolder -Force | Out-Null
    }

    function Test-ExtractedContent {
        param([string]$Path)
        if (-not (Test-Path -Path $Path)) { return $false }
        try {
            return ((Get-ChildItem -Path $Path -Force -ErrorAction Stop | Measure-Object).Count -gt 0)
        }
        catch {
            return $false
        }
    }

    try {
        Unblock-File -Path $SourceFile
        
        if ($Make -eq "Lenovo") {
            # Lenovo uses .exe with /VERYSILENT /DIR=...
            $SilentSwitches = "/VERYSILENT /DIR=`"$DestinationFolder`" /EXTRACT=`"YES`""
            Write-LogEntry -Value "- Using Lenovo silent switches: $SilentSwitches" -Severity 1

            # Use RunAsInvoker to avoid UAC prompts during extraction
            $OriginalCompat = $env:__COMPAT_LAYER
            try {
                $env:__COMPAT_LAYER = "RunAsInvoker"
                $Process = Start-Process -FilePath $SourceFile -ArgumentList $SilentSwitches -PassThru -Wait -NoNewWindow
            }
            finally {
                if ($null -eq $OriginalCompat) {
                    Remove-Item Env:\__COMPAT_LAYER -ErrorAction SilentlyContinue
                }
                else {
                    $env:__COMPAT_LAYER = $OriginalCompat
                }
            }
            
            if ($Process.ExitCode -eq 0) {
                Write-LogEntry -Value "- Extraction completed successfully" -Severity 1
                return $true
            }
            else {
                Write-LogEntry -Value "[Error] - Extraction failed with exit code $($Process.ExitCode)" -Severity 3
                return $false
            }
        }
        elseif ($Make -eq "Dell") {
            if ($SourceFile -match "\\.cab$") {
                Write-LogEntry -Value "- Dell CAB detected. Expanding to $DestinationFolder" -Severity 1
                & expand.exe "$SourceFile" "$DestinationFolder" -F:* | Out-Null
                Write-LogEntry -Value "- Extraction completed successfully" -Severity 1
                return $true
            }

            # Dell EXE fallback
            $SilentSwitches = "/s /e=`"$DestinationFolder`""
            Write-LogEntry -Value "- Using Dell silent switches: $SilentSwitches" -Severity 1
            $Process = Start-Process -FilePath $SourceFile -ArgumentList $SilentSwitches -PassThru -Wait -NoNewWindow
            if ($Process.ExitCode -eq 0) {
                Write-LogEntry -Value "- Extraction completed successfully" -Severity 1
                return $true
            }
            else {
                Write-LogEntry -Value "[Error] - Extraction failed with exit code $($Process.ExitCode)" -Severity 3
                return $false
            }
        }
        elseif ($Make -eq "HP") {
            # HP SoftPaq uses /s /e /f
            $SilentSwitches = "/s /e /f `"$DestinationFolder`""
            Write-LogEntry -Value "- Using HP silent switches: $SilentSwitches" -Severity 1

            $OriginalCompat = $env:__COMPAT_LAYER
            try {
                $env:__COMPAT_LAYER = "RunAsInvoker"
                $Process = Start-Process -FilePath $SourceFile -ArgumentList $SilentSwitches -PassThru -Wait -NoNewWindow
            }
            finally {
                if ($null -eq $OriginalCompat) {
                    Remove-Item Env:\__COMPAT_LAYER -ErrorAction SilentlyContinue
                }
                else {
                    $env:__COMPAT_LAYER = $OriginalCompat
                }
            }

            if (Test-ExtractedContent -Path $DestinationFolder) {
                if ($Process.ExitCode -eq 0 -or $Process.ExitCode -eq 1168) {
                    Write-LogEntry -Value "- Extraction completed successfully (ExitCode: $($Process.ExitCode))" -Severity 1
                }
                else {
                    Write-LogEntry -Value "[Warning] - HP extraction returned exit code $($Process.ExitCode) but content was extracted. Continuing." -Severity 2
                }
                return $true
            }

            Write-LogEntry -Value "[Warning] - HP extraction failed (exit code $($Process.ExitCode)). Retrying with elevation..." -Severity 2

            $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $IsAdmin) {
                Write-LogEntry -Value "[Error] - HP extraction requires elevation. Please run PowerShell as Administrator or run from SCCM (SYSTEM)." -Severity 3
                return $false
            }

            $ElevatedProcess = Start-Process -FilePath $SourceFile -ArgumentList $SilentSwitches -PassThru -Wait -NoNewWindow -Verb RunAs
            if ($ElevatedProcess.ExitCode -eq 0 -and (Test-ExtractedContent -Path $DestinationFolder)) {
                Write-LogEntry -Value "- Extraction completed successfully (elevated)" -Severity 1
                return $true
            }

            $AltDestination = ($DestinationFolder -replace '\s+', '')
            if ($AltDestination -ne $DestinationFolder) {
                Write-LogEntry -Value "[Warning] - Retrying HP extraction with no-space path (elevated): $AltDestination" -Severity 2
                if (-not (Test-Path -Path $AltDestination)) {
                    New-Item -ItemType Directory -Path $AltDestination -Force | Out-Null
                }

                $AltSwitches = "/s /e /f `"$AltDestination`""
                $AltProcess = Start-Process -FilePath $SourceFile -ArgumentList $AltSwitches -PassThru -Wait -NoNewWindow -Verb RunAs
                if ($AltProcess.ExitCode -eq 0 -and (Test-ExtractedContent -Path $AltDestination)) {
                    if (-not (Test-Path -Path $DestinationFolder)) {
                        New-Item -ItemType Directory -Path $DestinationFolder -Force | Out-Null
                    }
                    Get-ChildItem -Path $AltDestination -Force | Move-Item -Destination $DestinationFolder -Force
                    Remove-Item -Path $AltDestination -Recurse -Force -ErrorAction SilentlyContinue
                    Write-LogEntry -Value "- Extraction completed successfully (no-space path fallback, elevated)" -Severity 1
                    return $true
                }
            }

            Write-LogEntry -Value "[Error] - Extraction failed with exit code $($Process.ExitCode)" -Severity 3
            return $false
        }
        elseif ($Make -eq "Microsoft" -or $SourceFile -match "\\.msi$") {
            # Microsoft Surface drivers use MSI packages - extract using msiexec /a (administrative install)
            $SilentSwitches = "/a `"$SourceFile`" /qn TARGETDIR=`"$DestinationFolder`""
            Write-LogEntry -Value "- Using Microsoft MSI extraction: msiexec $SilentSwitches" -Severity 1

            $Process = Start-Process -FilePath "msiexec.exe" -ArgumentList $SilentSwitches -PassThru -Wait -NoNewWindow
            if ($Process.ExitCode -eq 0) {
                Write-LogEntry -Value "- MSI extraction completed successfully" -Severity 1
                return $true
            }
            else {
                Write-LogEntry -Value "[Error] - MSI extraction failed with exit code $($Process.ExitCode)" -Severity 3
                return $false
            }
        }
        # Add other manufacturer logic here when needed
    }
    catch {
        Write-LogEntry -Value "[Error] - Exception during extraction: $($_.Exception.Message)" -Severity 3
        return $false
    }
}

function New-DriverPackage {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Make,
        [Parameter(Mandatory = $true)]
        [string]$DriverExtractDest,
        [Parameter(Mandatory = $true)]
        [string]$Architecture,
        [Parameter(Mandatory = $true)]
        [string]$DriverPackageDest,
        [string]$PackageRootName,
        [boolean]$PackageCompression = $false,
        [string]$CompressionType = "Zip",
        [ValidateSet("Raw", "Zip", "WIM")]
        [string]$PackageFormat = "Raw"
    )

    $StagingRoot = $null
    try {
        $SourceRoot = $DriverExtractDest
        $ArchFolderUsed = $null
        if ($Make -eq "Dell") {
            $ArchFolder = Get-ChildItem -Path $DriverExtractDest -Recurse -Directory | Where-Object { $_.Name -eq "$Architecture" } | Select-Object -First 1
            if ($ArchFolder) {
                $SourceRoot = $ArchFolder.FullName
                $ArchFolderUsed = $ArchFolder.FullName
            }
        }
        if ($ArchFolderUsed) {
            Write-LogEntry -Value "- DriverPackage: Using architecture folder for $Make packaging: $ArchFolderUsed" -Severity 1
        }
        
        # Wrapping logic: ensures zip/wim/raw has a single root folder named after the package (e.g. Windows10-A20)
        $PackageRootName = if ($PackageRootName) { ($PackageRootName -replace '[<>:"/\\|?*]', '').Trim() } else { "Drivers" }
        $StagingRoot = Join-Path $global:TempDirectory ("DA_Stage_" + [System.IO.Path]::GetRandomFileName())
        $FinalStagingFolder = Join-Path $StagingRoot $PackageRootName
        
        Write-LogEntry -Value "- DriverPackage: Creating staging folder with root $PackageRootName" -Severity 1
        New-Item -ItemType Directory -Path $FinalStagingFolder -Force | Out-Null
        
        # Copy content into the wrapper folder
        Get-ChildItem -Path $SourceRoot | Copy-Item -Destination $FinalStagingFolder -Recurse -Force
        
        $PackageSource = if ($PackageFormat -eq "Zip") { $FinalStagingFolder } else { $StagingRoot }

        if ($PackageFormat -eq "Raw") {
            $PackageCompression = $false
        }
        elseif ($PackageFormat -eq "Zip") {
            $PackageCompression = $true
            $CompressionType = "Zip"
        }
        elseif ($PackageFormat -eq "WIM") {
            $PackageCompression = $true
            $CompressionType = "WIM"
        }

        if ($PackageCompression) {
            Write-LogEntry -Value "- DriverPackage: Package compression is enabled (Type: $CompressionType)" -Severity 1
            
            if ($CompressionType -eq "7-Zip") {
                if (-not (Test-Path -Path $(Join-Path -Path $global:7ZIPLocation -ChildPath "7z.exe"))) {
                    Write-LogEntry -Value "[Error] - 7-Zip executable not found at $($global:7ZIPLocation)" -Severity 3
                    return $false
                }

                Write-LogEntry -Value "- DriverPackage: Compressing files in $PackageSource" -Severity 1
                $ZipExe = Join-Path -Path $global:7ZIPLocation -ChildPath "7z.exe"
                $ZipArgs = "a -sfx7z.sfx DriverPackage.exe -r `"$PackageSource`""
                
                Set-Location -Path $PackageSource
                $Process = Start-Process $ZipExe -ArgumentList $ZipArgs -NoNewWindow -Wait -PassThru
                Set-Location -Path $global:TempDirectory

                if ($Process.ExitCode -eq 0 -and (Test-Path -Path (Join-Path $PackageSource "DriverPackage.exe"))) {
                    Write-LogEntry -Value "- DriverPackage: Self-extracting 7-Zip driver package created" -Severity 1
                    if (-not (Test-Path -Path $DriverPackageDest)) { New-Item -ItemType Directory -Path $DriverPackageDest -Force | Out-Null }
                    Move-Item -Path (Join-Path $PackageSource "DriverPackage.exe") -Destination $DriverPackageDest -Force
                    return $true
                }
                else {
                    Write-LogEntry -Value "[Error] - 7-Zip compression failed (Exit Code: $($Process.ExitCode))" -Severity 3
                    return $false
                }
            }
            elseif ($CompressionType -eq "WIM") {
                Write-LogEntry -Value "- DriverPackage: Creating WIM file" -Severity 1
                $DismPath = Join-Path $env:SystemRoot "System32\\dism.exe"
                if (-not (Test-Path -Path $DismPath)) {
                    Write-LogEntry -Value "[Error] - DISM not found at $DismPath" -Severity 3
                    return $false
                }

                if (-not (Test-Path -Path $DriverPackageDest)) { New-Item -ItemType Directory -Path $DriverPackageDest -Force | Out-Null }
                $WimPath = Join-Path -Path $DriverPackageDest -ChildPath "DriverPackage.wim"
                $DismArgs = "/Capture-Image /ImageFile:`"$WimPath`" /CaptureDir:`"$PackageSource`" /Name:`"Drivers`" /Compress:Max /CheckIntegrity"

                $Process = Start-Process -FilePath $DismPath -ArgumentList $DismArgs -NoNewWindow -Wait -PassThru
                if ($Process.ExitCode -eq 0 -and (Test-Path -Path $WimPath)) {
                    Write-LogEntry -Value "- DriverPackage: WIM file created" -Severity 1
                    return $true
                }
                else {
                    Write-LogEntry -Value "[Error] - WIM creation failed (Exit Code: $($Process.ExitCode))" -Severity 3
                    return $false
                }
            }
            else {
                # Default to Zip
                Write-LogEntry -Value "- DriverPackage: Creating zip file" -Severity 1
                $ZipPath = Join-Path -Path $DriverPackageDest -ChildPath "DriverPackage.zip"
                if (-not (Test-Path -Path $DriverPackageDest)) { New-Item -ItemType Directory -Path $DriverPackageDest -Force | Out-Null }
                Compress-Archive -Path $PackageSource -DestinationPath $ZipPath -CompressionLevel Optimal -Force
                return (Test-Path -Path $ZipPath)
            }
        }
        else {
            # No compression, just copy
            Write-LogEntry -Value "- DriverPackage: Copying drivers to $DriverPackageDest" -Severity 1
            if (-not (Test-Path -Path $DriverPackageDest)) { New-Item -ItemType Directory -Path $DriverPackageDest -Force | Out-Null }
            Get-ChildItem -Path $PackageSource | Copy-Item -Destination $DriverPackageDest -Container -Recurse -Force
            return $true
        }
    }
    catch {
        Write-LogEntry -Value "[Error] - Error in New-DriverPackage: $($_.Exception.Message)" -Severity 3
        return $false
    }
    finally {
        if ($StagingRoot -and (Test-Path -Path $StagingRoot)) {
            try {
                Remove-Item -Path $StagingRoot -Recurse -Force -ErrorAction Stop
                Write-LogEntry -Value "- DriverPackage: Removed staging folder $StagingRoot" -Severity 1
            }
            catch {
                Write-LogEntry -Value "[Warning] - DriverPackage: Failed to remove staging folder ${StagingRoot}: $($_.Exception.Message)" -Severity 2
            }
        }
    }
}

function Get-LenovoDownloadInfo {
    <#
    .SYNOPSIS
        Extracts driver download information from the Lenovo XML.
    .DESCRIPTION
        Searches the Lenovo SCCM catalog for a specific model, OS, and version to find the driver pack download URL.
    .PARAMETER Model
        The Lenovo model name.
    .PARAMETER OSName
        The OS name (e.g. "Windows 10").
    .PARAMETER OSVersion
        The OS version (e.g. "21H2").
    .EXAMPLE
        Get-LenovoDownloadInfo -Model "ThinkPad X1 Carbon" -OSName "Windows 10" -OSVersion "21H2"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Specify the Lenovo model name.")]
        [string]$Model,
        [Parameter(Mandatory = $true, HelpMessage = "Specify the OS name.")]
        [string]$OSName,
        [Parameter(Mandatory = $true, HelpMessage = "Specify the OS version.")]
        [string]$OSVersion
    )

    if (-not $global:LenovoModelDrivers) {
        Find-LenovoModel -Model "*" # Force population
    }

    Write-LogEntry -Value "- Searching for Lenovo driver pack for $Model, $OSName $OSVersion" -Severity 1
    
    $WindowsVersion = if ($OSName -match "10") { "10" } else { "11" }

    $MatchedSccm = ($global:LenovoModelDrivers | Where-Object {
            $_.Name -eq $Model
        }).SCCM | Where-Object {
        $_.os -match $WindowsVersion -and $_.version -match $OSVersion
    } | Select-Object -First 1

    if ($null -eq $MatchedSccm -or -not $MatchedSccm.'#text') {
        Write-LogEntry -Value "[Warning] - No driver package found for $Model ($OSName $OSVersion)" -Severity 2
        return $null
    }

    $DriverDownload = $MatchedSccm.'#text'
    $DriverCab = $DriverDownload | Split-Path -Leaf
    $DriverRevision = ($DriverCab.Split("_") | Select-Object -Last 1).Trim(".exe")
    $DriverRevision = ($DriverRevision -replace '[<>:"/\\|?*]', '').Trim()
    $DriverDateCompact = Get-LenovoDateCompact -DateValue $MatchedSccm.date
    if ($DriverDateCompact) {
        $DriverRevision = $DriverDateCompact
    }

    return @{
        URL      = $DriverDownload
        FileName = $DriverCab
        Revision = $DriverRevision
        Date     = $MatchedSccm.date
    }
}

function Get-LenovoDrivers {
    <#
    .SYNOPSIS
        Orchestrates the download, packaging, and SCCM registration of Lenovo drivers.
    .DESCRIPTION
        This is the main cmdlet for Lenovo driver management. It connects to ConfigMgr
        via CIM/DCOM (no WinRM required), finds the model information,
        downloads the driver pack, extracts it, creates a ConfigMgr package, and
        optionally distributes content to DP Groups.
    .PARAMETER Model
        The Lenovo model name (e.g., "ThinkPad X1 Carbon Gen 9"). If omitted, you will be prompted to search and select a pack.
    .PARAMETER OSName
        The operating system name (default from settings).
    .PARAMETER OSVersion
        The OS version/build (e.g., "21H2", "23H2"). If omitted when Model is specified, you will be prompted.
    .PARAMETER Architecture
        The OS architecture (default from settings).
    .PARAMETER SiteServer
        The ConfigMgr Site Server FQDN (default from settings).
    .PARAMETER PackagePath
        The UNC path for packages (default from settings).
    .PARAMETER PackageFormat
        Package storage format (Raw, Zip, WIM). Defaults to settings.
    .PARAMETER SkipDistribution
        Skip content distribution to DP Groups after package creation.
    .PARAMETER Force
        Force re-import even if the same package already exists in SCCM.
    .PARAMETER EnableBinaryDeltaReplication
        Enable BDR on the created package. Default from settings.
    .EXAMPLE
        Get-LenovoDrivers -Model "ThinkPad X1 Carbon Gen 9" -OSVersion "23H2"
    .EXAMPLE
        Get-LenovoDrivers -Model "ThinkPad L14 Gen 3" -OSVersion "22H2" -SkipDistribution
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, HelpMessage = "Specify the Lenovo model name.")]
        [string]$Model,

        [Parameter(Mandatory = $false, HelpMessage = "Specify the OS version (e.g. 23H2).")]
        [string]$OSVersion,

        [string]$OSName,
        [string]$Architecture,
        [ValidateSet("Raw", "Zip", "WIM")]
        [string]$PackageFormat,
        [string]$SiteServer,
        [string]$PackagePath,
        [switch]$SkipDistribution,
        [switch]$Force,
        [bool]$EnableBinaryDeltaReplication = $false
    )


    function Get-LenovoArchFromUrl {
        param([string]$Url, [string]$FallbackArch)
        if ($Url -match "w(?:10|11)64") { return "x64" }
        if ($Url -match "w(?:10|11)32") { return "x86" }
        return $FallbackArch
    }

    function Get-LenovoDateCompact {
        param([string]$DateValue)
        if (-not $DateValue) { return "" }
        return ($DateValue -replace "-", "")
    }

    # 1. Load Defaults if not provided
    $Settings = Get-DASettings
    $EffectivePackageFormat = if ($PSBoundParameters.ContainsKey('PackageFormat')) { $PackageFormat } else { $Settings.PackageFormat }
    if (-not $SiteServer) { $SiteServer = $Settings.SiteServer }
    if (-not $PackagePath) { $PackagePath = $Settings.PackagePath }
    if ($OSName) { $OSName = Convert-OSName -OSName $OSName }

    # 2. Check Prerequisites
    if (-not (Test-DASettings)) {
        return
    }

    # 3. Ensure ConfigMgr connection (CIM/DCOM)
    if (-not (Initialize-SCCMConnection)) {
        Write-LogEntry -Value "[Error] - Failed to connect to ConfigMgr." -Severity 3
        return
    }

    # 4. If no model is provided, prompt and search the catalog, then let the user pick a pack
    $SelectedPack = $null
    $SelectedPackOsName = $null
    $SelectedPackArch = $null
    $ModelTypes = @()

    $Automated = ($Model -and $OSName -and $OSVersion)
    if (-not $Automated) {
        if (-not $global:LenovoModelDrivers) {
            Find-LenovoModel -Model "*" | Out-Null # Force population
        }

        if (-not $Model) {
            $Model = Read-Host "Enter Lenovo model search (e.g. ThinkPad X1)"
            if (-not $Model) {
                Write-LogEntry -Value "[Warning] - No model search provided. Exiting." -Severity 2
                return
            }
        }

        $modelPattern = if ($Model -match "[\\*\\?]") { $Model } else { "*$Model*" }
        $ModelMatches = $global:LenovoModelDrivers | Where-Object { $_.Name -like $modelPattern }

        if (-not $ModelMatches) {
            Write-LogEntry -Value "[Warning] - No models found matching '$Model'" -Severity 2
            return
        }

        $PackResults = foreach ($m in $ModelMatches) {
            $types = @()
            if ($m.Types -and $m.Types.Type) {
                $types = @($m.Types.Type | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            }
            foreach ($s in $m.SCCM) {
                if ($s.'#text') {
                    $pkgOsName = Convert-OSName -OSName $s.os
                    $archValue = Get-LenovoArchFromUrl -Url $s.'#text' -FallbackArch $Architecture
                    $dateCompact = Get-LenovoDateCompact -DateValue $s.date
                    [pscustomobject]@{
                        ModelName    = $m.Name
                        os           = $s.os
                        version      = $s.version
                        date         = $s.date
                        DateCompact  = $dateCompact
                        DownloadUrl  = $s.'#text'
                        ModelTypes   = $types
                        WindowsName  = $pkgOsName
                        Architecture = $archValue
                    }
                }
            }
        }

        if (-not $PackResults) {
            Write-LogEntry -Value "[Warning] - No driver packs found for models matching '$Model'" -Severity 2
            return
        }

        # Filter by provided partial info
        $PackResults = Select-DriverPackResults -PackResults $PackResults -OSName $OSName -OSVersion $OSVersion -OsFamilyNameProperty 'WindowsName' -OsVersionProperty 'version'
        if (-not $PackResults) {
            Write-LogEntry -Value "[Warning] - No driver packs found matching '$Model' for specified OS criteria." -Severity 2
            return
        }

        # De-duplicate identical pack rows
        $PackResults = Merge-DriverPackDuplicates -PackResults $PackResults

        # Sort by Model > OS name > OS version for consistent selection output.
        # OS version is converted to a numeric sort key when possible (e.g. 22H2, 1909).
        $PackResults = $PackResults | Sort-Object -Property `
            ModelName,
        os,
        @{ Expression = {
                $key = Get-OSVersionSortKey -OSVersion $_.version
                if ($key -eq 0) { return [int]::MaxValue }
                return $key
            } 
        },
        @{ Expression = { $_.version } }

        $SelectedPack = Select-DriverPack -PackResults $PackResults -LineFormatter {
            param($p, $i)
            "{0}. {1} | {2} {3} | {4} | {5}" -f ($i + 1), $p.ModelName, $p.os, $p.version, $p.date, ($p.DownloadUrl | Split-Path -Leaf)
        }
        if (-not $SelectedPack) { return }

        $Model = $SelectedPack.ModelName
        $OSVersion = $SelectedPack.version
        $SelectedPackOsName = $SelectedPack.WindowsName
        $SelectedPackArch = $SelectedPack.Architecture
        $SelectedPackDate = $SelectedPack.DateCompact
        $ModelTypes = $SelectedPack.ModelTypes
        $OSName = $SelectedPackOsName
        $Architecture = $SelectedPackArch
    }


    Write-LogEntry -Value "======== Starting Get-LenovoDrivers for $Model ========" -Severity 1
    Write-LogEntry -Value "- OS: $OSName $OSVersion | Arch: $Architecture" -Severity 1

    # 5. Get Model Info
    $SKU = Find-LenovoModel -Model $Model
    if (-not $SKU) {
        Write-LogEntry -Value "[Error] - Could not identify Lenovo SKU for $Model" -Severity 3
        return
    }

    # 6. Get Download Info
    if ($SelectedPack) {
        $DriverCab = $SelectedPack.DownloadUrl | Split-Path -Leaf
        $DriverRevision = ($DriverCab.Split("_") | Select-Object -Last 1).Trim(".exe")
        $DriverRevision = ($DriverRevision -replace '[<>:"/\\|?*]', '').Trim()
        if ($SelectedPackDate) {
            $DriverRevision = $SelectedPackDate
        }
        $DownloadInfo = @{
            URL      = $SelectedPack.DownloadUrl
            FileName = $DriverCab
            Revision = $DriverRevision
        }
    }
    else {
        $DownloadInfo = Get-LenovoDownloadInfo -Model $Model -OSName $OSName -OSVersion $OSVersion
        if (-not $DownloadInfo) {
            Write-LogEntry -Value "[Error] - No driver package found for $Model on $OSName $OSVersion" -Severity 3
            return
        }

        $MatchedModel = $global:LenovoModelDrivers | Where-Object { $_.Name -eq $Model } | Select-Object -First 1
        if ($MatchedModel) {
            $osToken = if ($OSName -match "11") { "11" } else { "10" }
            $MatchedSccm = $MatchedModel.SCCM | Where-Object {
                $_.os -match $osToken -and $_.version -match $OSVersion -and $_.'#text' -eq $DownloadInfo.URL
            } | Select-Object -First 1

            if ($MatchedSccm) {
                $SelectedPackOsName = Convert-OSName -OSName $MatchedSccm.os
                $SelectedPackArch = Get-LenovoArchFromUrl -Url $MatchedSccm.'#text' -FallbackArch $Architecture
                $SelectedPackDate = Get-LenovoDateCompact -DateValue $MatchedSccm.date
                $OSName = $SelectedPackOsName
                $Architecture = $SelectedPackArch
            }

            if ($MatchedModel.Types -and $MatchedModel.Types.Type) {
                $ModelTypes = @($MatchedModel.Types.Type | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            }
        }
    }
    if (-not $DownloadInfo) {
        Write-LogEntry -Value "[Error] - No driver package found for $Model on $OSName $OSVersion" -Severity 3
        return
    }

    $FolderOs = ($SelectedPackOsName -replace 'Windows\s+', 'Windows')
    $FolderOs = ($FolderOs -replace '\s+', '')
    $FolderModel = $Model
    $FolderArch = if ($SelectedPackArch) { $SelectedPackArch } else { $Architecture }
    if ($OSVersion) {
        $FolderName = "$FolderOs-$OSVersion-$FolderArch-$($DownloadInfo.Revision)"
    }
    else {
        $FolderName = "$FolderOs-$FolderArch-$($DownloadInfo.Revision)"
    }
    
    $FinalPackageDest = Join-Path (Join-Path (Join-Path $PackagePath "Lenovo") $FolderModel) $FolderName

    # 7. Check if a ConfigMgr package already exists with this version
    $OSDisplay = ($OSName -replace "Windows(\\d+)", "Windows $1").Trim()
    $CMPackageName = Build-DriverPackageName -OEM "Lenovo" -Model $Model -OSName $OSDisplay -OSVersion $OSVersion -Architecture $Architecture
    Write-LogEntry -Value "- Checking for existing SCCM package: $CMPackageName" -Severity 1

    $ExistingPackages = Get-CMPackage -SiteServer $SiteServer -Name $CMPackageName -TimeoutSec 30
    $ExistingPackage = $ExistingPackages | Where-Object { $_.Version -eq $DownloadInfo.Revision } | Select-Object -First 1

    if ($ExistingPackage) {
        if ($Force) {
            Write-LogEntry -Value "- Package already exists for $FolderName. Force specified; removing existing package $($ExistingPackage.PackageID) and source files." -Severity 1
            Remove-CMPackage -SiteServer $SiteServer -PackageID $ExistingPackage.PackageID | Out-Null
            try {
                if (Test-Path -Path $FinalPackageDest) {
                    $Stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
                    $BackupPath = "${FinalPackageDest}_backup_$Stamp"
                    Move-Item -Path $FinalPackageDest -Destination $BackupPath -Force -ErrorAction Stop
                    Write-LogEntry -Value "- Archived existing package source files to $BackupPath" -Severity 1
                }
            }
            catch {
                Write-LogEntry -Value "[Warning] - Failed to archive existing package source files at ${FinalPackageDest}: $($_.Exception.Message)" -Severity 2
            }
        }
        else {
            Write-LogEntry -Value "- Package already exists for $FolderName (PackageID: $($ExistingPackage.PackageID)). Skipping." -Severity 1
            Write-LogEntry -Value "======== Get-LenovoDrivers Complete (Already Present) ========" -Severity 1
            return
        }
    }

    # 8. Download
    $TempDest = Join-Path $global:TempDirectory -ChildPath $DownloadInfo.FileName
    if (-not (Invoke-ContentDownload -DownloadURL $DownloadInfo.URL -DestinationPath $TempDest -ModelName $Model)) {
        return
    }

    # 9. Extract
    $ExtractSubDir = "$($Model.Replace(' ', ''))_Drivers_$($DownloadInfo.Revision)"
    $ExtractDest = Join-Path $global:TempDirectory -ChildPath $ExtractSubDir
    if (-not (Invoke-ContentExtraction -SourceFile $TempDest -DestinationFolder $ExtractDest -Make "Lenovo")) {
        return
    }

    # 10. Stage driver files to final UNC package source
    if (New-DriverPackage -Make "Lenovo" -DriverExtractDest $ExtractDest -Architecture $Architecture -DriverPackageDest $FinalPackageDest -PackageFormat $EffectivePackageFormat -PackageRootName $FolderName) {
        Write-LogEntry -Value "- Driver files staged to $FinalPackageDest" -Severity 1
    }
    else {
        Write-LogEntry -Value "[Error] - Failed to stage driver files." -Severity 3
        return
    }
    
    # (Cleanup logic has been moved to the end of the function)


    # 11. Create SCCM Package via CIM/DCOM
    $MifVersion = "$OSDisplay $Architecture"
    $SkuValue = if ($ModelTypes -and $ModelTypes.Count -gt 0) { ($ModelTypes -join ",") } elseif ($SKU -is [array]) { ($SKU | Select-Object -First 1).SKU } else { $SKU.SKU }
    $PackageDescription = "(Models included:$SkuValue)"

    # Create a new SCCM package (do not update existing packages)
    $NewPackage = New-CMPackage -SiteServer $SiteServer `
        -Name $CMPackageName `
        -PkgSourcePath $FinalPackageDest `
        -Manufacturer "Lenovo" `
        -Version $DownloadInfo.Revision `
        -Description $PackageDescription `
        -MifName $Model `
        -MifVersion $MifVersion `
        -EnableBinaryDeltaReplication $EnableBinaryDeltaReplication

    if (-not $NewPackage -or -not $NewPackage.PackageID) {
        Write-LogEntry -Value "[Error] - Failed to create SCCM package." -Severity 3
        return
    }
    $PackageID = $NewPackage.PackageID

    # Place package into "Driver Packages\Lenovo" console folder
    $FolderNodeId = Resolve-CMFolderPath -Path "Driver Packages\\Lenovo" -ObjectType 2
    if ($FolderNodeId) {
        if (Add-CMPackageToFolder -PackageID $PackageID -FolderNodeId $FolderNodeId -ObjectType 2) {
            Write-LogEntry -Value "- Package $PackageID placed in console folder: Driver Packages\\Lenovo" -Severity 1
        }
    }

    # 11. Remove older packages for the same model + OS family after successful import
    if ($PackageID) {
        $BasePrefix = "Drivers - Lenovo $Model - $OSDisplay "
        $EscPrefix = ConvertTo-WqlEscapedString $BasePrefix
        $PostPackages = Get-CMPackage -SiteServer $SiteServer -NameFilter "startswith(Name,'$EscPrefix')"
        $OldPackages = $PostPackages | Where-Object {
            $_.PackageID -ne $PackageID -and
            $_.Name -like "$BasePrefix*" -and
            $_.Name -like "* $Architecture"
        }
        foreach ($Old in $OldPackages) {
            Write-LogEntry -Value "- Removing older package $($Old.PackageID) for $Model $OSDisplay (SCCM only; source files retained)" -Severity 1
            Remove-CMPackage -SiteServer $SiteServer -PackageID $Old.PackageID | Out-Null
        }
    }

    # 12. Distribute Content to configured DP Groups
    if (-not $SkipDistribution -and $PackageID) {
        $DPGroups = $Settings.DistributionPointGroups
        if ($DPGroups -and $DPGroups.Count -gt 0) {
            Invoke-ContentDistribution -SiteServer $SiteServer -PackageID $PackageID -DistributionPointGroupNames $DPGroups
        }
        else {
            Write-LogEntry -Value "[Warning] - No DP Groups configured. Use Set-DASettings to configure." -Severity 2
        }
    }

    # 13. Cleanup staging if CleanupDownloadPath is enabled
    if ($Settings.CleanupDownloadPath -eq $true) {
        try {
            foreach ($p in @($TempDest, $ExtractDest)) {
                if ($p -and (Test-Path -Path $p)) {
                    Remove-Item -Path $p -Recurse -Force -ErrorAction Stop
                    Write-LogEntry -Value "- Cleanup: Removed $p" -Severity 1
                }
            }
        }
        catch {
            Write-LogEntry -Value "[Warning] - Cleanup failed: $($_.Exception.Message)" -Severity 2
        }
    }

    Write-LogEntry -Value "======== Get-LenovoDrivers Complete ========" -Severity 1
}

function Get-DellDrivers {
    <#
    .SYNOPSIS
        Orchestrates the download, packaging, and SCCM registration of Dell drivers.
    .DESCRIPTION
        This is the main cmdlet for Dell driver management. It connects to ConfigMgr
        via CIM/DCOM (no WinRM required), finds the model information,
        downloads the driver pack, extracts it, creates a ConfigMgr package, and
        optionally distributes content to DP Groups.
    .PARAMETER Model
        The Dell model name (e.g., "Latitude 7420"). If omitted, you will be prompted to search and select a pack.
    .PARAMETER OSName
        The operating system name (default from settings).
    .PARAMETER OSVersion
        The OS version/build (e.g., "21H2", "23H2"). If omitted when Model is specified, you will be prompted.
    .PARAMETER Architecture
        The OS architecture (default from settings).
    .PARAMETER SiteServer
        The ConfigMgr Site Server FQDN (default from settings).
    .PARAMETER PackagePath
        The UNC path for packages (default from settings).
    .PARAMETER PackageFormat
        Package storage format (Raw, Zip, WIM). Defaults to settings.
    .PARAMETER SkipDistribution
        Skip content distribution to DP Groups after package creation.
    .PARAMETER Force
        Force re-import even if the same package already exists in SCCM.
    .PARAMETER EnableBinaryDeltaReplication
        Enable BDR on the created package. Default from settings.
    .EXAMPLE
        Get-DellDrivers -Model "Latitude 7420" -OSVersion "23H2"
    .EXAMPLE
        Get-DellDrivers -Model "OptiPlex 7000" -OSVersion "22H2" -SkipDistribution
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, HelpMessage = "Specify the Dell model name.")]
        [string]$Model,

        [Parameter(Mandatory = $false, HelpMessage = "Specify the OS version (e.g. 23H2).")]
        [string]$OSVersion,

        [string]$OSName,
        [string]$Architecture,
        [ValidateSet("Raw", "Zip", "WIM")]
        [string]$PackageFormat,
        [string]$SiteServer,
        [string]$PackagePath,
        [switch]$SkipDistribution,
        [switch]$Force,
        [bool]$EnableBinaryDeltaReplication = $false
    )

    if ($Model -and $OSVersion -and -not $OSName -and ($OSVersion -match "^[0-9]+$")) {
        $Model = "$Model $OSVersion"
        $OSVersion = $null
    }


    function Get-DellArchFromOs {
        param([string]$OsArch, [string]$FallbackArch)
        if (-not $OsArch) { return $FallbackArch }
        if ($OsArch -match "64") { return "x64" }
        if ($OsArch -match "86|32") { return "x86" }
        return $OsArch
    }

    function Get-DellDateCompact {
        param([string]$DateValue)
        if (-not $DateValue) { return "" }
        try {
            $dt = [datetime]::Parse($DateValue)
            return $dt.ToString("yyyyMMdd")
        }
        catch {
            return ($DateValue -replace "[^0-9]", "")
        }
    }

    function Get-DellDownloadUrl {
        param([object]$PathValue)
        if (-not $PathValue) { return $null }
        $PathText = if ($PathValue.'#text') { $PathValue.'#text' } else { [string]$PathValue }
        if ($PathText -match "^https?://") { return $PathText }
        if ($DellDownloadBase) { return ("$DellDownloadBase/$PathText") }
        return $PathText
    }

    function Get-DellPackVersion {
        param([object]$Package)
        $ver = $Package.DellVersion
        if (-not $ver) { $ver = $Package.Version }
        if (-not $ver) { $ver = $Package.version }
        return $ver
    }

    # 1. Load Defaults if not provided
    $Settings = Get-DASettings
    $EffectivePackageFormat = if ($PSBoundParameters.ContainsKey('PackageFormat')) { $PackageFormat } else { $Settings.PackageFormat }
    if (-not $SiteServer) { $SiteServer = $Settings.SiteServer }
    if (-not $PackagePath) { $PackagePath = $Settings.PackagePath }

    # 2. Check Prerequisites
    if (-not (Test-DASettings)) {
        return
    }

    # 3. Ensure ConfigMgr connection (CIM/DCOM)
    if (-not (Initialize-SCCMConnection)) {
        Write-LogEntry -Value "[Error] - Failed to connect to ConfigMgr." -Severity 3
        return
    }

    # 4. If we don't have enough info to automate, prompt or search/select
    $SelectedPack = $null
    $SelectedPackOsName = $null
    $SelectedPackArch = $null
    $ModelTypes = @()

    $Automated = ($Model -and $OSName -and $OSVersion)
    if (-not $Automated) {
        if (-not $global:DellModelDrivers) {
            Find-DellModel -Model "*" | Out-Null # Force population without prompting
        }

        if (-not $Model) {
            $Model = Read-Host "Enter Dell model search (e.g. Latitude 7420)"
            if (-not $Model) {
                Write-LogEntry -Value "[Warning] - No model search provided. Exiting." -Severity 2
                return
            }
        }

        $modelPattern = if ($Model -match "[\\*\\?]") { $Model } else { "*$Model*" }
        $PackResults = foreach ($pkg in $global:DellModelDrivers) {
            $modelNodes = @($pkg.SupportedSystems.Brand.Model | Where-Object { $_.name -like $modelPattern })
            if (-not $modelNodes -or $modelNodes.Count -eq 0) { continue }

            $osNodes = @($pkg.SupportedOperatingSystems.OperatingSystem)
            if (-not $osNodes -or $osNodes.Count -eq 0) {
                $osNodes = @([pscustomobject]@{ osCode = ""; osArch = $Architecture; osVersion = "" })
            }

            $matchedModelName = $modelNodes[0].name
            $allTypes = @($modelNodes | ForEach-Object { $_.systemID } | Where-Object { $_ }) | Sort-Object -Unique

            foreach ($osNode in $osNodes) {
                $osCode = $osNode.osCode
                $osNameVal = Convert-OSName -OSName $osCode
                $osVersionStr = $osNode.osVersion
                $displayVersion = if ($osVersionStr) { $osVersionStr } else { "-" }
                $archValue = Get-DellArchFromOs -OsArch $osNode.osArch -FallbackArch $Architecture
                $dateValue = if ($pkg.dateTime) { $pkg.dateTime } elseif ($pkg.date) { $pkg.date } else { $null }
                $dateCompact = Get-DellDateCompact -DateValue $dateValue
                $pathValue = if ($pkg.Path) { $pkg.Path } else { $pkg.path }
                $downloadUrl = Get-DellDownloadUrl -PathValue $pathValue
                if (-not $downloadUrl) { continue }
                $packVersion = Get-DellPackVersion -Package $pkg

                [pscustomobject]@{
                    ModelName      = $matchedModelName
                    os             = $osCode
                    version        = $osVersionStr
                    DisplayVersion = $displayVersion
                    date           = $dateValue
                    DateCompact    = $dateCompact
                    DownloadUrl    = $downloadUrl
                    ModelTypes     = $allTypes
                    WindowsName    = $osNameVal
                    Architecture   = $archValue
                    PackVersion    = $packVersion
                }
            }
        }

        if (-not $PackResults) {
            Write-LogEntry -Value "[Warning] - No driver packs found for models matching '$Model'" -Severity 2
            return
        }

        # Filter by provided partial info
        $PackResults = Select-DriverPackResults -PackResults $PackResults -OSName $OSName -OSVersion $OSVersion -OsFamilyNameProperty 'WindowsName' -OsVersionProperty 'version'
        if (-not $PackResults) {
            Write-LogEntry -Value "[Warning] - No driver packs found matching '$Model' for specified OS criteria." -Severity 2
            return
        }

        # De-duplicate identical pack rows
        $PackResults = Merge-DriverPackDuplicates -PackResults $PackResults

        # Sort by Model > OS name > OS version for consistent selection output.
        # OS version is converted to a numeric sort key when possible (e.g. 22H2, 1909).
        $PackResults = $PackResults | Sort-Object -Property `
            ModelName,
        WindowsName,
        @{ Expression = {
                $key = Get-OSVersionSortKey -OSVersion $_.version
                if ($key -eq 0) { return [int]::MaxValue }
                return $key
            } 
        },
        @{ Expression = { $_.version } }

        $SelectedPack = Select-DriverPack -PackResults $PackResults -LineFormatter {
            param($p, $i)
            $osVersionLabel = if ($p.DisplayVersion) { $p.DisplayVersion } elseif ($p.version) { $p.version } else { "" }
            $osDisplay = if ($osVersionLabel -and $osVersionLabel -ne "-") { "$($p.WindowsName) $osVersionLabel" } else { $p.WindowsName }
            "{0}. {1} | {2} | {3} | {4}" -f ($i + 1), $p.ModelName, $osDisplay, $p.date, ($p.DownloadUrl | Split-Path -Leaf)
        }
        if (-not $SelectedPack) { return }

        $Model = $SelectedPack.ModelName
        $OSVersion = $SelectedPack.version
        $SelectedPackOsName = $SelectedPack.WindowsName
        $SelectedPackArch = $SelectedPack.Architecture
        $ModelTypes = $SelectedPack.ModelTypes
        $OSName = $SelectedPackOsName
        $Architecture = $SelectedPackArch
    }



    Write-LogEntry -Value "======== Starting Get-DellDrivers for $Model ========" -Severity 1
    Write-LogEntry -Value "- OS: $OSName $OSVersion | Arch: $Architecture" -Severity 1

    # 5. Get Download Info
    if (-not $SelectedPack) {
        if (-not $global:DellModelDrivers) {
            Find-DellModel -Model "" | Out-Null
        }

        $osToken = if ($OSName -match "11") { "11" } else { "10" }
        $Candidates = foreach ($pkg in $global:DellModelDrivers) {
            $modelNodes = @($pkg.SupportedSystems.Brand.Model | Where-Object { $_.name -eq $Model })
            if (-not $modelNodes -or $modelNodes.Count -eq 0) { continue }

            $osNodes = @($pkg.SupportedOperatingSystems.OperatingSystem | Where-Object { $_.osCode -match $osToken })
            if ($OSVersion) {
                $hasOsVersion = $osNodes | Where-Object { $_.osVersion }
                if ($hasOsVersion) {
                    $osNodes = $osNodes | Where-Object { $_.osVersion -match $OSVersion }
                }
            }
            if (-not $osNodes -or $osNodes.Count -eq 0) { continue }

            $dateValue = if ($pkg.dateTime) { $pkg.dateTime } elseif ($pkg.date) { $pkg.date } else { $null }
            $dateSort = $null
            try { $dateSort = [datetime]::Parse($dateValue) } catch { $dateSort = [datetime]::MinValue }

            [pscustomobject]@{
                Package    = $pkg
                OsNode     = $osNodes[0]
                ModelNodes = $modelNodes
                DateValue  = $dateValue
                DateSort   = $dateSort
            }
        }

        if (-not $Candidates) {
            Write-LogEntry -Value "[Error] - No driver package found for $Model on $OSName $OSVersion" -Severity 3
            return
        }

        $Best = $Candidates | Sort-Object DateSort -Descending | Select-Object -First 1
        $BestPath = if ($Best.Package.Path) { $Best.Package.Path } else { $Best.Package.path }
        $SelectedPack = [pscustomobject]@{
            ModelName    = $Model
            os           = $Best.OsNode.osCode
            version      = $Best.OsNode.osVersion
            date         = $Best.DateValue
            DateCompact  = Get-DellDateCompact -DateValue $Best.DateValue
            DownloadUrl  = Get-DellDownloadUrl -PathValue $BestPath
            ModelTypes   = @($Best.ModelNodes | ForEach-Object { $_.systemID } | Where-Object { $_ }) | Sort-Object -Unique
            WindowsName  = Convert-OSName -OSName $Best.OsNode.osCode
            Architecture = Get-DellArchFromOs -OsArch $Best.OsNode.osArch -FallbackArch $Architecture
            PackVersion  = Get-DellPackVersion -Package $Best.Package
        }
    }

    if (-not $SelectedPack -or -not $SelectedPack.DownloadUrl) {
        Write-LogEntry -Value "[Error] - No driver package found for $Model on $OSName $OSVersion" -Severity 3
        return
    }

    if (-not $OSVersion) {
        $OSVersion = ""
    }
    elseif ($OSVersion -match "^(Windows\\s*)?1[01]$") {
        # Avoid duplicating OS name in folder/package paths (e.g., Windows10-Windows10)
        $OSVersion = ""
    }

    $SelectedPackOsName = if ($SelectedPack.WindowsName) { $SelectedPack.WindowsName } else { $OSName }
    $SelectedPackArch = if ($SelectedPack.Architecture) { $SelectedPack.Architecture } else { $Architecture }
    if (-not $ModelTypes -or $ModelTypes.Count -eq 0) { $ModelTypes = $SelectedPack.ModelTypes }

    $DriverCab = $SelectedPack.DownloadUrl | Split-Path -Leaf
    $DriverRevision = if ($SelectedPack.PackVersion) { $SelectedPack.PackVersion } else { ($DriverCab -replace "\\.cab$|\\.exe$", "") }
    $DriverRevision = ($DriverRevision -replace '[<>:"/\\|?*]', '').Trim()
    $DownloadInfo = @{
        URL      = $SelectedPack.DownloadUrl
        FileName = $DriverCab
        Revision = $DriverRevision
    }

    $DisplayModel = ($Model -replace '^\s*Dell\s+', '')
    $FolderOs = ($SelectedPackOsName -replace 'Windows\s+', 'Windows')
    $FolderOs = ($FolderOs -replace '\s+', '')
    $FolderName = "$FolderOs-$($DownloadInfo.Revision)"
    
    $FinalPackageDest = Join-Path (Join-Path (Join-Path $PackagePath "Dell") $DisplayModel) $FolderName

    # 6. Check if a ConfigMgr package already exists with this version
    $OSDisplay = ($SelectedPackOsName -replace "Windows(\\d+)", "Windows $1").Trim()
    $CMPackageName = Build-DriverPackageName -OEM "Dell" -Model $Model -OSName $OSDisplay -OSVersion $OSVersion -Architecture $SelectedPackArch
    Write-LogEntry -Value "- Checking for existing SCCM package: $CMPackageName" -Severity 1

    $ExistingPackages = Get-CMPackage -SiteServer $SiteServer -Name $CMPackageName -TimeoutSec 30
    $ExistingPackage = $ExistingPackages | Where-Object { $_.Version -eq $DownloadInfo.Revision } | Select-Object -First 1

    if ($ExistingPackage) {
        if ($Force) {
            Write-LogEntry -Value "- Package already exists for $FolderName. Force specified; removing existing package $($ExistingPackage.PackageID) and source files." -Severity 1
            Remove-CMPackage -SiteServer $SiteServer -PackageID $ExistingPackage.PackageID | Out-Null
            try {
                if (Test-Path -Path $FinalPackageDest) {
                    $Stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
                    $BackupPath = "${FinalPackageDest}_backup_$Stamp"
                    Move-Item -Path $FinalPackageDest -Destination $BackupPath -Force -ErrorAction Stop
                    Write-LogEntry -Value "- Archived existing package source files to $BackupPath" -Severity 1
                }
            }
            catch {
                Write-LogEntry -Value "[Warning] - Failed to archive existing package source files at ${FinalPackageDest}: $($_.Exception.Message)" -Severity 2
            }
        }
        else {
            Write-LogEntry -Value "- Package already exists for $FolderName (PackageID: $($ExistingPackage.PackageID)). Skipping." -Severity 1
            Write-LogEntry -Value "======== Get-DellDrivers Complete (Already Present) ========" -Severity 1
            return
        }
    }

    # 7. Download
    $TempDest = Join-Path $global:TempDirectory -ChildPath $DownloadInfo.FileName
    if (-not (Invoke-ContentDownload -DownloadURL $DownloadInfo.URL -DestinationPath $TempDest -ModelName $Model)) {
        return
    }
    if (-not (Test-Path -Path $TempDest)) {
        Write-LogEntry -Value "[Error] - Download reported success but file not found: $TempDest" -Severity 3
        return
    }

    # 8. Extract (mirror original Dell behavior: Temp\<Model>\Windows<Version>-<Revision>)
    $WindowsVersionToken = if ($SelectedPackOsName -match "11") { "11" } else { "10" }
    $ExtractSubDir = Join-Path $Model -ChildPath ("Windows$WindowsVersionToken-$($DownloadInfo.Revision)")
    $ExtractSubDir = ($ExtractSubDir -replace '/', '-')
    $ExtractDest = Join-Path $global:TempDirectory -ChildPath $ExtractSubDir
    if (Test-Path -Path $ExtractDest) {
        try {
            Remove-Item -Path $ExtractDest -Recurse -Force -ErrorAction Stop
        }
        catch {
            Write-LogEntry -Value "[Warning] - Failed to clear existing Dell extract folder ${ExtractDest}: $($_.Exception.Message)" -Severity 2
        }
    }
    if (-not (Invoke-ContentExtraction -SourceFile $TempDest -DestinationFolder $ExtractDest -Make "Dell")) {
        return
    }

    # 9. Stage driver files to final UNC package source
    if (New-DriverPackage -Make "Dell" -DriverExtractDest $ExtractDest -Architecture $SelectedPackArch -DriverPackageDest $FinalPackageDest -PackageFormat $EffectivePackageFormat -PackageRootName $FolderName) {
        Write-LogEntry -Value "- Driver files staged to $FinalPackageDest" -Severity 1
    }
    else {
        Write-LogEntry -Value "[Error] - Failed to stage driver files." -Severity 3
        return
    }

    # (Cleanup logic has been moved to the end of the function)


    # 10. Create SCCM Package via CIM/DCOM
    $MifVersion = "$OSDisplay $SelectedPackArch"
    $SkuValue = if ($ModelTypes -and $ModelTypes.Count -gt 0) { ($ModelTypes -join ",") } else { $Model }
    $PackageDescription = "(Models included:$SkuValue)"

    $NewPackage = New-CMPackage -SiteServer $SiteServer `
        -Name $CMPackageName `
        -PkgSourcePath $FinalPackageDest `
        -Manufacturer "Dell" `
        -Version $DownloadInfo.Revision `
        -Description $PackageDescription `
        -MifName $Model `
        -MifVersion $MifVersion `
        -EnableBinaryDeltaReplication $EnableBinaryDeltaReplication

    if (-not $NewPackage -or -not $NewPackage.PackageID) {
        Write-LogEntry -Value "[Error] - Failed to create SCCM package." -Severity 3
        return
    }
    $PackageID = $NewPackage.PackageID

    # Place package into "Driver Packages\Dell" console folder
    $FolderNodeId = Resolve-CMFolderPath -Path "Driver Packages\\Dell" -ObjectType 2
    if ($FolderNodeId) {
        if (Add-CMPackageToFolder -PackageID $PackageID -FolderNodeId $FolderNodeId -ObjectType 2) {
            Write-LogEntry -Value "- Package $PackageID placed in console folder: Driver Packages\\Dell" -Severity 1
        }
    }

    # 11. Remove older packages for the same model + OS family after successful import
    if ($PackageID) {
        $BasePrefix = "Drivers - Dell $Model - $OSDisplay "
        $EscPrefix = ConvertTo-WqlEscapedString $BasePrefix
        $PostPackages = Get-CMPackage -SiteServer $SiteServer -NameFilter "startswith(Name,'$EscPrefix')"
        $OldPackages = $PostPackages | Where-Object {
            $_.PackageID -ne $PackageID -and
            $_.Name -like "$BasePrefix*" -and
            $_.Name -like "* $SelectedPackArch"
        }
        foreach ($Old in $OldPackages) {
            Write-LogEntry -Value "- Removing older package $($Old.PackageID) for $Model $OSDisplay (SCCM only; source files retained)" -Severity 1
            Remove-CMPackage -SiteServer $SiteServer -PackageID $Old.PackageID | Out-Null
        }
    }

    # 12. Distribute Content to configured DP Groups
    if (-not $SkipDistribution -and $PackageID) {
        $DPGroups = $Settings.DistributionPointGroups
        if ($DPGroups -and $DPGroups.Count -gt 0) {
            Invoke-ContentDistribution -SiteServer $SiteServer -PackageID $PackageID -DistributionPointGroupNames $DPGroups
        }
        else {
            Write-LogEntry -Value "[Warning] - No DP Groups configured. Use Set-DASettings to configure." -Severity 2
        }
    }

    # 13. Cleanup staging if CleanupDownloadPath is enabled
    if ($Settings.CleanupDownloadPath -eq $true) {
        try {
            foreach ($p in @($TempDest, $ExtractDest)) {
                if ($p -and (Test-Path -Path $p)) {
                    Remove-Item -Path $p -Recurse -Force -ErrorAction Stop
                    Write-LogEntry -Value "- Cleanup: Removed $p" -Severity 1
                }
            }
        }
        catch {
            Write-LogEntry -Value "[Warning] - Cleanup failed for ${TempDest} or ${ExtractDest}: $($_.Exception.Message)" -Severity 2
        }
    }

    Write-LogEntry -Value "======== Get-DellDrivers Complete ========" -Severity 1
}

function Get-HPDrivers {
    <#
    .SYNOPSIS
        Orchestrates the download, packaging, and SCCM registration of HP drivers.
    .DESCRIPTION
        This is the main cmdlet for HP driver management. It connects to ConfigMgr
        via CIM/DCOM (no WinRM required), finds the model information,
        downloads the driver pack, extracts it, creates a ConfigMgr package, and
        optionally distributes content to DP Groups.
    .PARAMETER Model
        The HP model name (e.g., "EliteBook 840 G7"). If omitted, you will be prompted to search and select a pack.
    .PARAMETER OSName
        The operating system name (e.g. "Windows 10" or "Windows 11"). Default from settings.
    .PARAMETER OSVersion
        The OS version/build (e.g., "21H2", "23H2"). If omitted when Model is specified, you will be prompted.
    .PARAMETER Architecture
        The OS architecture (default from settings).
    .PARAMETER SiteServer
        The ConfigMgr Site Server FQDN (default from settings).
    .PARAMETER PackagePath
        The UNC path for packages (default from settings).
    .PARAMETER PackageFormat
        Package storage format (Raw, Zip, WIM). Defaults to settings.
    .PARAMETER SkipDistribution
        Skip content distribution to DP Groups after package creation.
    .PARAMETER Force
        Force re-import even if the same package already exists in SCCM.
    .PARAMETER EnableBinaryDeltaReplication
        Enable BDR on the created package. Default from settings.
    .EXAMPLE
        Get-HPDrivers -Model "EliteBook 840 G7" -OSVersion "23H2"
    .EXAMPLE
        Get-HPDrivers -Model "ProBook 450 G8" -OSVersion "22H2" -SkipDistribution
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, HelpMessage = "Specify the HP model name.")]
        [string]$Model,

        [Parameter(Mandatory = $false, HelpMessage = "Specify the OS version (e.g. 23H2).")]
        [string]$OSVersion,

        [string]$OSName,
        [string]$Architecture,
        [ValidateSet("Raw", "Zip", "WIM")]
        [string]$PackageFormat,
        [string]$SiteServer,
        [string]$PackagePath,
        [switch]$SkipDistribution,
        [switch]$Force,
        [bool]$EnableBinaryDeltaReplication = $false
    )

    # PowerShell quirk: if the caller forgets to quote a model with spaces, extra tokens can
    # get bound positionally into $OSVersion (e.g. `-Model 430 g8` => $Model="430", $OSVersion="g8").
    # If $OSVersion doesn't look like a real Windows version token, treat it as part of $Model.
    if ($Model -and $OSVersion -and -not $OSName -and ($OSVersion -notmatch '^(?:\d{2}H[12]|\d{4})$')) {
        $Model = "$Model $OSVersion"
        $OSVersion = $null
    }

    # Helper: resolve OS family name from any freeform string

    # Helper: derive architecture from HP's OSName string (e.g. "Windows 10 64-bit, 22H2")
    function Get-HPArchFromOSName {
        param([string]$OsName, [string]$FallbackArch)
        if (-not $OsName) { return $FallbackArch }
        if ($OsName -match "64") { return "x64" }
        if ($OsName -match "86|32") { return "x86" }
        return $FallbackArch
    }

    # Helper: compact date string for folder naming
    function Get-HPDateCompact {
        param([string]$DateValue)
        if (-not $DateValue) { return "" }
        try {
            return ([datetime]::Parse($DateValue)).ToString("yyyyMMdd")
        }
        catch {
            return ($DateValue -replace "[^0-9]", "")
        }
    }

    # Helper: normalise ftp:// URLs to https://
    function Normalize-HPUrl {
        param([string]$Url)
        if (-not $Url) { return $null }
        return ($Url -replace "^ftp:", "https:")
    }

    # Helper: extract a Windows version token (e.g. "22H2", "1909") from a freeform string
    function Get-HPOSVersionFromText {
        param([string]$Text)
        if (-not $Text) { return $null }
        $m = [regex]::Match($Text, '\b(\d{2}H[12])\b')
        if ($m.Success) { return $m.Value }
        $m = [regex]::Match($Text, '\b(19\d{2}|20\d{2})\b')
        if ($m.Success) { return $m.Value }
        return $null
    }

    # Helper: produce a numeric sort key for OS family + version so that newer builds sort higher.
    # Used as a tiebreaker when catalog entries have no date (common in HP XML).
    function Get-HPOSSortKey {
        param([string]$OsName, [string]$OsVersion)
        $family = if ($OsName -match "11") { 11 } else { 10 }
        $versionKey = Get-OSVersionSortKey -OSVersion $OsVersion
        return ($family * 100000) + $versionKey
    }

    # Helper: walk down a chain of single-child directories to find the real driver root
    function Get-HPDeepestSingleFolder {
        param([string]$RootPath)
        $current = $RootPath
        while ($true) {
            $dirs = @(Get-ChildItem -Path $current -Directory -Force)
            if ($dirs.Count -eq 1) { $current = $dirs[0].FullName } else { break }
        }
        return $current
    }

    # Helper: resolve the OS version token from an HP catalog OSName string.
    # HP OSName examples: "Windows 10 64-bit, 22H2"  /  "Windows 10 64-bit, 1909"
    function Resolve-HPOsVersion {
        param([string]$OsNameRaw, [string]$FallbackText)
        # Prefer explicit trailing token after comma
        if ($OsNameRaw -match ',\s*(\d{2}H[12])\s*$') { return $Matches[1] }
        if ($OsNameRaw -match ',\s*(\d{4}[A-Za-z0-9]*)\s*$') { return $Matches[1] }
        # Fall back to regex scan of the OSName string
        $v = Get-HPOSVersionFromText -Text $OsNameRaw
        if ($v) { return $v }
        # Last resort: scan SoftPaq metadata text
        if ($FallbackText) { return (Get-HPOSVersionFromText -Text $FallbackText) }
        return $null
    }

    # -------------------------------------------------------------------------
    # 1. Load defaults
    # -------------------------------------------------------------------------
    $Settings = Get-DASettings
    $EffectivePackageFormat = if ($PSBoundParameters.ContainsKey('PackageFormat')) { $PackageFormat } else { $Settings.PackageFormat }
    if (-not $SiteServer) { $SiteServer = $Settings.SiteServer }
    if (-not $PackagePath) { $PackagePath = $Settings.PackagePath }

    # -------------------------------------------------------------------------
    # 2. Check Prerequisites
    # -------------------------------------------------------------------------
    if (-not (Test-DASettings)) {
        return
    }

    # Normalise OSName to canonical form if the caller supplied something like "10" or "Windows10"
    if ($OSName) { $OSName = Convert-OSName -OSName $OSName }

    # -------------------------------------------------------------------------
    # 3. Connect to ConfigMgr
    # -------------------------------------------------------------------------
    if (-not (Initialize-SCCMConnection)) {
        Write-LogEntry -Value "[Error] - Failed to connect to ConfigMgr." -Severity 3
        return
    }

    # -------------------------------------------------------------------------
    # 4. Ensure the HP catalog is loaded
    # -------------------------------------------------------------------------
    if (-not $global:HPModelDrivers) {
        Find-HPModel -Model "*" | Out-Null
    }

    # -------------------------------------------------------------------------
    # 4. Unified selection flow
    # -------------------------------------------------------------------------
    $SelectedPack = $null
    $ModelTypes = @()

    $Automated = ($Model -and $OSName -and $OSVersion)
    if (-not $Automated) {
        if (-not $global:HPModelDrivers) {
            Find-HPModel -Model "*" | Out-Null
        }

        if (-not $Model) {
            $Model = Read-Host "Enter HP model search (e.g. EliteBook 840)"
            if (-not $Model) {
                Write-LogEntry -Value "[Warning] - No model search provided. Exiting." -Severity 2
                return
            }
        }

        $modelPattern = if ($Model -match '[*?]') { $Model } else { "*$Model*" }
        $PackResults = foreach ($pkg in $global:HPModelDrivers) {
            $modelName = $pkg.SystemName
            if (-not $modelName -or ($modelName -notlike $modelPattern)) { continue }

            $osNameRaw = $pkg.OSName
            $rowOsName = Convert-OSName -OSName $osNameRaw
            $archValue = Get-HPArchFromOSName -OsName $osNameRaw -FallbackArch $Architecture
            $dateValue = if ($pkg.ReleaseDate) { $pkg.ReleaseDate } elseif ($pkg.Date) { $pkg.Date } else { $null }
            $dateCompact = Get-HPDateCompact -DateValue $dateValue

            $softPaqId = $pkg.SoftPaqId
            if (-not $softPaqId) { $softPaqId = $pkg.SoftPaqID }
            $softPaq = if ($softPaqId) {
                $global:HPSoftPaqList | Where-Object { $_.ID -eq $softPaqId } | Select-Object -First 1
            }
            $downloadUrl = Normalize-HPUrl -Url $softPaq.URL
            if (-not $downloadUrl) { continue }

            # Build SoftPaq metadata text for version fallback
            $spqText = (@('Title', 'Name', 'Description', 'Category', 'OSName', 'OS') |
                ForEach-Object { if ($softPaq.PSObject.Properties.Name -contains $_) { [string]$softPaq.$_ } }) -join ' '

            $rowOsVersion = Resolve-HPOsVersion -OsNameRaw $osNameRaw -FallbackText $spqText

            $types = @()
            if ($pkg.SystemID) {
                $types = @($pkg.SystemID | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ })
            }

            [pscustomobject]@{
                ModelName    = $modelName
                os           = $osNameRaw
                version      = $rowOsVersion
                date         = $dateValue
                DateCompact  = $dateCompact
                DownloadUrl  = $downloadUrl
                ModelTypes   = $types
                WindowsName  = $rowOsName
                Architecture = $archValue
                PackVersion  = $softPaq.Version
                SoftPaqId    = $softPaqId
            }
        }

        if (-not $PackResults) {
            Write-LogEntry -Value "[Warning] - No driver packs found matching '$Model'" -Severity 2
            return
        }

        # Filter by provided partial info
        $PackResults = Select-DriverPackResults -PackResults $PackResults -OSName $OSName -OSVersion $OSVersion -OsFamilyNameProperty 'WindowsName' -OsVersionProperty 'version'
        if (-not $PackResults) {
            Write-LogEntry -Value "[Warning] - No driver packs found matching '$Model' for specified OS criteria." -Severity 2
            return
        }

        # De-duplicate identical pack rows (consistent behavior with Lenovo/Dell)
        $PackResults = Merge-DriverPackDuplicates -PackResults $PackResults

        # Sort by Model > OS name > OS version for consistent selection output.
        $PackResults = $PackResults | Sort-Object -Property `
            ModelName,
        WindowsName,
        @{ Expression = { Get-HPOSSortKey -OsName $_.WindowsName -OsVersion $_.version }; Descending = $false },
        @{ Expression = { $_.version } }

        $SelectedPack = Select-DriverPack -PackResults $PackResults -LineFormatter {
            param($p, $i)
            $osDisplay = if ($p.version) { "$($p.WindowsName) $($p.version)" } else { $p.WindowsName }
            "{0}. {1} | {2} | {3} | {4}" -f ($i + 1), $p.ModelName, $osDisplay, $p.date, ($p.DownloadUrl | Split-Path -Leaf)
        }
        if (-not $SelectedPack) { return }

        $Model = $SelectedPack.ModelName
        $OSVersion = $SelectedPack.version
        $OSName = $SelectedPack.WindowsName
        $Architecture = $SelectedPack.Architecture
        $ModelTypes = $SelectedPack.ModelTypes
    }


    Write-LogEntry -Value "======== Starting Get-HPDrivers for $Model ========" -Severity 1
    Write-LogEntry -Value "- OS: $OSName $OSVersion | Arch: $Architecture" -Severity 1

    # -------------------------------------------------------------------------
    # 5. Resolve the best-matching SoftPaq when no pack was selected interactively
    # -------------------------------------------------------------------------
    if (-not $SelectedPack) {
        $Candidates = foreach ($pkg in $global:HPModelDrivers) {
            $modelName = $pkg.SystemName
            if ($modelName -ne $Model) { continue }

            $osNameRaw = $pkg.OSName
            $rowOsName = Convert-OSName -OSName $osNameRaw

            # Filter on OS family first (cheap, no SoftPaq lookup yet)
            if ($OSName -and ($rowOsName -ne $OSName)) { continue }

            $softPaqId = $pkg.SoftPaqId
            if (-not $softPaqId) { $softPaqId = $pkg.SoftPaqID }
            if (-not $softPaqId) { $softPaqId = $pkg.SoftpaqID }
            $softPaq = if ($softPaqId) {
                $global:HPSoftPaqList | Where-Object { $_.ID -eq $softPaqId } | Select-Object -First 1
            }
            $downloadUrl = Normalize-HPUrl -Url $softPaq.URL
            if (-not $downloadUrl) { continue }

            $spqText = (@('Title', 'Name', 'Description', 'Category', 'OSName', 'OS') |
                ForEach-Object { if ($softPaq.PSObject.Properties.Name -contains $_) { [string]$softPaq.$_ } }) -join ' '
            $rowOsVersion = Resolve-HPOsVersion -OsNameRaw $osNameRaw -FallbackText $spqText

            # Filter on OS version (after resolving it)
            if ($OSVersion) {
                if (-not $rowOsVersion) { continue }
                if ($rowOsVersion -ne $OSVersion -and $rowOsVersion.ToUpper() -ne $OSVersion.ToUpper()) { continue }
            }

            $dateValue = if ($pkg.ReleaseDate) { $pkg.ReleaseDate } elseif ($pkg.Date) { $pkg.Date } else { $null }
            $dateSort = try { [datetime]::Parse($dateValue) } catch { [datetime]::MinValue }

            [pscustomobject]@{
                Package     = $pkg
                DateValue   = $dateValue
                DateSort    = $dateSort
                SoftPaq     = $softPaq
                DownloadUrl = $downloadUrl
                OsName      = $rowOsName
                OsVersion   = $rowOsVersion
            }
        }

        if (-not $Candidates) {
            Write-LogEntry -Value "[Error] - No driver package found for $Model on $OSName $OSVersion" -Severity 3
            return
        }

        # Primary sort: date descending. Secondary: OS version sort key descending (tiebreaker when
        # dates are absent, which is common in the HP catalog — ensures 22H2 beats 1909).
        $Best = $Candidates | Sort-Object `
        @{ Expression = { $_.DateSort }; Descending = $true },
        @{ Expression = { Get-HPOSSortKey -OsName $_.OsName -OsVersion $_.OsVersion }; Descending = $true } |
        Select-Object -First 1

        $SelectedPack = [pscustomobject]@{
            ModelName    = $Model
            os           = $Best.Package.OSName
            version      = $Best.OsVersion
            date         = $Best.DateValue
            DateCompact  = Get-HPDateCompact -DateValue $Best.DateValue
            DownloadUrl  = $Best.DownloadUrl
            ModelTypes   = @($Best.Package.SystemID | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ }) | Sort-Object -Unique
            WindowsName  = $Best.OsName
            Architecture = Get-HPArchFromOSName -OsName $Best.Package.OSName -FallbackArch $Architecture
            PackVersion  = $Best.SoftPaq.Version
            SoftPaqId    = $Best.SoftPaq.ID
        }
    }

    if (-not $SelectedPack -or -not $SelectedPack.DownloadUrl) {
        Write-LogEntry -Value "[Error] - No driver package found for $Model on $OSName $OSVersion" -Severity 3
        return
    }

    # -------------------------------------------------------------------------
    # 6. Consolidate resolved values
    # -------------------------------------------------------------------------
    $SelectedPackOsName = if ($SelectedPack.WindowsName) { $SelectedPack.WindowsName } else { $OSName }
    $SelectedPackArch = if ($SelectedPack.Architecture) { $SelectedPack.Architecture } else { $Architecture }

    # Use the version resolved from the catalog; fall back to what the caller supplied
    if (-not $OSVersion) { $OSVersion = $SelectedPack.version }

    if (-not $ModelTypes -or $ModelTypes.Count -eq 0) { $ModelTypes = $SelectedPack.ModelTypes }

    $DriverCab = $SelectedPack.DownloadUrl | Split-Path -Leaf
    $DriverRevision = if ($SelectedPack.PackVersion) { $SelectedPack.PackVersion } else { ($DriverCab -replace '\.exe$|\.cab$', '') }
    $DriverRevision = ($DriverRevision -replace '[<>:"/\\|?*]', '').Trim()
    $DownloadInfo = @{
        URL      = $SelectedPack.DownloadUrl
        FileName = $DriverCab
        Revision = $DriverRevision
    }

    # Folder / package name components
    $DisplayModel = ($Model -replace '^\s*HP\s+', '')
    $FolderOs = ($SelectedPackOsName -replace 'Windows\s+', 'Windows')
    $FolderOs = ($FolderOs -replace '\s+', '')
    if ($OSVersion) {
        $FolderName = "$FolderOs-$OSVersion-$SelectedPackArch-$($DownloadInfo.Revision)"
    }
    else {
        $FolderName = "$FolderOs-$SelectedPackArch-$($DownloadInfo.Revision)"
    }
    $FinalPackageDest = Join-Path (Join-Path (Join-Path $PackagePath "HP") $DisplayModel) $FolderName

    # SCCM package name — "Drivers - HP <model> - Windows 10 22H2 x64"
    $OSDisplay = $SelectedPackOsName   # Already "Windows 10" / "Windows 11"
    $CMPackageName = Build-DriverPackageName -OEM "HP" -Model $Model -OSName $OSDisplay -OSVersion $OSVersion -Architecture $SelectedPackArch

    # -------------------------------------------------------------------------
    # 7. Check for existing SCCM package
    # -------------------------------------------------------------------------
    Write-LogEntry -Value "- Checking for existing SCCM package: $CMPackageName" -Severity 1
    $ExistingPackages = Get-CMPackage -SiteServer $SiteServer -Name $CMPackageName -TimeoutSec 30
    $ExistingPackage = $ExistingPackages | Where-Object { $_.Version -eq $DownloadInfo.Revision } | Select-Object -First 1

    if ($ExistingPackage) {
        if ($Force) {
            Write-LogEntry -Value "- Package already exists (PackageID: $($ExistingPackage.PackageID)). Force specified; removing." -Severity 1
            Remove-CMPackage -SiteServer $SiteServer -PackageID $ExistingPackage.PackageID | Out-Null
            try {
                if (Test-Path -Path $FinalPackageDest) {
                    $BackupPath = "${FinalPackageDest}_backup_$((Get-Date).ToString('yyyyMMdd_HHmmss'))"
                    Move-Item -Path $FinalPackageDest -Destination $BackupPath -Force -ErrorAction Stop
                    Write-LogEntry -Value "- Archived existing source files to $BackupPath" -Severity 1
                }
            }
            catch {
                Write-LogEntry -Value "[Warning] - Failed to archive source files at ${FinalPackageDest}: $($_.Exception.Message)" -Severity 2
            }
        }
        else {
            Write-LogEntry -Value "- Package already exists (PackageID: $($ExistingPackage.PackageID)). Skipping." -Severity 1
            Write-LogEntry -Value "======== Get-HPDrivers Complete (Already Present) ========" -Severity 1
            return
        }
    }

    # -------------------------------------------------------------------------
    # 8. Download
    # -------------------------------------------------------------------------
    $TempDest = Join-Path $global:TempDirectory -ChildPath $DownloadInfo.FileName
    if (-not (Invoke-ContentDownload -DownloadURL $DownloadInfo.URL -DestinationPath $TempDest -ModelName $Model)) {
        return
    }

    # -------------------------------------------------------------------------
    # 9. Extract
    # -------------------------------------------------------------------------
    $WindowsVersionToken = if ($SelectedPackOsName -match "11") { "11" } else { "10" }
    $ExtractSubDir = ($Model -replace '[/\\]', '-') + "\Win$WindowsVersionToken$SelectedPackArch"
    $ExtractDest = Join-Path $global:TempDirectory -ChildPath $ExtractSubDir

    if (Test-Path -Path $ExtractDest) {
        try { Remove-Item -Path $ExtractDest -Recurse -Force -ErrorAction Stop }
        catch { Write-LogEntry -Value "[Warning] - Could not clear extract folder ${ExtractDest}: $($_.Exception.Message)" -Severity 2 }
    }

    if (-not (Invoke-ContentExtraction -SourceFile $TempDest -DestinationFolder $ExtractDest -Make "HP")) {
        return
    }

    # -------------------------------------------------------------------------
    # 9a. Wrap extracted content under a versioned sub-folder so the SCCM package
    #     source has a clean, self-describing root (avoids a flat driver dump).
    # -------------------------------------------------------------------------
    # Find the actual driver root (HP SoftPaqs often have a nested folder)
    $ActualDriverSource = Get-HPDeepestSingleFolder -RootPath $ExtractDest

    # Stage to final UNC destination using the folder name as the internal root
    if (New-DriverPackage -Make "HP" -DriverExtractDest $ActualDriverSource -Architecture $SelectedPackArch -DriverPackageDest $FinalPackageDest -PackageFormat $EffectivePackageFormat -PackageRootName $FolderName) {
        Write-LogEntry -Value "- Driver files staged to $FinalPackageDest" -Severity 1
    }
    else {
        Write-LogEntry -Value "[Error] - Failed to stage driver files." -Severity 3
        return
    }

    # (Cleanup logic has been moved to the end of the function)


    # -------------------------------------------------------------------------
    # 11. Create SCCM package
    # -------------------------------------------------------------------------
    $MifVersion = "$OSDisplay $SelectedPackArch"
    $SkuValue = if ($ModelTypes -and $ModelTypes.Count -gt 0) { ($ModelTypes -join ",") } else { $DisplayModel }
    $PackageDescription = "(Models included:$SkuValue)"

    $NewPackage = New-CMPackage -SiteServer $SiteServer `
        -Name $CMPackageName `
        -PkgSourcePath $FinalPackageDest `
        -Manufacturer "HP" `
        -Version $DownloadInfo.Revision `
        -Description $PackageDescription `
        -MifName $DisplayModel `
        -MifVersion $MifVersion `
        -EnableBinaryDeltaReplication $EnableBinaryDeltaReplication

    if (-not $NewPackage -or -not $NewPackage.PackageID) {
        Write-LogEntry -Value "[Error] - Failed to create SCCM package." -Severity 3
        return
    }
    $PackageID = $NewPackage.PackageID

    # Place package into "Driver Packages\HP" console folder
    $FolderNodeId = Resolve-CMFolderPath -Path "Driver Packages\\HP" -ObjectType 2
    if ($FolderNodeId) {
        if (Add-CMPackageToFolder -PackageID $PackageID -FolderNodeId $FolderNodeId -ObjectType 2) {
            Write-LogEntry -Value "- Package $PackageID placed in console folder: Driver Packages\\HP" -Severity 1
        }
    }

    # -------------------------------------------------------------------------
    # 12. Remove stale packages for the same model + OS family
    # -------------------------------------------------------------------------
    $BasePrefix = "Drivers - HP $DisplayModel - $OSDisplay "
    $EscPrefix = ConvertTo-WqlEscapedString $BasePrefix
    $PostPackages = Get-CMPackage -SiteServer $SiteServer -NameFilter "startswith(Name,'$EscPrefix')"
    $OldPackages = $PostPackages | Where-Object {
        $_.PackageID -ne $PackageID -and
        $_.Name -like "$BasePrefix*" -and
        $_.Name -like "* $SelectedPackArch"
    }
    foreach ($Old in $OldPackages) {
        Write-LogEntry -Value "- Removing older package $($Old.PackageID) for $DisplayModel $OSDisplay (SCCM only; source files retained)" -Severity 1
        Remove-CMPackage -SiteServer $SiteServer -PackageID $Old.PackageID | Out-Null
    }

    # -------------------------------------------------------------------------
    # 13. Distribute content
    # -------------------------------------------------------------------------
    if (-not $SkipDistribution -and $PackageID) {
        $DPGroups = $Settings.DistributionPointGroups
        if ($DPGroups -and $DPGroups.Count -gt 0) {
            Invoke-ContentDistribution -SiteServer $SiteServer -PackageID $PackageID -DistributionPointGroupNames $DPGroups
        }
        else {
            Write-LogEntry -Value "[Warning] - No DP Groups configured. Use Set-DASettings to configure." -Severity 2
        }
    }

    # 14. Cleanup staging if CleanupDownloadPath is enabled
    if ($Settings.CleanupDownloadPath -eq $true) {
        try {
            foreach ($p in @($TempDest, $ExtractDest)) {
                if ($p -and (Test-Path -Path $p)) {
                    Remove-Item -Path $p -Recurse -Force -ErrorAction Stop
                    Write-LogEntry -Value "- Cleanup: Removed $p" -Severity 1
                }
            }
        }
        catch {
            Write-LogEntry -Value "[Warning] - Cleanup failed for ${TempDest} or ${ExtractDest}: $($_.Exception.Message)" -Severity 2
        }
    }

    Write-LogEntry -Value "======== Get-HPDrivers Complete ========" -Severity 1
}

# // =================== MICROSOFT DRIVER LOGIC ====================== //

function Find-MicrosoftModel {
    <#
    .SYNOPSIS
        Looks up a Microsoft Surface model in the JSON catalog.
    .DESCRIPTION
        Downloads the Microsoft Surface driver catalog if not present and searches for the model.
        Supports partial/wildcard matching (e.g. "Surface Pro" matches "Surface Pro 7").
        Returns objects with Name and SKU (Product ID) properties.
    .PARAMETER Model
        The model name to search for (e.g. "Surface Pro 7").
    .EXAMPLE
        Find-MicrosoftModel -Model "Surface Pro 7"
    .EXAMPLE
        Find-MicrosoftModel -Model "Surface Pro"  # Returns all Surface Pro variants
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, HelpMessage = "Specify the Microsoft model name.")]
        [string]$Model
    )

    Get-DASettings | Out-Null

    if ([string]::IsNullOrWhiteSpace($Model)) {
        $Model = Read-Host "Enter Microsoft model search (e.g. Surface Pro 7)"
        if (-not $Model) {
            Write-LogEntry -Value "[Warning] - No model search provided. Exiting." -Severity 2
            return $null
        }
    }

    if (-not $MicrosoftJSONSource) {
        Write-LogEntry -Value "[Error] - Microsoft JSON source not found in OEMLinks.xml." -Severity 3
        return $null
    }

    $microsoftJsonPath = Join-Path $global:TempDirectory -ChildPath $global:MicrosoftJSONFile

    $refreshNeeded = $false
    if (Test-Path -Path $microsoftJsonPath) {
        try {
            $AgeDays = (New-TimeSpan -Start (Get-Item $microsoftJsonPath).LastWriteTime -End (Get-Date)).TotalDays
            if ($AgeDays -ge 7) { $refreshNeeded = $true }
        }
        catch {
            $refreshNeeded = $true
        }
    }

    if (-not (Test-Path -Path $microsoftJsonPath) -or $refreshNeeded) {
        if ($refreshNeeded) {
            $global:MicrosoftModelDrivers = $null
        }
        Write-LogEntry -Value "======== Downloading Microsoft Surface Driver Catalog ========" -Severity 1
        try {
            # GitHub raw URLs need to use raw.githubusercontent.com
            $downloadUrl = $MicrosoftJSONSource -replace "github.com/([^/]+)/([^/]+)/blob/", "raw.githubusercontent.com/`$1/`$2/"
            if ($global:ProxySettingsSet) {
                Start-BitsTransfer -Source $downloadUrl -Destination $microsoftJsonPath @global:BitsProxyOptions
            }
            else {
                Start-BitsTransfer -Source $downloadUrl -Destination $microsoftJsonPath @global:BitsOptions
            }
            if (Test-Path -Path $microsoftJsonPath) {
                try { (Get-Item -Path $microsoftJsonPath).LastWriteTime = Get-Date } catch { }
            }
        }
        catch {
            Write-LogEntry -Value "[Error] - Failed to download Microsoft JSON: $($_.Exception.Message)" -Severity 3
            return $null
        }
    }

    if (Test-Path -Path $microsoftJsonPath) {
        if ($null -eq $global:MicrosoftModelDrivers) {
            Write-LogEntry -Value "- Reading Microsoft driver pack JSON file" -Severity 1
            $global:MicrosoftModelDrivers = Get-Content -Path $microsoftJsonPath -Raw | ConvertFrom-Json
        }

        $modelPattern = if ($Model -match "[\\*\\?]") { $Model } else { "*$Model*" }
        $Results = foreach ($pack in $global:MicrosoftModelDrivers) {
            if (($pack.Model -like $modelPattern) -or ($pack.Product -like $modelPattern)) {
                [pscustomobject]@{
                    Name     = $pack.Model
                    SKU      = $pack.Product
                    OS       = $pack.OSVersion
                    FileName = $pack.FileName
                }
            }
        }
        $Results = $Results | Sort-Object -Property Name, SKU, OS -Unique

        if ($Results -and $Results.Count -gt 0) {
            Write-LogEntry -Value "- Found $($Results.Count) matching model(s)" -Severity 1
            return $Results
        }
        else {
            if (-not [string]::IsNullOrWhiteSpace($Model) -and ($Model -notmatch '^[\\*\\?]+$')) {
                Write-LogEntry -Value "[Warning] - No models found matching '$Model'" -Severity 2
            }
            return $null
        }
    }
}

function Get-MicrosoftDrivers {
    <#
    .SYNOPSIS
        Orchestrates the download, packaging, and SCCM registration of Microsoft Surface drivers.
    .DESCRIPTION
        This is the main cmdlet for Microsoft Surface driver management. It connects to ConfigMgr
        via CIM/DCOM (no WinRM required), finds the model information,
        downloads the driver pack, extracts it, creates a ConfigMgr package, and
        optionally distributes content to DP Groups.
    .PARAMETER Model
        The Microsoft model name (e.g., "Surface Pro 7"). If omitted, you will be prompted to search and select a pack.
    .PARAMETER OSName
        The operating system name (e.g. "Windows 10", "Windows 11").
    .PARAMETER OSVersion
        The OS version/build (e.g., "21H2", "23H2"). If omitted when Model is specified, you will be prompted.
    .PARAMETER Product
        The product/SKU identifier to select a specific driver pack variant (e.g., "Surface_Pro_9_for_Business_2038").
    .PARAMETER PackageFormat
        Package storage format (Raw, Zip, WIM). Defaults to settings.
    .PARAMETER SkipDistribution
        Skip content distribution to DP Groups after package creation.
    .PARAMETER Force
        Force re-import even if the same package already exists in SCCM.
    .EXAMPLE
        Get-MicrosoftDrivers -Model "Surface Pro 7" -OSName "Windows 10" -OSVersion "22H2"
    .EXAMPLE
        Get-MicrosoftDrivers -Model "Surface Laptop 5" -OSName "Windows 11" -OSVersion "23H2"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, HelpMessage = "Specify the Microsoft model name.")]
        [string]$Model,
        [Parameter(Mandatory = $false, HelpMessage = "Specify the OS name (Windows 10 or Windows 11).")]
        [string]$OSName,
        [Parameter(Mandatory = $false, HelpMessage = "Specify the OS version (e.g. 22H2, 23H2).")]
        [string]$OSVersion,
        [Parameter(Mandatory = $false, HelpMessage = "Specify the product/SKU to select a specific driver pack variant.")]
        [string]$Product,
        [ValidateSet("Raw", "Zip", "WIM")]
        [string]$PackageFormat,
        [switch]$SkipDistribution,
        [switch]$Force
    )

    # 1. Load Defaults
    $Settings = Get-DASettings
    if (-not (Test-DASettings)) {
        return
    }
    $EffectivePackageFormat = if ($PSBoundParameters.ContainsKey('PackageFormat')) { $PackageFormat } else { $Settings.PackageFormat }
    $SiteServer = $Settings.SiteServer
    $PackagePath = $Settings.PackagePath

    # 2. Connect to ConfigMgr
    if (-not (Initialize-SCCMConnection)) {
        Write-LogEntry -Value "[Error] - Failed to connect to ConfigMgr." -Severity 3
        return
    }

    Write-LogEntry -Value "======== Starting Get-MicrosoftDrivers ========" -Severity 1

    # 3. Force load catalog if needed
    if (-not $global:MicrosoftModelDrivers) {
        Find-MicrosoftModel -Model "*" | Out-Null
    }

    # 4. Get model selection
    if (-not $Model) {
        $Model = Read-Host "Enter Microsoft model search (e.g. Surface Pro 7)"
        if (-not $Model) {
            Write-LogEntry -Value "[Warning] - No model search provided. Exiting." -Severity 2
            return
        }
    }

    # 5. Find matching driver packs
    $modelPattern = if ($Model -match "[\\*\\?]") { $Model } else { "*$Model*" }
    $MatchingPacks = $global:MicrosoftModelDrivers | Where-Object { $_.Model -like $modelPattern }

    if (-not $MatchingPacks) {
        Write-LogEntry -Value "[Warning] - No driver packs found for model matching '$Model'" -Severity 2
        return
    }

    # 6. Filter by OS if provided
    if ($OSName) {
        $osToken = if ($OSName -match "11") { "11" } else { "10" }
        $MatchingPacks = $MatchingPacks | Where-Object { $_.OSVersion -match $osToken }
    }

    if ($OSVersion) {
        $MatchingPacks = $MatchingPacks | Where-Object { $_.OSReleaseId -match $OSVersion }
    }

    if ($Product) {
        $MatchingPacks = $MatchingPacks | Where-Object { $_.Product -like "*$Product*" }
    }

    if (-not $MatchingPacks -or $MatchingPacks.Count -eq 0) {
        Write-LogEntry -Value "[Warning] - No driver packs found for $Model with specified OS criteria." -Severity 2
        return
    }

    # 7. Let user select pack if multiple options (skip if caller already narrowed it down)
    if ($MatchingPacks.Count -gt 1 -and -not $OSName -and -not $OSVersion -and -not $Product) {
        $SelectedPack = Select-DriverPack -PackResults $MatchingPacks -LineFormatter {
            param($p, $i)
            $osShort = if ($p.OSVersion -match "11") { "win11" } else { "win10" }
            "{0}. {1} | {2} | {3} {4} | {5}" -f ($i + 1), $p.Model, $p.Product, $osShort, $p.OSReleaseId, $p.FileName
        }
        if (-not $SelectedPack) { return }
    }
    else {
        # Pick latest by CatalogVersion
        $SelectedPack = $MatchingPacks | Sort-Object -Property CatalogVersion -Descending | Select-Object -First 1
    }

    $SelectedModel = $SelectedPack.Model
    $SelectedOSName = if ($SelectedPack.OSVersion -match "11") { "Windows 11" } else { "Windows 10" }
    $SelectedOSVersion = $SelectedPack.OSReleaseId
    $SelectedArchitecture = if ($SelectedPack.OSArchitecture -match "arm") { "arm64" } else { "x64" }
    $SelectedRevision = ($SelectedPack.FileName -replace '\.[^.]+$', '').Split('_')[-1]
    if (-not $SelectedRevision) { $SelectedRevision = "1.0" }

    Write-LogEntry -Value "- Selected: $SelectedModel - $SelectedOSName $SelectedOSVersion ($SelectedArchitecture)" -Severity 1
    Write-LogEntry -Value "- OS: $SelectedOSName $SelectedOSVersion | Arch: $SelectedArchitecture" -Severity 1

    # 8. Build folder structure - use Product (SKU) for unique folder naming per Microsoft convention
    $FolderOs = ($SelectedOSName -replace 'Windows\s+', 'Windows')
    $FolderOs = ($FolderOs -replace '\s+', '')
    $FolderModel = $SelectedPack.Product
    if ($SelectedOSVersion) {
        $FolderName = "$FolderOs-$SelectedOSVersion-$SelectedArchitecture-$SelectedRevision"
    }
    else {
        $FolderName = "$FolderOs-$SelectedArchitecture-$SelectedRevision"
    }

    $FinalPackageDest = Join-Path (Join-Path (Join-Path $PackagePath "Microsoft") $FolderModel) $FolderName

    # 9. Build SCCM package name
    $OSDisplay = $SelectedOSName
    $CMPackageName = Build-DriverPackageName -OEM "Microsoft" -Model $SelectedPack.Product -OSName $OSDisplay -OSVersion $SelectedOSVersion -Architecture $SelectedArchitecture

    Write-LogEntry -Value "- Checking for existing SCCM package: $CMPackageName" -Severity 1

    # 10. Check for existing package
    $ExistingPackages = Get-CMPackage -SiteServer $SiteServer -Name $CMPackageName -TimeoutSec 30
    $ExistingPackage = $ExistingPackages | Where-Object { $_.Version -eq $SelectedRevision } | Select-Object -First 1

    if ($ExistingPackage) {
        if ($Force) {
            Write-LogEntry -Value "- Package already exists. Force specified; removing existing package $($ExistingPackage.PackageID) and source files." -Severity 1
            Remove-CMPackage -SiteServer $SiteServer -PackageID $ExistingPackage.PackageID | Out-Null
            try {
                if (Test-Path -Path $FinalPackageDest) {
                    $Stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
                    $BackupPath = "${FinalPackageDest}_backup_$Stamp"
                    Move-Item -Path $FinalPackageDest -Destination $BackupPath -Force -ErrorAction Stop
                    Write-LogEntry -Value "- Archived existing package source files to $BackupPath" -Severity 1
                }
            }
            catch {
                Write-LogEntry -Value "[Warning] - Failed to archive existing package source files at ${FinalPackageDest}: $($_.Exception.Message)" -Severity 2
            }
        }
        else {
            Write-LogEntry -Value "- Package already exists (PackageID: $($ExistingPackage.PackageID)). Skipping." -Severity 1
            Write-LogEntry -Value "======== Get-MicrosoftDrivers Complete (Already Present) ========" -Severity 1
            return
        }
    }

    # 11. Download
    $TempDest = Join-Path $global:TempDirectory -ChildPath $SelectedPack.FileName
    if (-not (Invoke-ContentDownload -DownloadURL $SelectedPack.Url -DestinationPath $TempDest -ModelName $SelectedModel)) {
        return
    }

    # 12. Extract
    $ExtractSubDir = "$($SelectedModel.Replace(' ', ''))_Drivers_$SelectedRevision"
    $ExtractDest = Join-Path $global:TempDirectory -ChildPath $ExtractSubDir
    if (-not (Invoke-ContentExtraction -SourceFile $TempDest -DestinationFolder $ExtractDest -Make "Microsoft")) {
        return
    }

    # 13. Stage driver files
    if (New-DriverPackage -Make "Microsoft" -DriverExtractDest $ExtractDest -Architecture $SelectedArchitecture -DriverPackageDest $FinalPackageDest -PackageFormat $EffectivePackageFormat -PackageRootName $FolderName) {
        Write-LogEntry -Value "- Driver files staged to $FinalPackageDest" -Severity 1
    }
    else {
        Write-LogEntry -Value "[Error] - Failed to stage driver files." -Severity 3
        return
    }

    # 14. Create SCCM Package
    $MifVersion = "$OSDisplay $SelectedArchitecture"
    $SkuValue = $SelectedPack.Product
    $PackageDescription = "(Models included:$SkuValue)"

    $NewPackage = New-CMPackage -SiteServer $SiteServer `
        -Name $CMPackageName `
        -PkgSourcePath $FinalPackageDest `
        -Manufacturer "Microsoft" `
        -Version $SelectedRevision `
        -Description $PackageDescription `
        -MifName $SelectedModel `
        -MifVersion $MifVersion `
        -EnableBinaryDeltaReplication $Settings.EnableBinaryDeltaReplication

    if (-not $NewPackage -or -not $NewPackage.PackageID) {
        Write-LogEntry -Value "[Error] - Failed to create SCCM package." -Severity 3
        return
    }
    $PackageID = $NewPackage.PackageID
    Write-LogEntry -Value "- SCCM package created: $PackageID" -Severity 1

    # 15. Place package into "Driver Packages\Microsoft" console folder
    $ConsoleFolder = "Driver Packages\\Microsoft"
    $FolderNodeId = Resolve-CMFolderPath -Path $ConsoleFolder -ObjectType 2
    if ($FolderNodeId) {
        if (Add-CMPackageToFolder -PackageID $PackageID -FolderNodeId $FolderNodeId -ObjectType 2) {
            Write-LogEntry -Value "- Package $PackageID placed in console folder: $ConsoleFolder" -Severity 1
        }
    }

    # 16. Distribute content to DP Groups
    if (-not $SkipDistribution) {
        if ($Settings.DistributionPointGroups -and $Settings.DistributionPointGroups.Count -gt 0) {
            Invoke-ContentDistribution -SiteServer $SiteServer `
                -PackageID $PackageID `
                -DistributionPointGroupNames $Settings.DistributionPointGroups
        }
    }

    # 17. Cleanup
    if ($Settings.CleanupDownloadPath) {
        try {
            foreach ($p in @($TempDest, $ExtractDest)) {
                if ($p -and (Test-Path -Path $p)) {
                    Remove-Item -Path $p -Recurse -Force -ErrorAction Stop
                    Write-LogEntry -Value "- Cleanup: Removed $p" -Severity 1
                }
            }
        }
        catch {
            Write-LogEntry -Value "[Warning] - Cleanup failed for ${TempDest} or ${ExtractDest}: $($_.Exception.Message)" -Severity 2
        }
    }

    Write-LogEntry -Value "======== Get-MicrosoftDrivers Complete ========" -Severity 1
}

# // =================== CUSTOM DRIVER LOGIC ====================== //

function Get-CustomDrivers {
    <#
    .SYNOPSIS
        Creates a custom driver package in SCCM from a local folder.
    .DESCRIPTION
        Interactively prompts for all required details to stage drivers, create an
        SCCM package, and distribute content to DP Groups. For use with drivers
        that are not available from Lenovo, Dell, or HP catalogs.
    .PARAMETER Manufacturer
        The manufacturer name (e.g. "Microsoft", "VMware").
    .PARAMETER Model
        The model or device name (e.g. "Surface Pro 7", "VMware SVGA").
    .PARAMETER OSName
        The operating system name (e.g. "Windows 10", "Windows 11").
    .PARAMETER OSVersion
        The OS version (e.g. "22H2", "23H2").
    .PARAMETER Architecture
        The OS architecture (e.g. "x64", "x86").
    .PARAMETER SourceFolder
        The path to the folder containing the driver files.
    .PARAMETER PackageFormat
        Package storage format: Raw, Zip, or WIM. Defaults to settings.
    .PARAMETER SkipDistribution
        Skip content distribution to DP Groups after package creation.
    .PARAMETER Force
        Force re-import even if the same package already exists in SCCM.
    .EXAMPLE
        Get-CustomDrivers
    .EXAMPLE
        Get-CustomDrivers -SourceFolder "C:\Drivers\SurfacePro7" -Model "Surface Pro 7"
    #>
    [CmdletBinding()]
    param (
        [string]$Manufacturer,
        [string]$Model,
        [string]$OSName,
        [string]$OSVersion,
        [string]$Architecture,
        [string]$SourceFolder,
        [ValidateSet("Raw", "Zip", "WIM")]
        [string]$PackageFormat,
        [switch]$SkipDistribution,
        [switch]$Force
    )

    # 1. Validate settings
    $Settings = Get-DASettings
    if (-not (Test-DASettings)) {
        return
    }
    $EffectivePackageFormat = if ($PSBoundParameters.ContainsKey('PackageFormat')) { $PackageFormat } else { $Settings.PackageFormat }
    if (-not $SiteServer) { $SiteServer = $Settings.SiteServer }
    if (-not $PackagePath) { $PackagePath = $Settings.PackagePath }

    # 2. Connect to ConfigMgr
    if (-not (Initialize-SCCMConnection)) {
        Write-LogEntry -Value "[Error] - Failed to connect to ConfigMgr." -Severity 3
        return
    }

    Write-LogEntry -Value "======== Starting Get-CustomDrivers ========" -Severity 1

    # 3. Interactive prompts for missing parameters
    if (-not $Manufacturer) {
        $Manufacturer = Read-Host "Enter manufacturer name (e.g. Microsoft, VMware)"
        if (-not $Manufacturer) {
            Write-LogEntry -Value "[Warning] - No manufacturer provided. Exiting." -Severity 2
            return
        }
    }

    if (-not $Model) {
        $Model = Read-Host "Enter model name (e.g. Surface Pro 7)"
        if (-not $Model) {
            Write-LogEntry -Value "[Warning] - No model provided. Exiting." -Severity 2
            return
        }
    }

    if (-not $OSName) {
        $OsInput = Read-Host "Enter OS (1=Windows 10, 2=Windows 11)"
        switch ($OsInput) {
            "1" { $OSName = "Windows 10" }
            "2" { $OSName = "Windows 11" }
            default { $OSName = if ($OsInput -match "11") { "Windows 11" } else { "Windows 10" } }
        }
    }

    if (-not $OSVersion) {
        $OSVersion = Read-Host "Enter OS version (e.g. 22H2, 23H2, or leave blank)"
        if ([string]::IsNullOrWhiteSpace($OSVersion)) { $OSVersion = "" }
    }

    if (-not $Architecture) {
        $ArchInput = Read-Host "Enter architecture (1=x64, 2=x86) [1]"
        switch ($ArchInput) {
            "2" { $Architecture = "x86" }
            default { $Architecture = "x64" }
        }
    }

    if (-not $SourceFolder) {
        $SourceFolder = Read-Host "Enter path to source driver folder"
        if (-not $SourceFolder -or -not (Test-Path -Path $SourceFolder -PathType Container)) {
            Write-LogEntry -Value "[Error] - Source folder '$SourceFolder' not found." -Severity 3
            return
        }
    }

    Write-LogEntry -Value "- Manufacturer: $Manufacturer" -Severity 1
    Write-LogEntry -Value "- Model: $Model" -Severity 1
    Write-LogEntry -Value "- OS: $OSName $OSVersion | Arch: $Architecture" -Severity 1
    Write-LogEntry -Value "- Source: $SourceFolder" -Severity 1
    Write-LogEntry -Value "- Format: $EffectivePackageFormat" -Severity 1

    # 4. Build folder structure
    $FolderOs = ($OSName -replace 'Windows\s+', 'Windows')
    $FolderOs = ($FolderOs -replace '\s+', '')
    $FolderModel = ($Model -replace '[<>:"/\\|?*]', '').Trim()
    if ($OSVersion) {
        $FolderName = "$FolderOs-$OSVersion-$Architecture"
    }
    else {
        $FolderName = "$FolderOs-$Architecture"
    }

    $FinalPackageDest = Join-Path (Join-Path (Join-Path $PackagePath $Manufacturer) $FolderModel) $FolderName

    # 5. Build SCCM package name
    $OSDisplay = ($OSName -replace "Windows(\d+)", "Windows $1").Trim()
    $CMPackageName = Build-DriverPackageName -OEM "Custom" -Manufacturer $Manufacturer -Model $Model -OSName $OSDisplay -OSVersion $OSVersion -Architecture $Architecture

    Write-LogEntry -Value "- Checking for existing SCCM package: $CMPackageName" -Severity 1

    # 6. Check for existing package
    $ExistingPackages = Get-CMPackage -SiteServer $SiteServer -Name $CMPackageName -TimeoutSec 30
    $ExistingPackage = $ExistingPackages | Select-Object -First 1

    if ($ExistingPackage) {
        if (-not $Force) {
            Write-LogEntry -Value "- Package already exists (PackageID: $($ExistingPackage.PackageID))." -Severity 1
            $ForceInput = Read-Host "Package already exists. Force update? (Y/N)"
            if ($ForceInput -notmatch '^[Yy]') {
                Write-LogEntry -Value "======== Get-CustomDrivers Complete (Already Present) ========" -Severity 1
                return
            }
            $Force = $true
        }
        Write-LogEntry -Value "- Package already exists. Removing existing package $($ExistingPackage.PackageID) and source files." -Severity 1
        Remove-CMPackage -SiteServer $SiteServer -PackageID $ExistingPackage.PackageID | Out-Null
        try {
            if (Test-Path -Path $FinalPackageDest) {
                $Stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
                $BackupPath = "${FinalPackageDest}_backup_$Stamp"
                Move-Item -Path $FinalPackageDest -Destination $BackupPath -Force -ErrorAction Stop
                Write-LogEntry -Value "- Archived existing package source files to $BackupPath" -Severity 1
            }
        }
        catch {
            Write-LogEntry -Value "[Warning] - Failed to archive existing package source files at ${FinalPackageDest}: $($_.Exception.Message)" -Severity 2
        }
    }

    # 7. Stage driver files to final UNC package source
    if (New-DriverPackage -Make "Custom" -DriverExtractDest $SourceFolder -Architecture $Architecture -DriverPackageDest $FinalPackageDest -PackageFormat $EffectivePackageFormat -PackageRootName $FolderName) {
        Write-LogEntry -Value "- Driver files staged to $FinalPackageDest" -Severity 1
    }
    else {
        Write-LogEntry -Value "[Error] - Failed to stage driver files." -Severity 3
        return
    }

    # 8. Create SCCM Package
    $MifVersion = "$OSDisplay $Architecture"
    $NewPackage = New-CMPackage -SiteServer $SiteServer `
        -Name $CMPackageName `
        -PkgSourcePath $FinalPackageDest `
        -Manufacturer $Manufacturer `
        -Version "1.0" `
        -MifName $Model `
        -MifVersion $MifVersion `
        -EnableBinaryDeltaReplication $Settings.EnableBinaryDeltaReplication

    if (-not $NewPackage -or -not $NewPackage.PackageID) {
        Write-LogEntry -Value "[Error] - Failed to create SCCM package." -Severity 3
        return
    }
    $PackageID = $NewPackage.PackageID
    Write-LogEntry -Value "- SCCM package created: $PackageID" -Severity 1

    # Place package into "Driver Packages\<Manufacturer>" console folder
    $ConsoleFolder = "Driver Packages\\$Manufacturer"
    $FolderNodeId = Resolve-CMFolderPath -Path $ConsoleFolder -ObjectType 2
    if ($FolderNodeId) {
        if (Add-CMPackageToFolder -PackageID $PackageID -FolderNodeId $FolderNodeId -ObjectType 2) {
            Write-LogEntry -Value "- Package $PackageID placed in console folder: $ConsoleFolder" -Severity 1
        }
    }

    # 9. Distribute content to DP Groups
    if (-not $SkipDistribution) {
        if ($Settings.DistributionPointGroups -and $Settings.DistributionPointGroups.Count -gt 0) {
            Invoke-ContentDistribution -SiteServer $SiteServer `
                -PackageID $PackageID `
                -DistributionPointGroupNames $Settings.DistributionPointGroups
        }
    }

    Write-LogEntry -Value "======== Get-CustomDrivers Complete ========" -Severity 1
}

# // =================== PACKAGE MANAGEMENT ====================== //

function Get-Packages {
    <#
    .SYNOPSIS
        Lists existing driver packages in SCCM.
    .PARAMETER Make
        Filter by OEM: Lenovo, Dell, HP, Microsoft, Custom, or All.
    #>
    [CmdletBinding()]
    param (
        [ValidateSet("Lenovo", "Dell", "HP", "Microsoft", "Custom", "All")]
        [string]$Make = "All"
    )

    $Settings = Get-DASettings
    if (-not (Test-DASettings)) { return }

    $SiteServer = $Settings.SiteServer
    if (-not (Initialize-SCCMConnection)) {
        Write-LogEntry -Value "[Error] - Failed to connect to ConfigMgr." -Severity 3
        return
    }

    $NameFilter = "startswith(Name,'Drivers -')"
    Write-LogEntry -Value "- Querying SCCM for driver packages..." -Severity 1
    $AllPackages = Get-CMPackage -SiteServer $SiteServer -NameFilter $NameFilter -TimeoutSec 60

    if (-not $AllPackages) {
        Write-LogEntry -Value "- No driver packages found." -Severity 1
        return
    }

    if ($Make -eq "All") {
        $AllPackages = $AllPackages | Where-Object { $_.Name -match '^Drivers - (Lenovo|Dell|HP|Microsoft)' }
    }
    elseif ($Make -eq "Custom") {
        $AllPackages = $AllPackages | Where-Object { $_.Name -notmatch '^Drivers - (Lenovo|Dell|HP|Microsoft)' }
    }
    else {
        $AllPackages = $AllPackages | Where-Object { $_.Name -like "Drivers - $Make *" }
    }

    if (-not $AllPackages) {
        Write-LogEntry -Value "- No driver packages found for $Make." -Severity 1
        return
    }

    $Results = $AllPackages | Select-Object `
    @{N = 'Name'; E = { $_.Name } },
    @{N = 'PackageID'; E = { $_.PackageID } },
    @{N = 'Version'; E = { $_.Version } },
    @{N = 'Manufacturer'; E = { $_.Manufacturer } },
    @{N = 'SourcePath'; E = { $_.PkgSourcePath } } |
    Sort-Object -Property Manufacturer, Name

    Write-LogEntry -Value "- Found $($Results.Count) driver package(s)." -Severity 1
    return $Results
}

function Find-DriverModel {
    <#
    .SYNOPSIS
        Searches for a model across all OEMs.
    .PARAMETER Model
        The model name to search for (supports wildcards).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Model
    )

    Get-DASettings | Out-Null
    Write-LogEntry -Value "- Searching all OEM catalogs for '$Model'..." -Severity 1

    $Results = @()

    $lenovoResults = Find-LenovoModel -Model $Model
    if ($lenovoResults) { $Results += $lenovoResults | Select-Object @{N = 'OEM'; E = { 'Lenovo' } }, Name, SKU }

    $dellResults = Find-DellModel -Model $Model
    if ($dellResults) { $Results += $dellResults | Select-Object @{N = 'OEM'; E = { 'Dell' } }, Name, SKU }

    $hpResults = Find-HPModel -Model $Model
    if ($hpResults) { $Results += $hpResults | Select-Object @{N = 'OEM'; E = { 'HP' } }, Name, SKU }

    $msResults = Find-MicrosoftModel -Model $Model
    if ($msResults) { $Results += $msResults | Select-Object @{N = 'OEM'; E = { 'Microsoft' } }, Name, SKU }

    if ($Results.Count -gt 0) {
        Write-LogEntry -Value "- Found $($Results.Count) matching model(s) across all OEMs." -Severity 1
        return $Results | Sort-Object -Property OEM, Name
    }
    else {
        Write-LogEntry -Value "[Warning] - No models found matching '$Model' in any catalog." -Severity 2
        return $null
    }
}

function Update-Packages {
    <#
    .SYNOPSIS
        Checks SCCM packages against catalog versions and reports outdated ones.
    .PARAMETER Make
        Filter by OEM: Lenovo, Dell, HP, Microsoft.
    #>
    [CmdletBinding()]
    param (
        [ValidateSet("Lenovo", "Dell", "HP", "Microsoft")]
        [string]$Make,
        [switch]$HighlightUpdates
    )

    Write-LogEntry -Value "======== Starting Update-Packages ========" -Severity 1

    if ($Make) { $ExistingPackages = Get-Packages -Make $Make }
    else { $ExistingPackages = Get-Packages -Make All }

    if (-not $ExistingPackages) { return }

    Write-LogEntry -Value "- Found $($ExistingPackages.Count) package(s). Checking catalog versions..." -Severity 1

    # Ensure catalogs are loaded
    Find-LenovoModel -Model "*" | Out-Null
    Find-DellModel -Model "*" | Out-Null
    Find-HPModel -Model "*" | Out-Null
    Find-MicrosoftModel -Model "*" | Out-Null

    $Results = foreach ($pkg in $ExistingPackages) {
        # Parse package name: "Drivers - <Make> <Model> - Windows <Version> <Arch>"
        # or "Drivers - <Make> <SKU> - Windows <Version> <Arch>" (Microsoft)
        $nameParts = $pkg.Name -split ' - '
        if ($nameParts.Count -lt 2) { continue }

        $makeMatch = $nameParts[1] -match '^(Lenovo|Dell|HP|Microsoft)'
        if (-not $makeMatch) { continue }

        $pkgMake = $matches[1]
        $status = "Up to date"
        $catalogDate = "N/A"

        # Extract model/SKU from package name (everything after the make name)
        $modelOrSku = $nameParts[1] -replace "^$pkgMake\s+", ''

        # Extract OS info from second part
        $osPart = if ($nameParts.Count -ge 3) { $nameParts[2] } else { "" }

        try {
            switch ($pkgMake) {
                "Lenovo" {
                    # Find the model in the catalog
                    $catalogModel = $global:LenovoModelDrivers | Where-Object { $_.Name -eq $modelOrSku } | Select-Object -First 1
                    if ($catalogModel -and $catalogModel.SCCM) {
                        # Match by OS version (e.g. "Windows 11 23H2" -> os=win11, version=23H2)
                        $versionMatch = $osPart -match '(\d{2}H\d)'
                        $catalogOs = if ($osPart -match '11') { 'win11' } else { 'win10' }
                        $catalogVersion = if ($versionMatch) { $matches[1] } else { "" }

                        $matchingSccm = $catalogModel.SCCM | Where-Object {
                            $_.os -eq $catalogOs -and ($catalogVersion -eq "" -or $_.version -eq $catalogVersion -or $_.version -eq '*')
                        } | Sort-Object date -Descending | Select-Object -First 1

                        if ($matchingSccm) {
                            $catalogDate = $matchingSccm.date
                            if ($pkg.Version -and $catalogDate -gt $pkg.Version) {
                                $status = "Outdated (catalog: $catalogDate)"
                            }
                            elseif (-not $pkg.Version) {
                                $status = "No version set"
                            }
                        }
                    }
                }
                "Dell" {
                    $catalogModel = $global:DellModelDrivers | ForEach-Object { $_.SupportedSystems.Brand.Model } | Where-Object { $_.name -eq $modelOrSku } | Select-Object -First 1
                    if ($catalogModel) {
                        $catalogDate = $catalogModel.rtsDate
                        if ($catalogDate -and $pkg.Version -and $catalogDate -gt $pkg.Version) {
                            $status = "Outdated (catalog: $catalogDate)"
                        }
                    }
                }
                "HP" {
                    $catalogModel = $global:HPModelDrivers | Where-Object { $_.SystemName -eq $modelOrSku } | Select-Object -First 1
                    if ($catalogModel) {
                        $catalogDate = "Latest"
                    }
                }
                "Microsoft" {
                    $catalogModel = $global:MicrosoftModelDrivers | Where-Object { $_.Product -eq $modelOrSku } | Select-Object -First 1
                    if ($catalogModel) {
                        $catalogDate = $catalogModel.CatalogVersion
                    }
                }
            }
        }
        catch { $status = "Error: $($_.Exception.Message)" }

        [pscustomobject]@{
            Name           = $pkg.Name
            PackageID      = $pkg.PackageID
            CurrentVersion = $pkg.Version
            CatalogVersion = $catalogDate
            Status         = $status
        }
    }

    if ($Results) {
        # Filter to only show packages with updates available (not "Up to date")
        $UpdateResults = $Results | Where-Object { $_.Status -ne "Up to date" }
        
        if ($UpdateResults) {
            Write-LogEntry -Value "======== Update-Packages Report ========" -Severity 1
            if ($HighlightUpdates) {
                # Render as text so outdated rows can be colorized in interactive CLI output.
                $tableLines = $UpdateResults |
                Format-Table Name, PackageID, CurrentVersion, CatalogVersion, Status -AutoSize |
                Out-String -Width 4096 -Stream

                foreach ($line in $tableLines) {
                    if ($line -match 'Outdated') {
                        Write-Host $line -ForegroundColor Yellow
                    }
                    else {
                        Write-Host $line
                    }
                }
            }
            else {
                $UpdateResults | Format-Table -AutoSize
                return $UpdateResults
            }
        }
        else {
            Write-LogEntry -Value "- All packages are up to date." -Severity 1
        }
    }
}

# // =================== INTERACTIVE CLI ====================== //

function Start-DATCLI {
    <#
    .SYNOPSIS
        Launches an interactive command-line interface for the DATCLI.
    #>
    [CmdletBinding()]
    param ()

    $OEMMenu = @(
        @{ Key = "1"; Label = "Dell"; FindCmd = "Find-DellModel"; GetCmd = "Get-DellDrivers" },
        @{ Key = "2"; Label = "HP"; FindCmd = "Find-HPModel"; GetCmd = "Get-HPDrivers" },
        @{ Key = "3"; Label = "Lenovo"; FindCmd = "Find-LenovoModel"; GetCmd = "Get-LenovoDrivers" },
        @{ Key = "4"; Label = "Microsoft"; FindCmd = "Find-MicrosoftModel"; GetCmd = "Get-MicrosoftDrivers" },
        @{ Key = "5"; Label = "Custom"; FindCmd = $null; GetCmd = "Get-CustomDrivers" }
    )

    function Show-Header {
        param([string]$Breadcrumb = "Main Menu")
        Clear-Host
        Write-Host ""
        Write-Host "  ==============================================" -ForegroundColor DarkCyan
        Write-Host "   DATCLI $ScriptRelease > $Breadcrumb" -ForegroundColor White
        Write-Host "  ==============================================" -ForegroundColor DarkCyan
    }

    function Show-Status {
        $connected = if ($global:ConfigMgrValidation -and $global:SiteServer) { "$global:SiteServer" } else { "Not connected" }
        Write-Host ""
        Write-Host "    Connected:  $connected" -ForegroundColor Gray
        $catalogAge = @()
        $catalogMap = @(
            @{ File = $global:LenovoXMLFile; Name = "Lenovo" },
            @{ File = $global:DellXMLFile; Name = "Dell" },
            @{ File = $global:HPXMLFile; Name = "HP" },
            @{ File = $global:MicrosoftJSONFile; Name = "Microsoft" }
        )
        foreach ($entry in $catalogMap) {
            if (-not $entry.File) { continue }
            $path = Join-Path $global:TempDirectory $entry.File
            if (Test-Path $path) {
                $age = [math]::Round((New-TimeSpan -Start (Get-Item $path).LastWriteTime -End (Get-Date)).TotalHours, 1)
                $catalogAge += "$($entry.Name) ${age}h"
            }
        }
        if ($catalogAge.Count -gt 0) {
            Write-Host "    Catalogs:   $($catalogAge -join ' | ')" -ForegroundColor Gray
        }
    }

    function Show-OEMMenu {
        param([string]$Action, [string]$Filter, [string]$Breadcrumb)
        Show-Header -Breadcrumb $Breadcrumb
        Write-Host ""
        Write-Host "  Select OEM for ${Action}:" -ForegroundColor Cyan
        $filteredOEMs = if ($Filter -eq "FindModel") { $OEMMenu | Where-Object { $_.FindCmd } } else { $OEMMenu }
        foreach ($oem in $filteredOEMs) {
            Write-Host "    [$($oem.Key)] $($oem.Label)"
        }
        Write-Host "    [B] Back"
        return (Read-Host "  Selection")
    }

    function Show-SubMenu {
        param([string]$Title, [string[]]$Items, [string]$Breadcrumb)
        Show-Header -Breadcrumb $Breadcrumb
        Write-Host ""
        Write-Host "  $Title" -ForegroundColor Cyan
        for ($i = 0; $i -lt $Items.Count; $i++) {
            Write-Host "    [$($i + 1)] $($Items[$i])"
        }
        Write-Host "    [B] Back"
        return (Read-Host "  Selection")
    }

    function Format-PackDisplay {
        param([psobject]$Pack)
        $parts = @($Pack.Name)
        if ($Pack.SKU) { $parts += "| $($Pack.SKU)" }
        if ($Pack.OS) { $parts += "| $($Pack.OS)" }
        if ($Pack.FileName) { $parts += "| $($Pack.FileName)" }
        return ($parts -join ' ')
    }

    function Show-PackResults {
        param([object[]]$Results)
        for ($i = 0; $i -lt $Results.Count; $i++) {
            Write-Host "    [$($i + 1)] $(Format-PackDisplay -Pack $Results[$i])"
        }
    }

    function Select-PackFromResults {
        param([object[]]$Results)
        while ($true) {
            Write-Host "    [S] Search again"
            Write-Host "    [B] Back"
            $selection = Read-Host "  Select pack number"
            switch ($selection.ToUpper()) {
                "B" { return [pscustomobject]@{ Action = "back"; Pack = $null } }
                "S" { return [pscustomobject]@{ Action = "search"; Pack = $null } }
                default {
                    if ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $Results.Count) {
                        return [pscustomobject]@{ Action = "select"; Pack = $Results[[int]$selection - 1] }
                    }
                    Write-Host "  Invalid selection. Enter a pack number, S, or B." -ForegroundColor Yellow
                }
            }
        }
    }

    function Invoke-CLIPackagePrecheck {
        param([hashtable]$SelectedOEM, [psobject]$SelectedModel, [psobject]$Settings)
        $packInput = if ($SelectedOEM.FindCmd) { Resolve-DriverPackageCheckInput -OEM $SelectedOEM.Label -SelectedModel $SelectedModel } else { $null }
        $hasExistingPackage = $false

        if ($Settings.SiteServer -and $SelectedOEM.FindCmd) {
            Write-Host ""
            Write-Host "  Checking for existing SCCM package..." -ForegroundColor Yellow
            $pkgCheck = Test-DriverPackageExists -SiteServer $Settings.SiteServer -OEM $SelectedOEM.Label -SelectedModel $SelectedModel -TimeoutSec 10
            if ($pkgCheck.CanCheck) {
                Write-Host "  Checking for package: $($pkgCheck.PackageName)" -ForegroundColor Yellow
                if ($pkgCheck.ExistingPackage) {
                    $hasExistingPackage = $true
                    Write-Host "  Found existing SCCM package: $($pkgCheck.PackageName)" -ForegroundColor Yellow
                    Write-Host "  Package ID: $($pkgCheck.ExistingPackage.PackageID), Version: $($pkgCheck.ExistingPackage.Version)" -ForegroundColor Yellow
                }
                elseif ($pkgCheck.NewerPackage) {
                    $hasExistingPackage = $true
                    Write-Host "  Found newer package in SCCM for this model/OS family/arch: $($pkgCheck.NewerPackage.Name)" -ForegroundColor Yellow
                    Write-Host "  Package ID: $($pkgCheck.NewerPackage.PackageID), Version: $($pkgCheck.NewerPackage.Version)" -ForegroundColor Yellow
                    Write-Host "  Selected pack is older than existing content. Use Force to replace it." -ForegroundColor Yellow
                }
            }
            elseif ($pkgCheck.Reason) {
                Write-Host "  Package pre-check skipped: $($pkgCheck.Reason)" -ForegroundColor DarkYellow
            }
        }

        return [pscustomobject]@{
            PackInput          = $packInput
            HasExistingPackage = $hasExistingPackage
        }
    }

    function Select-PackAction {
        param([psobject]$SelectedModel, [bool]$HasExistingPackage)
        while ($true) {
            Write-Host ""
            Write-Host "  Selected: $(Format-PackDisplay -Pack $SelectedModel)" -ForegroundColor Green
            if ($HasExistingPackage) {
                Write-Host "    [F] Force update" -ForegroundColor Cyan
            }
            else {
                Write-Host "    [D] Download" -ForegroundColor Cyan
            }
            Write-Host "    [S] Search again"
            Write-Host "    [B] Back"

            $confirm = Read-Host "  Selection"
            if ($HasExistingPackage) {
                switch ($confirm.ToUpper()) {
                    "F" { return [pscustomobject]@{ Action = "start"; Force = $true } }
                    "S" { return [pscustomobject]@{ Action = "search"; Force = $false } }
                    "B" { return [pscustomobject]@{ Action = "back"; Force = $false } }
                    default { Write-Host "  Invalid selection. Enter F, S, or B." -ForegroundColor Yellow }
                }
            }
            else {
                switch ($confirm.ToUpper()) {
                    "D" { return [pscustomobject]@{ Action = "start"; Force = $false } }
                    "S" { return [pscustomobject]@{ Action = "search"; Force = $false } }
                    "B" { return [pscustomobject]@{ Action = "back"; Force = $false } }
                    default { Write-Host "  Invalid selection. Enter D, S, or B." -ForegroundColor Yellow }
                }
            }
        }
    }

    function Invoke-CLISelectedDownload {
        param([hashtable]$SelectedOEM, [psobject]$SelectedModel, [psobject]$PackInput, [bool]$ForcePrompt)
        Write-Host ""
        Write-Host "  Starting $($SelectedOEM.Label) driver workflow..." -ForegroundColor Green
        Write-Host ""

        if ($SelectedOEM.Label -eq "Microsoft" -and $SelectedModel.SKU) {
            $invokeParams = @{
                Model   = $SelectedModel.Name
                Product = $SelectedModel.SKU
            }
            if ($PackInput) {
                if ($PackInput.OSName) { $invokeParams.OSName = $PackInput.OSName }
                if ($PackInput.OSVersion) { $invokeParams.OSVersion = $PackInput.OSVersion }
            }
            if ($ForcePrompt) { $invokeParams.Force = $true }
            & $SelectedOEM.GetCmd @invokeParams
        }
        else {
            $invokeParams = @{ Model = $SelectedModel.Name }
            if ($PackInput) {
                if ($PackInput.OSName) { $invokeParams.OSName = $PackInput.OSName }
                if ($PackInput.OSVersion) { $invokeParams.OSVersion = $PackInput.OSVersion }
                if ($PackInput.Architecture) { $invokeParams.Architecture = $PackInput.Architecture }
            }
            if ($ForcePrompt) { $invokeParams.Force = $true }
            & $SelectedOEM.GetCmd @invokeParams
        }

        Read-Host "  Press Enter to continue"
    }

    function Invoke-CLIDownloadSearchFlow {
        param([hashtable]$SelectedOEM, [psobject]$Settings)
        while ($true) {
            Show-Header -Breadcrumb "Download Drivers > $($SelectedOEM.Label)"
            Write-Host ""
            $searchTerm = Read-Host "  Enter model search (B=Back, Q=Quit)"
            switch ($searchTerm.ToUpper()) {
                "B" { return "back" }
                "Q" { return "quit" }
                "" { continue }
            }

            Write-Host ""
            $results = & $SelectedOEM.FindCmd -Model $searchTerm
            if (-not $results) {
                Write-Host "  No models found matching '$searchTerm'." -ForegroundColor Yellow
                Write-Host "    [S] Search again" -ForegroundColor Cyan
                Write-Host "    [B] Back"
                $action = Read-Host "  Selection"
                if ($action.ToUpper() -eq "B") { return "back" }
                continue
            }

            Write-Host "  Found $($results.Count) matching pack(s):" -ForegroundColor Green
            Write-Host ""
            Show-PackResults -Results $results
            Write-Host ""

            $selected = Select-PackFromResults -Results $results
            if ($selected.Action -eq "search" -or $selected.Action -eq "back") { continue }
            if (-not $selected.Pack) { continue }

            $precheck = Invoke-CLIPackagePrecheck -SelectedOEM $SelectedOEM -SelectedModel $selected.Pack -Settings $Settings
            $actionResult = Select-PackAction -SelectedModel $selected.Pack -HasExistingPackage $precheck.HasExistingPackage
            if ($actionResult.Action -eq "search" -or $actionResult.Action -eq "back") { continue }

            Invoke-CLISelectedDownload -SelectedOEM $SelectedOEM -SelectedModel $selected.Pack -PackInput $precheck.PackInput -ForcePrompt $actionResult.Force
            return "done"
        }
    }

    while ($true) {
        Show-Header
        Show-Status
        Write-Host ""
        Write-Host "    [1] Model Lookup"
        Write-Host "    [2] Download Drivers"
        Write-Host "    [3] Create Custom Driver Package"
        Write-Host "    [4] Browse Packages"
        Write-Host "    [5] Settings"
        Write-Host "    [Q] Quit"
        Write-Host ""
        Write-Host "  ==============================================" -ForegroundColor DarkCyan

        $mainChoice = Read-Host "  Selection"

        switch ($mainChoice.ToUpper()) {
            "1" {
                $lookupChoice = Show-SubMenu -Title "Model Lookup" -Items @("Search all OEMs", "Lenovo", "Dell", "HP", "Microsoft") -Breadcrumb "Model Lookup"
                if ($lookupChoice -match '^[1-5]$') {
                    $searchModel = Read-Host "  Enter model search term"
                    if ($searchModel) {
                        Write-Host ""
                        if ($lookupChoice -eq "1") {
                            $results = Find-DriverModel -Model $searchModel
                        }
                        else {
                            $oemMap = @{ "2" = "Find-LenovoModel"; "3" = "Find-DellModel"; "4" = "Find-HPModel"; "5" = "Find-MicrosoftModel" }
                            $results = & $oemMap[$lookupChoice] -Model $searchModel
                        }
                        if ($results) {
                            $results | Format-Table -AutoSize
                        }
                        else {
                            Write-Host "  No models found matching '$searchModel'." -ForegroundColor Yellow
                        }
                        Read-Host "  Press Enter to continue"
                    }
                }
            }
            "2" {
                try {
                    $oemChoice = Show-OEMMenu -Action "Download Drivers" -Breadcrumb "Download Drivers"
                    if ($oemChoice -match '^\d+$' -and [int]$oemChoice -ge 1 -and [int]$oemChoice -le 5) {
                        $selectedOEM = $OEMMenu[[int]$oemChoice - 1]
                        $settings = Get-DASettings
                        if (-not $selectedOEM.FindCmd) {
                            Write-Host ""
                            Write-Host "  Starting $($selectedOEM.Label) driver workflow..." -ForegroundColor Green
                            Write-Host ""
                            & $selectedOEM.GetCmd
                            Read-Host "  Press Enter to continue"
                        }
                        else {
                            $flowResult = Invoke-CLIDownloadSearchFlow -SelectedOEM $selectedOEM -Settings $settings
                            if ($flowResult -eq "quit") { return }
                        }
                    }
                }
                catch {
                    Write-LogEntry -Value "[Error] - Download Drivers menu failed: $($_.Exception.Message)" -Severity 3
                    Write-Host ""
                    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
                    Read-Host "  Press Enter to continue"
                }
            }
            "3" {
                Write-Host ""
                Write-Host "  Starting custom driver package creation..." -ForegroundColor Green
                Write-Host ""
                Get-CustomDrivers
                Read-Host "  Press Enter to continue"
            }
            "4" {
                $pkgMenuLoop = $true
                while ($pkgMenuLoop) {
                    $pkgChoice = Show-SubMenu -Title "Browse Packages" -Items @("Browse Packages", "Check for Updates") -Breadcrumb "Browse Packages"
                    if ($pkgChoice -eq "1") {
                        $filterLoop = $true
                        while ($filterLoop) {
                            $makeChoice = Show-SubMenu -Title "Filter by OEM" -Items @("All OEMs", "Lenovo", "Dell", "HP", "Microsoft", "Custom") -Breadcrumb "Browse Packages > Filter"
                            if ($makeChoice -match '^[1-6]$') {
                                $makeMap = @{ "1" = "All"; "2" = "Lenovo"; "3" = "Dell"; "4" = "HP"; "5" = "Microsoft"; "6" = "Custom" }
                                Write-Host ""
                                $packages = Get-Packages -Make $makeMap[$makeChoice]
                                if ($packages) {
                                    $packages | Format-Table -AutoSize
                                }
                                else {
                                    Write-Host "  No packages found." -ForegroundColor Yellow
                                }
                                Read-Host "  Press Enter to continue"
                            }
                            elseif ($makeChoice -eq "B") {
                                $filterLoop = $false
                            }
                        }
                    }
                    elseif ($pkgChoice -eq "2") {
                        Write-Host ""
                        Write-Host "  Checking packages against catalog versions..." -ForegroundColor Green
                        Write-Host ""
                        Update-Packages -HighlightUpdates
                        Read-Host "  Press Enter to continue"
                    }
                    elseif ($pkgChoice -eq "B") {
                        $pkgMenuLoop = $false
                    }
                }
            }
            "5" {
                $settingsChoice = Show-SubMenu -Title "Settings" -Items @("View Settings", "Configure Settings", "Refresh Catalogs") -Breadcrumb "Settings"
                if ($settingsChoice -eq "1") {
                    Write-Host ""
                    $settings = Get-DASettings
                    if ($settings) {
                        $settings | Format-List
                    }
                    Write-Host "  [1] Modify Settings" -ForegroundColor Cyan
                    Write-Host "  [B] Back to menu"
                    $afterView = Read-Host "  Selection"
                    if ($afterView -eq "1") {
                        Write-Host ""
                        Write-Host "  Launching interactive settings configuration..." -ForegroundColor Green
                        Write-Host ""
                        Set-DASettings
                    }
                }
                elseif ($settingsChoice -eq "2") {
                    Write-Host ""
                    Write-Host "  Launching interactive settings configuration..." -ForegroundColor Green
                    Write-Host ""
                    Set-DASettings
                }
                elseif ($settingsChoice -eq "3") {
                    Write-Host ""
                    Write-Host "  Forcing catalog refresh for all OEMs..." -ForegroundColor Green
                    Write-Host ""
                    $global:LenovoModelXML = $null
                    $global:LenovoModelDrivers = $null
                    $global:DellModelXML = $null
                    $global:DellModelDrivers = $null
                    $global:HPModelXML = $null
                    $global:HPModelDrivers = $null
                    $global:MicrosoftModelDrivers = $null
                    foreach ($file in @($global:LenovoXMLFile, $global:LenovoXMLCabFile, $global:DellXMLFile, $global:DellXMLCabFile, $global:HPXMLFile, $global:HPXMLCabFile, $global:MicrosoftJSONFile)) {
                        if ($file) {
                            $path = Join-Path $global:TempDirectory $file
                            if (Test-Path $path) {
                                Remove-Item $path -Force -ErrorAction SilentlyContinue
                            }
                        }
                    }
                    Write-Host "  Downloading Lenovo catalog..." -ForegroundColor Cyan
                    Find-LenovoModel -Model "*" | Out-Null
                    Write-Host "  Downloading Dell catalog..." -ForegroundColor Cyan
                    Find-DellModel -Model "*" | Out-Null
                    Write-Host "  Downloading HP catalog..." -ForegroundColor Cyan
                    Find-HPModel -Model "*" | Out-Null
                    Write-Host "  Downloading Microsoft catalog..." -ForegroundColor Cyan
                    Find-MicrosoftModel -Model "*" | Out-Null
                    Write-Host ""
                    Write-Host "  All catalogs refreshed." -ForegroundColor Green
                    Read-Host "  Press Enter to continue"
                }
            }
            "Q" {
                Write-Host ""
                Write-Host "  Goodbye." -ForegroundColor DarkCyan
                return
            }
            default {
                Write-Host "  Invalid selection." -ForegroundColor Red
                Start-Sleep -Milliseconds 500
            }
        }
    }
}

function Start-DriverAutomationCLI {
    <#
    .SYNOPSIS
        Backward-compatible wrapper for Start-DATCLI.
    #>
    [CmdletBinding()]
    param()

    Start-DATCLI
}

# Export functions - only user-facing commands
Export-ModuleMember -Function @(
    # Settings
    'Get-DASettings',
    'Set-DASettings',
    # OEM / Lenovo Driver Automation
    'Find-LenovoModel',
    'Get-LenovoDrivers',
    # OEM / Dell Driver Automation
    'Find-DellModel',
    'Get-DellDrivers',
    # OEM / HP Driver Automation
    'Find-HPModel',
    'Get-HPDrivers',
    # OEM / Microsoft Driver Automation
    'Find-MicrosoftModel',
    'Get-MicrosoftDrivers',
    # Custom Driver Automation
    'Get-CustomDrivers',
    # Package Management
    'Get-Packages',
    'Find-DriverModel',
    'Update-Packages',
    # Interactive CLI
    'Start-DATCLI',
    'Start-DriverAutomationCLI'
)



