<#
.SYNOPSIS
    Analyzes FlexLM license usage logs to calculate session durations and frequencies.

.DESCRIPTION
    Parses FlexLM debug logs, tracking TIMESTAMP, OUT, and IN events. 
    Handles multi-day sessions and provides a summary report by Feature and User.
    Automatically exports results to an Excel (.xlsx) file if the ImportExcel module is available.

.PARAMETER LogPath
    Path to the FlexLM log file to analyze.

.PARAMETER ExportCsv
    Optional path to export raw session data to a CSV file.

.EXAMPLE
    .\Analyze-FlexLMUsage.ps1 -LogPath "C:\Logs\flexlm.log"
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$LogPath,

    [Parameter(Mandatory = $false)]
    [string]$ExportCsv
)

if (-not (Test-Path $LogPath)) {
    Write-Error "Log file not found: $LogPath"
    return
}
$LogPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogPath)

$sessions = New-Object System.Collections.Generic.List[PSObject]
$activeCheckouts = @{} # Key: "feature|user|hostname"

$currentDate = $null
$minDate = $null
$maxDate = $null

# Regex patterns
$tsRegex = 'TIMESTAMP\s+(?<date>\d{1,2}/\d{1,2}/\d{4})'
$startRegex = '\((?<date>\d{1,2}/\d{1,2}/\d{4})\)$'
$outRegex = '^\s*(?<time>\d{1,2}:\d{2}:\d{2})\s+\((?<daemon>\w+)\)\s+OUT:\s+"(?<feature>.+)"\s+(?<user>.+?)@(?<host>.+)\s*$'
$inRegex = '^\s*(?<time>\d{1,2}:\d{2}:\d{2})\s+\((?<daemon>\w+)\)\s+IN:\s+"(?<feature>.+)"\s+(?<user>.+?)@(?<host>.+)\s*$'

# Read file using Get-Content (more resilient than .NET StreamReader for some log artifacts)
try {
    foreach ($line in Get-Content -Path $LogPath -ErrorAction Stop) {
        # 1. Look for Date initialization
        if ($line -match $tsRegex) {
            $currentDate = [DateTime]::ParseExact($Matches.date, "M/d/yyyy", [System.Globalization.CultureInfo]::InvariantCulture)
            if ($null -eq $minDate -or $currentDate -lt $minDate) { $minDate = $currentDate }
            if ($null -eq $maxDate -or $currentDate -gt $maxDate) { $maxDate = $currentDate }
            continue
        }
        if ($null -eq $currentDate -and $line -match $startRegex) {
            $currentDate = [DateTime]::ParseExact($Matches.date, "M/d/yyyy", [System.Globalization.CultureInfo]::InvariantCulture)
            if ($null -eq $minDate -or $currentDate -lt $minDate) { $minDate = $currentDate }
            if ($null -eq $maxDate -or $currentDate -gt $maxDate) { $maxDate = $currentDate }
            continue
        }

        if ($null -eq $currentDate) { continue }

        # 2. Handle OUT
        if ($line -match $outRegex) {
            $timeStr = $Matches.time
            $feature = $Matches.feature.Trim()
            $user = $Matches.user.Trim()
            $hostname = $Matches.host.Trim()

            $checkoutTime = [DateTime]::ParseExact("$($currentDate.ToString('yyyy-MM-dd')) $timeStr", "yyyy-MM-dd H:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
            
            $key = "$feature|$user|$hostname"
            if (-not $activeCheckouts.ContainsKey($key)) {
                $activeCheckouts[$key] = New-Object System.Collections.Generic.Stack[DateTime]
            }
            $activeCheckouts[$key].Push($checkoutTime)
            continue
        }

        # 3. Handle IN
        if ($line -match $inRegex) {
            $timeStr = $Matches.time
            $feature = $Matches.feature.Trim()
            $user = $Matches.user.Trim()
            $hostname = $Matches.host.Trim()

            $checkinTime = [DateTime]::ParseExact("$($currentDate.ToString('yyyy-MM-dd')) $timeStr", "yyyy-MM-dd H:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
            
            $key = "$feature|$user|$hostname"
            if ($activeCheckouts.ContainsKey($key) -and $activeCheckouts[$key].Count -gt 0) {
                $checkoutTime = $activeCheckouts[$key].Pop()
                
                # Handle cases where IN is slightly before OUT due to midnight or clock drift
                if ($checkinTime -lt $checkoutTime) {
                    $checkinTime = $checkinTime.AddDays(1)
                }

                $duration = $checkinTime - $checkoutTime
                
                $sessions.Add([PSCustomObject]@{
                        Feature         = $feature
                        User            = $user
                        Host            = $hostname
                        Checkout        = $checkoutTime
                        Checkin         = $checkinTime
                        DurationSeconds = $duration.TotalSeconds
                        DurationString  = "$($duration.Hours):$($duration.Minutes):$($duration.Seconds)"
                    })
            }
            continue
        }
    }
}
catch {
    Write-Error "Error reading log file: $($_.Exception.Message)"
}
finally {
    # No reader to close with Get-Content
}

Write-Host "Processed $($sessions.Count) sessions."
if ($null -ne $minDate -and $null -ne $maxDate) {
    Write-Host "Usage Stats Date Range: $($minDate.ToShortDateString()) to $($maxDate.ToShortDateString())" -ForegroundColor Cyan
}

if ($sessions.Count -gt 0) {
    # Summarize By Feature and User
    $report = $sessions | Group-Object Feature, User | Select-Object `
    @{Name = "Feature"; Expression = { $_.Values[0] } },
    @{Name = "User"; Expression = { $_.Values[1] } },
    @{Name = "SessionCount"; Expression = { $_.Count } },
    @{Name = "TotalTimeSeconds"; Expression = { ($_.Group | Measure-Object DurationSeconds -Sum).Sum } },
    @{Name = "AvgTimeSeconds"; Expression = { ($_.Group | Measure-Object DurationSeconds -Average).Average } }

    $finalReport = $report | Select-Object *, 
    @{Name = "TotalTimeFormatted"; Expression = {
            $t = [Timespan]::FromSeconds($_.TotalTimeSeconds)
            "$( [Math]::Floor($t.TotalHours) ):$($t.Minutes.ToString('00')):$($t.Seconds.ToString('00'))"
        }
    } | Sort-Object TotalTimeSeconds -Descending

    $finalReport | Format-Table -AutoSize

    # Excel Export
    if (Get-Module -ListAvailable ImportExcel) {
        $excelPath = Join-Path $PSScriptRoot "FlexLM_Usage_Report.xlsx"
        try {
            # Export Summary and Raw Sessions to different sheets
            $finalReport | Export-Excel -Path $excelPath -WorksheetName "Usage Summary" -AutoSize -TableStyle Medium2 -Show:$false
            $sessions | Export-Excel -Path $excelPath -WorksheetName "Raw Sessions" -AutoSize -TableStyle Medium1 -Show:$false
            Write-Host "Excel report exported to: $excelPath" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to export to Excel: $($_.Exception.Message)"
        }
    }
    else {
        Write-Verbose "ImportExcel module not found. Skipping Excel export."
    }

    if ($ExportCsv) {
        $sessions | Export-Csv -Path $ExportCsv -NoTypeInformation
        Write-Host "Full session data exported to $ExportCsv"
    }
}
else {
    Write-Warning "No license sessions found in log."
}
