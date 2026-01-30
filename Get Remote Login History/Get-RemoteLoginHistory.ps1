<#
.SYNOPSIS
    Retrieves the history of users who have logged into a remote computer in the last X days.
.DESCRIPTION
    Queries the Security event log for Event ID 4624 (Successful Logon) and filters for interactive/remote interactive logon types.
.PARAMETER ComputerName
    The name or IP address of the remote computer.
.PARAMETER Days
    The number of days to look back for logon events. Defaults to 10.
.EXAMPLE
    .\Get-RemoteLoginHistory.ps1 -ComputerName "PC01" -Days 10
#>
param (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [string]$ComputerName,

    [Parameter(Mandatory = $false)]
    [int]$Days = 10
)

process {
    try {
        Write-Host "Connecting to $ComputerName to retrieve login history from the last $Days days..." -ForegroundColor Gray
        
        # Event ID 4624: An account was successfully logged on.
        # Logon Types:
        # 2: Interactive (Keyboard/Console)
        # 7: Unlock (Workstation unlock)
        # 10: RemoteInteractive (RDP)
        # 11: CachedInteractive (Offline logon)
        
        $FilterXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) &lt;= $((($Days * 86400 * 1000)))]]]
      and
      *[EventData[
        (Data[@Name='LogonType']='2' or 
         Data[@Name='LogonType']='7' or 
         Data[@Name='LogonType']='10' or 
         Data[@Name='LogonType']='11')
      ]]
    </Select>
  </Query>
</QueryList>
"@

        $Events = Get-WinEvent -ComputerName $ComputerName -FilterXml $FilterXml -ErrorAction Stop

        $Results = foreach ($LogonEvent in $Events) {
            $EventXml = [xml]$LogonEvent.ToXml()
            $TargetUserName = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
            $TargetDomainName = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetDomainName" }).'#text'
            $LogonType = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq "LogonType" }).'#text'
            
            # Skip system/service accounts
            if ($TargetUserName -match '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|UMFD-\d+|DWM-\d+)$' -or $TargetUserName -match '\$$') {
                continue
            }

            $LogonTypeName = switch ($LogonType) {
                '2' { "Interactive" }
                '7' { "Unlock" }
                '10' { "Remote (RDP)" }
                '11' { "Cached Interactive" }
                Default { "Other ($LogonType)" }
            }

            [PSCustomObject]@{
                TimeCreated  = $Event.TimeCreated
                UserName     = "$TargetDomainName\$TargetUserName"
                LogonType    = $LogonTypeName
                ComputerName = $ComputerName
            }
        }

        if ($Results) {
            $Results | Sort-Object TimeCreated -Descending | Out-Host
        }
        else {
            Write-Warning "No interactive logon events found for $ComputerName in the last $Days days."
        }
    }
    catch {
        Write-Error "Failed to retrieve logs from $ComputerName. Error: $($_.Exception.Message)"
    }
}
