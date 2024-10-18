# Script version
$scriptVersion = "3.0d"

# Script to read a host name from user
# Output to screen if PC online, Login details, IP address, OS used and Diskspace, S/N
# AP 22/2/16
# v2.1  - added functions, blank hostname input an exit command. Display description and service pack if exists in AD object
# v2.2  - added more functions and reduced size of code for disk space display. Added checks for access denied to hosts
# v2.3  - display different format for where host is in the AD structure
# v2.4  - added checking to remove spaces after hostname when input
# v2.5  - added install date and last restart date
# v2.6  - 29/04/16 - Only check for patch group if not in Workstations OU
# v2.7  - 05/05/16 - Added make and model to output
# v2.8  - 23/05/16 - Added chassis type to script
# v2.9  - 07/06/16 - Added lastuser name details if no one logged in
# v2.10 - 08/04/2024 - Update get_last_user to handle empty username more gracefully
# v2.11 - 15/04/2024 - Update get_last_user to handle Administrator
# v2.12 - 03/05/2024 - Fix issues with get_last_user introduced in previous versions
# v2.13 - 29/05/2024 - Large rewrite to getting last user inc new function from GitHub. Fixed issue using c$ to detect Windows device.
# v2.14 - 15/10/2024 - Include check for SCCM Primary user and current user
# v3.0a - 18/10/2024 - Modularised
# v3.0b - 18/10/2024 - Renamed and standardised functions and variables
# v3.0c - 18/10/2024 - Further modularisation and add extra comments
# v3.0d - 18/10/2024 - Optimised cmdlets

# Import the SCCM module
Import-Module 'C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1'

# Connect to the SCCM site
cd "UN2:"

# Clear PS Window
clear

# Function to pause the script
function Pause {
    param (
        [string]$Message = "Press Enter to continue ... "
    )
    Read-Host -Prompt $Message
}

# Get the last logged in date for a computer
function GetLastLoggedIn {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$hostName
    )
    Get-ADComputer -Identity $hostName -Properties * | FT LastLogonDate -Autosize -SearchBase $ou
}

# Get the primary user of a device from SCCM
function GetSCCMPrimaryUser {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$deviceName
    )
    $primaryUser = Get-CMUserDeviceAffinity -DeviceName $deviceName | Select-Object -ExpandProperty UniqueUserName
    if ($primaryUser) {
        return "$primaryUser"
    } else {
        return "No primary user found"
    }
}

# Get the currently logged on user of a device from SCCM
function GetSCCMCurrentLoggedOnUser {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$deviceName
    )
    $loggedOnUser = Get-CMDevice -Name $deviceName | Select-Object -ExpandProperty UserName
    if ($loggedOnUser) {
        return "$loggedOnUser"
    } else {
        return "No user currently logged on"
    }
}

# Get the logged in user of a computer
function GetLoggedInUser {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [Alias("CN","Name","MachineName")]
        [string[]]$ComputerName = $ENV:ComputerName
    )
    process {
        foreach ($computer in $ComputerName) {
            try {
                Write-Information "Testing connection to $computer" -Tags 'Process'
                if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
                    $whoLoggedIn = Get-CimInstance -ComputerName $computer -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty UserName
                    if (!$whoLoggedIn) {
                        Write-Warning "No users logged into $computer"
                    } else {
                        [PSCustomObject]@{
                            PSTypeName = "AdminTools.LoggedInUser"
                            ComputerName = $computer
                            UserName = $whoLoggedIn
                            SessionName = "N/A"
                            SessionId = "N/A"
                            State = "Active"
                            IdleTime = "N/A"
                            LogonTime = "N/A"
                            LockScreenPresent = $false
                            LockScreenTimer = (New-TimeSpan)
                            SessionType = "N/A"
                        }
                    }
                } else {
                    $ErrorRecord = [System.Management.Automation.ErrorRecord]::new(
                        [System.Net.NetworkInformation.PingException]::new("$computer is unreachable"),
                        'TestConnectionException',
                        [System.Management.Automation.ErrorCategory]::ConnectionError,
                        $computer
                    )
                    $PSCmdlet.WriteError($ErrorRecord)
                }
            } catch [System.Management.Automation.RemoteException] {
                if ($_.Exception.Message -like "*The RPC server is unavailable*") {
                    Write-Warning "WMI query failed on $computer. Ensure 'Netlogon Service (NP-In)' firewall rule is enabled"
                    $PSCmdlet.WriteError($_)
                } else {
                    $PSCmdlet.WriteError($_)
                }
            } catch [System.Runtime.InteropServices.COMException] {
                Write-Warning "WMI query failed on $computer. Ensure 'Windows Management Instrumentation (WMI-In)' firewall rule is enabled."
                $PSCmdlet.WriteError($_)
            } catch {
                Write-Information "Unexpected error occurred with $computer"
                $PSCmdlet.WriteError($_)
            }
        }
    }
}

# Get the serial number and model information of a computer
function GetSerialNumber {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$hostName
    )
    $PCtype = [int]
    $sn = Get-CimInstance -ClassName Win32_Bios -ComputerName $hostName
    $model = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $hostName
    $model2 = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ComputerName $hostName
    $PCtype = $model.PCSystemType
    $PCSystemType_ReturnValue = @{
        0='Unspecified'
        1='Desktop'
        2='Laptop'
        3='Workstation'
        4='Enterprise Server'
        5='SOHO Server'
        6='Appliance PC'
        7='Performance Server'
        8='Maximum'
    }
    [int]$PCtype = $PCtype
    $PCtype2 = $PCSystemType_ReturnValue.item($PCtype)
    $PCtype2 = $PCtype2.ToUpper()
    Write-Host ""
    if ($sn.Manufacturer -eq "LENOVO") {
        Write-Host "Model: " $model2.Vendor $model2.Version $PCtype2
    } else {
        Write-Host "Model: " $model.Manufacturer $model.Model $PCtype2
    }
    Write-Host "Serial Number: " $sn.SerialNumber
}

# Get the boot time information of a computer
function GetBootTime {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$hostName
    )
    $boot_time = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $hostName
    $installDate = Get-Date $boot_time.InstallDate
    $lastBootUpTime = Get-Date $boot_time.LastBootUpTime
    Write-Host "Install Date: " $installDate
    Write-Host "Last Boot Time: " $lastBootUpTime
    Write ""
}


# Get the disk space information of a computer
function GetDiskSpace {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$hostName
    )
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $hostName -Filter "DeviceID='C:'" | Select-Object Size,FreeSpace
    if ([math]::round($disk.FreeSpace / 1GB) -lt 1) {
        Write-Host -NoNewLine "Disk Size on C: " ([math]::round($disk.Size / 1GB)) "GB" "- Free Disk Space on C: "
        Write-Host -ForegroundColor "red" ([math]::round($disk.FreeSpace / 1MB)) "MB"
    } else {
        Write-Host "Disk Size on C: " ([math]::round($disk.Size / 1GB)) "GB" "- Free Disk Space on C: " ([math]::round($disk.FreeSpace / 1GB, 1)) "GB"
    }
}

# Get Active Directory information of a computer
function GetADInfo {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$hostName
    )
    $ad_loc = (Get-ADComputer $hostName).DistinguishedName
    $ad_loc = $ad_loc -replace ",DC.*"
    $info = Get-ADComputer -Identity $hostName -Properties *
    Write-Host $info.CanonicalName $info.IPv4Address
    Write-Host "Last login Date: " $info.LastLogonDate
    Write-Host -NoNewLine "Operating System installed: " $info.OperatingSystem $info.OperatingSystemVersion
    if ([string]::IsNullOrWhiteSpace($info.OperatingSystemServicePack)) {
        Write-Host ""
    } else {
        Write-Host " " $info.OperatingSystemServicePack
        Write-Host ""
    }
    if ([string]::IsNullOrWhiteSpace($info.Description)) {
    } else {
        Write-Host "Description: " $info.Description
        Write-Host ""
    }
    $primaryUser = GetSCCMPrimaryUser -deviceName $hostName
    Write-Host "SCCM Primary User(s): $primaryUser"
    $currentUser = GetSCCMCurrentLoggedOnUser -deviceName $hostName
    Write-Host "SCCM Current User: $currentUser"
    Write-Host ""
    if ($ad_loc -NotMatch "OU=Workstations") {
        CheckPatchGroup -hostName $hostName
    }
}

# Check the patch group of a computer
function CheckPatchGroup {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$hostName
    )
    $Groups = (Get-ADComputer -Identity $hostName -Properties *).MemberOf
    if ([string]::IsNullOrWhiteSpace($Groups)) {
        Write-Host "Not in any Patch groups"
    } else {
        $Groups | ForEach-Object {
            $groupName = $_.Split(",").Split("=")
            if ($groupName -match "SRV-") {
                Write-Host "In Patch group: $groupName"
            }
        }
    }
}

# Check if the computer is in Active Directory and get its information
function CheckInAD {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$hostName
    )
    try {
        GetADInfo -hostName $hostName
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Warning "AD computer object not found"
    }
}

# Get the last user who logged into the computer
function GetLastUser {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$hostName
    )
    $currentUser = $null
    $lastUsedUser = $null
    $loggedInUsers = GetLoggedInUser -ComputerName $hostName
    if ($loggedInUsers) {
        $currentUser = $loggedInUsers | Select-Object -First 1
        $currentUserName = $currentUser.UserName
        $currentUserLogonTime = $currentUser.LogonTime
        $ukDateFormat = $currentUserLogonTime.ToString("dd/MM/yyyy HH:mm:ss")
        try {
            $currentUserDetails = Get-ADUser -Identity $currentUserName -Properties GivenName, Surname, Department -ErrorAction Ignore
            Write-Host "Current logged on user: $currentUserName       $($currentUserDetails.GivenName) $($currentUserDetails.Surname)       $($currentUserDetails.Department)" -ForegroundColor Red
            Write-Host "Logon time: $ukDateFormat" -ForegroundColor Red
        } catch {
            Write-Warning "Error occurred while retrieving current user details from Active Directory."
        }
    } else {
        $userProfiles = Get-CimInstance -ClassName Win32_UserProfile -ComputerName $hostName -Filter "Special='False'" | Select @{Name='UserName';Expression={Split-Path $_.LocalPath -Leaf}}, Loaded, @{Name='LastUsed';Expression={$_.ConvertToDateTime($_.LastUseTime)}} | Sort LastUsed -Descending
        $lastUser = $userProfiles.username
        try {
            $lastUserDetails = Get-ADUser -Identity $lastUser -Properties * -ErrorAction Continue
        } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Warning "Using a local account or inactive AD account"
        }
        Write-Host "Last logged on user: " -ForegroundColor Red -NoNewline
        Write-Host "$lastUser - " -ForegroundColor Red -NoNewline
        Write-Host $lastUserDetails.CN -ForegroundColor Red -NoNewline
        Write-Host " - " -ForegroundColor Red -NoNewline
        Write-Host $lastUserDetails.Department -ForegroundColor Red
        Write-Host "Last logon time: " $userProfiles.lastused -ForegroundColor "red" " "
    }
    Write-Host ""
}

# Process the host information
function ProcessHost {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$hostName
    )
    $hostName = $hostName.ToUpper().Trim()
    if (($hostName -As [IPAddress]) -As [Bool]) {
        $hostName = [System.Net.Dns]::GetHostByAddress("$hostName").HostName
        $hostName = $hostName.Substring(0, $hostName.IndexOf('.'))
    }
    if (Test-Connection -ComputerName $hostName -BufferSize 16 -Count 1 -Quiet) {
        Write-Host -NoNewLine $hostName.ToUpper() "is online and "
        CheckInAD -hostName $hostName
        try {
            $temp = Get-CimInstance -ClassName Win32_NetworkAdapter -ComputerName $hostName -ErrorAction Continue
            $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $hostName -ErrorAction SilentlyContinue
            if ($osInfo) {
                Write-Host -NoNewLine "IP address (from host): "
                Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ComputerName $hostName | Where-Object { $_.IPAddress -like "1*" } | Select-Object -ExpandProperty IPAddress | Select-Object -First 1
                $whoLoggedIn = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $hostName | Select-Object -ExpandProperty UserName
                if ($whoLoggedIn) {
                    Write-Host "Currently logged in by: $whoLoggedIn" -ForegroundColor Red
                } else {
                    Write-Warning "No current login details"
                    Write-Host ""
                    $userProfiles = Get-CimInstance -ClassName Win32_UserProfile -ComputerName $hostName -Filter "Special='False'" | Select @{Name='UserName';Expression={Split-Path $_.LocalPath -Leaf}}, Loaded, @{Name='LastUsed';Expression={$_.ConvertToDateTime($_.LastUseTime)}} | Sort LastUsed -Descending
                    $lastUser = $userProfiles.username[0]
                    Write-Host -NoNewline "Last used logged in by " $userProfiles.username[0] $userProfiles.lastused[0] -ForegroundColor "red" " "
                    try {
                        $lastUser = Get-ADUser -Identity $lastUser -Properties *
                        Write-Host $lastUser.GivenName $lastUser.Surname "" - $lastUser.Department -ForegroundColor "red"
                    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                        Write-Warning "Using a local account or inactive AD account"
                    }
                }
                GetDiskSpace -hostName $hostName
                GetSerialNumber -hostName $hostName
                GetBootTime -hostName $hostName
            } else {
                Write-Host $hostName "is not running Windows or not connected to AD"
            }
        } catch [System.UnauthorizedAccessException] {
            Write-Host $hostName -ForegroundColor "red" "Access Denied to host"
            Write-Host ""
        } catch [System.Runtime.InteropServices.COMException] {
            if ($_.Exception.ErrorCode -eq 0x800706BA) {
                Write-Error -Message "RPC Server Unavailable"
            } else {
                Write-Error -Message "Some other COMException was thrown"
            }
        }
    } else {
        Write-Host $hostName "is offline"
        CheckInAD -hostName $hostName
    }
}

# MAIN SCRIPT BODY #
do {
    clear
    do {
        clear
        $hostName = Read-Host 'Hostname/IP? (exit to quit)'
    } while ($hostName -eq "")
    if ($hostName -eq "exit") {
        exit
    }
    Write-Host "Script version $scriptVersion"
    ProcessHost -hostName $hostName
    Pause
} while ($hostName -ne "exit")
