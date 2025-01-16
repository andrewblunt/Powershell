# Script version
$scriptVersion = "3.5"

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
# v3.1a - 21/10/2024 - Attempting to accommodate for locked users. Working!
# v3.1b - 21/10/2024 - Attempting to figure out which loaded profile is active. Using quser which I'm worried may add an extra logon and ruin last logged on when no user is logged on now.
# v3.2  - 10/01/2024 - Improved the GetLastUser and ProcessHost functions. RetrieveAndDisplayADUserDetails function added.
# v3.3  - 13/01/2024 - Working on issues where there are multiple previous profiles. Array is required for multiple but then doesn't work if only 1 last user.
# v3.4  - 13/01/2024 - Copilot suggested optimisations: Reduce redundant calls, improve error handling to be more specific and informative, group related options into try and catch, simplified logic checking for $userProfiles.
# v3.5  - 16/01/2024 - Modularised ProcessHost, added parameter validation, improved error handing, added comments to code.

# Import the SCCM module
Import-Module 'C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1'

# Connect to the SCCM site
Set-Location "UN2:"

# Clear PS Window
Clear-Host

# Function to pause the script
function Pause {
    param (
        [string]$Message = "Press Enter to continue ... "  # Default message to display
    )
    Read-Host -Prompt $Message  # Pause and wait for user input
}

# Get the last logged in date for a computer
function GetLastLoggedIn {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$hostName  # Hostname of the computer
    )
    # Retrieve and display the last logon date of the computer from Active Directory
    Get-ADComputer -Identity $hostName -Properties * | Format-Table LastLogonDate -Autosize -SearchBase $ou
}

# Get the primary user of a device from SCCM
function GetSCCMPrimaryUser {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$deviceName  # Device name in SCCM
    )
    # Retrieve the primary user of the device from SCCM
    $primaryUser = Get-CMUserDeviceAffinity -DeviceName $deviceName | Select-Object -ExpandProperty UniqueUserName
    if ($primaryUser) {
        Write-Output "$primaryUser"  # Return the primary user if found
    } else {
        Write-Output "No primary user found"  # Return a message if no primary user is found
    }
}

# Get the currently logged on user of a device from SCCM
function GetSCCMCurrentLoggedOnUser {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$deviceName  # Device name in SCCM
    )
    # Retrieve the currently logged on user of the device from SCCM
    $loggedOnUser = Get-CMDevice -Name $deviceName | Select-Object -ExpandProperty CurrentLogonUser
    if ($loggedOnUser) {
        Write-Output "$loggedOnUser"  # Return the logged on user if found
    } else {
        Write-Output "No user currently logged on"  # Return a message if no user is currently logged on
    }
}

# Get the logged in user of a computer
function GetLoggedInUser {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [Alias("CN","Name","MachineName")]
        [string[]]$ComputerName = $ENV:ComputerName  # Computer name(s) to check
    )
    process {
        foreach ($computer in $ComputerName) {
            try {
                Write-Information "Testing connection to $computer" -Tags 'Process'
                if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
                    # Retrieve the logged in user of the computer
                    $whoLoggedIn = Get-CimInstance -ComputerName $computer -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty UserName
                    if (!$whoLoggedIn) {
                        Write-Warning "No users logged into $computer"
                    } else {
                        # Return the logged in user information as a custom object
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
                    # Handle unreachable computer
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
        [string]$hostName  # Hostname of the computer
    )
    $PCtype = [int]
    # Retrieve BIOS, computer system, and computer system product information
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
    # Display model and serial number information
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
        [string]$hostName  # Hostname of the computer
    )
    try {
        # Retrieve boot time information
        $boot_time = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $hostName
        $installDate = Get-Date $boot_time.InstallDate
        $lastBootUpTime = Get-Date $boot_time.LastBootUpTime
        # Display install date and last boot time
        Write-Host "Install Date: " $installDate
        Write-Host "Last Boot Time: " $lastBootUpTime
        Write-Host ""
    } catch {
        Write-Warning "Failed to retrieve boot time information for $hostName"
    }
}

# Get the disk space information of a computer
function GetDiskSpace {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$hostName  # Hostname of the computer
    )
    try {
        # Retrieve disk space information
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $hostName -Filter "DeviceID='C:'" | Select-Object Size,FreeSpace
        # Display disk size and free space
        if ([math]::round($disk.FreeSpace / 1GB) -lt 1) {
            Write-Host -NoNewLine "Disk Size on C: " ([math]::round($disk.Size / 1GB)) "GB" "- Free Disk Space on C: "
            Write-Host -ForegroundColor "red" ([math]::round($disk.FreeSpace / 1MB)) "MB"
        } else {
            Write-Host "Disk Size on C: " ([math]::round($disk.Size / 1GB)) "GB" "- Free Disk Space on C: " ([math]::round($disk.FreeSpace / 1GB, 1)) "GB"
        }
    } catch {
        Write-Warning "Failed to retrieve disk space information for $hostName"
    }
}

# Get Active Directory information of a computer
function GetADInfo {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$hostName  # Hostname of the computer
    )
    try {
        # Retrieve AD information
        $ad_loc = (Get-ADComputer $hostName).DistinguishedName
        $ad_loc = $ad_loc -replace ",DC.*"
        $info = Get-ADComputer -Identity $hostName -Properties *
        # Display AD information
        Write-Host $info.CanonicalName $info.IPv4Address
        Write-Host "Last login Date: " $info.LastLogonDate
        Write-Host -NoNewLine "Operating System installed: " $info.OperatingSystem $info.OperatingSystemVersion
        if ([string]::IsNullOrWhiteSpace($info.OperatingSystemServicePack)) {
            Write-Host ""
        } else {
            Write-Host " " $info.OperatingSystemServicePack
            Write-Host ""
        }
        if (![string]::IsNullOrWhiteSpace($info.Description)) {
            Write-Host "Description: " $info.Description
            Write-Host ""
        }
        # Retrieve and display SCCM primary and current user information
        $primaryUser = GetSCCMPrimaryUser -deviceName $hostName
        Write-Host "SCCM Primary User(s): $primaryUser"
        $currentUser = GetSCCMCurrentLoggedOnUser -deviceName $hostName
        Write-Host "SCCM Current User: $currentUser"
        Write-Host ""
        # Check and display patch group information if applicable
        if ($ad_loc -NotMatch "OU=Workstations") {
            CheckPatchGroup -hostName $hostName
        }
    } catch {
        Write-Warning "Failed to retrieve AD information for $hostName"
    }
}

# Check the patch group of a computer
function CheckPatchGroup {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$hostName  # Hostname of the computer
    )
    try {
        # Retrieve patch group information
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
    } catch {
        Write-Warning "Failed to retrieve patch group information for $hostName"
    }
}

# Check if the computer is in Active Directory and get its information
function CheckInAD {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$hostName  # Hostname of the computer
    )
    try {
        GetADInfo -hostName $hostName
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Warning "AD computer object not found"
    } catch {
        Write-Warning "Failed to check AD information for $hostName"
    }
}

# Get the last user who logged into the computer
function GetLastUser {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$hostName  # Hostname of the computer
    )
    try {
        $currentUser = $null
        $loggedInUsers = GetLoggedInUser -ComputerName $hostName
        if ($loggedInUsers) {
            $currentUser = $loggedInUsers | Select-Object -First 1
            $currentUserName = $currentUser.UserName
            $currentUserLogonTime = $currentUser.LogonTime
            $ukDateFormat = $currentUserLogonTime.ToString("dd/MM/yyyy HH:mm:ss")
            try {
                # Retrieve and display current user details from AD
                $currentUserDetails = Get-ADUser -Identity $currentUserName -Properties GivenName, Surname, Department -ErrorAction Ignore
                Write-Host "Current logged on user: $currentUserName       $($currentUserDetails.GivenName) $($currentUserDetails.Surname)       $($currentUserDetails.Department)" -ForegroundColor Red
                Write-Host "Logon time: $ukDateFormat" -ForegroundColor Red
            } catch {
                Write-Warning "Error occurred while retrieving current user details from Active Directory."
            }
        } else {
            # Retrieve and display last user profile information
            $userProfiles = Get-CimInstance -ClassName Win32_UserProfile -ComputerName $hostName -Filter "Special='False'" | 
                            Select-Object @{Name='UserName';Expression={Split-Path $_.LocalPath -Leaf}}, 
                                          Loaded, 
                                          @{Name='LastUseTime';Expression={if ($_.LastUseTime) { Get-Date $_.LastUseTime } else { $null }}} | 
                            Sort-Object LastUseTime -Descending
            if ($userProfiles) {
                $lastUser = $userProfiles.UserName
                Write-Host -NoNewline "Last logged in by " $userProfiles.UserName $userProfiles.LastUseTime[0] -ForegroundColor "red" " "

                # Enhanced validation for $lastUser before calling Get-ADUser
                if ($lastUser -match '^[a-zA-Z0-9][a-zA-Z0-9._-]{2,}$') {
                    try {
                        RetrieveAndDisplayADUserDetails -UserName $lastUser
                    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                        Write-Warning "Using a local account or inactive AD account"
                    }
                } else {
                    Write-Warning "Invalid username detected: $lastUser"
                }
            } else {
                Write-Warning "No user profiles found on $hostName"
            }
        }
        Write-Host ""
    } catch {
        Write-Warning "Failed to retrieve last user information for $hostName"
    }
}

# Helper function to retrieve and display AD user details
function RetrieveAndDisplayADUserDetails {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserName  # Username to retrieve details for
    )
    try {
        # Retrieve and display AD user details
        $adUser = Get-ADUser -Identity $UserName -Properties GivenName, Surname, Department -ErrorAction Ignore
        if ($adUser) {
            Write-Host "$($adUser.GivenName) $($adUser.Surname) - $($adUser.Department)" -ForegroundColor "red"
        }
    } catch {
        Write-Warning "Failed to retrieve AD user details for $UserName"
    }
}

# Function to retrieve host information
function Get-HostInfo {
    param (
        [string]$hostName
    )
    # Retrieve OS information
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $hostName -ErrorAction SilentlyContinue
    if ($osInfo) {
        # Retrieve and display IP address
        Write-Host -NoNewline "IP address (from host): "
        $ipAddress = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ComputerName $hostName | Where-Object { $_.IPAddress -like "1*" } | Select-Object -ExpandProperty IPAddress | Select-Object -First 1
        Write-Host $ipAddress

        # Retrieve logged in user and loaded profiles
        $whoLoggedIn = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $hostName | Select-Object -ExpandProperty UserName
        $loadedProfiles = Get-CimInstance -ClassName Win32_UserProfile -ComputerName $hostName -Filter "Special='False' AND Loaded='True'" | 
                          Select-Object @{Name='UserName';Expression={Split-Path $_.LocalPath -Leaf}}, 
                                        Loaded, 
                                        @{Name='LastUseTime';Expression={if ($_.LastUseTime) { Get-Date $_.LastUseTime } else { $null }}}
        
        # Return the retrieved information
        return @{
            WhoLoggedIn = $whoLoggedIn
            LoadedProfiles = $loadedProfiles
        }
    } else {
        Write-Warning "Failed to retrieve OS information for $hostName"
        return $null
    }
}

# Function to process loaded profiles
function ProcessLoadedProfiles {
    param (
        [array]$loadedProfiles,
        [string]$hostName
    )
    if ($loadedProfiles.Count -gt 0) {
        Write-Warning "No current login details or the machine is locked."
        
        # Get user session information using quser
        $sessions = Invoke-Command -ComputerName $hostName -ScriptBlock { quser } | Select-String -Pattern "(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)" | ForEach-Object {
            $sessionMatches = [regex]::Matches($_, "(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)")
            [PSCustomObject]@{
                UserName = $sessionMatches[0].Groups[1].Value
                SessionName = $sessionMatches[0].Groups[2].Value
                ID = $sessionMatches[0].Groups[3].Value
                State = $sessionMatches[0].Groups[4].Value
                IdleTime = $sessionMatches[0].Groups[5].Value
                LogonTime = $sessionMatches[0].Groups[6].Value
            }
        }
        
        # Process each loaded profile
        foreach ($profile in $loadedProfiles) {
            $userName = $profile.UserName
            $lastUseTime = $profile.LastUseTime
            $session = $sessions | Where-Object { $_.UserName -eq $userName }
            
            if ($session) {
                $state = $session.State
                Write-Host "User: $userName, Last Use Time: $lastUseTime, State: $state" -ForegroundColor "yellow"
            } else {
                Write-Host "User: $userName, Last Use Time: $lastUseTime, State: Unknown" -ForegroundColor "yellow"
            }
        }
        Write-Host ""
    } else {
        Write-Warning "No current login details."
        # Retrieve user profiles
        $userProfiles = Get-CimInstance -ClassName Win32_UserProfile -ComputerName $hostName -Filter "Special='False'" | 
                        Select-Object @{Name='UserName';Expression={Split-Path $_.LocalPath -Leaf}}, 
                                      Loaded, 
                                      @{Name='LastUseTime';Expression={if ($_.LastUseTime) { Get-Date $_.LastUseTime } else { $null }}} | 
                        Sort-Object LastUseTime -Descending
        if ($userProfiles) {
            # Handle single or multiple user profiles
            $lastUser = if ($userProfiles -is [array]) { $userProfiles.UserName[0] } else { $userProfiles.UserName }
            Write-Host -NoNewline "Last logged in by $lastUser $($userProfiles.LastUseTime[0])" -ForegroundColor "red"

            try {
                $adUser = Get-ADUser -Identity $lastUser -Properties *
                Write-Host "$($adUser.GivenName) $($adUser.Surname) - $($adUser.Department)" -ForegroundColor "red"
            } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                Write-Warning "Using a local account or inactive AD account"
            } catch {
                Write-Warning "Error occurred while retrieving AD user details: $_"
            }
        } else {
            Write-Warning "No user profiles found on $hostName"
        }
        Write-Host ""
    }
}

# Main function to process the host
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

    # Check if the host is reachable
    $isReachable = Test-Connection -ComputerName $hostName -BufferSize 16 -Count 1 -Quiet

    if ($isReachable) {
        Write-Host -NoNewline "$hostName is online and "
        CheckInAD -hostName $hostName
        try {
            # Retrieve host information
            $hostInfo = Get-HostInfo -hostName $hostName
            if ($hostInfo) {
                $whoLoggedIn = $hostInfo.WhoLoggedIn
                $loadedProfiles = $hostInfo.LoadedProfiles
                
                if ($whoLoggedIn) {
                    Write-Host "Currently logged in by: $whoLoggedIn" -ForegroundColor "red"
                    $whoLoggedIn = $whoLoggedIn -replace ".*\\"
                    try {
                        $adUser = Get-ADUser -Identity $whoLoggedIn -Properties *
                        Write-Host "$($adUser.GivenName) $($adUser.Surname) - $($adUser.Department)" -ForegroundColor "red"
                    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                        Write-Warning "User is not an AD user account"
                    }
                } else {
                    ProcessLoadedProfiles -loadedProfiles $loadedProfiles -hostName $hostName
                }
                
                # Retrieve additional information
                GetDiskSpace -hostName $hostName
                GetSerialNumber -hostName $hostName
                GetBootTime -hostName $hostName
            }
        } catch {
            Write-Warning "Error occurred while processing $hostName - $_"
        }
    } else {
        Write-Warning "$hostName is not reachable"
        # Continue processing AD information even if the host is unreachable
        CheckInAD -hostName $hostName
    }
}

# MAIN SCRIPT BODY #
do {
    Clear-Host
    $hostName = Read-Host 'Hostname/IP? (exit to quit)'
    if ($hostName -eq "exit") {
        break  # Use break instead of exit for better script control
    }
    if ($hostName -ne "") {
        Write-Host "Script version $scriptVersion"
        ProcessHost -hostName $hostName
        Pause
    }
} while ($hostName -ne "exit")
