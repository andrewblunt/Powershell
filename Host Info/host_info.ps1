# Script version
$scriptVersion = "2.14"

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

$hostn = $null
$whologgedIn =$null
$ou="DC=ad,DC=nottingham,DC=ac,DC=uk"
# $ou="OU=Information Services IE8,OU=Information Services,OU=University Administration,OU=Workstations,OU=University,DC=ad,DC=nottingham,DC=ac,DC=uk"

# Import the SCCM module
Import-Module 'C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1'

# Connect to the SCCM site
cd "UN2:"

# Clear PS Window
clear

# Function Pause($M="Press any key to continue . . . "){If($psISE){$S=New-Object -ComObject "WScript.Shell";$B=$S.Popup("Click OK to continue.",0,"Script Paused",0);Return};Write-Host -NoNewline $M;$I=16,17,18,20,91,92,93,144,145,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183;While($K.VirtualKeyCode -Eq $Null -Or $I -Contains $K.VirtualKeyCode){$K=$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")};Write-Host}

function LastLoggedIn
{
# Display when last logged in
    Get-ADComputer -identity $hostn -Properties * | FT LastLogonDate -Autosize -SearchBase $ou
}

<#
.SYNOPSIS
    This function gets the current user sesions on a remote or local computer.
.DESCRIPTION
    This function uses quser.exe to get the current user sessions from a remote or local computer.
.PARAMETER ComputerName
    Use this paramter to specify the computer you want to run the command aganist using its name or IPAddress.

.EXAMPLE
    PS C:\> Get-LoggedInUser

    ComputerName    UserName ID SessionType State  ScreenLocked IdleTime
    ------------    -------- -- ----------- -----  ------------ --------
    DESKTOP-D7FU4K5 pwsh.cc  1  DirectLogon Active False        0

    This examples gets the logged in users of the local computer.
.EXAMPLE
    Get-LoggedInUser -ComputerName $env:COMPUTERNAME,dc01v

    ComputerName    UserName      ID SessionType State  ScreenLocked IdleTime
    ------------    --------      -- ----------- -----  ------------ --------
    DESKTOP-D7FU4K5 pwsh.cc       1  DirectLogon Active False        0
    dc01v           administrator 1  DirectLogon Active False        0

    This example gets the currently logged on users for the local computer and a remote computer called dc01v.
.INPUTS
    System.String
        You can pipe a string that contains the computer name.
.OUTPUTS
    AdminTools.LoggedInuser
        Outputs a custom powershell object
.NOTES
    Requires Admin
.LINK
    https://github.com/MrPig91/SysAdminTools/wiki/Get%E2%80%90LoggedInUser
#>

function Get-PrimaryUser {
    param (
        [string]$deviceName
    )

    # Get the primary user of the device
    $primaryUser = Get-CMUserDeviceAffinity -DeviceName $deviceName | Select-Object -ExpandProperty UniqueUserName

    if ($primaryUser) {
        # Output the primary user
        return "$primaryUser"
    } else {
        # Output message if no primary user is found
        return "No primary user found"
    }
}

function Get-CurrentLoggedOnUser {
    param (
        [string]$deviceName
    )

    # Get the currently logged-on user for the device
    $loggedOnUser = Get-CMDevice -Name $deviceName | Select-Object -ExpandProperty UserName

    if ($loggedOnUser) {
        # Return the currently logged-on user
        return "$loggedOnUser"
    } else {
        # Return a message if no user is logged on
        return "No user currently logged on"
    }
}

function Get-LoggedInUser () {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [Alias("CN","Name","MachineName")]
        [string[]]$ComputerName = $ENV:ComputerName
    )

    PROCESS {
        foreach ($computer in $ComputerName){
            try{
                Write-Information "Testing connection to $computer" -Tags 'Process'
                if (Test-Connection -ComputerName $computer -Count 1 -Quiet){
                    $Users = quser.exe /server:$computer 2>$null | select -Skip 1

                    if (!$?){
                        Write-Information "Error with quser.exe" -Tags 'Process'
                        if ($Global:Error[0].Exception.Message -eq ""){
                            throw $Global:Error[1]
                        }
                        elseif ($Global:Error[0].Exception.Message -like "No User exists*"){
                            Write-Warning "No users logged into $computer"
                        }
                        else{
                            throw $Global:Error[0]
                        }
                    }
    
                    $LoggedOnUsers = foreach ($user in $users){
                        [PSCustomObject]@{
                            PSTypeName = "AdminTools.LoggedInUser"
                            ComputerName = $computer
                            UserName = (-join $user[1 .. 20]).Trim()
                            SessionName = (-join $user[23 .. 37]).Trim()
                            SessionId = [int](-join $user[38 .. 44])
                            State = (-join $user[46 .. 53]).Trim()
                            IdleTime = (-join $user[54 .. 63]).Trim()
                            #LogonTime = [datetime](-join $user[65 .. ($user.Length - 1)])
                            LogonTime = [datetime]::ParseExact((-join $user[65 .. ($user.Length - 1)]), "dd/MM/yyyy HH:mm", $null)
                            LockScreenPresent = $false
                            LockScreenTimer = (New-TimeSpan)
                            SessionType = "TBD"
                        }
                    }
                    try {
                        Write-Information "Using WinRM and CIM to grab LogonUI process" -Tags 'Process'
                        $LogonUI = Get-CimInstance -ClassName win32_process -Filter "Name = 'LogonUI.exe'" -ComputerName $Computer -Property SessionId,Name,CreationDate -OperationTimeoutSec 1 -ErrorAction Stop
                    }
                    catch{
                        Write-Information "WinRM is not configured for $computer, using Dcom and WMI to grab LogonUI process" -Tags 'Process'
                        $LogonUI = Get-WmiObject -Class win32_process -ComputerName $computer -Filter "Name = 'LogonUI.exe'" -Property SessionId,Name,CreationDate -ErrorAction Stop |
                        select name,SessionId,@{n="Time";e={[DateTime]::Now - $_.ConvertToDateTime($_.CreationDate)}}
                    }
    
                    foreach ($user in $LoggedOnUsers){
                        if ($LogonUI.SessionId -contains $user.SessionId){
                            $user.LockScreenPresent = $True
                            $user.LockScreenTimer = ($LogonUI | where SessionId -eq $user.SessionId).Time
                        }
                        if ($user.State -eq "Disc"){
                            $user.State = "Disconnected"
                        }
                        $user.SessionType = switch -wildcard ($user.SessionName){
                            "Console" {"DirectLogon"; Break}
                            "" {"Unkown"; Break}
                            "rdp*" {"RDP"; Break}
                            default {""}
                        }
                        if ($user.IdleTime -ne "None" -and $user.IdleTime -ne "."){
                            if ($user.IdleTime -Like "*+*"){
                                $user.IdleTime = New-TimeSpan -Days $user.IdleTime.Split('+')[0] -Hours $user.IdleTime.Split('+')[1].split(":")[0] -Minutes $user.IdleTime.Split('+')[1].split(":")[1]
                            }
                            elseif($user.IdleTime -like "*:*"){
                                $user.idleTime = New-TimeSpan -Hours $user.IdleTime.Split(":")[0] -Minutes $user.IdleTime.Split(":")[1]
                            }
                            else{
                                $user.idleTime = New-TimeSpan -Minutes $user.IdleTime
                            }
                        }
                        else{
                            $user.idleTime = New-TimeSpan
                        }
    
                        $user | Add-Member -Name LogOffUser -Value {logoff $this.SessionId /server:$($this.ComputerName)} -MemberType ScriptMethod
                        $user | Add-Member -MemberType AliasProperty -Name ScreenLocked -Value LockScreenPresent

                        Write-Information "Outputting user object $($user.UserName)" -Tags 'Process'
                        $user
                    } #foreach
                } #if ping
                else{
                    $ErrorRecord = [System.Management.Automation.ErrorRecord]::new(
                        [System.Net.NetworkInformation.PingException]::new("$computer is unreachable"),
                        'TestConnectionException',
                        [System.Management.Automation.ErrorCategory]::ConnectionError,
                        $computer
                    )
                    $PSCmdlet.WriteError($ErrorRecord)
                }
            } #try
            catch [System.Management.Automation.RemoteException]{
                if ($_.Exception.Message -like "*The RPC server is unavailable*"){
                    Write-Warning "quser.exe failed on $comptuer, Ensure 'Netlogon Service (NP-In)' firewall rule is enabled"
                    $PSCmdlet.WriteError($_)
                }
                else{
                    $PSCmdlet.WriteError($_)
                }
            }
            catch [System.Runtime.InteropServices.COMException]{
                Write-Warning "WMI query failed on $computer. Ensure 'Windows Management Instrumentation (WMI-In)' firewall rule is enabled."
                $PSCmdlet.WriteError($_)
            }
            catch{
                Write-Information "Unexpected error occurred with $computer"
                $PSCmdlet.WriteError($_)
            }
        } #foreach
    } #process
}

function get_sn
# Display serial number, Make/Model and system type of the host

{
    $PCtype = [int]
    $sn = Get-wmiobject Win32_Bios -ComputerName $hostn
    $model = Get-wmiobject -ComputerName $hostn Win32_ComputerSystem
    $model2 = Get-wmiobject -ComputerName $hostn Win32_Computersystemproduct # Used to store Lenovo model numbers
    $PCtype = $model.PCSystemType # Store the PCSystemType value from WMI

    $PCSystemType_ReturnValue =   # Hash Table for PC System Type
    @{
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

    [int]$PCtype = $PCtype # Convert PCSystemType value to interger
    $PCtype2 = $PCSystemType_ReturnValue.item($PCtype) # Look up the System Type from Hash table
    $PCtype2 = $PCtype2.toupper() # Make System type uppercase

    write-host ""

    if ($sn.Manufacturer -eq "LENOVO")
    {
        write-host "Model: " $model2.Vendor $model2.Version $PCtype2        
        # write-host "Model: " $model.Manufacturer $model.systemfamily $PCtype2
    }
    else # Not a Lenovo model
    {
        write-host "Model: " $model.Manufacturer $model.Model $PCtype2
    }
        
    write-host "Serial Number: " $sn.SerialNumber
}

function get_boot_time
# Display boot time of the PC
{
    #$boot_time = (Get-wmiobject -Class Win32_OperatingSystem -ComputerName $hostn).LastBootUpTime
    $boot_time = Get-WmiObject -Class Win32_OperatingSystem -Computer "$hostn"
    write-host "Install Date: " $boot_time.ConvertToDateTime($boot_time.installdate)
    write-host "Last Boot Time: " $boot_time.ConvertToDateTime($boot_time.LastBootUpTime)
    write ""
}

function get_disk_space # Get disk c: drive details from host
{
    $disk = Get-WmiObject Win32_LogicalDisk -ComputerName $hostn -Filter "DeviceID='C:'" | Select-Object Size,FreeSpace

    # Display Disk Capacity and Freespace of C: Drive
    if ([math]::round($disk.freespace / 1GB) -lt 1) # If less than 1GB hard disk space on C:
    { 
        write-host -NoNewLine "Disk Size on C: " ([math]::round($disk.size / 1GB)) "GB" "- Free Disk Space on C: "
        Write-Host -foreground "red" ([math]::round($disk.freespace / 1MB)) "MB"
    } 

    else # If more than 1GB hard disk space on C:
    {
        write-host "Disk Size on C: " ([math]::round($disk.size / 1GB)) "GB" "- Free Disk Space on C: " ([math]::round($disk.freespace / 1GB, 1)) "GB"
    }
}

function ad_info {
    # Check if PC in AD
    $ad_loc = (get-ADComputer $hostn).distinguishedName  
    $ad_loc = $ad_loc -replace ",DC.*"  # Replace anything including and after ",DC." with nothing

    $info = Get-ADComputer -identity $hostn -Properties *  # Get all AD properties from host
    write-host $info.CanonicalName $info.IPv4Address # Display OU info and Last IP address used

    Write-Host "Last login Date: " $info.LastLogonDate # Display when last logged in
    Write-Host -nonewline "Operating System installed: " $info.OperatingSystem $info.OperatingSystemVersion  # Display OS installed

    if([string]::IsNullOrWhiteSpace($info.OperatingSystemServicePack)) { # Check if Service Pack field in AD is NULL, EMPTY or Whitespace
        write-host "" # Display blank line if no Service Pack
    } else { # Display Service Pack if there is one
        Write-Host " "$info.OperatingSystemServicePack 
        write-host ""
    }

    if ([string]::IsNullOrWhiteSpace($info.Description)) { # Check if Description field in AD is NULL, EMPTY or Whitespace
        #write-host "" # Display blank line if no description
    } else { # Display Description if there is one
        Write-Host "Description: " $info.Description # Display Description if there is one
        write-host ""
    }

    # Get primary user from SCCM
    $primaryUser = Get-PrimaryUser -deviceName $hostn
    Write-Host "SCCM Primary User(s): $primaryUser"
    $currentUser = Get-CurrentLoggedOnUser -deviceName $hostn
    Write-Host "SCCM Current User: $currentUser"
    write-host ""

    if ($ad_loc -NotMatch "OU=Workstations") { # Check if host is in the Workstations OU and if it's not look for patch group
        check_patch_group # Run the check_patch_group function to check which patch group if any the host is in
    }
}


function check_patch_group
{

    $Groups = (Get-ADComputer -identity $hostn -properties *).Memberof # Find which groups host is in

    if ([string]::IsNullOrWhiteSpace($groups)) # Check if Description field in AD is NULL, EMPTY or Whitespace
    {
        Write-Host "Not in any Patch groups"
    }

    else
    {
        $Groups | foreach {
            $groupsa = $_.split(",")[0].Split("=")[1] # Split to just hold just the group name
            if ($groupsa -match "SRV-") # If group name has SRV-
            {
                write-host "In Patch group: $groupsa" # Output the  patch group
            }
        }
    }
}

function in_AD # Check if host in AD and display info about it or display it's not
{
        try 
        {
            ad_info # Check if AD object exists and display info about it
        }

        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]  # If no AD object exists display warning
        {
            Write-Warning "AD computer object not found" # If error when looking up hostname in AD display message
        }
}

function get_last_user {
    $currentUser = $null
    $lastUsedUser = $null

    $loggedInUsers = Get-LoggedInUser -ComputerName $hostn

    if ($loggedInUsers) {
        $currentUser = $loggedInUsers | Select-Object -First 1
        $currentUserName = $currentUser.UserName
        $currentUserLogonTime = $currentUser.LogonTime
        $ukDateFormat = $currentUserLogonTime.ToString("dd/MM/yyyy HH:mm:ss")
        
        #Write-Host "Currently logged in by: $currentUserName" -ForegroundColor Red

        try {
            $currentUserDetails = Get-ADUser -Identity $currentUserName -Properties GivenName, Surname, Department -ErrorAction Ignore
            Write-Host "Current logged on user: $currentUserName       $($currentUserDetails.GivenName) $($currentUserDetails.Surname)       $($currentUserDetails.Department)" -ForegroundColor Red
            Write-Host "Logon time: $ukDateFormat" -ForegroundColor Red
        } catch {
            Write-Warning "Error occurred while retrieving current user details from Active Directory."
        }
    } else {
        #Write-Warning "No user currently logged in."

        $queryLastUser = Get-WmiObject -ComputerName $hostn -Class Win32_UserProfile -Filter "Special='False'" | select @{Name='UserName';Expression={Split-Path $_.LocalPath -Leaf}}, Loaded, @{Name='LastUsed';Expression={$_.ConvertToDateTime($_.LastUseTime)}} | sort LastUsed -Descending 

        $lastUser = $queryLastUser.username[0]

        try
        {
            $lastUserDetails = Get-ADUser -Identity $lastUser -Properties * -ErrorAction Continue # Access all properties for username
            #write-host $un.givenname $un.surname "" - $un.department -foregroundcolor "red" # Display first and surname and department
        }

        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
        {
            Write-Warning "Using a local account or inactive AD account"
        }

            Write-Host "Last logged on user: " -foregroundcolor Red -NoNewline
            Write-Host "$lastUser - " -foregroundcolor Red -NoNewline
            Write-Host $lastUserDetails.CN -foregroundcolor Red -NoNewline
            Write-Host " - " -foregroundcolor Red -NoNewline
            Write-Host $lastUserDetails.department -foregroundcolor Red
            Write-Host "Last logon time: "$queryLastUser.lastused[0] -foregroundcolor "red" " "
    }

    Write-Host ""
}


function process_host {
    $hostn = $hostn.toupper() # Convert hostname into capital letters

    # Removes all leading and trailing white-space characters from the current String object.
    $hostn = $hostn.trim()

    if (($hostn -As [IPAddress]) -As [Bool]) { # Check if input is a valid IP address
        $hostn = [System.Net.Dns]::GetHostbyAddress("$hostn").HostName # If so convert to hostname

        # Remove any text after first .
        $hostn = $hostn.Substring(0, $hostn.IndexOf('.'))
    }

    if (Test-Connection -Computername $hostn -BufferSize 16 -Count 1 -Quiet) { # Test if PC on network by pinging it
        Write-Host -NoNewLine $hostn.toupper() "is online and "
        in_AD # Check if in AD

        try { 
            $temp = Get-WmiObject -ComputerName $hostn -Class "Win32_NetworkAdapter" -ErrorAction continue # Check if host is Windows

            $scriptBlock = { Test-Path "C:\Windows" }
            $isWindowsDevice = Invoke-Command -ComputerName $hostn -ScriptBlock $scriptBlock
            
            if ($isWindowsDevice) { # If host has a Windows folder get information from it such as IP address, last user and disk space
                # Get IP address
                Write-Host -NoNewLine "IP address (from host): "
                Get-WmiObject win32_networkadapterconfiguration -ComputerName $hostn | where { $_.ipaddress -like "1*" } | select -ExpandProperty ipaddress | select -First 1
                
                get_last_user # Run get_last_user function
                get_disk_space # Run get_disk_space function
                get_sn # Run get_sn function
                get_boot_time # Run get_boot_time function
            } else {
                Write-Host $hostn is "not running Windows or not connected to AD"
            }

        } catch [System.UnauthorizedAccessException] {
            Write-host $hostn -foreground "red" "Access Denied to host"
            write-host ""
        } catch [System.Runtime.InteropServices.COMException] {
            if ($_.Exception.ErrorCode -eq 0x800706BA) {
                Write-Error -Message "RPC Server Unavailable"
            } else {
                Write-Error -Message "Some other COMException was thrown"
            }
        }                     
    } else { # Not online
        Write-Host $hostn is offline
        in_AD # Check if offline host is in AD
    }
}



# MAIN SCRIPT BODY #

do # Keep repeating asking for host name until user types in "exit"
{
    clear
    do
    {
        clear
        $hostn = Read-Host 'Hostname/IP? (exit to quit)'
    }
    while ($hostn -eq "") # Keeping asking for hostname until user does not enter a blank one

if ($hostn -eq "exit") # If user types exit, quit the script

{
exit
}

Write-Host "Script version $scriptVersion"
process_host # Run main host processing function
pause # Run pause function on command prompt or ISE
}

while ($hostn -ne "exit")
