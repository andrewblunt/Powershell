# 1. Check the Registry Status (Best for managed fleets)
$ServicingPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
$Status = Get-ItemProperty -Path $ServicingPath -Name "UEFICA2023Status" -ErrorAction SilentlyContinue

# 2. Check for the specific 2023 Certificate in UEFI
$IsCertPresent = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'

Write-Host "--- Secure Boot 2023 Cert Audit ---"
if ($Status) {
    Write-Host "Update Status: $($Status.UEFICA2023Status)" 
} else {
    Write-Host "Update Status: Not Started / Key Missing"
}

Write-Host "Cert Present in UEFI: $IsCertPresent"

# 3. Check System Event Log for success (Event ID 1808)
$Event = Get-WinEvent -FilterHashtable @{LogName='System'; Id=1808} -MaxEvents 1 -ErrorAction SilentlyContinue
if ($Event) {
    Write-Host "Last Success Event: $($Event.TimeCreated)"
}