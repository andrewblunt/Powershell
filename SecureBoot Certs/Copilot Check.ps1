
# Check Secure Boot Certificate Update Status
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Updates"
$regName = "UEFICA2023Status"

if (Test-Path $regPath) {
    $status = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $regName
    if ($null -ne $status) {
        Write-Host "UEFICA2023Status: $status"
        switch ($status) {
            0 { Write-Host "Status: Not Installed" -ForegroundColor Yellow }
            1 { Write-Host "Status: Installed" -ForegroundColor Green }
            default { Write-Host "Status: Unknown ($status)" -ForegroundColor Red }
        }
    } else {
        Write-Host "UEFICA2023Status value not found." -ForegroundColor Red
    }
} else {
    Write-Host "Secure Boot Updates registry path not found." -ForegroundColor Red
}
