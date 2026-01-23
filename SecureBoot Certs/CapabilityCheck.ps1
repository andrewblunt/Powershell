# 1. Check if the hardware actually supports the 2023 cert in its 'Factory' state
$ActiveDB = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'
$DefaultDB = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbdefault).bytes) -match 'Windows UEFI CA 2023'

# 2. Check for the 2023 KEK (The "Permission Slip" for the update)
$KekPresent = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI kek).bytes) -match '2023'

Write-Host "--- Hardware Readiness Report ---" -ForegroundColor Cyan
if ($DefaultDB) {
    Write-Host "[READY] BIOS natively contains 2023 certs." -ForegroundColor Green
} elseif ($KekPresent) {
    Write-Host "[READY] BIOS has the 2023 KEK. It will accept the OS update." -ForegroundColor Green
} else {
    Write-Host "[AT RISK] No 2023 KEK found. This device likely needs a BIOS update before June." -ForegroundColor Red
}

Write-Host "Current Status: " -NoNewline
if ($ActiveDB) { Write-Host "Already Updated" -ForegroundColor Green } else { Write-Host "Pending Update" -ForegroundColor Yellow }