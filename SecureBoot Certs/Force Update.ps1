# Trigger the update via registry
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name 'AvailableUpdates' -Value 0x5944

# Start the background update task
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"