# Host Info (host_info.ps1)

A convenience PowerShell script to query a Windows host for basic inventory and session details:
- Online status
- Current / last logged-on user (AD + local profiles)
- IP address
- Operating system, build number and service pack
- Disk space (C:)
- Serial number, model and chassis type
- Install date / last reboot
- SCCM primary user and current user (if SCCM console available)
- AD Object Owner display (with local admin group membership check)
- Standardized user information display formatting
- Version: 3.7 (see script header for full history)

---

## Quick start

This script is intended to be run from a management workstation with domain access and the SCCM Admin Console installed.

1. Open PowerShell with an account that has:
   - Permission to query Active Directory (Get-ADComputer / Get-ADUser)
   - Remote CIM/WMI/WinRM access to target machines
   - Access to the SCCM Admin Console (if you want SCCM user info)
2. From the script folder run:
   ```powershell
   .\host_info.ps1
   ```
3. When prompted, enter a Hostname or IP (or type `exit` to quit).

After processing a host you can:
- Press Enter at the prompt to return to the main prompt, or
- Type another hostname/IP to process immediately (chained processing).

---

## Requirements

- Windows PowerShell (version compatible with CIM/WMI and Invoke-Command)
- ActiveDirectory PowerShell module (RSAT) available to the running account
- SCCM Admin Console installed (script looks for ConfigurationManager.psd1 in standard locations):
  - `C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1`
  - `D:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1`
  - Update this path in the script if your console is installed elsewhere.
- SCCM site PSDrive set in the script with `Set-Location "UN2:"` — change as required for your environment.
- Network connectivity and remote query permissions to target hosts (CIM/WMI/WinRM).
- Firewall rules on the target hosts:
  - Netlogon Service (NP-In) — for some WMI queries
  - Windows Management Instrumentation (WMI-In)
- (Optional) SCCM permissions to run `Get-CMUserDeviceAffinity` and `Get-CMDevice`.

---

## What it does (high level)

- Tests connectivity to the specified host using `Test-Connection`.
- Queries Active Directory for the computer object (CN, OU, LastLogonDate, OS info).
- Uses CIM/WMI to fetch OS info, network adapter IP, user session info, user profiles, disk free space, BIOS/serial/model, and boot/installation dates.
- Uses SCCM cmdlets (if available) to find primary and currently logged-on users.
- Attempts to find the last logged-on user via:
  - Current interactive session (Win32_ComputerSystem.UserName)
  - Loaded profiles + `quser` output (via `Invoke-Command`) when the machine is locked/no user
  - Win32_UserProfile LastUseTime as fallback
- Outputs friendly messages and colours (Write-Host / Write-Warning) for human operators.

---

## Usage examples

Interactive run:
```powershell
PS> .\host_info.ps1
Hostname/IP? (exit to quit) : HOST123
# Script prints online status, AD info, SCCM users, IP, OS, disk, serial, boot times...
# At the "Press Enter to continue... " prompt you can:
# - Press Enter to stop chaining hosts
# - Type another hostname to process immediately
# - Type "exit" to quit the script
```

Direct pipeline (advanced): you can call `ProcessHost -hostName 'HOST123'` from PowerShell if you dot-source the script or import functions in a session.

---

## Notable script behaviours & caveats

- The script imports a hard-coded SCCM module path and sets location to `UN2:`. Edit these lines to match your environment (site code / console install path).
- `Invoke-Command` is used to run `quser` remotely — on some systems `quser` may affect session data or trigger logon behavior. Use with caution.
- The script uses `Get-CimInstance`/WMI and `Invoke-Command` which require remote management to be enabled on target hosts (WinRM/CIM/WMI and firewall rules).
- If a target host is offline, the script will still try to display AD properties for the computer object.
- Usernames detected from profiles are validated with a regex before calling `Get-ADUser` to reduce failures against local or invalid accounts.
- Output is intended for interactive use (Write-Host). If you need machine-readable output, consider refactoring to emit objects instead of formatted strings.

---

## Troubleshooting

- If `Get-ADComputer` or `Get-ADUser` fails: ensure the ActiveDirectory module is installed and the running account has permission.
- If WMI/CIM queries fail with RPC or COM exceptions: ensure firewall rules for Netlogon (NP-In) and WMI-In are allowed and the target host accepts remote management.
- If SCCM queries fail: confirm the Configuration Manager console is installed and the account has rights to query SCCM; update the `Import-Module` path if necessary.
- If `Invoke-Command` fails: verify WinRM is configured on the target (`winrm quickconfig`) and network ACLs allow remote commands.

---

## Suggested improvements (small, low-risk)

- Parameterise the SCCM module path and site PSDrive instead of hard-coding.
- Add a `-Verbose` or `-NoColor` flag to control output formatting for automation.
- Return structured objects (PSCustomObject) for each host to allow piping results to exports (CSV/JSON).
- Add a dedicated `Test-Environment` helper to validate AD, SCCM, and WinRM availability before running queries.

---

## License & author

Author: (from script header) — original author initials `AP` (see header history).  
License: (none specified) — add a LICENSE file if you want this script to be reused publicly.

---

## Changelog (excerpts from script header)

- v3.7 — 23/01/2026 — Integrated Get-ComputerOwner logic for AD Object Owner display
  - Refactored function names to standard Verb-Noun syntax
  - Removed unused GetLastLoggedIn function and undefined variables
  - Soft-coded SCCM module import for better compatibility
  - Standardised user information display formatting with Get-FormattedUserDetails
  - Modernised script documentation with Comment-Based Help
  - Added whitelist for specific accounts to be always green (AD\cczrembo, AD\Service_Rembo)
  - Renamed $profile loop variable to $profileObj to avoid conflict with automatic variable
- v3.6 — 22/09/2025 — Include OS Build Number in output (remote reg query)
- v3.5 — 16/01/2024 — Modularised ProcessHost, added parameter validation, improved error handling
- (See `host_info.ps1` header for full history)
