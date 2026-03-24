# Driver Automation CLI (Lenovo)

Current version: **1.3.1**  
See `CHANGELOG.md` for release history.

A headless, modular PowerShell CLI for automating Lenovo driver pack download, extraction, SCCM package creation, and distribution. Designed for ConfigMgr environments and a CLI‑first workflow.

## Features
- Lenovo driver pack search (catalog XML) with interactive selection.
- Dell driver pack search (catalog CAB/XML) with interactive selection.
- HP driver pack search (catalog CAB/XML) with interactive selection.
- Downloads via BITS, extracts, stages, and packages to SCCM.
- CIM/DCOM only (no AdminService, no WinRM).
- Optional distribution to DP Groups.
- Package source formats: Raw, Zip, or WIM.
- Automatic cleanup of download/extract staging (optional).

## Requirements
- Windows PowerShell 5.1+
- ConfigMgr access with CIM/DCOM permissions
- BITS enabled
- DISM available (for WIM packaging)

## Quick Start
1. Open PowerShell in this repo.
2. Import the module:
   ```powershell
   Import-Module .\DriverAutomation.psm1 -Force
   ```
3. Configure settings:
   ```powershell
   Set-DASettings -SiteServer "your.sccm.server" -PackagePath "\\server\share\drivers"
   Set-DASettings -DPGroups @("Standard OSD Distribution")
   ```
4. Run interactively (no model specified):
   ```powershell
   Get-LenovoDrivers
   ```

## Settings (DASettings.json)
Key settings you may want to adjust:
- `SiteServer`: SCCM site server FQDN
- `SiteCode`: SCCM site code
- `SCCMNamespace`: WMI namespace override (e.g. `root\SMS\site_UN2`)
- `PackagePath`: UNC path for package sources
- `DownloadPath`: staging path (relative paths supported, e.g. `.\Temp`)
- `Architecture`: default architecture (`x64`, `x86`)
- `PackageFormat`: `Raw`, `Zip`, or `WIM`
- `CleanupDownloadPath`: `true` or `false`
- `DistributionPointGroups`: array of DP Group names

## Common Commands
Interactive selection:
```powershell
Get-LenovoDrivers
```

Specify model and OS version:
```powershell
Get-LenovoDrivers -Model "ThinkPad X395" -OSVersion "24H2"
```

Dell example:
```powershell
Get-DellDrivers -Model "Latitude 7420" -OSVersion "23H2"
```

HP example:
```powershell
Get-HPDrivers -Model "EliteBook 840 G7" -OSVersion "23H2"
```

Force re‑import (removes existing SCCM package; archives old source folder):
```powershell
Get-LenovoDrivers -Model "ThinkPad X395" -OSVersion "24H2" -Force
```

Set package format:
```powershell
Set-DASettings -PackageFormat Zip
```

Enable cleanup:
```powershell
Set-DASettings -CleanupDownloadPath Yes
```

## Module Commands
User-facing functions exported by the module:
- `Get-DASettings` — reads the current JSON settings.
- `Set-DASettings` — updates JSON settings (interactive if no switches provided).
- `Find-LenovoModel` — searches Lenovo catalog for model names.
- `Get-LenovoDrivers` — main workflow: search, download, extract, package, and distribute.
- `Find-DellModel` — searches Dell catalog for model names.
- `Get-DellDrivers` — main workflow: search, download, extract, package, and distribute.
- `Find-HPModel` — searches HP catalog for model names.
- `Get-HPDrivers` — main workflow: search, download, extract, package, and distribute.
- `Get-OEMLinks` — downloads/reads OEM links (Lenovo, Dell, HP, Microsoft).

Internal/advanced (not typically called directly):
- `Get-CMPackage` — wrapper for package queries.
- `New-CMPackage` — wrapper for package creation.
- `Set-CMPackage` — wrapper for package updates.
- `Get-CMPackageCim` — CIM/DCOM query for packages.
- `New-CMPackageCim` — CIM/DCOM create package.
- `Set-CMPackageCim` — CIM/DCOM update package.

## Notes
- Lenovo catalog XML is cached in `DownloadPath` and refreshed if older than 1 day.
- Lenovo catalog is retrieved as XML (no CAB dependency).
- Dell catalog CAB/XML is cached in `DownloadPath` and refreshed if older than 1 day.
- HP catalog CAB/XML is cached in `DownloadPath` and refreshed if older than 1 day.
- Package names follow:
  `Drivers - <Manufacturer> <Model> - Windows <Version> <Arch>`
- Package source folders use no spaces in folder names (for file paths only).

## Troubleshooting
- If CIM/DCOM fails, confirm RPC/DCOM access and credentials.
- If namespace errors occur, set `SCCMNamespace` in `DASettings.json`.

## License
Add your preferred license here.
