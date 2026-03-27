# DATCLI (Driver Automation Tool CLI)

Current version: **2.2.1**
See `CHANGELOG.md` for release history.

A modular PowerShell CLI for automating driver pack download, extraction, SCCM package creation, and distribution. Supports Lenovo, Dell, HP, Microsoft Surface, and custom driver packages. Designed for ConfigMgr environments with an interactive menu-driven interface.

## Features
- **Interactive CLI** - Menu-driven interface for all operations
- **Multi-OEM support** - Lenovo, Dell, HP, Microsoft Surface
- **Custom driver packages** - Create packages from local driver folders
- **Model search** - Search across individual OEMs or all at once
- **Package management** - Browse and audit existing SCCM driver packages
- **BITS downloads** - Resilient transfers with speed/ETA reporting
- **Package formats** - Raw, Zip, or WIM
- **CIM/DCOM only** - No AdminService, no WinRM required
- **Configurable** - Settings stored in DASettings.json

## Requirements
- Windows PowerShell 5.1+
- ConfigMgr access with CIM/DCOM permissions
- BITS enabled
- DISM available (for WIM packaging)

## Quick Start

1. Open PowerShell in this directory.

2. Import the module:
   ```powershell
   Import-Module .\DATCLI.psd1 -Force
   ```

3. Launch the interactive CLI:
   ```powershell
   Start-DATCLI
   ```

   Or run `.\DATCLI.ps1` directly.

4. First-time setup will create `DASettings.json` with blank values. Configure via Settings menu or:
   ```powershell
   Set-DASettings
   ```

## Interactive CLI

The `Start-DATCLI` command launches a menu-driven interface:

```
  DATCLI 2.2.1 > Main Menu

    Connected:  your.sccm.server
    Catalogs:   LenovoXML 3.2h | DellXML 3.2h | HPXML 3.2h | build-driverpack 3.2h

    [1] Model Lookup
    [2] Download Drivers
    [3] Create Custom Driver Package
    [4] Browse Packages
    [5] Settings
    [Q] Quit
```

### Model Lookup
Search for models across individual OEMs or all at once:
- **Search all OEMs** - Uses `Find-DriverModel` to search Lenovo, Dell, HP, and Microsoft catalogs
- **OEM-specific** - Search within a single OEM's catalog

### Download Drivers
Select an OEM to start the driver download workflow. The tool will:
1. Search the catalog for your model
2. Let you select the appropriate driver pack
3. Download via BITS (with speed and ETA)
4. Extract the drivers
5. Create an SCCM package
6. Distribute to DP Groups (optional)

### Browse Packages
View existing driver packages in your SCCM site, filterable by OEM.

## Settings (DASettings.json)

Key settings:
- `SiteServer` - SCCM site server FQDN
- `SiteCode` - SCCM site code (auto-detected on connection)
- `SCCMNamespace` - WMI namespace override (e.g. `root\SMS\site_UN2`)
- `PackagePath` - UNC path for package sources
- `DownloadPath` - Staging path (relative paths supported, e.g. `.\Temp`)
- `PackageFormat` - `Raw`, `Zip`, or `WIM`
- `CleanupDownloadPath` - `true` or `false`
- `DistributionPointGroups` - Array of DP Group names
- `EnableBinaryDeltaReplication` - `true` or `false`
- `DistributionPriority` - `Low`, `Medium`, or `High`

## Commands

### Driver Automation
```powershell
# Lenovo
Get-LenovoDrivers -Model "ThinkPad X1 Carbon Gen 9" -OSVersion "23H2"
Get-LenovoDrivers -Model "ThinkPad X395" -OSVersion "24H2" -Force

# Dell
Get-DellDrivers -Model "Latitude 7420" -OSVersion "23H2"

# HP
Get-HPDrivers -Model "EliteBook 840 G7" -OSVersion "23H2"

# Microsoft Surface
Get-MicrosoftDrivers -Model "Surface Pro 7" -OSName "Windows 11" -OSVersion "23H2"

# Custom (interactive - prompts for all details)
Get-CustomDrivers
```

### Model Search
```powershell
# Search individual OEMs
Find-LenovoModel -Model "ThinkPad X1"
Find-DellModel -Model "Latitude"
Find-HPModel -Model "EliteBook"
Find-MicrosoftModel -Model "Surface Pro"

# Search all OEMs at once
Find-DriverModel -Model "X1 Carbon"
```

### Package Management
```powershell
# List all driver packages in SCCM
Get-Packages

# List packages for a specific OEM
Get-Packages -Make Lenovo

# Check for outdated packages
Update-Packages
Update-Packages -Make Dell
```

### Configuration
```powershell
# View current settings
Get-DASettings

# Configure interactively
Set-DASettings
```

## Exported Functions

| Function | Description |
|----------|-------------|
| `Start-DATCLI` | Interactive menu-driven interface |
| `Start-DriverAutomationCLI` | Interactive menu-driven interface |
| `Get-LenovoDrivers` | Download and package Lenovo drivers |
| `Find-LenovoModel` | Search Lenovo catalog |
| `Get-DellDrivers` | Download and package Dell drivers |
| `Find-DellModel` | Search Dell catalog |
| `Get-HPDrivers` | Download and package HP drivers |
| `Find-HPModel` | Search HP catalog |
| `Get-MicrosoftDrivers` | Download and package Microsoft Surface drivers |
| `Find-MicrosoftModel` | Search Microsoft catalog |
| `Get-CustomDrivers` | Create custom driver package from local folder |
| `Get-Packages` | List SCCM driver packages |
| `Find-DriverModel` | Search all OEM catalogs |
| `Update-Packages` | Check packages against catalog versions |
| `Get-DASettings` | View current settings |
| `Set-DASettings` | Configure settings |

## Notes
- All OEM catalogs are cached in `DownloadPath` and refreshed if older than 7 days
- Package names follow: `Drivers - <Manufacturer> <Model> - Windows <Version> <Arch>`
- Microsoft packages use SKU (Product ID) for folder/naming to avoid collisions between variants
- Lenovo package versioning uses catalog XML `SCCM` date metadata when available
- Logs are written to the `Logs/` directory in CMTrace format

## Troubleshooting
- If CIM/DCOM fails, confirm RPC/DCOM access and credentials
- If namespace errors occur, set `SCCMNamespace` in `DASettings.json`
- Run `Test-DASettings` to validate all required settings are configured
- Check `Logs/` directory for detailed error information
