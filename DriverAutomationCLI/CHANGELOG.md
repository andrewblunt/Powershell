# Changelog

All notable changes to this project will be documented in this file.

## 1.5.4 - 2026-03-24
- Added `Get-CustomDrivers` for creating custom (non-OEM) driver packages in SCCM.
- Fixed `Get-CustomDrivers` to place SCCM package in a manufacturer-specific console folder (e.g. `Driver Packages\Microsoft`).
- Removed `Get-OEMLinks` and `Write-LogEntry` from module exports - both are internal and not intended for direct use.

## 1.5.3 - 2026-03-24
- Removed Architecture setting from configuration - no longer needed with current module workflow.
- Module will auto-create DASettings.json on first run if it does not exist.
- Added `Test-DASettings` helper to validate all settings - checks that no settings are blank/empty.
- Updated `Get-LenovoDrivers`, `Get-DellDrivers`, and `Get-HPDrivers` to validate settings before running.
- `Find-LenovoModel` now returns objects with Name and SKU (machine type) properties.
- `Find-DellModel` now returns objects with Name and SKU (system ID) properties.
- `Find-HPModel` now returns objects with Name and SKU (system ID) properties.
- Fixed `Find-HPModel` to use `SystemName` instead of missing `ProductNames.ProductName` property.

## 1.5.2 - 2026-03-20
- New Internal Helpers: Added Filter-DriverPackResults, Merge-DriverPackDuplicates, and Select-DriverPack to standardize filtering and interactive selection.
- Consolidated Provider Logic: Refactored Get-LenovoDrivers, Get-DellDrivers, and Get-HPDrivers to utilize shared helpers, ensuring consistent UI/selection behavior across vendors.
- Enhanced HP Logic: Integrated deduplication into the HP selection path via composite key merging and ModelTypes unioning.
- Stability: Maintained existing sort orders and UI prompts; verified via successful module import and linting.
- Improved Parameter Handling in Get-HPDrivers:
    - Positional Binding Guard: Added logic to catch unquoted model names (e.g., -Model 430 g8) that PowerShell incorrectly binds to -OSVersion.
    - Automatic Recovery: If a positional $OSVersion does not match a valid Windows version pattern (e.g., 22H2, 1909), the value is now automatically appended back to $Model.
    - Improved Reliability: Prevents "No driver packs found" errors caused by bogus OS version tokens during interactive CLI use.

## 1.5.1 - 2026-03-20
### Fixed
- Fixed some issues with driver selection
- Fixed sort order for driver packs to go Model > OS Name > OS Version
- General bug fixes

## 1.4.1 - 2026-03-20
### Improved
- Restored original, descriptive folder naming for HP and Lenovo (keeping Dell on the simplified version) while maintaining the centralized "internal root folder" wrapping logic.
- Restored spaces in Lenovo model folder names (e.g., "ThinkStation P360 TINY") for better readability.
- Postponed local file cleanup (removing downloaded and extracted drivers) until after the SCCM package has been successfully created and distributed to DPs, providing better recoverability.
- Consolidated final staged package naming across all vendors to ensure internal consistency.

## 1.4.0 - 2026-03-20
### Added
- New interactive numbered selection (1, 2, 3) for `PackageFormat` in `Set-DASettings`.
- Strict validation (`ValidateSet`) added to the `PackageFormat` parameter in `Set-DASettings`.
- Standardized driver package folder naming across all vendors (HP, Dell, Lenovo) using a simplified `WindowsOS-Revision` format (later refined in v1.5.0).
- Integrated centralized package "wrapping" into `New-DriverPackage` to ensure a consistent internal root folder for Zip, WIM, and Raw formats.

### Fixed
- Fixed case-insensitive variable shadowing bug in `Get-HPDrivers` and `Get-LenovoDrivers` that caused incorrect driver selection.
- Hardened BITS download logic in `Invoke-ContentDownload` and `Invoke-BitsJobMonitor` to resolve `0x80070002` errors.
- Improved BITS job naming convention to include the target model (`DA-<Model>-<UID>`) for better identification.
- Added proactive BITS job cleanup and destination file removal to prevent transfer stalls.
- Refined CIM `NameFilter` regex to be more flexible with OData expressions, resolving "Unsupported NameFilter" warnings.
- Suppressed harmless warning for HP extraction exit code `1168` when running on non-target hardware.
- Fixed a `Substring` length calculation crash in the BITS download handler.

## 1.3.6 - 2026-03-19
- HP package/folder naming now avoids duplicated `HP` prefix when model names already include it.
- HP packages now wrap driver folders inside a single OS/version root folder for cleaner ZIP/Raw layouts.
- HP ZIPs now use the OS/version root folder as the archive root (no extra staging path or nested HP subfolders).
- HP extraction now mirrors original tool behavior (Temp\<Model>\Win<Version><Arch> with deepest-folder driver root detection).
- Dell extraction now mirrors original tool behavior (Temp\<Model>\Windows<Version>-<Revision>).
- Dell raw packaging now mirrors original tool behavior (copies architecture folder only when present).
- Dell zip/wim packaging now mirrors original tool behavior (uses architecture folder only when present).
- Packaging logs now include the source root used for archive/copy operations (and Dell arch folder when applicable).
- HP packaging logs now include the wrapper folder name used for HP archives.

## 1.3.5 - 2026-03-19
- Fix `Invoke-ContentDownload` inadvertently succeeding on BitsTransfer failure due to un-suppressed `BitsJob` pipeline leakage which caused script to attempt extract on non-existent files.
- Fix extraction folder path creation bugs by explicitly stripping invalid filesystem characters (e.g. `"` quotes often present in HP XML versions) from the driver package revision before formatting extraction directory names.
- Fix double-prompt in `Get-HPDrivers` interactive mode (same `""` → `"*"` fix as Dell in 1.3.2).
- Dell pack list no longer shows trailing ` -` when OS version is absent.
- Fix duplicate results in `Get-DellDrivers` interactive pack list (caused by multiple model node entries per package).
- HP pack list now shows OS version extracted from `OSName` or SoftPaq metadata when `OSVersion` is blank (e.g. `Windows 10 2009`, `Windows 11 22H2`).
- Fix duplicate results in `Get-HPDrivers` interactive pack list (caused by multiple system ID entries per pack).


## 1.3.2 - 2026-03-19
- Fix Dell/HP model folder names preserving spaces (e.g. `Latitude 5520` not `Latitude5520`).
- Fix OS subfolder names stripping spaces correctly (`Windows10` not `Windows 10`) for Dell and HP.
- Remove duplicate `$FolderModel` space-strip lines in both `Get-DellDrivers` and `Get-HPDrivers`.

## 1.3.1 - 2026-03-18
- Normalize Windows folder names to remove spaces (Windows10/Windows11).
- Dell/HP folder naming fixes and OS-version de-duplication.

## 1.3.0 - 2026-03-18
- Added HP model search and driver pack import (Find-HPModel, Get-HPDrivers).
- HP catalog CAB/XML cached in DownloadPath with daily refresh.

## 1.2.0 - 2026-03-18
- Added Dell model search and driver pack import (Find-DellModel, Get-DellDrivers).
- Dell catalog CAB/XML cached in DownloadPath with daily refresh.

## 1.1.2 - 2026-03-18
- OEMLinks.xml now stored in script root.
- Removed redundant globals and unused Settings folder.
- Reduced console noise for CIM/DCOM connection logs.
- Lenovo catalog refresh now stamps local XML with current timestamp to avoid repeated downloads.
- Documentation clarifies Lenovo catalog is fetched as XML (no CAB dependency).

## 1.1.1 - 2026-03-18
- OS-family cleanup: Windows 11 packs replace older Windows 11 packs (Windows 10 unaffected).
- Renamed AdminService-named internal functions to CIM/DCOM equivalents.

## 1.1.0 - 2026-03-18
- CIM/DCOM-only workflow; AdminService removed from runtime path.
- Added provider/namespace resolution and override support.
- Interactive Lenovo pack selection with metadata (OS/version/date/url/types).
- Package naming and folder path conventions updated.
- Added package format options (Raw/Zip/WIM) with max ZIP compression.
- Added `-Force` re-import with source archive backups.
- Added DownloadPath cleanup option and staged file cleanup.
- Added daily Lenovo XML refresh and cache invalidation.
- Added CIM namespace troubleshooting helpers and test script.

## 1.0.0 - 2026-03-17
- Initial release.
