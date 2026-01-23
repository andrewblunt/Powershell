# Remove Visual C++ Redistributables (Remove-VCRedist.ps1)

A PowerShell script to automate the uninstallation of Microsoft Visual C++ Redistributable packages by year. It handles both x86 and x64 architectures and provides a safe, silent removal process.

## Features

- **Year-Based Removal**: Target specific years for uninstallation (2005, 2008, 2010, 2012, 2013, 2015, 2017, 2019, 2022).
- **Dual Architecture Support**: Automatically identifies and removes both x86 and x64 versions of the selected years.
- **Unified 2015-2022 Support**: Smartly handles the unified "Visual C++ 2015-2022" redistributable line.
- **Silent Uninstallation**: Automatically appends `/qn`, `/quiet`, and `/norestart` flags to avoid user interaction.
- **Safety First**: Supports standard PowerShell `-WhatIf` and `-Verbose` parameters to preview changes before they happen.

---

## Quick Start

1. Open PowerShell as an **Administrator**.
2. Run the script with the `-Years` parameter:
   ```powershell
   .\Remove-VCRedist.ps1 -Years 2008, 2010
   ```
3. (Recommended) Use `-WhatIf` first to see what will be removed:
   ```powershell
   .\Remove-VCRedist.ps1 -Years 2015 -WhatIf
   ```

---

## Parameters

| Parameter | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| **Years** | `String[]` | **Yes** | An array of years to uninstall. Valid: `2005`, `2008`, `2010`, `2012`, `2013`, `2015`, `2017`, `2019`, `2022`. |
| **WhatIf** | `Switch` | No | Shows what would happen without performing any uninstallation. |
| **Verbose** | `Switch` | No | Provides detailed technical output about the commands being executed. |

---

## Requirements

- **PowerShell 5.1** or newer.
- **Administrative Privileges** (required to search registry and invoke uninstallers).
- Target system: Windows 7 / Server 2008 R2 or later.

---

## How it Works

1. **Registry Scan**: Searches `HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall` and the `Wow6432Node` counterpart.
2. **Pattern Matching**: Filters installed programs based on the years provided using regex patterns.
3. **Uninstall String Parsing**: Extracts the native uninstaller commands.
4. **Silent Invocation**: Executes the uninstaller with appropriate silent/norestart arguments.

> [!CAUTION]
> **Warning**: Uninstalling Visual C++ Redistributables may cause software that depends on them to stop working. Only remove versions you are certain are no longer required by your environment.

---

## Author
Original Script logic for Visual C++ cleanup.
