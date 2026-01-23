# SecureBoot UEFI 2023 Cert Servicing (WIP)

> [!IMPORTANT]
> **Status**: Work in Progress / Developmental
> These scripts are currently in a testing phase and are intended for internal auditing purposes regarding the transition to the **Windows UEFI CA 2023** certificate.

## Overview

A collection of utility scripts to assist with the audit and readiness assessment of the Secure Boot 2023 Certificate update. These tools help identify hardware capability and track the servicing status across managed endpoints.

## Included Scripts

- **`CapabilityCheck.ps1`**: Performs a hardware readiness report. Checks if the 2023 KEK (Key Exchange Key) is present and whether the system natively supports the 2023 DB cert.
- **`Gemini Check.ps1` / `Copilot Check.ps1`**: Audits the local registry servicing status and verifies the presence of the 2023 certificate in the UEFI DB.
- **`Force Update.ps1`**: Utility for manual status manipulation during testing scenarios.
- **`Gemini Quick Check.ps1`**: A minimal one-liner/short check for rapid status verification.

## Requirements

- **Administrative Privileges**: Necessary for registry and UEFI access.
- **UEFI Mode**: `Get-SecureBootUEFI` requires the host to be in UEFI mode with Secure Boot available.
- **PowerShell 5.1+**.

## Usage

Scripts should be run individually as needed for auditing. Results are generally output to the console with color-coded status indicators (Green for Ready/Updated, Red/Yellow for Pending).

---
*Last Updated: 2026-01-23*
