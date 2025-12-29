# Protocol 2: Active Directory Hardening Script

**Filename:** `protocol2.ps1`
**Version:** 1.0

## Overview
`protocol2.ps1` is a PowerShell script designed for rapid Active Directory environment hardening (commonly used in Red/Blue team competitions). It audits user accounts against a strict allowlist, disables unauthorized users, checks administrative privileges, and rotates passwords for all authorized accounts.

## Prerequisites
* **Privileges:** Must be run as a **Domain Administrator**.
* **Environment:** Domain Controller or machine with RSAT (Active Directory module) installed.
* **Execution Policy:** PowerShell Execution Policy must allow scripts (e.g., `Set-ExecutionPolicy RemoteSigned`).

## Configuration Files
1.  **`protocol2.ps1`**: The main script.
2.  **`allowed.txt`**: A plaintext file listing the `SamAccountName` of every authorized user. **CRITICAL: Include your own username.**
3.  **`scriptOut.txt`**: The generated output log.

## Usage
1.  Create `allowed.txt` in the same directory as the script.
2.  Open PowerShell as Administrator.
3.  Run the script:
    ```powershell
    .\protocol2.ps1
    ```

## Output Breakdown (`scriptOut.txt`)
The script output is divided into three sections:
* **Phase 1: Wrong Users**: Lists accounts not found in `allowed.txt` that were successfully **disabled**.
* **Phase 2: User Admin Status**: specific audit of whether the remaining users are members of "Domain Admins" or "Administrators".
* **Phase 3: User Passwords**: A table containing the **new 15-character random passwords** for every active user.

## Safety & Exclusions
* **System Accounts:** The script contains an `$ExcludePatterns` variable to automatically skip critical system accounts like `krbtgt`, `svc_` accounts, and `gmsa$` to prevent breaking the domain trust or services.
* **File Security:** The script attempts to modify the Access Control List (ACL) of the output file so only Domain Admins can read it.

**⚠️ WARNING:** `scriptOut.txt` contains cleartext passwords. Delete or secure this file immediately after use.