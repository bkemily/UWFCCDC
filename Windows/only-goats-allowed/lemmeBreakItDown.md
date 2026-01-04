# Protocol 1: Initialization & Reconnaissance

**Filename:** `protocol1.ps1`
**Version:** 1.0 (The WARCAT Protocol)

## Overview
`protocol1.ps1` is the setup script that prepares the engagement environment. It establishes a workspace, gathers critical system intelligence (Recon), ensures the dependencies for Protocol 2/3 are met, and installs the Sysinternals Suite for deep-dive analysis.

## Key Actions
* **Workspace Setup:** Creates `C:\WARCAT_Work` to store logs and tools.
* [cite_start]**Reconnaissance:** Automatically runs and logs `ipconfig`, `arp`, `route`, `systeminfo`, `tasklist`, and `netstat` to text files[cite: 19, 21, 22, 102].
* **Dependency Check:** Verifies if the **Active Directory PowerShell Module** is installed. [cite_start]If missing, it attempts to install the RSAT capability[cite: 588].
* [cite_start]**User Dump:** Exports current Local Admins and Domain Admins to `Reference_Users.txt` to assist you in filling out the `allowed.txt` file for Protocol 3[cite: 12, 143].
* [cite_start]**Tool Installation:** Downloads and extracts the **Sysinternals Suite** (ProcMon, Autoruns, Process Explorer) [cite: 1077-1096].

## Usage
1.  Open PowerShell as Administrator.
2.  Run the script:
    ```powershell
    .\protocol1.ps1
    ```
3.  **Critical Next Step:** Open `C:\WARCAT_Work\Reference_Users.txt`, copy the legitimate admin usernames, and paste them into your `allowed.txt` file before running Protocol 3.

# Protocol 2: Active Directory & System Hardening

**Filename:** `protocol2.ps1`  
**Version:** 2.0 (The WARCAT Protocol)

## Overview
`protocol2.ps1` is a comprehensive infrastructure hardening script derived from the "GOATED AD + WINDOWS CHECKLIST." It focuses on securing the Domain Controller and Windows Server environment by enforcing registry keys, disabling vulnerable services, and maximizing audit visibility. It implements "Set-and-Forget" policies for immediate security gains during a competition.

## Prerequisites
* **Privileges:** Must be run as a **Domain Administrator**.
* **Reboot:** A server reboot is **required** after execution for registry changes (specifically LSASS and SMB) to take effect.
* **Environment:** Windows Server 2016/2019/2022 (Domain Controller preferred).

## Key Features & Hardening Actions
The script automates the following checklist items:
1. **Password & Lockout Policy:** Enforces a 14-character minimum length, 24-password history, and 15-minute lockout duration.
2. **Registry Hardening:**
    * **LSASS Protection:** Sets `RunAsPPL` to prevent credential dumping (Mimikatz).
    * **SMB Security:** Disables SMBv1 (EternalBlue mitigation) and enforces SMB Signing.
    * **NetBIOS:** Disables NetBIOS over TCP/IP to reduce lateral movement risk.
3. **Service Management:** Automatically identifies and disables high-risk services including Print Spooler (PrintNightmare), Telnet, FTP, and Bluetooth.
4. **Advanced Auditing:** Enables "Success and Failure" logging for critical subcategories (Account Logon, Privilege Use, Process Tracking).
5. **Logging Retention:** Increases Security Log size to 512MB to prevent overwrite during attacks.

## Usage
1. Open PowerShell as Administrator.
2. Run the script:
   ```powershell
   .\protocol2.ps1
3. Reboot the server immediately after the script completes.

**⚠️ WARNING ** : This script modifies network stack settings (SMB/NetBIOS). Ensure you have console access (VMware/Hyper-V console) in case RDP is temporarily disrupted during the transition.

# Protocol 3: Active Directory Hardening Script

**Filename:** `protocol3.ps1`
**Version:** 1.0

## Overview
`protocol3.ps1` is a PowerShell script designed for rapid Active Directory environment hardening (commonly used in Red/Blue team competitions). It audits user accounts against a strict allowlist, disables unauthorized users, checks administrative privileges, and rotates passwords for all authorized accounts.

## Prerequisites
* **Privileges:** Must be run as a **Domain Administrator**.
* **Environment:** Domain Controller or machine with RSAT (Active Directory module) installed.
* **Execution Policy:** PowerShell Execution Policy must allow scripts (e.g., `Set-ExecutionPolicy RemoteSigned`).

## Configuration Files
1.  **`protocol3.ps1`**: The main script.
2.  **`allowed.txt`**: A plaintext file listing the `SamAccountName` of every authorized user. **CRITICAL: Include your own username.**
3.  **`scriptOut.txt`**: The generated output log.

## Usage
1.  Create `allowed.txt` in the same directory as the script.
2.  Open PowerShell as Administrator.
3.  Run the script:
    ```powershell
    .\protocol.ps1
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