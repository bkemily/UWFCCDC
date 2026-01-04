# Check for Admin Privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "[-] Script must be run as Administrator."
    break
}

# --- Helper Functions ---
function Write-Section {
    param([string]$Title)
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host " [+] $Title" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Message)
    Write-Host "  > $Message" -ForegroundColor Green
}

# Import AD Module if available
try { Import-Module ActiveDirectory -ErrorAction SilentlyContinue } catch {}

# ========================================================
# PHASE 1: ACCOUNT & PASSWORD POLICIES
# ========================================================
Write-Section "PHASE 1: Enforcing Domain Password & Lockout Policies"

try {
    Write-Step "Setting Domain Password Policy (Min: 14, History: 24, Age: 1 Day)"
    Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).Name `
        -MinPasswordLength 14 `
        -PasswordHistoryCount 24 `
        -MinPasswordAge "1.00:00:00" `
        -MaxPasswordAge "30.00:00:00" `
        -ComplexityEnabled $true `
        -ReversibleEncryptionEnabled $false -ErrorAction Stop

    Write-Step "Setting Account Lockout Policy (Threshold: 5, Duration: 15m)"
    Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).Name `
        -LockoutDuration "00:15:00" `
        -LockoutObservationWindow "00:30:00" `
        -LockoutThreshold 5 -ErrorAction Stop
} catch {
    Write-Warning "  [!] Could not set AD policies (Are you on the DC?). Skipping..."
}

# ========================================================
# PHASE 2: REGISTRY HARDENING (Security Options)
# ========================================================
Write-Section "PHASE 2: Registry Hardening"

# 1. Disable LM Hash & Force SMB Signing
Write-Step "Disabling LM Hash & Enforcing SMB Signing"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 1 -Force

# 2. Disable SMBv1 (EternalBlue)
Write-Step "Disabling SMBv1"
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWORD -Force

# 3. LSASS Protection 
Write-Step "Enabling LSASS PPL (Mimikatz Protection)"
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue

# 4. Clear Pagefile at Shutdown 
Write-Step "Enabling 'Clear Virtual Memory Pagefile on Shutdown'"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 1 -Type DWORD -Force

# 5. Prevent Automatic Login 
Write-Step "Disabling AutoAdminLogon"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "0" -Force

# ========================================================
# PHASE 3: NETWORK & FIREWALL SECURITY
# ========================================================
Write-Section "PHASE 3: Network & Firewall Security"

# 1. Enable Windows Firewall Profiles
Write-Step "Enabling all Windows Firewall Profiles (Domain, Public, Private)"
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# 2. RDP Network Level Authentication (NLA) 
Write-Step "Enforcing Network Level Authentication (NLA) for RDP"
(Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(1) | Out-Null

# 3. Disable NetBIOS over TCP/IP
Write-Step "Disabling NetBIOS over TCP/IP"
Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" | ForEach-Object { $_.SetTcpipNetbios(2) | Out-Null }

# 4. Disable File & Printer Sharing (Network Adapter Level) 
Write-Step "Disabling File & Printer Sharing Binding on Adapters"
Get-NetAdapterBinding | Where-Object { $_.ComponentID -eq "ms_server" } | Disable-NetAdapterBinding -Confirm:$false

# ========================================================
# PHASE 4: SERVICE MANAGEMENT
# ========================================================
Write-Section "PHASE 4: Disabling Risky Services"

$services = @("RemoteRegistry", "Spooler", "TlntSvr", "MSFtpsvc", "SNMP", "bthserv", "MapsBroker", "upnphost", "SSDPSRV", "Mcx2Svc")
foreach ($srv in $services) {
    if (Get-Service -Name $srv -ErrorAction SilentlyContinue) {
        Write-Step "Disabling: $srv"
        Stop-Service -Name $srv -Force -ErrorAction SilentlyContinue
        Set-Service -Name $srv -StartupType Disabled -ErrorAction SilentlyContinue
    }
}

# ========================================================
# PHASE 5: ADVANCED AUDITING & LOGGING
# ========================================================
Write-Section "PHASE 5: Logging & Auditing"

# 1. Basic Audit Policies 
Write-Step "Enabling Success/Failure Auditing"
$cats = @("Account Logon","Account Management","Logon/Logoff","Policy Change","Privilege Use","System","Detailed Tracking")
foreach ($c in $cats) { auditpol /set /category:"$c" /success:enable /failure:enable | Out-Null }

# 2. Command Line Process Auditing 
Write-Step "Enabling Command Line Process Auditing (Event 4688)"
$auditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (!(Test-Path $auditPath)) { New-Item -Path $auditPath -Force | Out-Null }
Set-ItemProperty -Path $auditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWORD -Force

Write-Step "Setting LDAP Interface Events to Level 5"
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" -Name "16 LDAP Interface Events" -Value 5 -PropertyType DWORD -Force -ErrorAction SilentlyContinue

Write-Step "Enabling Granular Operational Logs (DNS, BITS, WinUpdate)"
$logs = @(
    "Microsoft-Windows-DNS-Client/Operational",
    "Microsoft-Windows-Bits-Client/Operational",
    "Microsoft-Windows-WindowsUpdateClient/Operational"
)
foreach ($l in $logs) {
    wevtutil sl $l /e:true -ErrorAction SilentlyContinue
}

Write-Step "Increasing Security Log to 512MB"
wevtutil sl Security /rt:true /ms:512000

# ========================================================
# PHASE 6: MAINTENANCE
# ========================================================
Write-Section "PHASE 6: Maintenance Configuration"

Write-Step "Enabling Automatic Windows Updates"
$wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
if (!(Test-Path $wuPath)) { New-Item -Path $wuPath -Force | Out-Null }
Set-ItemProperty -Path $wuPath -Name "NoAutoUpdate" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path $wuPath -Name "AUOptions" -Value 4 -Type DWORD -Force # 4 = Auto download and schedule install

Write-Section "HARDENING COMPLETE. PLEASE REBOOT."