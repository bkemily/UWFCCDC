# Check for Admin Privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "[-] Script must be run as Administrator."
    break
}

# --- Helper Function for Output ---
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

function Write-ErrorStep {
    param([string]$Message)
    Write-Host "  [!] ERROR: $Message" -ForegroundColor Red
}

# Import AD Module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Warning "Active Directory module not found. Some domain-specific commands may fail."
}

# ========================================================
# PHASE 1: ACCOUNT & PASSWORD POLICIES
# ========================================================
Write-Section "PHASE 1: Enforcing Domain Password & Lockout Policies"

try {
    Write-Step "Setting Domain Password Policy (Min Length: 14, History: 24, Age: 1 Day)"
    [cite_start]
    Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).Name `
        -MinPasswordLength 14 `
        -PasswordHistoryCount 24 `
        -MinPasswordAge "1.00:00:00" `
        -MaxPasswordAge "30.00:00:00" `
        -ComplexityEnabled $true `
        -ReversibleEncryptionEnabled $false -ErrorAction Stop

    Write-Step "Setting Account Lockout Policy (Threshold: 5, Duration: 15m)"
    [cite_start]
    Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).Name `
        -LockoutDuration "00:15:00" `
        -LockoutObservationWindow "00:30:00" `
        -LockoutThreshold 5 -ErrorAction Stop
} catch {
    Write-ErrorStep "Failed to apply AD Password Policy. (Are you on the DC?)"
}

# ========================================================
# PHASE 2: REGISTRY HARDENING (AD SPECIFIC)
# ========================================================
Write-Section "PHASE 2: Registry Hardening (SMB, LDAP, LSASS)"

# 1. Disable LM Hash Storage 
Write-Step "Disabling LAN Manager (LM) Hash storage"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -Force

# 2. Enforce SMB Signing 
Write-Step "Enforcing SMB Signing (Digitally sign communications)"
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 1 -Force

# 3. LDAP Signing Requirements 
Write-Step "Enforcing LDAP Server Signing"
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2 -PropertyType DWORD -Force -ErrorAction SilentlyContinue

# 4. Disable SMBv1 (EternalBlue Mitigation)
Write-Step "Disabling SMBv1 Protocol (EternalBlue Mitigation)"
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWORD -Force

# 5. LSASS Protection (RunAsPPL) 
Write-Step "Enabling LSASS Protection (RunAsPPL) to block Mimikatz"
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue

# 6. Disable NetBIOS over TCP/IP 
Write-Step "Disabling NetBIOS over TCP/IP"
Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" | ForEach-Object {
    $_.SetTcpipNetbios(2) | Out-Null
}

# ========================================================
# PHASE 3: SERVICE MANAGEMENT 
# ========================================================
Write-Section "PHASE 3: Disabling Vulnerable/Unnecessary Services"

$servicesToDisable = @(
    [cite_start]"RemoteRegistry",      
    [cite_start]"Spooler",             # Print Spooler (PrintNightmare) 
    [cite_start]"TlntSvr",             # Telnet 
    [cite_start]"MSFtpsvc",            # FTP 
    [cite_start]"SNMP",                # SNMP 
    [cite_start]"bthserv",             # Bluetooth Support 
    "MapsBroker",          # Downloaded Maps Manager
    [cite_start]"upnphost",            # UPnP Device Host 
    [cite_start]"SSDPSRV",             # SSDP Discovery 
    "Mcx2Svc"              # Media Center Extender
)

foreach ($service in $servicesToDisable) {
    if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
        Write-Step "Disabling Service: $service"
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
        Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
    }
}

# ========================================================
# PHASE 4: ADVANCED AUDITING & LOGGING
# ========================================================
Write-Section "PHASE 4: Configuring Advanced Audit Policies"

# Enabling specific audit categories mentioned in the checklist
$auditCategories = @(
    "Logon/Logoff", "Account Logon", "Account Management", "DS Access", 
    "Object Access", "Policy Change", "Privilege Use", "System", "Detailed Tracking"
)

# Note: 'auditpol' requires standard category names.
Write-Step "Enabling Success/Failure Auditing for critical subsystems"
auditpol /set /category:"Account Logon" /success:enable /failure:enable | Out-Null
auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
auditpol /set /category:"Policy Change" /success:enable /failure:enable | Out-Null
auditpol /set /category:"Privilege Use" /success:enable /failure:enable | Out-Null
auditpol /set /category:"System" /success:enable /failure:enable | Out-Null
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable | [cite_start]Out-Null

# Increase Event Log Size (Security Log to 512MB) 
Write-Step "Increasing Security Log retention to 512MB"
wevtutil sl Security /rt:true /ms:512000

# Enable PowerShell ScriptBlock Logging 
Write-Step "Enabling PowerShell ScriptBlock Logging"
$PSPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (!(Test-Path $PSPath)) { New-Item -Path $PSPath -Force | Out-Null }
Set-ItemProperty -Path $PSPath -Name "EnableScriptBlockLogging" -Value 1 -Force

# Enable Windows Defender Logging 
Write-Step "Enabling Windows Defender Logging"
Set-MpPreference -EnableLogging $true -ErrorAction SilentlyContinue
[cite_start]Set-MpPreference -DisableTamperProtection $false -ErrorAction SilentlyContinue # 

# ========================================================
# PHASE 5: COMPLETION
# ========================================================
Write-Section "HARDENING COMPLETE"
Write-Host "
Action Required:
1. REBOOT the server to finalize LSASS and SMBv1 changes.
2. Verify 'scriptOut.txt' (from Protocol 2) for disabled users.
3. Review Event Viewer > Security for new audit logs.
" -ForegroundColor Yellow