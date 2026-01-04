# Check for Admin Privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "[-] Script must be run as Administrator."
    break
}

# --- Setup Variables ---
$WorkDir = "C:\WARCAT_Work"
$LogDir = "$WorkDir\Logs"
$ToolDir = "$WorkDir\Tools"
$SysinternalsUrl = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
$SysinternalsZip = "$ToolDir\SysinternalsSuite.zip"

# --- Helper Function ---
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

# ========================================================
# PHASE 1: WORKSPACE CREATION
# ========================================================
Write-Section "PHASE 1: Creating Workspace"

if (!(Test-Path $WorkDir)) {
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
    Write-Step "Created Work Directory: $WorkDir"
}
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    Write-Step "Created Log Directory: $LogDir"
}
if (!(Test-Path $ToolDir)) {
    New-Item -ItemType Directory -Force -Path $ToolDir | Out-Null
    Write-Step "Created Tool Directory: $ToolDir"
}

# ========================================================
# PHASE 2: INITIAL RECONNAISSANCE
# ========================================================
Write-Section "PHASE 2: System Reconnaissance (Documentation)"

Write-Step "Exporting IP Configuration to $LogDir\ip.txt"
ipconfig /all > "$LogDir\ip.txt" 

Write-Step "Exporting ARP Table to $LogDir\arp.txt"
arp -a > "$LogDir\arp.txt" 

Write-Step "Exporting Route Table to $LogDir\route.txt"
route print > "$LogDir\route.txt" 

Write-Step "Exporting System Info (OS/Hotfixes) to $LogDir\os.txt"
systeminfo > "$LogDir\os.txt" 
Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version | Out-File "$LogDir\os_version.txt"

Write-Step "Exporting Running Processes to $LogDir\tasklist.txt"
tasklist /v > "$LogDir\tasklist.txt" 

Write-Step "Exporting Listening Ports to $LogDir\netstat.txt"
netstat -anob > "$LogDir\netstat.txt" 

# ========================================================
# PHASE 3: DEPENDENCY CHECK (RSAT / AD MODULE)
# ========================================================
Write-Section "PHASE 3: Checking Protocol Dependencies"

$adModule = Get-Module -ListAvailable -Name ActiveDirectory
if ($adModule) {
    Write-Step "Active Directory Module is ALREADY INSTALLED."
} else {
    Write-Step "Active Directory Module NOT FOUND. Attempting Installation..."
    try {
        Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -ErrorAction Stop
        Install-WindowsFeature RSAT-AD-PowerShell
        Write-Host "  [+] RSAT Installed Successfully." -ForegroundColor Green
    } catch {
        Write-Host "  [!] FAILED to install RSAT via PowerShell. If this is a DC, it should be there." -ForegroundColor Red
        Write-Host "  [!] If this is a member server, please install RSAT manually via 'Manage Optional Features'." -ForegroundColor Yellow
    }
}

# ========================================================
# PHASE 4: USER & ADMIN DUMP (Prep for Protocol 3)
# ========================================================
Write-Section "PHASE 4: Prepping 'allowed.txt' Reference"

$refFile = "$WorkDir\Reference_Users.txt"
"--- LOCAL ADMINISTRATORS ---" | Out-File $refFile
net localgroup Administrators | Out-File $refFile -Append

"--- ALL LOCAL USERS ---" | Out-File $refFile -Append
net user | Out-File $refFile -Append

if (Get-Module -ListAvailable -Name ActiveDirectory) {
    "--- DOMAIN ADMINS ---" | Out-File $refFile -Append
    try {
        Get-ADGroupMember "Domain Admins" | Select-Object SamAccountName, Name | Out-File $refFile -Append
    } catch {
        "Could not query Domain Admins (RPC unavailable or not a DC)" | Out-File $refFile -Append
    }
}

Write-Step "Reference user lists saved to: $refFile"
Write-Step "Use this file to copy/paste authorized users into 'allowed.txt'."

# Create the actual allowed.txt if it doesn't exist
if (!(Test-Path ".\allowed.txt")) {
    New-Item -ItemType File -Path ".\allowed.txt" -Force | Out-Null
    Write-Step "Created empty 'allowed.txt' in current directory. PLEASE POPULATE THIS."
}

# ========================================================
# PHASE 5: SYSINTERNALS INSTALLATION
# ========================================================
Write-Section "PHASE 5: Installing Sysinternals Suite"

if (Test-Path "$ToolDir\SysinternalsSuite") {
    Write-Step "Sysinternals already appears to be installed."
} else {
    Write-Step "Downloading Sysinternals Suite..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $SysinternalsUrl -OutFile $SysinternalsZip -UseBasicParsing
        
        Write-Step "Unzipping Tools..."
        Expand-Archive -Path $SysinternalsZip -DestinationPath "$ToolDir\SysinternalsSuite" -Force
        
        Write-Host "  [+] Sysinternals Installed to: $ToolDir\SysinternalsSuite" -ForegroundColor Green
        Write-Step "Key Tools Available: ProcExp, Autoruns, TcpView, ProcMon"
    } catch {
        Write-Host "  [!] Download Failed. Internet may be disconnected." -ForegroundColor Red
        Write-Host "  [!] Manual Step: Copy Sysinternals to $ToolDir" -ForegroundColor Yellow
    }
}

# ========================================================
# PHASE 6: BACKUP REMINDER
# ========================================================
Write-Section "PHASE 6: Final Checks"

Write-Host "Action Required:" -ForegroundColor Yellow
Write-Host "1. Review $WorkDir\Reference_Users.txt" -ForegroundColor White
Write-Host "2. Populate 'allowed.txt' with YOUR USERNAME and authorized admins." -ForegroundColor White
Write-Host "3. Consider running a system state backup now:" -ForegroundColor White
Write-Host "   Command: wbadmin start systemstatebackup -backupTarget:<DriveLetter>:" -ForegroundColor Cyan

Write-Host "`nSETUP COMPLETE." -ForegroundColor Cyan