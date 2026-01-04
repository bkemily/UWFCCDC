# Check for Admin Privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "[-] Script must be run as Administrator."
    break
}

# --- Configuration ---
$allowedUsersFile = "allowed.txt"
$OutputFile = "scriptOut.txt"

# Accounts that should NEVER be touched (Regex patterns)
# 'krbtgt' is the Key Distribution Center Service Account - do not touch.
$ExcludePatterns = @('krbtgt', 'Guest', 'DefaultAccount', 'svc_', 'gmsa$') 

# --- Setup & Checks ---
if (-not (Test-Path $allowedUsersFile)) {
    Write-Error "CRITICAL: allowed.txt not found. Create it with a list of authorized SAMAccountNames."
    exit
}

$allowedUsers = Get-Content $allowedUsersFile

# --- Functions ---

# Function: Restrict access to Domain Admins only
function Secure-OutputFile {
    param($path)
    try {
        $acl = Get-Acl $path
        $acl.SetAccessRuleProtection($true, $false) # Disable inheritance
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Admins","FullControl","Allow")
        $acl.SetAccessRule($rule)
        Set-Acl $path $acl
    } catch {
        Write-Warning "Could not secure output file permissions. Ensure you are running as Admin."
    }
}

# Function: Generate 15-char complex password
function New-RandomPassword {
    param([int]$Length = 15)
    $lower = 'abcdefghijklmnopqrstuvwxyz'
    $upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $digits = '0123456789'
    $symbols = '!@#$%^&*()-_=+[]{}<>?'
    
    $all = ($lower + $upper + $digits + $symbols).ToCharArray()
    $pwChars = @()
    
    # Ensure at least one of each class is present
    $pwChars += ($lower.ToCharArray() | Get-Random -Count 1)
    $pwChars += ($upper.ToCharArray() | Get-Random -Count 1)
    $pwChars += ($digits.ToCharArray() | Get-Random -Count 1)
    $pwChars += ($symbols.ToCharArray() | Get-Random -Count 1)
    
    # Fill the remaining length
    $remaining = $Length - $pwChars.Count
    for ($i = 0; $i -lt $remaining; $i++) {
        $pwChars += $all | Get-Random -Count 1
    }
    
    # Shuffle the result
    return -join ($pwChars | Get-Random -Count $pwChars.Count)
}

# --- Execution ---

# Initialize Output File
"DOMAIN USER CONFIGURATION AUDIT" | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
"Generated on: $(Get-Date)" | Out-File -FilePath $OutputFile -Append
"--------------------------------" | Out-File -FilePath $OutputFile -Append

$allUsers = Get-ADUser -Filter * -Properties MemberOf, Enabled, SamAccountName

# List to track who is allowed and needs processing in Phase 2 & 3
$activeUsers = @()

# === Phase 1: Wrong Users ===
"`nPhase 1: Wrong Users (Disabled)" | Out-File -FilePath $OutputFile -Append
"-----------------------" | Out-File -FilePath $OutputFile -Append
$formatString = "{0,-20} {1,-10}"
$formatString -f "Username", "Action" | Out-File -FilePath $OutputFile -Append
$formatString -f "--------", "------" | Out-File -FilePath $OutputFile -Append

foreach ($user in $allUsers) {
    $sam = $user.SamAccountName
    
    # Check Exclusions
    $isExcluded = $false
    foreach ($pat in $ExcludePatterns) { if ($sam -match $pat) { $isExcluded = $true; break } }
    
    if ($isExcluded) {
        continue # Skip system accounts entirely
    }

    if ($allowedUsers -contains $sam) {
        # User is allowed: Add to active list for later processing
        $activeUsers += $user
    } else {
        # User is NOT allowed: Disable
        try {
            Disable-ADAccount -Identity $user.DistinguishedName -ErrorAction Stop
            $formatString -f $sam, "Disabled" | Out-File -FilePath $OutputFile -Append
            Write-Host "DISABLED: $sam" -ForegroundColor Red
        } catch {
            $formatString -f $sam, "ERROR" | Out-File -FilePath $OutputFile -Append
            Write-Host "ERROR Disabling $sam" -ForegroundColor Yellow
        }
    }
}

# === Phase 2: User Admin Status ===
# Checks only the Allowed Users from Phase 1
"`nPhase 2: User Admin Status" | Out-File -FilePath $OutputFile -Append
"-----------------------" | Out-File -FilePath $OutputFile -Append
$formatString -f "Username", "IsAdmin" | Out-File -FilePath $OutputFile -Append
$formatString -f "--------", "-------" | Out-File -FilePath $OutputFile -Append

foreach ($user in $activeUsers) {
    $isAdmin = "No"
    # Check "Domain Admins" and standard "Administrators"
    $groups = Get-ADPrincipalGroupMembership -Identity $user.DistinguishedName -ErrorAction SilentlyContinue
    if ($groups.Name -contains "Domain Admins" -or $groups.Name -contains "Administrators") {
        $isAdmin = "Yes"
    }
    
    $formatString -f $user.SamAccountName, $isAdmin | Out-File -FilePath $OutputFile -Append
}

# === Phase 3: User Passwords ===
# Rotates passwords for all Allowed Users
"`nPhase 3: User Passwords" | Out-File -FilePath $OutputFile -Append
"-----------------------" | Out-File -FilePath $OutputFile -Append
$passFormat = "{0,-20} {1,-25}"
$passFormat -f "Username", "New Password" | Out-File -FilePath $OutputFile -Append
$passFormat -f "--------", "------------" | Out-File -FilePath $OutputFile -Append

foreach ($user in $activeUsers) {
    try {
        $plain = New-RandomPassword -Length 15
        $secure = ConvertTo-SecureString $plain -AsPlainText -Force
        
        # 1. Reset Password
        Set-ADAccountPassword -Identity $user.DistinguishedName -NewPassword $secure -Reset -ErrorAction Stop
        
        # 2. Unlock Account (if locked)
        Unlock-ADAccount -Identity $user.DistinguishedName -ErrorAction SilentlyContinue
        
        # 3. Force change at next logon (Security best practice)
        Set-ADUser -Identity $user.DistinguishedName -ChangePasswordAtLogon $true -ErrorAction Stop
        
        # Log credentials
        $passFormat -f $user.SamAccountName, $plain | Out-File -FilePath $OutputFile -Append
        Write-Host "ROTATED: $($user.SamAccountName)" -ForegroundColor Green
    } catch {
        $passFormat -f $user.SamAccountName, "ERROR: $($_.Exception.Message)" | Out-File -FilePath $OutputFile -Append
        Write-Host "FAILED ROTATION: $($user.SamAccountName)" -ForegroundColor Red
    }
}

# Secure the output file
Secure-OutputFile -path $OutputFile
Write-Host "`nDONE. Results saved to $OutputFile" -ForegroundColor Cyan