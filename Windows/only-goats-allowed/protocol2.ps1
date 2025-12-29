# Run as Domain Admin on a Domain Controller or machine with RSAT tools
Import-Module ActiveDirectory -ErrorAction Stop

# --- Configuration ---
$allowedUsersFile = "allowed.txt"
$OutputFile = "scriptOut.txt"

# Accounts that should NEVER be touched (Regex patterns)
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
    # Remove inheritance and grant Full control to Domain Admins only
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
    
    # Ensure at least one of each class
    $pwChars += ($lower.ToCharArray() | Get-Random -Count 1)
    $pwChars += ($upper.ToCharArray() | Get-Random -Count 1)
    $pwChars += ($digits.ToCharArray() | Get-Random -Count 1)
    $pwChars += ($symbols.ToCharArray() | Get-Random -Count 1)
    
    # Fill the rest
    $remaining = $Length - $pwChars.Count
    for ($i = 0; $i -lt $remaining; $i++) {
        $pwChars += $all | Get-Random -Count 1
    }
    
    # Shuffle
    return -join ($pwChars | Get-Random -Count $pwChars.Count)
}

# --- Execution ---

# Initialize Output File
"DOMAIN USER CONFIGURATION AUDIT" | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
"Generated on: $(Get-Date)" | Out-File -FilePath $OutputFile -Append
"--------------------------------" | Out-File -FilePath $OutputFile -Append

$allUsers = Get-ADUser -Filter * -Properties MemberOf, Enabled, SamAccountName

# List to track who survives Phase 1
$activeUsers = @()

# === Phase 1: Wrong Users (Disable) ===
"`nPhase 1: Wrong Users" | Out-File -FilePath $OutputFile -Append
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
        # Skip excluded accounts entirely
        continue
    }

    if ($allowedUsers -contains $sam) {
        # User is allowed, keep them for next phases
        $activeUsers += $user
    } else {
        # User is NOT allowed -> Disable
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
"`nPhase 2: User Admin Status" | Out-File -FilePath $OutputFile -Append
"-----------------------" | Out-File -FilePath $OutputFile -Append
$formatString -f "Username", "IsAdmin" | Out-File -FilePath $OutputFile -Append
$formatString -f "--------", "-------" | Out-File -FilePath $OutputFile -Append

foreach ($user in $activeUsers) {
    # Check recursive membership in Domain Admins
    # Note: This is a basic check. For comprehensive checks, one might check "Administrators" group too.
    $isAdmin = "No"
    $groups = Get-ADPrincipalGroupMembership -Identity $user.DistinguishedName -ErrorAction SilentlyContinue
    if ($groups.Name -contains "Domain Admins" -or $groups.Name -contains "Administrators") {
        $isAdmin = "Yes"
    }
    
    $formatString -f $user.SamAccountName, $isAdmin | Out-File -FilePath $OutputFile -Append
}

# === Phase 3: User Passwords ===
"`nPhase 3: User Passwords" | Out-File -FilePath $OutputFile -Append
"-----------------------" | Out-File -FilePath $OutputFile -Append
$passFormat = "{0,-20} {1,-25}"
$passFormat -f "Username", "New Password" | Out-File -FilePath $OutputFile -Append
$passFormat -f "--------", "------------" | Out-File -FilePath $OutputFile -Append

foreach ($user in $activeUsers) {
    try {
        $plain = New-RandomPassword -Length 15
        $secure = ConvertTo-SecureString $plain -AsPlainText -Force
        
        # Reset Password
        Set-ADAccountPassword -Identity $user.DistinguishedName -NewPassword $secure -Reset -ErrorAction Stop
        
        # Enable account if it was somehow disabled but allowed
        if ($user.Enabled -eq $false) { Enable-ADAccount -Identity $user.DistinguishedName }
        
        # Log
        $passFormat -f $user.SamAccountName, $plain | Out-File -FilePath $OutputFile -Append
        Write-Host "ROTATED: $($user.SamAccountName)" -ForegroundColor Green
    } catch {
        $passFormat -f $user.SamAccountName, "ERROR: $($_.Exception.Message)" | Out-File -FilePath $OutputFile -Append
        Write-Host "FAILED ROTATION: $($user.SamAccountName)" -ForegroundColor Red
    }
}

# Secure the file
Secure-OutputFile -path $OutputFile
Write-Host "`nDONE. Results saved to $OutputFile" -ForegroundColor Cyan