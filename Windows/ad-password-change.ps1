# Run as Domain Admin on a domain-joined machine
Import-Module ActiveDirectory -ErrorAction Stop

# Output file (will be overwritten if exists)
$OutputFile = "C:\Temp\DomainUserPasswords.txt"

# Create folder if needed
$dir = Split-Path $OutputFile
if (!(Test-Path -Path $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

# Overwrite any existing file
"" | Out-File -FilePath $OutputFile -Encoding UTF8 -Force

# Restrict access to Domain Admins (adjust group as needed) - will be applied after file is populated
function Secure-OutputFile {
    param($path)
    # Remove inheritance and grant Full control to Domain Admins only
    icacls $path /inheritance:r /grant:r "Domain Admins:F" /c | Out-Null
}

# Password generator: ensures 15+ chars, and at least 1 upper, lower, digit, symbol
function New-RandomPassword {
    param([int]$Length = 15)

    if ($Length -lt 15) { $Length = 15 }

    $lower = 'abcdefghijklmnopqrstuvwxyz'
    $upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $digits = '0123456789'
    $symbols = '!@#$%^&*()-_=+[]{}<>?'

    $all = ($lower + $upper + $digits + $symbols).ToCharArray()

    # Ensure each class present
    $pwChars = @()
    $pwChars += ($lower.ToCharArray() | Get-Random -Count 1)
    $pwChars += ($upper.ToCharArray() | Get-Random -Count 1)
    $pwChars += ($digits.ToCharArray() | Get-Random -Count 1)
    $pwChars += ($symbols.ToCharArray() | Get-Random -Count 1)

    $remaining = $Length - $pwChars.Count
    for ($i = 1; $i -le $remaining; $i++) {
        $pwChars += $all | Get-Random -Count 1
    }

    # Shuffle
    -join ($pwChars | Get-Random -Count $pwChars.Count)
}

# Optional: list of SamAccountName patterns to skip (service accounts, gMSA, etc.)
$ExcludePatterns = @('svc_', 'gmsa$', 'krbtgt')  # tweak patterns as needed (case-insensitive)

# Get AD users - adjust filter if you want different selection (e.g., exclude disabled, system accounts, OU scope)
$users = Get-ADUser -Filter { Enabled -eq $true } -Properties SamAccountName, UserPrincipalName, DistinguishedName

foreach ($user in $users) {
    # Skip accounts matching exclude patterns
    $sam = $user.SamAccountName
    $skip = $false
    foreach ($pat in $ExcludePatterns) {
        if ($sam -match $pat) { $skip = $true; break }
    }
    if ($skip) {
        "$sam - SKIPPED (matches exclusion pattern)" | Out-File -FilePath $OutputFile -Append
        Write-Host "SKIP: $sam" -ForegroundColor Yellow
        continue
    }

    try {
        $plain = New-RandomPassword -Length 15
        $secure = ConvertTo-SecureString $plain -AsPlainText -Force

        # Reset (overwrite) the AD account password
        Set-ADAccountPassword -Identity $user.DistinguishedName -NewPassword $secure -Reset -ErrorAction Stop

        # Optional: force change at next logon
        Set-ADUser -Identity $user.DistinguishedName -ChangePasswordAtLogon $true -ErrorAction Stop

        # Optional: unlock account if locked
        try { Unlock-ADAccount -Identity $user.DistinguishedName -ErrorAction SilentlyContinue } catch {}

        # Log UPN/SAM and plain password
        $logLine = "{0}`t{1}`t{2}" -f $user.SamAccountName, $user.UserPrincipalName, $plain
        $logLine | Out-File -FilePath $OutputFile -Append -Encoding UTF8

        Write-Host "RESET: $($user.SamAccountName)" -ForegroundColor Green
    }
    catch {
        $err = $_.Exception.Message
        $msg = "{0}`t{1}`tERROR: {2}" -f $user.SamAccountName, $user.UserPrincipalName, $err
        $msg | Out-File -FilePath $OutputFile -Append -Encoding UTF8
        Write-Host "FAILED: $($user.SamAccountName) - $err" -ForegroundColor Red
    }
}

# Secure the output file permissions
try {
    Secure-OutputFile -path $OutputFile
    Write-Host "Output file written and ACL set: $OutputFile" -ForegroundColor Cyan
}
catch {
    Write-Host "WARNING: Could not set ACL on $OutputFile. Error: $_" -ForegroundColor Yellow
}

Write-Host "Done. Review $OutputFile, then securely delete it when finished." -ForegroundColor Cyan
