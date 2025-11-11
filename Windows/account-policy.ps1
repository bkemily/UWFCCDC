# Basic CIS-style Account & Lockout Policy for Windows
# Covers:
# 1.1.1–1.1.7, 1.2.1–1.2.4

# Optional: values as variables (easy to tweak)
$EnforcePasswordHistory = 24      # 1.1.1
$MaxPasswordAgeDays     = 365     # 1.1.2
$MinPasswordAgeDays     = 1       # 1.1.3
$MinPasswordLength      = 14      # 1.1.4

$AccountLockoutDuration = 15      # minutes, 1.2.1
$AccountLockoutThreshold = 5      # attempts, 1.2.2
$ResetLockoutAfter      = 15      # minutes, 1.2.4

Write-Host "Setting password and lockout policy with net accounts..." -ForegroundColor Cyan

# net accounts handles:
# - Enforce password history
# - Max/Min password age
# - Minimum password length
# - Lockout duration/threshold/reset
net accounts `
    /uniquepw:$EnforcePasswordHistory `
    /maxpwage:$MaxPasswordAgeDays `
    /minpwage:$MinPasswordAgeDays `
    /minpwlen:$MinPasswordLength `
    /lockoutduration:$AccountLockoutDuration `
    /lockoutthreshold:$AccountLockoutThreshold `
    /lockoutwindow:$ResetLockoutAfter

if ($LASTEXITCODE -ne 0) {
    Write-Warning "net accounts returned exit code $LASTEXITCODE"
} else {
    Write-Host "net accounts settings applied." -ForegroundColor Green
}

Write-Host "Setting registry-based policy values..." -ForegroundColor Cyan

# 1.1.5 Password must meet complexity requirements = Enabled
# HKLM\SYSTEM\CurrentControlSet\Control\Lsa\PasswordComplexity (REG_DWORD) = 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                 -Name "PasswordComplexity" -Type DWord -Value 1

# 1.1.6 Relax minimum password length limits = Enabled
# HKLM\SYSTEM\CurrentControlSet\Control\SAM\RelaxMinimumPasswordLengthLimits (REG_DWORD) = 1
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SAM" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SAM" `
                 -Name "RelaxMinimumPasswordLengthLimits" -Type DWord -Value 1

# 1.1.7 Store passwords using reversible encryption = Disabled
# HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ClearTextPassword (REG_DWORD) = 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                 -Name "ClearTextPassword" -Type DWord -Value 0

# 1.2.3 Allow Administrator account lockout = Enabled (MS only)
# HKLM\SYSTEM\CurrentControlSet\Control\Lsa\AllowAdministratorLockout (REG_DWORD) = 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                 -Name "AllowAdministratorLockout" -Type DWord -Value 1

Write-Host "Registry values applied." -ForegroundColor Green

Write-Host "`nDone. You may need to reboot or run 'gpupdate /force' for everything to fully take effect." -ForegroundColor Yellow
