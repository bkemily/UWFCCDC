# Enable Audit Policies
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable

Write-Host "Audit policies enabled."
