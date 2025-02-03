$securePassword = ConvertTo-SecureString "CyberPatriot!1" -AsPlainText -Force
Get-LocalUser | Where-Object { $_.Name -ne "Administrator" } | ForEach-Object {
    Set-LocalUser -Name $_.Name -Password $securePassword
}
Write-Host "All user passwords have been reset."
