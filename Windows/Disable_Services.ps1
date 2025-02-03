# List services that are running
Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object Name, DisplayName, StartType

# Disable known unnecessary services
$services = @("RemoteRegistry", "SSDPSRV", "upnphost", "wuauserv", "RemoteAccess")
foreach ($service in $services) {
    Set-Service -Name $service -StartupType Disabled
    Stop-Service -Name $service -Force
}
Write-Host "Unnecessary services disabled."
