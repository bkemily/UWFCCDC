# Enable Windows Defender Firewall
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True

# Block all incoming connections unless explicitly allowed
Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultInboundAction Block -DefaultOutboundAction Allow

Write-Host "Firewall enabled and inbound connections blocked."
