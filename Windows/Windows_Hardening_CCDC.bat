@echo off
:: Windows Security Hardening Script for CCDC
:: Author: Emily Miller
:: Purpose: This script automates common Windows security hardening steps used in CCDC competitions.

:: SECTION 1: User and Group Management
echo [*] Managing Users and Groups...
net user > users_list.txt
net localgroup > groups_list.txt
net localgroup administrators > admin_list.txt
:: Remove unauthorized users from admin group (Replace <username>)
:: net localgroup administrators <username> /delete

:: SECTION 2: Password Policies
echo [*] Enforcing Password Policies...
net accounts /minpwlen:12
net accounts /maxpwage:90
net accounts /lockoutthreshold:5
net accounts /lockoutwindow:15
net accounts /lockoutduration:30

:: SECTION 3: Network Security and Monitoring
echo [*] Checking Network Security...
netstat -naob > network_connections.txt
nbtstat -S > netbios_activity.txt
net share > shares_list.txt
net session > open_sessions.txt

:: SECTION 4: Service Hardening
echo [*] Hardening Windows Services...
sc config RemoteRegistry start= disabled
sc config TlntSvr start= disabled
sc config SSDPDiscovery start= disabled
sc config wuauserv start= disabled

:: SECTION 5: Firewall and Defender Configuration
echo [*] Enabling Firewall and Defender...
netsh advfirewall set allprofiles state on
netsh advfirewall set currentprofile firewallpolicy blockinbound,allowoutbound
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
sc config WinDefend start= auto
net start WinDefend

:: SECTION 6: System Auditing and Log Analysis
echo [*] Enabling Logging and Auditing...
wevtutil qe Security /c:10 /rd:true /f:text > security_logs.txt
auditpol /set /subcategory:"Logon/Logoff" /success:enable /failure:enable
schtasks /query /fo LIST /v > scheduled_tasks.txt
wmic startup list full > startup_programs.txt

:: SECTION 7: File and Permissions Security
echo [*] Setting File Permissions...
icacls "C:\sensitive-folder" /reset
icacls "C:\sensitive-folder" /grant User:R
icacls "C:\sensitive-folder" /deny User:F

:: SECTION 8: System Hardening
echo [*] Hardening Windows System Settings...
net user Guest /active:no
net user Administrator /active:no
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
bcdedit /set nx AlwaysOn
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v Enabled /t REG_DWORD /d 1 /f

echo [*] Security Hardening Complete!
pause
