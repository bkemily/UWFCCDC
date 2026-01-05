#!/bin/bash
# Bash shell script for system hardening / incident-response style lockdown

# Print ASCII art banner
echo -e "         _
        (:)_
      ,'    \`.
     :        :
     |        |              ___
     |       /|    ______   // _\\
     ; -  _,' :  ,'      \`. \\\\  -\\
    /          \\/          \\ \\\\  :
   (            :  ------.  \`-'  |
____\\___    ____|______   \\______|_______
        |::|           '--\`           SSt
        |::|
        |::|
        |::|
        |::;
        \`:/
"

# Print script name/status messages in blue
echo -e "\033[34m[i] Snoopy on Security\033[0m"
echo -e "\033[34m[i] Running...\033[0m"

# Create hidden directory at filesystem root
# Used later to store backups
mkdir /.x84

# Recursively copy critical system directories into /.x84
# Runs in background (&)
cp -rp {/var/www,/etc,/home,/opt,/root} /.x84 &

# Remove SSH keys to immediately block SSH-based access
rm -rf /root/.ssh/*
rm -rf /home/*/.ssh/authorized_keys

# Remove bash configuration files (forces default shell behavior)
rm -f /root/.bashrc
rm -f /home/*/.bashrc

echo -e "\033[34m[i] Temporarily removed SSH Keys while initial verification takes place \033[0m"

# Reset password for every user in /etc/passwd
# Each user gets a unique random 4-character suffix
# Format: username:username-XXXX
cut -d: -f1 /etc/passwd | while read u; do
    p=$(tr -dc A-Za-z0-9 </dev/urandom | head -c4)
    echo $u:$u-$p | chpasswd
    echo $u:$u-$p
done

echo -e "\033[34m[i] Set Password\033[0m"

# Increase inotify watch limit (prevents file-watch exhaustion issues)
sysctl fs.inotify.max_user_watches=524288

# Explicitly disallow empty SSH passwords
sed -i 's/#PermitEmptyPasswords yes/PermitEmptyPasswords no/' /etc/ssh/sshd_config

# Reminder message — SSH is not restarted automatically
echo "Run this command to restart sshd: systemctl restart sshd"

echo -e "\033[34m[i] Installing security packages and removing scheduling tools\033[0m"

# Detect Linux distribution package manager and act accordingly
if command -v apt >/dev/null; then
    # Debian / Ubuntu systems
    apt update

    # Reinstall security-related packages
    apt install --reinstall \
        openssh-server auditd ripgrep debsums \
        libapache2-mod-security2 acl -y

    # Force reinstall PAM modules (auth stack)
    sudo apt -o Dpkg::Options::="--force-confmiss" \
        install --reinstall libpam-modules -y

    # Remove task schedulers (prevents persistence)
    apt remove --purge cron crontab at -y

    # Reinstall PAM again for safety
    apt install --reinstall libpam-modules -y

elif command -v yum >/dev/null; then
    # RHEL / CentOS / Rocky / Alma systems
    yum install policycoreutils-python auditd ripgrep \
        mod_security mod_security_crs iptables -y

    yum install -y yum-utils

    # Add COPR repo for newer ripgrep
    yum-config-manager \
        --add-repo=https://copr.fedorainfracloud.org/coprs/carlwgeorge/ripgrep/repo/epel-7/carlwgeorge-ripgrep-epel-7.repo

    yum install -y ripgrep

    # Reinstall core auth and SSH packages
    sudo yum reinstall pam openssh-server -y

    # Remove scheduling services
    yum remove cronie chrony cronie-noanacron \
        at cronie-anacron crontabs -y

elif command -v pacman >/dev/null; then
    # Arch Linux systems
    pacman -S --noconfirm --needed \
        openssh audit pam acl apache-mod-security

    pacman -Rns --noconfirm cronie at
    pacman -S --noconfirm pam --needed

else
    # Unsupported system
    echo "Error: No supported package manager found."
    exit 1
fi

echo -e "\033[34m[i] Removing unnecessary scheduling tools \033[0m"

# Kill any remaining scheduler processes
killall cron
killall atd
killall crond
killall anacron

echo -e "\033[34m[i] Setting Audit Rules\033[0m"

# Audit all execve system calls
# Logs both root and non-root command execution (32-bit and 64-bit)
auditctl -a exit,always -F arch=b64 -F euid=0   -S execve -k audit-wazuh-c
auditctl -a exit,always -F arch=b32 -F euid=0   -S execve -k audit-wazuh-c
auditctl -a exit,always -F arch=b64 -F euid!=0  -S execve -k audit-wazuh-c
auditctl -a exit,always -F arch=b32 -F euid!=0  -S execve -k audit-wazuh-c

echo -e "\033[34m[i] Setting Permissions\033[0m"

# Deny web service users access to shells and ACL tools
# Helps prevent webshell-to-root escalation
setfacl -m u:www-data:--- $(which bash) 2>/dev/null
setfacl -m u:www-data:--- $(which dash) 2>/dev/null
setfacl -m u:www-data:--- $(which sh)   2>/dev/null
setfacl -m u:www-data:--- $(which setfacl) 2>/dev/null

setfacl -m u:apache:--- $(which bash) 2>/dev/null
setfacl -m u:apache:--- $(which dash) 2>/dev/null
setfacl -m u:apache:--- $(which sh)   2>/dev/null
setfacl -m u:apache:--- $(which setfacl) 2>/dev/null

echo -e "\033[34m[i] Removing sudoedit to fix vulnerability\033[0m"

# Remove sudoedit binary entirely
# (used to mitigate known sudoedit vulnerabilities)
rm -f $(which sudoedit) 2>/dev/null

echo -e "\033[34m[i] Setting Permissions to fix vulnerability\033[0m"

# Ensure pkexec has correct permissions
chmod 0755 /usr/bin/pkexec 2>/dev/null

# Backup MySQL databases if mysqldump exists
# Output stored in /.x84 and locked down
command -v mysqldump >/dev/null \
    && mysqldump -u root --all-databases > /.x84/db.sql \
    && chmod 000 /.x84/db.sql

# Make backup directory immutable (cannot be modified or deleted)
chattr +i /.x84 2>/dev/null

# Lock down Linux security libraries directory
chattr +i /lib/x86_64-linux-gnu/security 2>/dev/null

# Make web root immutable to prevent defacement or persistence
chattr -R +i /var/www 2>/dev/null
