#!/bin/bash

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
  echo "THIS SCRIPT MUST BE RUN AS ROOT!" >&2
  exit 1
fi

# Set temporary directory
TEMP_DIR=$(mktemp -d)
TEMP1="$TEMP_DIR/temp1"
TEMP2="$TEMP_DIR/temp2"
TEMP3="$TEMP_DIR/temp3"

# Hash critical files for tracking changes
md5sum /etc/passwd /etc/group /etc/profile /etc/sudoers /etc/hosts /etc/ssh/ssh_config /etc/ssh/sshd_config > "$TEMP2"

# Find .bashrc locations asynchronously
find / -name .bashrc > "$TEMP_DIR/temp4" &

while true; do
    clear
    echo "ACTIVE NETWORK CONNECTIONS:"
    echo "---------------------------"
    ss -tan | grep ESTABLISHED > "$TEMP1"
    
    incoming_ftp=$(grep ":21" "$TEMP1" | wc -l)
    outgoing_ftp=$(grep ":21" "$TEMP1" | wc -l)
    incoming_ssh=$(grep ":22" "$TEMP1" | wc -l)
    outgoing_ssh=$(grep ":22" "$TEMP1" | wc -l)
    incoming_telnet=$(grep ":23" "$TEMP1" | wc -l)
    outgoing_telnet=$(grep ":23" "$TEMP1" | wc -l)

    [[ $outgoing_telnet -gt 0 ]] && echo "$outgoing_telnet successful outgoing telnet connections."
    [[ $incoming_telnet -gt 0 ]] && echo "$incoming_telnet successful incoming telnet sessions."
    [[ $outgoing_ssh -gt 0 ]] && echo "$outgoing_ssh successful outgoing SSH connections."
    [[ $incoming_ssh -gt 0 ]] && echo "$incoming_ssh successful incoming SSH sessions."
    [[ $outgoing_ftp -gt 0 ]] && echo "$outgoing_ftp successful outgoing FTP connections."
    [[ $incoming_ftp -gt 0 ]] && echo "$incoming_ftp successful incoming FTP sessions."

    sleep 5
    clear

    echo "CURRENT LOGIN SESSIONS:"
    echo "-----------------------"
    w
    echo
    echo "RECENT LOGIN SESSIONS:"
    echo "----------------------"
    last | head -n5
    sleep 5
    clear

    # Check for Sleeping Processes
    sleepingProcs=$(ps aux | awk '$8 ~ /S/ {print}')
    if [[ -n "$sleepingProcs" ]]; then
        echo "SLEEP PROCESSES DETECTED!"
        sleep 5
        clear
    fi

    # Track Changes to Important Files
    md5sum /etc/passwd /etc/group /etc/profile /etc/sudoers /etc/hosts /etc/ssh/ssh_config /etc/ssh/sshd_config > "$TEMP3"
    if ! diff -q "$TEMP2" "$TEMP3" > /dev/null; then
        echo "CHANGE TRACKER:"
        echo "---------------"
        diff "$TEMP2" "$TEMP3"
        sleep 5
        clear
    fi

    # Cron Jobs
    echo "CRON JOBS:"
    echo "Found Cronjobs for the following users:"
    echo "---------------------------------------"
    ls /var/spool/cron/crontabs
    echo "Cronjobs in cron.d:"
    echo "-------------------"
    ls /etc/cron.d/
    sleep 5
    clear

    # Display Users Able to Log In
    echo "USERS ABLE TO LOGIN:"
    echo "--------------------"
    awk -F: '($7 !~ "/bin/false|/sbin/nologin") {print $1}' /etc/passwd
    sleep 5
    clear

    # Current Process Tree
    echo "CURRENT PROCESS TREE:"
    echo "---------------------"
    pstree
    sleep 7
    clear
done
