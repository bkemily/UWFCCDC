#!/bin/bash
read -p "Are you sure you want to clear system logs? (y/n) " answer
if [[ $answer == "y" ]]; then
    sudo truncate -s 0 /var/log/syslog
    echo "Logs cleared!"
else
    echo "Operation cancelled."
fi
