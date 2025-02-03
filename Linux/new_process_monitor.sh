#!/bin/bash
# Enhanced script for detecting new processes
# @author JaminB

# Take initial process snapshot
ps -eo pid,comm | sort -k2 > snapshot

while true; do
    # Capture current processes
    current_proc=$(ps -eo pid,comm | sort -k2)

    echo "NEW PROCESSES DETECTED:"
    echo "------------------------"

    # Find new processes (those not in the snapshot)
    comm -13 snapshot <(echo "$current_proc") > possiblyBad

    while read line; do
        echo "$line"
    done < possiblyBad

    # Sleep before checking again
    sleep 3
done
