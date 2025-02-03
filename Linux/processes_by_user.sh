#!/bin/bash
echo "Processes grouped by user:"
ps aux --sort=-%cpu | awk '{print $1}' | uniq -c
