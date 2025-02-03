#!/bin/bash
find / -type f -perm -o+w -exec ls -lh {} + 2>/dev/null
