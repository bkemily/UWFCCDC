#!/bin/bash
echo "Failed login attempts:"
cat /var/log/auth.log | grep "Failed"
