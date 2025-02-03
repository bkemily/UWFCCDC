#!/bin/bash
echo "System Information:"
uname -a
echo "CPU Info:"
lscpu | grep "Model name"
echo "Memory Info:"
free -h
