#!/bin/bash
echo "0 0 * * * root apt update && apt upgrade -y" | sudo tee -a /etc/crontab
echo "Updates scheduled for midnight."
