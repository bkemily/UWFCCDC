#!/bin/bash
# This script is made to block known dangerous ports
sudo ufw deny 7
sudo ufw deny 9
sudo ufw deny 13
sudo ufw deny 17
sudo ufw deny 19
sudo ufw deny 23
sudo ufw deny 111
sudo ufw deny 113
sudo ufw deny 123
sudo ufw deny 135
sudo ufw deny 137
sudo ufw deny 139
sudo ufw deny 389
sudo ufw deny 445
sudo ufw deny 500
sudo ufw deny 515
sudo ufw deny 520
sudo ufw deny 1002
sudo ufw deny 1024
sudo ufw deny 1025
sudo ufw deny 1026
sudo ufw deny 1027
sudo ufw deny 1028
sudo ufw deny 1029
sudo ufw deny 1030
sudo ufw deny 1337
sudo ufw deny 1433
sudo ufw deny 1444
sudo ufw deny 1701
sudo ufw deny 1720
sudo ufw deny 1723
sudo ufw deny 2049
sudo ufw deny 2869
sudo ufw deny 4500
#Restart the godscript
sudo ./godscript.sh