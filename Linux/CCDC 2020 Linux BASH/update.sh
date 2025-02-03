#!/bin/bash
#This script is made to update the unix system
sudo apt-get -V -y install firefox hardinfo chkrootkit iptables portsentry lynis ufw gufw sysv-rc-conf nessus clamav
sudo apt-get -V -y install --reinstall coreutils
apt-get -y install bum libpam-cracklib auditd gufw
apt-get -y install unattended-upgrades
sudo apt-get update
sudo apt-get upgrade
sudo apt-get dist-upgrade