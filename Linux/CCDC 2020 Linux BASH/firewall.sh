#!/bin/bash
#Meant to check if firewall is enabled, enable firewall
$stat = sudo ufw status
echo $stat
if [ ${stat} = "Status: inactive" ]
	then
	sudo ufw enable
fi
sudo aot-get install firestarter