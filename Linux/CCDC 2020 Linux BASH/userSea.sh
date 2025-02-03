#!/bin/bash
# This script is made to delete unauthorized user accounts
echo "How many Administrators do you have?"
read numAdmins
echo "How many users do you have?"
read numUsers

declare -a admins
declare -a 
countA = 0
countU = 0

while [  ${countA} -lt numAdmins ]; 
	do
    echo "Name the Administrator in the " ${numAdmins} "place"
	read temp
	admins[${countA}] = temp
	#DO: find out if the admin exists as a user, if not create, if so, then check if they are admin, if not make so, if so, then move on
    let countA=countA+1 
done

while [  ${countU} -lt numUsers ]; 
	do
    echo "Name the Administrator in the " ${numUsers} "place"
	read temp
	users[${countU}] = temp
	#DO: find out if the user exists as a user, if not create, if so, then check if they are admin, if not move on, if so, then undo
    let countU=countU+1 
done



#to use var "${varName}"
#Restart the godscript
sudo ./godscript.sh