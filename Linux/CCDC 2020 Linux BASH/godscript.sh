#!/bin/bash
# This script consolidates multiple security scripts into one.

# Function for formatted output
becho() {
    echo "$(tput bold)$1$(tput sgr0)"
}

# Function for checking script existence before execution
run_script() {
    if [[ -f "$1" ]]; then
        sudo chmod 755 "$1"
        sudo "$1"
    else
        echo "Error: $1 not found!"
    fi
}

# Function for displaying the menu
show_menu() {
    clear
    becho "Welcome!"
    becho "Please enter the password:"
    read -s password

    # Password validation
    if [[ "$password" != "password" ]]; then
        echo "Incorrect password. Exiting..."
        exit 1
    fi

    while true; do
        echo ""
        echo "1. Port Block - Blocks all known potentially dangerous ports."
        echo "2. Media Delete - Deletes all unauthorized media files."
        echo "3. User Search - Deletes bad users, changes groups to proper, and sets passwords."
        echo "4. PAM Configuration - Sets up automatic auditing."
        echo "5. Exit"
        echo ""
        echo "Please type the number you wish to activate:"

        read activate

        case $activate in
            1) run_script "./portBlock.sh" ;;
            2) run_script "./mediaDel.sh" ;;
            3) run_script "./userSea.sh" ;;
            4) run_script "./pamConfig.sh" ;;
            5) echo "Exiting..."; exit 0 ;;
            *) echo "Invalid choice. Please enter a number from 1 to 5." ;;
        esac
    done
}

# Run the script
show_menu
