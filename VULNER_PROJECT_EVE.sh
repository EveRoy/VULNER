#!/bin/bash

function START() {
    echo "------ Starting START at $(date) ------"
cols=$(tput cols)
banner=$(figlet -f slant -w $cols "PENETRATION TESTING")
project=$(figlet -f slant -w $cols "PROJECT: VULNER")

echo -e "${blue}$(printf '%*s' $(((${#banner} + cols) / 2)) "$banner")${reset}"
echo -e "${blue}$(printf '%*s' $(((${#project} + cols) / 2)) "$project")${reset}"

    # Checks if the script is run as root for proper permissions.
    user=$(whoami)
    if [ "$user" == "root" ]; then
        echo "You are root.. continuing.."

        for ((attempts = 1; attempts <= 3; attempts++)); do
            read -p "Enter a valid network (e.g., 10.0.0.0/24): " user_network                                                #1.1 Get from the user a network to scan.
            if validate_network "$user_network"; then
                echo "Valid network: $user_network"
                DIRoutput
                exit 0
            else
                echo "Invalid network. Try again."
            fi
        done

        echo "Too many invalid attempts. Exiting."
        exit 1

    else
        echo "You are not root.. exiting..."
        exit
    fi

    echo "------ Finished at $(date) ------"
}

function validate_network() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]
}

function DIRoutput() {
    Tools
    echo "Creating a directory for the penetration testing..."
    echo "Please provide path+name of the output directory (e.g., /home/kali/Desktop/Testing)"                             #1.2 Get from the user a name for the output directory.
    read OUTPUT_DIR
    mkdir -p "$OUTPUT_DIR"

    # Ensure rockyou.txt is available                                                                                      #2.1.Built-in password.lst to check for weak passwords
    if [ ! -f /usr/share/wordlists/rockyou.txt ]; then
        echo "Unzipping rockyou.txt.gz..."
        gunzip /usr/share/wordlists/rockyou.txt.gz
    fi
    cp /usr/share/wordlists/rockyou.txt "$OUTPUT_DIR"

    echo "Please choose a mode:"                                                                                          #1.3 Allow the user to choose 'Basic' or 'Full'.
    echo "1) Basic - Scans the network for TCP and UDP, including the service version and weak passwords"
    echo "2) Full - Include NSE, weak passwords, and vulnerability analysis."

    read -p "Enter your choice (1 or 2): " choice

    case $choice in
    1)
        Basic
        ;;
    2)
        Full
        ;;
    *)
        echo "Invalid choice. Exiting the script in 5 sec..."
        sleep 5
        ;;
    esac
}

function END_SCRIPT() {
    echo "------ Finished at $(date) ------"
    echo "The result saved into text files. Would you like to search inside the results? [Y/N]"                            #4.2 At the end, show the user the found information. 4.3 Allow the user to search inside the results.
    read search
    if [ "$search" == "y" ]; then
        echo "You chose to search in the results files. What keyword would you like to use?"
        read key
        grep -i "$key" "$OUTPUT_DIR"/*
    else
        echo "You chose not to search into the results."
    fi

    echo "Now proceeding to save the files into a ZIP archive."                                                           #4.4 Allow to save all results into a Zip file.
    zip -r "$OUTPUT_DIR.zip" "$OUTPUT_DIR" > /dev/null 2>&1
    echo "------ Output directory has been zipped to $OUTPUT_DIR.zip ------"
}

function HYDRA() {
    echo "Starting Hydra brute-force for RDP service... Do you want to use rockyou.txt file or your own? please write full path. [e.g. /home/kali/testing/list.txt]"
    read list
    username_list=$list
    password_list=$list
	
    if [ ! -f "$username_list" ] || [ ! -f "$password_list" ]; then
        echo "Error: Username or password list not found in $OUTPUT_DIR."
        return 1
    fi
    # Execute Hydra
hydra -t 4 -L "$username_list" -P "$password_list" rdp://"$target_ip"  | tee -a "$OUTPUT_DIR/hydra_rdp_$TIMESTAMP.txt"

    echo "Hydra brute-force completed. Results saved in $OUTPUT_DIR/hydra_rdp_$TIMESTAMP.txt"
}

function PASSWORD_BRUTE() {
    echo -e "Looking for weak login passwords. For brute-forcing, please choose a password list:\n\n[1] rockyou.txt\n[2] Default list\n[3] I want to supply my own list\n"
    read -p "Choose 1, 2, or 3: " brute_choice

    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    output_file="$OUTPUT_DIR/Brute_${brute_choice}_${choice}_${TIMESTAMP}.txt"

    case $brute_choice in                                                                                                   #2.2 Login services to check include: SSH, RDP, FTP, and TELNET
    1)
        echo "Using rockyou.txt for brute-forcing."
        protocols=("ftp" "ssh" "telnet")
        for protocol in "${protocols[@]}"; do
            nmap --script="${protocol}-brute" --script-args passdb=rockyou.txt -T4 "$user_network" -sV >>"$output_file"
        done
        read -p "Would you like to brute-force RDP service? [y/n] " answer
answer=$(echo "$answer" | tr -d '[:space:]')  # Remove spaces or newlines

if [[ "$answer" == "y" ]]; then
    echo "You chose to brute force RDP service. Please wait."
    HYDRA
else
    echo "You chose not to Brute force RDP service."
fi
        ;;
    2)
        echo "Using the default password list for brute-forcing."
        protocols=("ftp" "ssh" "telnet")
        for protocol in "${protocols[@]}"; do
            nmap --script="${protocol}-brute" -T4 "$user_network" -sV >>"$output_file"
        done
        ;;
    3)
        echo "Provide the full path to your custom password list:"                                                              #2.1.2 Allow the user to supply their own password list.
        read password_list
        if [ ! -f "$password_list" ]; then
            echo "Password list not found. Exiting brute-forcing..."
            return 1
        fi
        protocols=("ftp" "ssh" "telnet")
        for protocol in "${protocols[@]}"; do
            nmap --script="${protocol}-brute" --script-args passdb="$password_list" -T4 "$user_network" -sV >>"$output_file"
        done
         read -p "Would you like to brute-force RDP service? [y/n] " answer
answer=$(echo "$answer" | tr -d '[:space:]')  # Remove spaces or newlines

if [[ "$answer" == "y" ]]; then
    echo "You chose to brute force RDP service. Please wait."
    HYDRA
else
    echo "You chose not to Brute force RDP service."
fi
        ;;
    *)
        echo "Invalid choice. Returning to PASSWORD_BRUTE."
        return 1
        ;;
    esac
}

function Basic() {                                                                                                                 #1.3.1 Basic: scans the network for TCP and UDP, including the service version and weak passwords.
    echo "You selected Basic Mode."
    echo "Scanning the network..."
    nmap -p- -sV -T4 "$user_network" >>"$OUTPUT_DIR/scan_version.txt"
    masscan -pU:1-65535 "$user_network" --rate 10000 -oG "$OUTPUT_DIR/udp_ports.txt"
    echo "Detecting weak passwords..."
	nmap --script=ftp-brute,ssh-brute,telnet-brute -T4 "$user_network" -sV > $OUTPUT_DIR/user_pass.lst                              #2.1 weak passwords used in the network for login services.
    cat $OUTPUT_DIR/user_pass.lst | grep pair | awk '{print $NF}' | sed 's/:/ /g' | awk '{print $1}'| sort | uniq  > $OUTPUT_DIR/weak_user_pass.txt
    END_SCRIPT
}

function Full() {                                                                                                                 #1.3.2 Full: Nmap Scripting Engine (NSE), weak passwords, and vulnerability analysis.
    echo "You selected Full Mode."
    read -p "Enter a valid IP address: " target_ip                                                                                #1.4 Making sure the input is valid.
    if validate_ip "$target_ip"; then
        echo "Scanning the IP address for vulnerabilities and weak passwords..."
        nmap -sV --script=vuln -T4 "$target_ip" | grep open >"$OUTPUT_DIR/full_vuln.txt"                                          #3.1 Mapping vulnerabilities should only take place if Full was chosen
        echo "Potential vulnerabilities via NSE and searchsploit:"                                                                #3.2 Display potential vulnerabilities via NSE and Searchsploit.
        awk '{print $3, $4, $5}' "$OUTPUT_DIR/full_vuln.txt" | while read service version extra; do
            searchsploit "$service $version $extra" | tee -a "$OUTPUT_DIR/Full_searchsploit.txt"
        done
        PASSWORD_BRUTE
        END_SCRIPT
    else
        echo "Invalid IP address."
    fi
}

function validate_ip() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && for octet in ${1//./ }; do
        ((octet >= 0 && octet <= 255)) || return 1
    done
    return 0
}

function Tools() {
    tools=("searchsploit" "hydra" "nmap" "masscan")
    for tool in "${tools[@]}"; do
        if which "$tool" > /dev/null; then
            echo "$tool is already installed."
        else
            echo "$tool is not installed, installing now..."
            sudo apt install -y "$tool"
        fi
    done
}

# Start the process
START
