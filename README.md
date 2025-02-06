# VULNER
A Bash script that automates penetration testing tasks, including network scanning, vulnerability detection, and password brute-forcing, with customizable modes.

# Penetration Testing Automation Script

This script automates various aspects of penetration testing, including network scanning, vulnerability assessment, brute force attacks, and weak password detection. It offers two modes: **Basic** and **Full**, allowing users to customize their testing approach based on requirements.

---

## Features

- **Network Scanning:**
  - Scans TCP and UDP ports.
  - Includes service version detection.
  - Identifies open ports and potential vulnerabilities.

- **Weak Password Detection:**
  - Detects weak login credentials for services like FTP, SSH, Telnet, and RDP.
  - Supports built-in `rockyou.txt` or user-supplied password lists.

- **Brute-Force Attacks:**
  - Uses `Hydra` and `Nmap` for brute-forcing login services.
  - Allows selection of custom or built-in password lists.

- **Vulnerability Analysis:**
  - Utilizes Nmap Scripting Engine (NSE) and `searchsploit` to detect vulnerabilities and map them to exploits.

- **Output Management:**
  - Saves results to user-defined directories.
  - Compresses output files into a ZIP archive.
  - Allows keyword-based searches within results.

---

## Prerequisites

Ensure the following tools are installed:
- `figlet`
- `nmap`
- `masscan`
- `hydra`
- `searchsploit`
- `rockyou.txt` (available in Kali Linux or `/usr/share/wordlists/`)

Install any missing tools using:
```bash
sudo apt install figlet nmap masscan hydra exploitdb -y
```

---

## Usage

### 1. **Run the Script**
```bash
sudo ./script.sh
```

### 2. **Choose a Network**
Provide a valid network CIDR (e.g., `10.0.0.0/24`) for scanning.

### 3. **Select Mode**
- **Basic Mode:** 
  - Scans network for TCP/UDP ports and detects weak passwords.
- **Full Mode:**
  - Includes vulnerability analysis, weak passwords, and exploit mapping.

### 4. **Search Results**
After the script finishes, you can search the output for specific keywords or compress the results into a ZIP file.

---

## Example Output

### **Basic Mode**
- Scan results saved as `scan_version.txt` and `udp_ports.txt`.
- Weak passwords listed in `weak_user_pass.txt`.

### **Full Mode**
- Vulnerabilities saved as `full_vuln.txt`.
- Exploits mapped using `searchsploit` and saved to `Full_searchsploit.txt`.

---

## Functions Overview

- **`START`**: Initializes the script and checks user permissions.
- **`validate_network`**: Validates user-provided network addresses.
- **`DIRoutput`**: Sets up the output directory and ensures tools are available.
- **`Basic`**: Performs a quick network scan and weak password detection.
- **`Full`**: Includes detailed vulnerability analysis and brute-forcing.
- **`HYDRA`**: Performs brute-force attacks for RDP services.
- **`PASSWORD_BRUTE`**: Checks for weak passwords in various protocols.
- **`END_SCRIPT`**: Finalizes the script, offers search functionality, and compresses results.

---

## Example Commands

### **Run a Basic Scan**
```bash
sudo ./script.sh
# Choose Basic Mode and enter network details (e.g., 192.168.1.0/24).
```

### **Perform Brute-Force Attacks**
- Choose `rockyou.txt` or supply your own password list.
- Run brute-force for SSH, FTP, Telnet, and RDP services.

---

## Troubleshooting

- **Error: `Command not found`:** Ensure all tools (`nmap`, `masscan`, etc.) are installed and available in your PATH.
- **Invalid Network:** Double-check the format of your network (e.g., `10.0.0.0/24`).

---

## Disclaimer

This script is intended for **educational purposes only**. Unauthorized use against systems you do not own or have explicit permission to test is illegal.

---

## License

This project is open-source and licensed under the [MIT License](https://opensource.org/licenses/MIT).
