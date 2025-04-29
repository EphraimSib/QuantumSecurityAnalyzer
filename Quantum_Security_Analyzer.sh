#!/bin/bash                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                
# ༺༻༺༻༺༻༺༻༻༺༻༺༻༺༻༺༻༺༻༺༻༺༻༺༻༺༻༺༻༺༻༺༻༺༻༺༻
# CYBER SENTINEL PRO - Enterprise Penetration Testing Framework
# ༺༻༺༻༺༻༺༻༻༺༻༺༻༺༻༺༻༺༻༺༻༺༻༺༻༺༻༺༻༺༻༺༻༺༻༺༻

# Configuration
REPORT_DIR="$HOME/security_reports"
TEMP_DIR="/tmp/cyber_scan_$(date +%s)"

# Generate a UUID for session token with fallback if uuidgen is not available
if command -v uuidgen &> /dev/null; then
    SESSION_TOKEN=$(uuidgen)
elif [ -r /proc/sys/kernel/random/uuid ]; then
    SESSION_TOKEN=$(cat /proc/sys/kernel/random/uuid)
else
    # Fallback: generate random hex string
    SESSION_TOKEN=$(head -c 16 /dev/urandom | xxd -p)
fi

LEGAL_WARNING="Unauthorized access violates international laws. You MUST have written authorization."

# Text formatting
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Initialize target data
TARGET_DOMAIN=""
TARGET_IP=""
YOUR_EMAIL=""
AUTH_CODE=""

# Professional Tools Config
declare -A WORDLISTS=(
    ["DIRB"]="/usr/share/wordlists/dirb/common.txt"
    ["FUZZ"]="/usr/share/wordlists/wfuzz/general/common.txt"
    ["USERNAMES"]="/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt"
)

# Dependency Check
check_dependencies() {
    declare -A tools=(
        ["nmap"]="Network Mapper"
        ["nikto"]="Web Server Scanner"
        ["dirb"]="Directory Bruteforcer"
        ["whois"]="Domain Information"
        ["sqlmap"]="SQL Injection Testing"  # Ensure sqlmap is installed to avoid missing dependency
        ["msfconsole"]="Metasploit Framework"
        ["dnsenum"]="DNS Enumeration"
    )

    for cmd in "${!tools[@]}"; do
        if ! command -v $cmd &> /dev/null; then
            echo -e "${RED}✗ Missing: ${tools[$cmd]}${NC}"
            exit 1
        fi
    done
}

# Legal Compliance
verify_authorization() {
    echo -e "${YELLOW}${BOLD}[Legal Notice] ${LEGAL_WARNING}${NC}"
    read -p "Enter Authorization Code/Token: " AUTH_CODE
    if [[ ${#AUTH_CODE} -lt 25 ]]; then
        echo -e "${RED}Invalid authorization token!${NC}"
        exit 1
    fi
    echo "$AUTH_CODE" > "$TEMP_DIR/authorization_proof.txt"
}

# Reconnaissance Suite
advanced_recon() {
    echo -e "${BLUE}[+] WHOIS Intelligence Gathering${NC}"
    whois $TARGET_DOMAIN | tee "$TEMP_DIR/whois_$SESSION_TOKEN.txt"

    echo -e "${BLUE}[+] DNS Enumeration & Zone Transfer${NC}"
    dnsenum --threads 8 $TARGET_DOMAIN | tee "$TEMP_DIR/dnsenum_$SESSION_TOKEN.txt"

    echo -e "${BLUE}[+] Subdomain Bruteforcing${NC}"
    knockpy $TARGET_DOMAIN | tee "$TEMP_DIR/subdomains_$SESSION_TOKEN.txt"
}

# Web Application Testing
web_assessment() {
    echo -e "${BLUE}[+] Nikto Vulnerability Scan${NC}"
    nikto -h $TARGET_DOMAIN -output "$TEMP_DIR/nikto_$SESSION_TOKEN.xml" -Format xml

    echo -e "${BLUE}[+] DIRB Directory Bruteforce${NC}"
    dirb "https://$TARGET_DOMAIN" "${WORDLISTS[DIRB]}" -o "$TEMP_DIR/dirb_$SESSION_TOKEN.txt"

    echo -e "${BLUE}[+] XSS & SQLi Testing${NC}"
    sqlmap -u "https://$TARGET_DOMAIN/login" --level=5 --risk=3 --batch | tee "$TEMP_DIR/sqlmap_$SESSION_TOKEN.txt"
}

# Network Exploitation
network_exploitation() {
    echo -e "${BLUE}[+] Nmap Vulnerability Scan${NC}"
    nmap -sV --script vuln -T4 $TARGET_IP -oN "$TEMP_DIR/nmap_vuln_$SESSION_TOKEN.txt"

    echo -e "${BLUE}[+] Metasploit Framework Integration${NC}"
    msfconsole -q -x "use auxiliary/scanner/http/title; set RHOSTS $TARGET_IP; run; exit" | tee "$TEMP_DIR/metasploit_$SESSION_TOKEN.txt"
}

# Post-Exploitation
post_exploit() {
    echo -e "${BLUE}[+] Privilege Escalation Checks${NC}"
    linpeas | tee "$TEMP_DIR/linpeas_$SESSION_TOKEN.txt"

    echo -e "${BLUE}[+] Network Sniffing (10s capture)${NC}"
    tcpdump -i any -w "$TEMP_DIR/pcap_$SESSION_TOKEN.pcap" -c 500
}

# Reporting System
generate_report() {
    echo -e "${BLUE}[+] Compiling Technical Report${NC}"
    echo "Penetration Test Report" > "$REPORT_DIR/report_$SESSION_TOKEN.md"
    echo "======================" >> "$REPORT_DIR/report_$SESSION_TOKEN.md"
    echo "Date: $(date)" >> "$REPORT_DIR/report_$SESSION_TOKEN.md"
    echo "Target: $TARGET_DOMAIN ($TARGET_IP)" >> "$REPORT_DIR/report_$SESSION_TOKEN.md"

    echo -e "\n## Findings" >> "$REPORT_DIR/report_$SESSION_TOKEN.md"
    cat $TEMP_DIR/*_$SESSION_TOKEN.txt >> "$REPORT_DIR/report_$SESSION_TOKEN.md"

    pandoc "$REPORT_DIR/report_$SESSION_TOKEN.md" -o "$REPORT_DIR/report_$SESSION_TOKEN.pdf"

    echo -e "${GREEN}Report generated: $REPORT_DIR/report_$SESSION_TOKEN.pdf${NC}"
}

# Main Interface
show_header() {
    clear
    echo -e "${MAGENTA}"
    echo "    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄"
    echo "    █                                    █"
    echo "    █ Q U A N T U M .S. A N A L Y Z E R  █"
    echo "    █       Ethical Security Core        █"
    echo "    █          by Ephraim sib @github    █"
    echo "    ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀"
    echo -e "${NC}"
}

# Main Interface
main_menu() {
    while true; do
        echo -e "\n${BOLD}Professional Penetration Menu:${NC}"
        echo "1. Full Reconnaissance Suite"
        echo "2. Web Application Assessment"
        echo "3. Network Exploitation"
        echo "4. Post-Exploitation Activities"
        echo "5. Generate Technical Report"
        echo "6. Exit and Cleanup"

        read -p "Select Operation: " choice

        case $choice in
            1) advanced_recon ;;
            2) web_assessment ;;
            3) network_exploitation ;;
            4) post_exploit ;;
            5) generate_report ;;
            6) echo -e "${RED}Sanitizing environment...${NC}"; rm -rf $TEMP_DIR; exit 0 ;;
            *) echo -e "${RED}Invalid selection!${NC}" ;;
        esac
    done
}

# Initialization
mkdir -p $REPORT_DIR $TEMP_DIR
check_dependencies
verify_authorization

read -p "Enter target domain: " TARGET_DOMAIN
read -p "Enter target IP: " TARGET_IP
read -p "Enter your email: " YOUR_EMAIL

main_menu








