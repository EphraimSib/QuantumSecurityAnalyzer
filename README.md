# Quantum Security Analyzer Requirements
# For Professional Ethical Hackers Only

=== CORE DEPENDENCIES ===
nmap - Network exploration and security auditing
nikto - Web server vulnerability scanner
dirb - Web directory brute-forcer
whois - Domain information lookup
sqlmap - Automatic SQL injection tool
metasploit-framework - Penetration testing framework
dnsenum - DNS enumeration tool
knockpy - Subdomain discovery tool
linpeas - Linux privilege escalation checker
tcpdump - Network packet analyzer
pandoc - Universal document converter (for PDF reports)
wkhtmltopdf - HTML to PDF conversion
figlet - ASCII banner generator
openssl - Cryptography toolkit
sshpass - SSH automation tool

=== PYTHON LIBRARIES ===
python3 - Python interpreter
python3-pip - Python package manager
pycryptodome - Cryptographic functions (AES/RSA)
termcolor - Terminal color formatting
requests - API communication

=== MANUAL INSTALLATIONS ===
# Install these first on Debian/Ubuntu:
sudo apt update && sudo apt install -y \
  nmap nikto dirb whois sqlmap metasploit-framework \
  dnsenum wkhtmltopdf pandoc figlet openssl sshpass \
  python3 python3-pip tcpdump

# Python packages:
pip3 install pycryptodome termcolor requests

=== AUTHORIZATION SETUP ===
1. Generate Authokey after installation:
   ./quantum_analyzer.sh --setup-auth

2. Store Authokey.txt in encrypted volume
3. Rotate keys every 30 days:
   ./quantum_analyzer.sh --rotate-keys

=== USAGE NOTES ===
1. Requires root privileges for network operations
2. Legal authorization mandatory for all scans
3. Tested on Kali Linux 2023.4 and Ubuntu 22.04 LTS
4. Isolated Docker environment recommended
5. Internet connection required for vulnerability DB updates

# Ethical Compliance
- Penetration Testing Execution Standard (PTES) compliant
- GDPR/CCPA aware data handling
- Automatic audit trail generation
