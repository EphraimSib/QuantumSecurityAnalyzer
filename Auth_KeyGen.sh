#!/bin/bash                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              
# ༺༻༺༻༺༻ Authorization Protocol ༺༻༺༻༺༻
AUTH_FILE="$HOME/Authokey.txt"
AUTH_DIR="$HOME/.quantum_auth"

# Generate cryptographic authorization token
generate_authokey() {
    mkdir -p "$AUTH_DIR"
    echo -e "\033[35mGenerating Quantum Authorization Token...\033[0m"

    # Create 2048-bit RSA key pair
    openssl genrsa -out "$AUTH_DIR/private.pem" 2048 2>/dev/null
    openssl rsa -in "$AUTH_DIR/private.pem" -pubout -out "$AUTH_DIR/public.pem" 2>/dev/null

    # Generate UUID token with quantum entropy
    TOKEN=$(uuidgen | sha256sum | base64 | head -c 32)
    echo "$TOKEN" > "$AUTH_FILE"

    # Encrypt token with public key
    openssl rsautl -encrypt -inkey "$AUTH_DIR/public.pem" -pubin -in "$AUTH_FILE" -out "$AUTH_DIR/auth_token.enc" 2>/dev/null

    chmod 600 "$AUTH_FILE"
    echo -e "\033[32mAuthokey generated at: $AUTH_FILE\033[0m"
    echo -e "\033[31mTHIS IS A SENSITIVE FILE - STORE SECURELY\033[0m"
    exit 0
}

# Verify authorization token
verify_authokey() {
    if [ ! -f "$AUTH_FILE" ]; then
        echo -e "\033[31mFATAL: Missing Authokey.txt - Generating new token...\033[0m"
        generate_authokey
    fi

    # Decrypt stored token
    DECRYPTED_TOKEN=$(openssl rsautl -decrypt -inkey "$AUTH_DIR/private.pem" -in "$AUTH_DIR/auth_token.enc" 2>/dev/null)

    if ! grep -q "$DECRYPTED_TOKEN" "$AUTH_FILE"; then
        echo -e "\033[31mINVALID AUTHOKEY - UNAUTHORIZED ACCESS DETECTED\033[0m"
        exit 1
    fi

    echo -e "\033[32mQuantum Authorization Validated\033[0m"
}

# ༺༻༺༻༺༻ Quantum Core ༺༻༺༻༺༻
setup_wsl_quantum_auth() {
    verify_authokey  # Authorization check

    echo -e "\033[36m[QCN] Initializing WSL Quantum Bridge...\033[0m"

    # Existing quantum bridge setup code
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh

    if [ ! -f ~/.ssh/quantum_key ]; then
        echo -e "\033[33mGenerating ED25519 Quantum Key Pair...\033[0m"
        ssh-keygen -t ed25519 -f ~/.ssh/quantum_key -N "" -q
    fi

    if ! grep -q "quantum_key" ~/.ssh/config; then
        cat << EOF >> ~/.ssh/config
Host qcn-access
    HostName localhost
    User \$USER
    IdentityFile ~/.ssh/quantum_key
    IdentitiesOnly yes
EOF
    fi

    if ! dpkg -l openssh-server &> /dev/null; then
        sudo apt update
        sudo apt install -y openssh-server
        sudo service ssh start
    fi

    sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sudo service ssh restart

    if ! grep -q "$(cat ~/.ssh/quantum_key.pub)" ~/.ssh/authorized_keys; then
        cat ~/.ssh/quantum_key.pub >> ~/.ssh/authorized_keys
        chmod 600 ~/.ssh/authorized_keys
    fi

    echo -e "\033[32mQuantum Bridge Established!\033[0m"
}

# ༺༻༺༻༺༻ Verification & Execution ༺༻༺༻༺༻
verify_quantum_connection() {
    echo -e "\033[35mTesting Quantum Entanglement...\033[0m"
    ssh -q -o BatchMode=yes -o ConnectTimeout=5 qcn-access exit

    if [ $? -eq 0 ]; then
        echo -e "\033[32mQuantum Signature Verified!\033[0m"
        return 0
    else
        echo -e "\033[31mQuantum Link Failed!\033[0m"
        return 1
    fi
}

# ༺༻༺༻༺༻ Main Execution Flow ༺༻༺༻༺༻
{
    setup_wsl_quantum_auth
    verify_quantum_connection

    if [ $? -eq 0 ]; then
        echo -e "\033[36mQuantum Nexus Ready for Cyber Operations!\033[0m"
        echo -e "\033[33mAuthokey Valid Until: $(date -d '+30 days' +%Y-%m-%d)\033[0m"
    else
        echo -e "\033[31mRun manual connection test:\033[0m"
        echo "ssh -i ~/.ssh/quantum_key localhost"
    fi
}




