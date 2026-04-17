#!/bin/bash

# Secure TURN Server Startup Script for Linux
# This script sets up and starts a Coturn TURN server with TLS and authentication

set -e

TURN_DIR="/workspaces/4messenger-privaterepo/server/turn"
CERTS_DIR="$TURN_DIR/certs"
CONFIG_FILE="$TURN_DIR/turnserver.conf"
LOG_FILE="$TURN_DIR/turnserver.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting TURN Server Setup...${NC}"

# Check if running as root (needed for port binding)
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root (use sudo)${NC}"
   exit 1
fi

# Install Coturn if not installed
if ! command -v turnserver &> /dev/null; then
    echo -e "${YELLOW}Installing Coturn TURN server...${NC}"
    apt update
    apt install -y coturn
    echo -e "${GREEN}Coturn installed successfully.${NC}"
else
    echo -e "${GREEN}Coturn is already installed.${NC}"
fi

# Create certs directory
mkdir -p "$CERTS_DIR"

# Generate self-signed certificate if not exists
if [[ ! -f "$CERTS_DIR/turnserver.crt" || ! -f "$CERTS_DIR/turnserver.key" ]]; then
    echo -e "${YELLOW}Generating self-signed TLS certificate...${NC}"
    openssl req -x509 -newkey rsa:4096 -keyout "$CERTS_DIR/turnserver.key" -out "$CERTS_DIR/turnserver.crt" -days 365 -nodes -subj "/C=US/ST=State/L=City/O=4Messenger/CN=4messenger-turn"
    chmod 600 "$CERTS_DIR/turnserver.key"
    echo -e "${GREEN}Certificate generated.${NC}"
else
    echo -e "${GREEN}Certificate already exists.${NC}"
fi

# Generate random auth secret if not set
if grep -q "CHANGE_THIS_TO_A_SECURE_RANDOM_SECRET" "$CONFIG_FILE"; then
    SECRET=$(openssl rand -hex 32)
    sed -i "s/CHANGE_THIS_TO_A_SECURE_RANDOM_SECRET/$SECRET/" "$CONFIG_FILE"
    echo -e "${GREEN}Generated secure auth secret.${NC}"
fi

# Get public IP (optional, user should set manually in config)
# PUBLIC_IP=$(curl -s ifconfig.me)
# sed -i "s/# relay-ip=YOUR_PUBLIC_IP/relay-ip=$PUBLIC_IP/" "$CONFIG_FILE"
# sed -i "s/# external-ip=YOUR_PUBLIC_IP/external-ip=$PUBLIC_IP/" "$CONFIG_FILE"

echo -e "${YELLOW}Note: Please edit $CONFIG_FILE to set your public IP in relay-ip and external-ip fields.${NC}"

# Start the TURN server
echo -e "${GREEN}Starting TURN server...${NC}"
turnserver -c "$CONFIG_FILE" --daemon

# Check if it's running
sleep 2
if pgrep -f "turnserver" > /dev/null; then
    echo -e "${GREEN}TURN server started successfully.${NC}"
    echo -e "${GREEN}Log file: $LOG_FILE${NC}"
    echo -e "${GREEN}Auth secret: $(grep 'static-auth-secret' $CONFIG_FILE | cut -d'=' -f2)${NC}"
else
    echo -e "${RED}Failed to start TURN server. Check logs.${NC}"
    exit 1
fi

echo -e "${GREEN}TURN server is running securely with TLS and authentication.${NC}"