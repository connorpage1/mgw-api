#!/bin/bash
# Mardi Gras World - Pixie Viewer Certificate Authority Setup

set -e

# Create CA directory structure
mkdir -p certs/{ca,displays,sales,revoked}
cd certs

echo "🏗️  Setting up Mardi Gras World Certificate Authority..."

# Generate CA private key (keep this VERY secure!)
openssl genrsa -aes256 -out ca/mardi-gras-ca.key 4096

# Generate CA certificate (valid for 10 years)
openssl req -new -x509 -days 3650 -key ca/mardi-gras-ca.key \
    -out ca/mardi-gras-ca.crt \
    -subj "/C=US/ST=Louisiana/L=New Orleans/O=Mardi Gras World/OU=IT/CN=Mardi Gras World Pixie CA"

# Create certificate serial number file
echo 1000 > ca/serial

# Create certificate index
touch ca/index.txt

echo "✅ Certificate Authority created successfully!"
echo "🔐 CA Certificate: certs/ca/mardi-gras-ca.crt"
echo "🗝️  CA Private Key: certs/ca/mardi-gras-ca.key (KEEP SECURE!)"