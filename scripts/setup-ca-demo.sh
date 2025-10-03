#!/bin/bash
# Mardi Gras World - Pixie Viewer Certificate Authority Setup (Demo Version)

set -e

# Create CA directory structure
mkdir -p certs/{ca,displays,sales,revoked}
cd certs

echo "🏗️  Setting up Mardi Gras World Certificate Authority..."

# For demo purposes, we'll use a fixed password
# In production, you'd want a strong, unique password
CA_PASSWORD="MardiGrasWorld2024!"

echo "🔐 Using demo CA password: $CA_PASSWORD"
echo "⚠️  IMPORTANT: In production, use a strong, unique password!"

# Generate CA private key (demo password)
openssl genrsa -aes256 -passout pass:$CA_PASSWORD -out ca/mardi-gras-ca.key 4096

# Generate CA certificate (valid for 10 years)
openssl req -new -x509 -days 3650 -key ca/mardi-gras-ca.key -passin pass:$CA_PASSWORD \
    -out ca/mardi-gras-ca.crt \
    -subj "/C=US/ST=Louisiana/L=New Orleans/O=Mardi Gras World/OU=IT/CN=Mardi Gras World Pixie CA"

# Create certificate serial number file
echo 1000 > ca/serial

# Create certificate index
touch ca/index.txt

# Store CA password for script usage
echo $CA_PASSWORD > ca/.ca_password
chmod 600 ca/.ca_password

echo "✅ Certificate Authority created successfully!"
echo "🔐 CA Certificate: certs/ca/mardi-gras-ca.crt"
echo "🗝️  CA Private Key: certs/ca/mardi-gras-ca.key"
echo "🔑 CA Password: $CA_PASSWORD (stored in ca/.ca_password)"
echo ""
echo "📋 Next steps:"
echo "1. Create display certificates with: ./create-display-cert-demo.sh"
echo "2. Install certificates on iPads"
echo "3. Test access to Pixie viewer"