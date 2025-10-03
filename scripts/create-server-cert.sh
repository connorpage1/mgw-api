#!/bin/bash
# Create server certificate for pixie-viewer HTTPS

CERT_DIR="certs/server"
SERVER_NAME="pixie-viewer"

# Read CA password from file
CA_PASSWORD=$(cat certs/ca/.ca_password)

echo "🌐 Creating server certificate for: $SERVER_NAME"

# Generate private key for server
openssl genrsa -out "$CERT_DIR/${SERVER_NAME}.key" 2048

# Create certificate signing request
openssl req -new \
    -key "$CERT_DIR/${SERVER_NAME}.key" \
    -out "$CERT_DIR/${SERVER_NAME}.csr" \
    -subj "/C=US/ST=Louisiana/L=New Orleans/O=Mardi Gras World/OU=IT/CN=pixie.mardigrasworld.com"

# Sign the certificate (valid for 2 years)
openssl x509 -req -days 730 \
    -in "$CERT_DIR/${SERVER_NAME}.csr" \
    -CA certs/ca/mardi-gras-ca.crt \
    -CAkey certs/ca/mardi-gras-ca.key \
    -passin pass:$CA_PASSWORD \
    -out "$CERT_DIR/${SERVER_NAME}.crt" \
    -extensions server_cert \
    -extfile <(echo "[server_cert]
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:pixie.mardigrasworld.com,DNS:localhost,IP:127.0.0.1")

echo "✅ Server certificate created successfully!"
echo "📄 Certificate: $CERT_DIR/${SERVER_NAME}.crt"
echo "🔑 Private Key: $CERT_DIR/${SERVER_NAME}.key"
echo ""
echo "🚀 Ready for HTTPS with client certificate validation!"