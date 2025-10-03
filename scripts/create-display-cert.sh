#!/bin/bash
# Create certificate for a dedicated display device

if [ $# -ne 2 ]; then
    echo "Usage: $0 <display-name> <display-location>"
    echo "Example: $0 display-1 main-entrance"
    exit 1
fi

DISPLAY_NAME=$1
LOCATION=$2
CERT_DIR="certs/displays"

echo "🖥️  Creating certificate for display: $DISPLAY_NAME ($LOCATION)"

# Generate private key for display
openssl genrsa -out "$CERT_DIR/${DISPLAY_NAME}.key" 2048

# Create certificate signing request
openssl req -new \
    -key "$CERT_DIR/${DISPLAY_NAME}.key" \
    -out "$CERT_DIR/${DISPLAY_NAME}.csr" \
    -subj "/C=US/ST=Louisiana/L=New Orleans/O=Mardi Gras World/OU=Displays/CN=${DISPLAY_NAME}.mardigrasworld.com"

# Sign the certificate (valid for 5 years)
openssl x509 -req -days 1825 \
    -in "$CERT_DIR/${DISPLAY_NAME}.csr" \
    -CA certs/ca/mardi-gras-ca.crt \
    -CAkey certs/ca/mardi-gras-ca.key \
    -out "$CERT_DIR/${DISPLAY_NAME}.crt" \
    -extensions display_cert \
    -extfile <(echo "[display_cert]
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=DNS:${DISPLAY_NAME}.mardigrasworld.com,DNS:${DISPLAY_NAME}")

# Create PKCS#12 bundle for easy installation
openssl pkcs12 -export \
    -in "$CERT_DIR/${DISPLAY_NAME}.crt" \
    -inkey "$CERT_DIR/${DISPLAY_NAME}.key" \
    -certfile certs/ca/mardi-gras-ca.crt \
    -out "$CERT_DIR/${DISPLAY_NAME}.p12" \
    -name "${DISPLAY_NAME} - Mardi Gras World Display"

echo "✅ Display certificate created!"
echo "📄 Certificate: $CERT_DIR/${DISPLAY_NAME}.crt"
echo "🔑 Private Key: $CERT_DIR/${DISPLAY_NAME}.key"  
echo "📦 PKCS#12 Bundle: $CERT_DIR/${DISPLAY_NAME}.p12"
echo ""
echo "🚀 To install on display device:"
echo "   1. Copy ${DISPLAY_NAME}.p12 to the device"
echo "   2. Import into browser/system certificate store"
echo "   3. Select certificate when accessing pixie viewer"