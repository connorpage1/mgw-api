#!/bin/bash
# Create certificate for a dedicated display device (Demo Version)

if [ $# -ne 2 ]; then
    echo "Usage: $0 <display-name> <display-location>"
    echo "Example: $0 main-entrance-display \"Main Entrance\""
    exit 1
fi

DISPLAY_NAME=$1
LOCATION=$2
CERT_DIR="certs/displays"

# Read CA password from file
CA_PASSWORD=$(cat certs/ca/.ca_password)

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
    -passin pass:$CA_PASSWORD \
    -out "$CERT_DIR/${DISPLAY_NAME}.crt" \
    -extensions display_cert \
    -extfile <(echo "[display_cert]
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=DNS:${DISPLAY_NAME}.mardigrasworld.com,DNS:${DISPLAY_NAME}")

# Create PKCS#12 bundle for easy installation
# Use a simple password for demo
P12_PASSWORD="display123"

openssl pkcs12 -export \
    -in "$CERT_DIR/${DISPLAY_NAME}.crt" \
    -inkey "$CERT_DIR/${DISPLAY_NAME}.key" \
    -certfile certs/ca/mardi-gras-ca.crt \
    -out "$CERT_DIR/${DISPLAY_NAME}.p12" \
    -name "${DISPLAY_NAME} - Mardi Gras World Display" \
    -passout pass:$P12_PASSWORD

# Create installation instructions
cat > "$CERT_DIR/${DISPLAY_NAME}-installation.txt" << EOF
📱 INSTALLATION INSTRUCTIONS: $DISPLAY_NAME
Location: $LOCATION

iPad Installation:
1. Email the ${DISPLAY_NAME}.p12 file to yourself
2. Open Mail on iPad and tap the attachment
3. Tap "Install Profile"
4. Enter password: $P12_PASSWORD
5. Tap "Install" and enter iPad passcode
6. Tap "Done"

Browser Installation (Desktop):
1. Double-click ${DISPLAY_NAME}.p12
2. Enter password: $P12_PASSWORD
3. Follow browser prompts to install

Testing Access:
1. Open browser and go to: https://pixie.mardigrasworld.com
2. When prompted, select certificate: "${DISPLAY_NAME} - Mardi Gras World Display"
3. You should now have access to Pixie viewer!

Certificate Details:
- Display: $DISPLAY_NAME
- Location: $LOCATION
- Valid for: 5 years (1825 days)
- Password: $P12_PASSWORD
- Type: Display Certificate

Created: $(date)
EOF

echo "✅ Display certificate created successfully!"
echo "📄 Certificate: $CERT_DIR/${DISPLAY_NAME}.crt"
echo "🔑 Private Key: $CERT_DIR/${DISPLAY_NAME}.key"  
echo "📦 PKCS#12 Bundle: $CERT_DIR/${DISPLAY_NAME}.p12"
echo "📋 Instructions: $CERT_DIR/${DISPLAY_NAME}-installation.txt"
echo "🔐 P12 Password: $P12_PASSWORD"
echo ""
echo "🚀 Ready for installation on: $LOCATION"
echo "   Send ${DISPLAY_NAME}.p12 and installation instructions to device"