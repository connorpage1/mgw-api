#!/bin/bash
# Create iPad-optimized certificate

if [ $# -ne 3 ]; then
    echo "Usage: $0 <device-name> <device-type> <duration-days>"
    echo "Examples:"
    echo "  $0 main-entrance-ipad display 1825  # 5-year display"
    echo "  $0 jane-smith-ipad sales 30         # 30-day sales"
    exit 1
fi

DEVICE_NAME=$1
DEVICE_TYPE=$2
DURATION_DAYS=$3
CERT_DIR="certs/${DEVICE_TYPE}"

# Generate a strong password for the PKCS#12 file
P12_PASSWORD=$(openssl rand -base64 12)

echo "📱 Creating iPad certificate for: $DEVICE_NAME ($DEVICE_TYPE, $DURATION_DAYS days)"

# Generate private key
openssl genrsa -out "$CERT_DIR/${DEVICE_NAME}.key" 2048

# Create certificate signing request with iPad-friendly attributes
openssl req -new \
    -key "$CERT_DIR/${DEVICE_NAME}.key" \
    -out "$CERT_DIR/${DEVICE_NAME}.csr" \
    -subj "/C=US/ST=Louisiana/L=New Orleans/O=Mardi Gras World/OU=${DEVICE_TYPE}/CN=${DEVICE_NAME}.mardigrasworld.com/emailAddress=tech@mardigrasworld.com"

# Sign the certificate with iPad-compatible extensions
openssl x509 -req -days $DURATION_DAYS \
    -in "$CERT_DIR/${DEVICE_NAME}.csr" \
    -CA certs/ca/mardi-gras-ca.crt \
    -CAkey certs/ca/mardi-gras-ca.key \
    -out "$CERT_DIR/${DEVICE_NAME}.crt" \
    -extensions ipad_cert \
    -extfile <(echo "[ipad_cert]
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=critical,clientAuth
subjectAltName=DNS:${DEVICE_NAME}.mardigrasworld.com,DNS:${DEVICE_NAME}
basicConstraints=critical,CA:FALSE
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer")

# Create iPad-optimized PKCS#12 bundle with strong encryption
openssl pkcs12 -export \
    -in "$CERT_DIR/${DEVICE_NAME}.crt" \
    -inkey "$CERT_DIR/${DEVICE_NAME}.key" \
    -certfile certs/ca/mardi-gras-ca.crt \
    -out "$CERT_DIR/${DEVICE_NAME}.p12" \
    -name "Mardi Gras World - ${DEVICE_NAME}" \
    -passout pass:$P12_PASSWORD \
    -keypbe AES-256-CBC \
    -certpbe AES-256-CBC

# Create installation instructions for iPad
cat > "$CERT_DIR/${DEVICE_NAME}-instructions.txt" << EOF
📱 iPad Installation Instructions for: $DEVICE_NAME

STEP 1: Install Certificate
1. Email yourself the attached ${DEVICE_NAME}.p12 file
2. On iPad, open Mail app and tap the attachment
3. Tap "Install Profile" 
4. Enter password when prompted: $P12_PASSWORD
5. Tap "Install" (top right)
6. Enter iPad passcode if prompted
7. Tap "Install" again to confirm
8. Tap "Done"

STEP 2: Verify Installation
1. Go to Settings > General > VPN & Device Management
2. Under "Configuration Profiles", you should see "Mardi Gras World"
3. Tap it to verify the certificate is installed

STEP 3: Access Pixie Viewer
1. Open Safari on iPad
2. Navigate to: https://pixie.mardigrasworld.com
3. When prompted "Select a certificate", choose "Mardi Gras World - ${DEVICE_NAME}"
4. Tap "Continue"
5. You should now have access to the Pixie viewer!

TROUBLESHOOTING:
- If certificate doesn't appear in Safari, restart the iPad
- If installation fails, check that the certificate hasn't expired
- For kiosk mode, enable Guided Access in Settings > Accessibility

CERTIFICATE INFO:
- Device: $DEVICE_NAME
- Type: $DEVICE_TYPE
- Valid for: $DURATION_DAYS days
- Password: $P12_PASSWORD

SECURITY NOTE: Keep this password secure and delete this file after installation.
EOF

echo "✅ iPad certificate created successfully!"
echo "📄 Certificate: $CERT_DIR/${DEVICE_NAME}.crt"
echo "🔑 Private Key: $CERT_DIR/${DEVICE_NAME}.key"
echo "📦 iPad Bundle: $CERT_DIR/${DEVICE_NAME}.p12"
echo "📋 Instructions: $CERT_DIR/${DEVICE_NAME}-instructions.txt"
echo "🔐 P12 Password: $P12_PASSWORD"
echo ""
echo "🚀 Ready for iPad deployment!"
echo "   Send both the .p12 file and instructions to the device owner"