#!/bin/bash
# Create short-lived certificate for sales team member

if [ $# -ne 2 ]; then
    echo "Usage: $0 <staff-name> <duration-days>"
    echo "Example: $0 john-doe 30"
    exit 1
fi

STAFF_NAME=$1
DURATION_DAYS=$2
CERT_DIR="certs/sales"

echo "👔 Creating sales certificate for: $STAFF_NAME (valid for $DURATION_DAYS days)"

# Generate private key
openssl genrsa -out "$CERT_DIR/${STAFF_NAME}.key" 2048

# Create certificate signing request
openssl req -new \
    -key "$CERT_DIR/${STAFF_NAME}.key" \
    -out "$CERT_DIR/${STAFF_NAME}.csr" \
    -subj "/C=US/ST=Louisiana/L=New Orleans/O=Mardi Gras World/OU=Sales/CN=${STAFF_NAME}.sales.mardigrasworld.com"

# Sign the certificate (short duration)
openssl x509 -req -days $DURATION_DAYS \
    -in "$CERT_DIR/${STAFF_NAME}.csr" \
    -CA certs/ca/mardi-gras-ca.crt \
    -CAkey certs/ca/mardi-gras-ca.key \
    -out "$CERT_DIR/${STAFF_NAME}.crt" \
    -extensions sales_cert \
    -extfile <(echo "[sales_cert]
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=DNS:${STAFF_NAME}.sales.mardigrasworld.com")

# Create PKCS#12 bundle
openssl pkcs12 -export \
    -in "$CERT_DIR/${STAFF_NAME}.crt" \
    -inkey "$CERT_DIR/${STAFF_NAME}.key" \
    -certfile certs/ca/mardi-gras-ca.crt \
    -out "$CERT_DIR/${STAFF_NAME}.p12" \
    -name "${STAFF_NAME} - Mardi Gras World Sales"

echo "✅ Sales certificate created!"
echo "📱 Send to staff member: $CERT_DIR/${STAFF_NAME}.p12"
echo "⏰ Expires in $DURATION_DAYS days"
echo ""
echo "📧 Email instructions:"
echo "   1. Install ${STAFF_NAME}.p12 on your device"
echo "   2. Visit pixie viewer URL"
echo "   3. Select your certificate when prompted"