#!/usr/bin/env python3
"""
Test certificate validation functionality
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from app import validate_client_certificate

def test_certificate_validation():
    """Test our certificate validation function"""
    
    # Read the display certificate we just created
    cert_path = 'certs/displays/main-entrance-ipad.crt'
    
    if not os.path.exists(cert_path):
        print(f"❌ Certificate not found: {cert_path}")
        return False
    
    try:
        with open(cert_path, 'r') as f:
            cert_pem = f.read()
        
        print("🔍 Testing certificate validation...")
        print(f"📄 Certificate: {cert_path}")
        
        # Validate the certificate
        result = validate_client_certificate(cert_pem)
        
        print("\n📋 Validation Result:")
        print(f"Valid: {result['valid']}")
        
        if result['valid']:
            print(f"✅ Subject: {result['subject']}")
            print(f"🏷️  Type: {result['type']}")
            print(f"⏰ Expires: {result['expires']}")
            print(f"🔒 Fingerprint: {result['fingerprint'][:16]}...")
            print("\n🎉 Certificate validation successful!")
            return True
        else:
            print(f"❌ Reason: {result['reason']}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing certificate: {e}")
        return False

if __name__ == "__main__":
    success = test_certificate_validation()
    sys.exit(0 if success else 1)