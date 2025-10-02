#!/usr/bin/env python3
"""
Upload existing certificates to database for Railway deployment
This script reads certificate files and stores them in the database
"""

import os
import sys
import glob
from datetime import datetime
import hashlib
import subprocess

# Add the app directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, Certificate
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def extract_certificate_info(cert_path):
    """Extract certificate information from a .crt file"""
    try:
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        
        # Parse certificate
        cert_obj = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        # Extract common name from subject
        common_name = None
        for attribute in cert_obj.subject:
            if attribute.oid.dotted_string == '2.5.4.3':  # Common Name OID
                common_name = attribute.value
                break
        
        # Generate fingerprint
        fingerprint = hashlib.sha256(cert_obj.public_bytes()).hexdigest()
        
        return {
            'common_name': common_name,
            'certificate_data': cert_data.decode('utf-8'),
            'fingerprint': fingerprint,
            'subject': str(cert_obj.subject),
            'issuer': str(cert_obj.issuer),
            'valid_from': cert_obj.not_valid_before.replace(tzinfo=None),
            'valid_until': cert_obj.not_valid_after.replace(tzinfo=None)
        }
    except Exception as e:
        print(f"Error parsing certificate {cert_path}: {e}")
        return None

def upload_certificate_to_db(cert_info, cert_type, purpose):
    """Upload certificate information to database"""
    try:
        # Check if certificate already exists
        existing = Certificate.query.filter_by(common_name=cert_info['common_name']).first()
        if existing:
            print(f"⚠️  Certificate {cert_info['common_name']} already exists in database")
            return False
        
        # Create new certificate record
        certificate = Certificate(
            common_name=cert_info['common_name'],
            certificate_type=cert_type,
            purpose=purpose,
            certificate_data=cert_info['certificate_data'],
            private_key_data=None,  # Client certificates don't need private keys in DB
            fingerprint=cert_info['fingerprint'],
            issuer=cert_info['issuer'],
            subject=cert_info['subject'],
            valid_from=cert_info['valid_from'],
            valid_until=cert_info['valid_until'],
            is_active=True,
            is_revoked=False
        )
        
        db.session.add(certificate)
        db.session.commit()
        
        print(f"✅ Uploaded certificate: {cert_info['common_name']}")
        return True
        
    except Exception as e:
        print(f"❌ Error uploading certificate {cert_info['common_name']}: {e}")
        db.session.rollback()
        return False

def main():
    """Main function to upload all certificates"""
    print("🚀 Starting certificate upload to database...")
    
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
        
        uploaded_count = 0
        
        # Upload display certificates
        print("\n📱 Processing display certificates...")
        display_certs = glob.glob("certs/displays/*.crt")
        for cert_path in display_certs:
            cert_info = extract_certificate_info(cert_path)
            if cert_info:
                if upload_certificate_to_db(cert_info, 'client', 'display'):
                    uploaded_count += 1
        
        # Upload sales certificates
        print("\n👔 Processing sales certificates...")
        sales_certs = glob.glob("certs/sales/*.crt")
        for cert_path in sales_certs:
            cert_info = extract_certificate_info(cert_path)
            if cert_info:
                if upload_certificate_to_db(cert_info, 'client', 'sales'):
                    uploaded_count += 1
        
        # Upload CA certificate
        print("\n🏛️  Processing CA certificate...")
        ca_cert_path = "certs/ca/mardi-gras-ca.crt"
        if os.path.exists(ca_cert_path):
            cert_info = extract_certificate_info(ca_cert_path)
            if cert_info:
                if upload_certificate_to_db(cert_info, 'ca', 'ca'):
                    uploaded_count += 1
        
        # Upload server certificates
        print("\n🖥️  Processing server certificates...")
        server_certs = glob.glob("certs/server/*.crt")
        for cert_path in server_certs:
            cert_info = extract_certificate_info(cert_path)
            if cert_info:
                # For server certificates, try to load private key too
                key_path = cert_path.replace('.crt', '.key')
                private_key_data = None
                if os.path.exists(key_path):
                    try:
                        with open(key_path, 'r') as f:
                            private_key_data = f.read()
                    except Exception as e:
                        print(f"⚠️  Could not read private key for {cert_path}: {e}")
                
                # Add private key to cert_info if available
                if private_key_data:
                    cert_info['private_key_data'] = private_key_data
                
                if upload_certificate_to_db(cert_info, 'server', 'pixie-viewer'):
                    uploaded_count += 1
        
        print(f"\n🎉 Certificate upload complete! Uploaded {uploaded_count} certificates to database.")
        
        # Display summary
        print("\n📊 Database Summary:")
        total_certs = Certificate.query.count()
        active_certs = Certificate.query.filter_by(is_active=True, is_revoked=False).count()
        display_certs = Certificate.query.filter_by(purpose='display').count()
        sales_certs = Certificate.query.filter_by(purpose='sales').count()
        server_certs = Certificate.query.filter_by(certificate_type='server').count()
        ca_certs = Certificate.query.filter_by(certificate_type='ca').count()
        
        print(f"   Total certificates: {total_certs}")
        print(f"   Active certificates: {active_certs}")
        print(f"   Display certificates: {display_certs}")
        print(f"   Sales certificates: {sales_certs}")
        print(f"   Server certificates: {server_certs}")
        print(f"   CA certificates: {ca_certs}")

if __name__ == '__main__':
    main()