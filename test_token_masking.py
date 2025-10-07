#!/usr/bin/env python3
"""
Test token masking specifically
"""
import sys
import os

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models import db, AppToken, User, Role

def test_token_masking():
    """Test token masking functionality"""
    flask_app = create_app()
    
    with flask_app.app_context():
        # Get a token
        token = AppToken.query.first()
        if token:
            print(f"Token hash: {token.token_hash}")
            print(f"Masked token: {token.masked_token}")
            
            # Test the template
            client = flask_app.test_client()
            
            # Login as admin
            superadmin = User.query.join(User.roles).filter(Role.name == 'superadmin').first()
            with client.session_transaction() as sess:
                sess['_user_id'] = str(superadmin.id)
                sess['_fresh'] = True
            
            response = client.get('/admin/tokens')
            html = response.get_data(as_text=True)
            
            # Search for token-related content
            lines = html.split('\n')
            token_lines = [line for line in lines if 'mg_' in line]
            
            print(f"\nLines containing 'mg_':")
            for line in token_lines:
                print(f"  {line.strip()}")
            
            # Check if masking is working
            if token.masked_token in html:
                print(f"\n✅ Masked token found in HTML: {token.masked_token}")
            else:
                print(f"\n❌ Masked token NOT found in HTML")
            
            # Check for any full tokens
            all_tokens = AppToken.query.all()
            for t in all_tokens:
                if t.token_hash in html:
                    print(f"⚠️ Token hash found in HTML: {t.token_hash[:10]}...")

if __name__ == "__main__":
    test_token_masking()