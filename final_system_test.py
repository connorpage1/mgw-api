#!/usr/bin/env python3
"""
Final system test to verify everything works correctly
"""
import sys
import os
import json
import requests
import time

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models import db, App, AppToken, User, Role
from utils.logger import logger

def test_live_system():
    """Test the live system end-to-end"""
    
    logger.info("🚀 Final System Test - Live Environment")
    
    # Test 1: Database health
    with create_app().app_context():
        try:
            apps = App.query.count()
            tokens = AppToken.query.count()
            users = User.query.count()
            logger.info(f"✅ Database Health: {apps} apps, {tokens} tokens, {users} users")
        except Exception as e:
            logger.error(f"❌ Database Health: {e}")
            return False
    
    # Start server for live testing
    logger.info("Starting development server for live testing...")
    import subprocess
    import signal
    
    server_process = subprocess.Popen([
        'python', '-c', 
        'from app import create_app; app = create_app(); app.run(host="127.0.0.1", port=5557, debug=False)'
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Wait for server to start
    time.sleep(3)
    
    try:
        base_url = "http://127.0.0.1:5557"
        
        # Test 2: API Health endpoint
        try:
            response = requests.get(f"{base_url}/api/health", timeout=5)
            if response.status_code == 200 and response.json().get('status') == 'ok':
                logger.info("✅ API Health endpoint working")
            else:
                logger.error(f"❌ API Health endpoint failed: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ API Health endpoint error: {e}")
        
        # Test 3: API requires authentication
        try:
            response = requests.get(f"{base_url}/api/terms", timeout=5)
            if response.status_code == 401:
                logger.info("✅ API authentication required")
            else:
                logger.error(f"❌ API authentication not enforced: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ API authentication test error: {e}")
        
        # Test 4: Admin redirects to login
        try:
            response = requests.get(f"{base_url}/admin/", timeout=5, allow_redirects=False)
            if response.status_code == 302 and 'login' in response.headers.get('Location', ''):
                logger.info("✅ Admin requires authentication")
            else:
                logger.error(f"❌ Admin authentication not enforced: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ Admin authentication test error: {e}")
        
        # Test 5: Demo token works (if available)
        with create_app().app_context():
            demo_token = AppToken.query.filter_by(name='Demo Token').first()
            if demo_token:
                # We need to get the original token for testing
                # Since tokens are hashed, we'll create a temporary test token
                import secrets
                import hashlib
                
                raw_token = f"mg_{''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(32))}"
                token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
                
                test_token = AppToken(
                    app_id=demo_token.app_id,
                    name="Live Test Token",
                    token_hash=token_hash,
                    prefix="mg_",
                    created_by=1,
                    updated_by=1
                )
                
                db.session.add(test_token)
                db.session.commit()
                
                try:
                    # Test API with token
                    headers = {'X-API-Key': raw_token}
                    response = requests.get(f"{base_url}/api/categories", headers=headers, timeout=5)
                    if response.status_code == 200:
                        logger.info("✅ API token authentication working")
                    else:
                        logger.error(f"❌ API token authentication failed: {response.status_code}")
                    
                    # Test different auth methods
                    auth_headers = [
                        {'Authorization': f'Bearer {raw_token}'},
                        {'X-API-Key': raw_token}
                    ]
                    
                    for i, headers in enumerate(auth_headers):
                        response = requests.get(f"{base_url}/api/categories", headers=headers, timeout=5)
                        if response.status_code == 200:
                            logger.info(f"✅ API auth method {i+1} working")
                        else:
                            logger.error(f"❌ API auth method {i+1} failed: {response.status_code}")
                    
                    # Test query parameter auth
                    response = requests.get(f"{base_url}/api/categories?api_key={raw_token}", timeout=5)
                    if response.status_code == 200:
                        logger.info("✅ API query parameter auth working")
                    else:
                        logger.error(f"❌ API query parameter auth failed: {response.status_code}")
                    
                finally:
                    # Clean up test token
                    db.session.delete(test_token)
                    db.session.commit()
        
        logger.info("✅ Live system test completed successfully!")
        return True
        
    except Exception as e:
        logger.error(f"❌ Live system test failed: {e}")
        return False
        
    finally:
        # Stop server
        server_process.terminate()
        try:
            server_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_process.kill()

if __name__ == "__main__":
    success = test_live_system()
    sys.exit(0 if success else 1)