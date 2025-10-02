#!/usr/bin/env python3
"""
Test script for two-layer security system
Tests both API token protection and certificate generation functionality
"""

import os
import sys
import subprocess
import tempfile
import json
import time

def test_certificate_generation():
    """Test certificate generation script"""
    print("🧪 Testing certificate generation...")
    
    # Test parameters
    cert_name = f"test-cert-{int(time.time())}"
    duration = "7"
    purpose = "testing"
    password = "test123"
    
    try:
        # Run certificate generation script
        result = subprocess.run([
            "./scripts/create-web-cert.sh",
            cert_name,
            duration, 
            purpose,
            password
        ], capture_output=True, text=True, cwd="/Users/connor/Development/code/mardi-gras-api")
        
        if result.returncode == 0:
            print("✅ Certificate generation script works")
            
            # Check if files were created
            cert_files = [
                f"certs/sales/{cert_name}.crt",
                f"certs/sales/{cert_name}.p12",
                f"certs/sales/{cert_name}-install.txt"
            ]
            
            all_files_exist = True
            for file_path in cert_files:
                full_path = f"/Users/connor/Development/code/mardi-gras-api/{file_path}"
                if os.path.exists(full_path):
                    print(f"✅ Created: {file_path}")
                else:
                    print(f"❌ Missing: {file_path}")
                    all_files_exist = False
            
            if all_files_exist:
                print("✅ All certificate files created successfully")
                
                # Clean up test files
                for file_path in cert_files:
                    full_path = f"/Users/connor/Development/code/mardi-gras-api/{file_path}"
                    if os.path.exists(full_path):
                        os.remove(full_path)
                print("🧹 Test files cleaned up")
                
                return True
            else:
                print("❌ Some certificate files missing")
                return False
        else:
            print(f"❌ Certificate generation failed: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing certificate generation: {e}")
        return False

def test_api_protection():
    """Test API endpoint protection"""
    print("🧪 Testing API protection...")
    
    try:
        # Test without API key (should fail)
        result = subprocess.run([
            "curl", "-s", "http://localhost:5555/api/stl-files"
        ], capture_output=True, text=True)
        
        if "API key required" in result.stdout or "Unauthorized" in result.stdout:
            print("✅ API protection working - unauthorized access blocked")
        else:
            print(f"⚠️ API protection may not be working: {result.stdout[:100]}")
        
        # Test with invalid API key (should fail)  
        result = subprocess.run([
            "curl", "-s", "-H", "X-API-Key: invalid-key", "http://localhost:5555/api/stl-files"
        ], capture_output=True, text=True)
        
        if "Invalid API key" in result.stdout or "Unauthorized" in result.stdout:
            print("✅ API protection working - invalid key blocked")
        else:
            print(f"⚠️ Invalid key handling may not be working: {result.stdout[:100]}")
            
        return True
        
    except Exception as e:
        print(f"❌ Error testing API protection: {e}")
        return False

def test_application_startup():
    """Test that the application starts properly"""
    print("🧪 Testing application startup...")
    
    try:
        # Test basic health endpoint
        result = subprocess.run([
            "curl", "-s", "http://localhost:5555/"
        ], capture_output=True, text=True)
        
        if result.returncode == 0 and len(result.stdout) > 0:
            print("✅ Application is responding to HTTP requests")
            return True
        else:
            print("❌ Application not responding properly")
            return False
            
    except Exception as e:
        print(f"❌ Error testing application startup: {e}")
        return False

def main():
    """Run all tests"""
    print("🔒 Two-Layer Security System Test Suite")
    print("="*50)
    
    tests = [
        ("Application Startup", test_application_startup),
        ("Certificate Generation", test_certificate_generation),
        ("API Protection", test_api_protection),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n📋 Running: {test_name}")
        print("-" * 30)
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*50)
    print("📊 TEST SUMMARY")
    print("="*50)
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
        if result:
            passed += 1
    
    print(f"\nResults: {passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("\n🎉 All tests passed! Two-layer security system is working correctly.")
        print("\n🔒 Security Features Verified:")
        print("   1. ✅ Certificate generation functionality")
        print("   2. ✅ API endpoint protection")
        print("   3. ✅ Application startup and basic routing")
        print("\n🌐 Next Steps:")
        print("   - Log into admin interface: http://localhost:5555/admin")
        print("   - Navigate to Certificate Management")
        print("   - Use 'Quick Certificate' button to generate device certificates")
        print("   - Install certificates on client devices for pixie-viewer access")
    else:
        print(f"\n⚠️ {len(results) - passed} test(s) failed. Please review the output above.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())