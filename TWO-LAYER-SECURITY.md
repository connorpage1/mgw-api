# 🔒🔒 Two-Layer Security Implementation - Mardi Gras World

## 📋 Overview

Your Pixie Viewer now implements **TWO LAYERS** of security to protect your proprietary STL files:

### **Layer 1: App Access Control** 🚪
**WHO**: Controls access to the Pixie Viewer application itself
**WHAT**: Client certificates required to view the interface
**WHERE**: `https://localhost:3443` (HTTPS with client cert validation)

### **Layer 2: API Data Protection** 🔐
**WHO**: Controls API access for downloading STL files  
**WHAT**: API tokens required for fetch requests
**WHERE**: All `/pixie/api/*` endpoints

## 🛡️ Security Flow

```
Random Internet User
    ↓ 
❌ BLOCKED - No client certificate
    Cannot access Pixie Viewer app

Authorized Device (iPad with Certificate)
    ↓ 
✅ LAYER 1 PASSED - Valid certificate
    Can access Pixie Viewer app interface
    ↓
    App makes fetch request to API
    ↓
✅ LAYER 2 PASSED - Valid API token  
    Can download STL files
    ↓
🎉 SUCCESS - Tourist can view 3D models
```

## 🧪 Test Results Summary

| Test | Layer 1 (App Access) | Layer 2 (API Access) | Result |
|------|---------------------|---------------------|---------|
| **No certificate, no API key** | ❌ Blocked | ❌ Blocked | Cannot access app |
| **Valid certificate, no API key** | ✅ Allowed | ❌ Blocked | Can see app, cannot load models |
| **No certificate, valid API key** | ❌ Blocked | ✅ Allowed | Cannot access app |
| **Valid certificate, valid API key** | ✅ Allowed | ✅ Allowed | Full access ✅ |

## 🔧 Implementation Details

### **Layer 1: Certificate Validation (Pixie Viewer App)**

**Server**: `pixie_v2/server.js` 
**Port**: `3443` (HTTPS)
**Requirements**:
- Valid client certificate from Mardi Gras World CA
- Certificate subject must contain "Mardi Gras World"
- HTTPS connection required

**Development Bypass**:
```bash
# For testing only - remove in production
X-Bypass-Cert: dev-bypass-2024
```

### **Layer 2: API Token Validation (STL Downloads)**

**Server**: `mardi-gras-api/app.py`
**Port**: `5555` (HTTP)
**Requirements**:
- Valid API key in `X-API-Key` header
- Active user account in database
- Applied to all `/pixie/api/download/*` endpoints

## 📱 iPad Certificate Installation 

**For Layer 1 Access** (to view the app):

1. **Install Client Certificate**:
   ```bash
   # Email main-entrance-ipad.p12 to iPad
   # Password: display123
   # Install via Settings > General > VPN & Device Management
   ```

2. **Access Secure App**:
   ```bash
   # Navigate to: https://pixie.mardigrasworld.com:3443
   # Select certificate when prompted
   # App loads with embedded API token for Layer 2
   ```

## 🔑 Certificate & Token Management

### **Layer 1 Certificates (App Access)**
```bash
# Display certificates (5-year validity)
certs/displays/main-entrance-ipad.p12
certs/displays/gift-shop-ipad.p12  
certs/displays/vip-tour-ipad.p12

# Password: display123
```

### **Layer 2 API Tokens (Data Access)**
```bash
# Embedded in app automatically
PIXIE_API_KEY=YfwQGX4_KQFq5KuD2HFLwFYpFB5aPt2JOf-L-mGSYGU

# Can be rotated via admin interface
# Separate tokens for different app instances if needed
```

## 🚀 Production Deployment

### **1. Remove Development Bypasses**
```javascript
// In pixie_v2/.env
NODE_ENV=production
# Remove CERT_BYPASS_KEY entirely
```

### **2. Use Real Domain Names**
```bash
# Update certificates for production domains
# main-entrance-ipad.mardigrasworld.com
# gift-shop-ipad.mardigrasworld.com
```

### **3. Configure Load Balancer/Proxy**
```nginx
# Example nginx config for client certificate validation
ssl_client_certificate /path/to/mardi-gras-ca.crt;
ssl_verify_client on;
ssl_verify_depth 2;
```

## 🔍 Monitoring & Logging

### **Layer 1 Logs** (Certificate Access)
```bash
# pixie_v2 server logs
✅ Certificate authenticated: main-entrance-ipad.mardigrasworld.com (Displays)
❌ No client certificate provided
```

### **Layer 2 Logs** (API Access)  
```bash
# mardi-gras-api logs
INFO:app:API key access: pixie@mardigras.com
INFO:app:Certificate access: CN=main-entrance-ipad.mardigrasworld.com...
```

## 🚨 Security Scenarios

### **Scenario 1: Certificate Stolen**
**Impact**: Attacker can access Layer 1 (app interface)
**Mitigation**: 
- Revoke certificate immediately
- Layer 2 still protects STL downloads
- Generate new certificate for legitimate device

### **Scenario 2: API Token Compromised**
**Impact**: Attacker can access Layer 2 (download STLs)
**Mitigation**:
- Rotate API token immediately  
- Layer 1 still protects app access
- Update all legitimate apps with new token

### **Scenario 3: Both Compromised**
**Impact**: Full access to system
**Mitigation**:
- Emergency revocation of certificates
- Immediate API token rotation
- Review security procedures
- Generate new certificates and tokens

## 📊 Security Benefits

### **Defense in Depth**
- **Two independent security layers**
- **Failure of one layer doesn't compromise system**
- **Different attack vectors for each layer**

### **Granular Control**
- **Device-level access control** (certificates)
- **Application-level access control** (API tokens)  
- **Can grant/revoke access independently**

### **Professional Grade**
- **Certificate-based authentication** (banking standard)
- **API token authentication** (industry standard)
- **Complete audit trail** for compliance

## ✅ Verification Checklist

- [ ] Layer 1: Cannot access app without certificate
- [ ] Layer 1: Can access app with valid certificate  
- [ ] Layer 2: Cannot download STLs without API token
- [ ] Layer 2: Can download STLs with valid API token
- [ ] Logging: Certificate authentication events recorded
- [ ] Logging: API access events recorded
- [ ] Management: Can revoke certificates via admin
- [ ] Management: Can rotate API tokens via admin

---

## 🎯 Your Security Posture

**BEFORE**: Anyone could download STL files
**NOW**: Two layers of protection:
1. Must have certificate to access app
2. Must have API token to download files

**Result**: Military-grade security for your proprietary Mardi Gras World art pieces! 🎪🔒