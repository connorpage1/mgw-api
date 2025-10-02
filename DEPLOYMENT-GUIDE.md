# 🎪 Mardi Gras World - Pixie Viewer Certificate Deployment Guide

## 📋 Overview

This guide walks you through deploying client certificates for secure access to the Pixie Viewer at Mardi Gras World. The system uses a three-tier approach:

- **Display Certificates**: 5-year certificates for dedicated iPad displays
- **Sales Certificates**: 30-day certificates for sales team devices  
- **API Key Fallback**: Emergency access during troubleshooting

## 🏗️ Phase 1: Initial Setup (COMPLETED)

### ✅ Certificate Authority Created
- **Location**: `certs/ca/mardi-gras-ca.crt`
- **Password**: `MardiGrasWorld2024!` (stored in `certs/ca/.ca_password`)
- **Validity**: 10 years (until 2035)

### ✅ Display Certificates Generated
1. **Main Entrance iPad** (`main-entrance-ipad.p12`)
2. **Gift Shop iPad** (`gift-shop-ipad.p12`)
3. **VIP Tour iPad** (`vip-tour-ipad.p12`)

**Certificate Details:**
- **Password**: `display123`
- **Validity**: 5 years (until 2030)
- **Type**: Display certificates

## 📱 iPad Installation Instructions

### For Each Display Location:

1. **Email the Certificate**
   ```bash
   # Email the .p12 file to yourself or AirDrop to iPad
   # Files located in: certs/displays/[device-name].p12
   ```

2. **Install on iPad**
   - Open Mail app and tap the `.p12` attachment
   - Tap "Install Profile"
   - Enter password: `display123`
   - Tap "Install" and enter iPad passcode
   - Tap "Done"

3. **Verify Installation**
   - Go to Settings > General > VPN & Device Management
   - Under "Configuration Profiles", verify "Mardi Gras World" appears
   - Tap to view certificate details

4. **Test Access**
   - Open Safari and navigate to: `https://pixie.mardigrasworld.com`
   - When prompted, select certificate: "[device-name] - Mardi Gras World Display"
   - Verify access to Pixie viewer

## 🔧 Kiosk Configuration (Recommended)

### Enable Guided Access for True Kiosk Mode:

1. **Settings > Accessibility > Guided Access**
2. Turn on Guided Access
3. Set a passcode
4. Open Safari to Pixie viewer
5. Triple-click home button to start Guided Access
6. Draw around areas to disable (if needed)
7. Tap "Start"

### Optional: Create Shortcuts
1. **Settings > Shortcuts**
2. Create automation to open Pixie viewer on startup
3. Set up auto-lock prevention

## 👔 Sales Team Access (Future)

When needed, sales certificates can be generated:

```bash
# Create 30-day sales certificate
./scripts/create-sales-cert.sh jane-smith 30

# Email jane-smith.p12 to sales person
# Password will be provided in instructions
```

## 🚨 Emergency Access

If certificates fail, emergency API key access is available:

```bash
# Current API key: YfwQGX4_KQFq5KuD2HFLwFYpFB5aPt2JOf-L-mGSYGU
# Add to browser request header: X-API-Key
```

## 🔄 Certificate Management

### Check Certificate Status
```bash
# View certificate details
openssl x509 -in certs/displays/[device-name].crt -text -noout

# Check expiration
openssl x509 -in certs/displays/[device-name].crt -noout -dates
```

### Renew Certificates (Before Expiration)
```bash
# Generate new certificate with same name
./scripts/create-display-cert-demo.sh [device-name] "[location]"

# Install new certificate on device
# Old certificate will be automatically replaced
```

### Revoke Certificates (If Compromised)
```bash
# Add to revocation list
echo "01" > certs/revoked/[device-name].txt

# Update server to check revocation list
# (Advanced: implement CRL checking)
```

## 📊 Monitoring and Maintenance

### Weekly Tasks
- [ ] Check server logs for certificate access
- [ ] Verify all displays are functioning
- [ ] Monitor certificate expiration dates

### Monthly Tasks  
- [ ] Review access logs for unusual activity
- [ ] Test emergency API key access
- [ ] Backup certificate files and CA key

### Yearly Tasks
- [ ] Plan certificate renewal strategy
- [ ] Review and update security procedures
- [ ] Consider CA key rotation

## 🔐 Security Best Practices

### Production Recommendations
1. **Store CA private key offline** after certificate generation
2. **Use hardware security modules (HSM)** for CA key protection
3. **Implement certificate revocation** checking
4. **Regular security audits** of certificate usage
5. **Monitor for certificate enumeration** attempts

### File Security
```bash
# Secure file permissions
chmod 600 certs/ca/mardi-gras-ca.key
chmod 600 certs/ca/.ca_password
chmod 644 certs/ca/mardi-gras-ca.crt
chmod 644 certs/displays/*.crt
chmod 600 certs/displays/*.key
```

## 📞 Troubleshooting

### Certificate Not Appearing in Safari
1. Restart iPad
2. Verify certificate installation in Settings
3. Check certificate hasn't expired
4. Try installing certificate again

### "Invalid Certificate" Error
1. Verify server has CA certificate
2. Check system clock on iPad
3. Ensure certificate hasn't been revoked
4. Test with API key as fallback

### Installation Failed
1. Check certificate password
2. Verify .p12 file isn't corrupted
3. Try different installation method (AirDrop vs email)
4. Contact IT support

## 📁 File Structure
```
certs/
├── ca/
│   ├── mardi-gras-ca.crt      # CA certificate (public)
│   ├── mardi-gras-ca.key      # CA private key (SECURE!)
│   └── .ca_password           # CA password (SECURE!)
├── displays/
│   ├── main-entrance-ipad.p12      # Ready for installation
│   ├── gift-shop-ipad.p12          # Ready for installation
│   ├── vip-tour-ipad.p12           # Ready for installation
│   └── *-installation.txt          # Installation instructions
└── sales/
    └── (Future sales certificates)
```

## 🎯 Deployment Status

- [x] Certificate Authority established
- [x] Display certificates generated  
- [x] Installation instructions created
- [x] Server certificate validation implemented
- [ ] Install certificates on physical iPads
- [ ] Configure kiosk mode on displays
- [ ] Train staff on troubleshooting
- [ ] Set up monitoring and alerts

---

**Next Step**: Install certificates on your actual iPad displays and test the complete flow!

**Support**: Keep this guide and certificate files secure. The CA private key is the master key for your entire certificate infrastructure.