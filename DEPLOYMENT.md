# 🚀 Railway Deployment Guide for Mardi Gras API

## Pre-Deployment Checklist ✅

- [x] `Procfile` created
- [x] `requirements.txt` updated with production dependencies
- [x] `railway.json` configuration added
- [x] `.env.example` updated with production variables
- [x] Database initialization script ready
- [x] All code committed to Git

---

## Step 1: Railway Account Setup

1. **Create Railway Account**: https://railway.app
2. **Connect GitHub**: Link your GitHub account
3. **Install Railway CLI** (optional but recommended):
   ```bash
   npm install -g @railway/cli
   railway login
   ```

---

## Step 2: Deploy Your App

### Option A: Web Dashboard (Easiest)
1. Go to https://railway.app/dashboard
2. Click "New Project"
3. Select "Deploy from GitHub repo"
4. Choose your `mardi-gras-api` repository
5. Railway will auto-detect it's a Python/Flask app

### Option B: Railway CLI
```bash
cd /Users/connor/Development/code/mardi-gras-api
railway login
railway init
railway up
```

---

## Step 3: Add PostgreSQL Database

1. **In Railway Dashboard**:
   - Go to your project
   - Click "Add Service"
   - Select "PostgreSQL"
   - Railway automatically creates `DATABASE_URL` variable

2. **Database will be available immediately** - no additional setup needed!

---

## Step 4: Configure Environment Variables

In Railway Dashboard → Your Project → Variables, add:

### Required Variables:
```bash
SECRET_KEY=generate-a-long-random-32-character-key-here
JWT_SECRET_KEY=generate-another-long-random-jwt-key-here
FLASK_ENV=production
CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

### Optional (Email functionality):
```bash
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-gmail-app-password
MAIL_DEFAULT_SENDER=your-email@gmail.com
```

### 🔐 Generate Secure Keys:
```bash
# Generate SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"

# Generate JWT_SECRET_KEY  
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Step 5: Initialize Production Database

1. **After first deployment**, run the database initialization:
   ```bash
   # Using Railway CLI
   railway run python init_production_db.py
   ```

2. **Or use Railway Dashboard**:
   - Go to your service
   - Open "Deploy Logs"
   - Run: `python init_production_db.py`

3. **Save the admin credentials** that are output!

---

## Step 6: Custom Domain (Optional)

1. **In Railway Dashboard**:
   - Go to Project → Service → Settings → Domains
   - Click "Custom Domain"
   - Enter your domain: `yourdomain.com`

2. **Update DNS Records**:
   - Add the A record Railway provides
   - SSL certificate auto-generated

3. **Update CORS_ORIGINS**:
   ```bash
   CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
   ```

---

## Step 7: Test Your Deployment

### Health Check:
```bash
curl https://your-app.up.railway.app/health
```

### Admin Access:
1. Go to: `https://your-app.up.railway.app/login`
2. Use the admin credentials from Step 5
3. **Change the password immediately!**

---

## Post-Deployment Tasks

### Security:
- [ ] Change default admin password
- [ ] Create additional admin users
- [ ] Review CORS origins
- [ ] Set up monitoring

### Data:
- [ ] Import existing terms/categories
- [ ] Set up regular backups
- [ ] Test email functionality

### Performance:
- [ ] Monitor response times
- [ ] Check database performance
- [ ] Set up error tracking

---

## Useful Railway Commands

```bash
# View logs
railway logs

# Open app in browser
railway open

# Run commands in production
railway run python --version

# Connect to database
railway connect

# View environment variables
railway variables
```

---

## Troubleshooting

### Common Issues:

**App won't start:**
- Check logs: `railway logs`
- Verify all environment variables are set
- Ensure `DATABASE_URL` is automatically provided

**Database connection errors:**
- Verify PostgreSQL service is running
- Check `DATABASE_URL` format
- Run database initialization script

**CORS errors:**
- Update `CORS_ORIGINS` with your domain
- Include both `www` and non-`www` versions

**Email not working:**
- Verify Gmail app password is correct
- Check email configuration variables
- Test with a simple email send

---

## Production Checklist ✅

- [ ] App deploys successfully
- [ ] Database connected and initialized
- [ ] Admin login working
- [ ] Environment variables configured
- [ ] Custom domain set up (if needed)
- [ ] SSL certificate active
- [ ] Email functionality tested
- [ ] Admin password changed
- [ ] Backups configured

---

## Support

- **Railway Docs**: https://docs.railway.app
- **Railway Discord**: https://discord.gg/railway
- **Flask on Railway**: https://docs.railway.app/guides/flask

Your Mardi Gras API is now production-ready! 🎭✨