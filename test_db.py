#!/usr/bin/env python3
"""
Test database connection on Railway
"""
import os
import sys

print("🔍 Environment Variables:")
for key in sorted(os.environ.keys()):
    if 'DATABASE' in key or 'POSTGRES' in key or 'PG' in key:
        value = os.environ[key]
        # Mask passwords for security
        if '@' in value:
            parts = value.split('@')
            if len(parts) >= 2:
                masked = parts[0].split(':')
                if len(masked) >= 2:
                    masked[-1] = '***'
                    value = ':'.join(masked) + '@' + '@'.join(parts[1:])
        print(f"  {key}: {value}")

print("\n🔍 Railway Environment:")
print(f"  RAILWAY_ENVIRONMENT: {os.environ.get('RAILWAY_ENVIRONMENT', 'NOT_SET')}")
print(f"  RAILWAY_PROJECT_ID: {os.environ.get('RAILWAY_PROJECT_ID', 'NOT_SET')}")

print("\n🔍 Database Connection Test:")
try:
    from sqlalchemy import create_engine, text
    
    database_url = os.environ.get('DATABASE_URL', 'NOT_FOUND')
    if database_url == 'NOT_FOUND':
        print("❌ DATABASE_URL not found")
        sys.exit(1)
    
    # Fix postgres:// to postgresql://
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
        print("✅ Fixed postgres:// to postgresql://")
    
    print(f"📍 Connecting to: {database_url[:50]}...")
    
    engine = create_engine(database_url)
    with engine.connect() as conn:
        result = conn.execute(text("SELECT version();"))
        version = result.fetchone()[0]
        print(f"✅ PostgreSQL Connection Successful!")
        print(f"📊 Version: {version}")
        
except Exception as e:
    print(f"❌ Database Connection Failed: {e}")
    sys.exit(1)

print("\n🎉 All tests passed!")