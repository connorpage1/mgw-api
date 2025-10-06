"""
Authentication service for password hashing and validation
"""
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from collections import defaultdict
from time import time

class SecurePasswordHasher:
    """Secure password hasher using Argon2id"""
    
    def __init__(self):
        self.ph = PasswordHasher(
            memory_cost=65536,   # 64 MB
            time_cost=2,         # 2 iterations
            parallelism=4,       # 4 parallel threads
            hash_len=32,         # 32 byte hash
            salt_len=16          # 16 byte salt
        )
    
    def hash_password(self, password: str) -> str:
        """Hash password with Argon2id"""
        return self.ph.hash(password)
    
    def verify_password(self, password: str, hash_str: str) -> bool:
        """Verify password against hash"""
        try:
            self.ph.verify(hash_str, password)
            return True
        except VerifyMismatchError:
            return False
        except Exception:
            return False

class RateLimiter:
    """Simple in-memory rate limiter for login attempts"""
    
    def __init__(self):
        self.login_attempts = defaultdict(list)
    
    def is_rate_limited(self, identifier, max_attempts=5, window_minutes=15):
        """Check if identifier is rate limited"""
        now = time()
        window_start = now - (window_minutes * 60)
        
        # Clean old attempts
        self.login_attempts[identifier] = [
            attempt_time for attempt_time in self.login_attempts[identifier] 
            if attempt_time > window_start
        ]
        
        # Check if limit exceeded
        return len(self.login_attempts[identifier]) >= max_attempts
    
    def record_login_attempt(self, identifier):
        """Record a failed login attempt"""
        self.login_attempts[identifier].append(time())

# Initialize services
secure_hasher = SecurePasswordHasher()
rate_limiter = RateLimiter()