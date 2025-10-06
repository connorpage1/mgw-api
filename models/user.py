"""
User authentication and management models
"""
from datetime import datetime
from flask_login import UserMixin
from . import db

# Association table for many-to-many relationship between users and roles
roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    """User model for authentication and management"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=True)
    first_name = db.Column(db.String(100), nullable=True)
    last_name = db.Column(db.String(100), nullable=True)
    password = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean(), default=True)
    
    # Login tracking
    current_login_at = db.Column(db.DateTime())
    current_login_ip = db.Column(db.String(45))
    last_login_at = db.Column(db.DateTime())
    last_login_ip = db.Column(db.String(45))
    login_count = db.Column(db.Integer, default=0)
    
    # API Access
    api_key = db.Column(db.String(255), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    roles = db.relationship('Role', secondary='roles_users', backref=db.backref('users', lazy='dynamic'))

    def has_role(self, role_name):
        """Check if user has a specific role"""
        return any(role.name == role_name for role in self.roles)
    
    @property
    def display_name(self):
        """Return the user's display name (first name, or username, or email)"""
        if self.first_name:
            return self.first_name
        elif self.username:
            return self.username
        else:
            return self.email.split('@')[0]
    
    @property
    def is_active(self):
        return self.active
    
    @property
    def is_authenticated(self):
        return True
    
    @property
    def is_anonymous(self):
        return False
    
    def get_id(self):
        return str(self.id)
    
    def set_password(self, password):
        """Set user password using secure hasher"""
        # Import here to avoid circular imports
        from services.auth_service import secure_hasher
        self.password = secure_hasher.hash_password(password)

    @property
    def role(self):
        """Get primary role name for API responses"""
        if self.roles:
            return self.roles[0].name
        return 'user'

    @property
    def name(self):
        """Get full name or display name"""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.display_name

class Role(db.Model):
    """User roles for authorization"""
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class PasswordResetToken(db.Model):
    """Track one-time use password reset tokens for security"""
    __tablename__ = 'password_reset_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    token_hash = db.Column(db.String(255), unique=True, nullable=False)  # Hashed token
    used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    user = db.relationship('User', backref='reset_tokens')