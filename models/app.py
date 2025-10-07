"""
App and token management models
"""
from datetime import datetime
from . import db

class App(db.Model):
    """Application model for API access management"""
    __tablename__ = 'apps'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    active = db.Column(db.Boolean(), default=True, nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Created/updated by (superadmin user references)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Relationships
    tokens = db.relationship('AppToken', backref='app', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<App {self.name}>'

class AppToken(db.Model):
    """API tokens associated with applications"""
    __tablename__ = 'app_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey('apps.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(255), nullable=False)  # Token name/description
    token_hash = db.Column(db.String(255), unique=True, nullable=False)  # Hashed token
    prefix = db.Column(db.String(10), nullable=False)  # Token prefix for identification (e.g., "mg_")
    active = db.Column(db.Boolean(), default=True, nullable=False)
    
    # Usage tracking
    last_used_at = db.Column(db.DateTime, nullable=True)
    last_used_ip = db.Column(db.String(45), nullable=True)
    usage_count = db.Column(db.Integer, default=0, nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Created/updated by (superadmin user references)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    def __repr__(self):
        return f'<AppToken {self.name} for {self.app.name}>'
    
    @property
    def masked_token(self):
        """Return a masked version of the token for display"""
        # Show prefix + asterisks + last 4 chars of hash (safe to show)
        return f"{self.prefix}{'*' * 28}{self.token_hash[-4:]}"