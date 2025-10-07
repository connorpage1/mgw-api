"""
Database models for the Mardi Gras API
"""
from datetime import datetime
import uuid
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy import func

# Database instance - will be initialized in main app
db = SQLAlchemy()

# Import all models
from .user import User, Role, roles_users, PasswordResetToken
from .glossary import Category, Term  
from .files import STLFile, VideoFile, FileUploadLog
from .app import App, AppToken

__all__ = [
    'db',
    'User', 
    'Role', 
    'roles_users', 
    'PasswordResetToken',
    'Category', 
    'Term',
    'STLFile', 
    'VideoFile', 
    'FileUploadLog',
    'App',
    'AppToken'
]