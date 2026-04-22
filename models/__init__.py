"""
Database models for the Mardi Gras API
"""
from flask_sqlalchemy import SQLAlchemy

# Database instance - will be initialized in main app
db = SQLAlchemy()

# Import all models
from .legacy_auth import Role, User
from .glossary import Category, Term
from .files import STLFile, VideoFile, FileUploadLog
from .app import App, AppToken
from .customer_data import Customer, RollerDataSync
from .tour_evaluation import (
    TourEvalCriterion,
    TourEvalQuestion,
    TourEvalSection,
    TourEvaluation,
    TourEvaluationCriteriaScore,
    TourEvaluationItemScore,
)

__all__ = [
    'db',
    'User',
    'Role',
    'Category',
    'Term',
    'STLFile',
    'VideoFile',
    'FileUploadLog',
    'App',
    'AppToken',
    'Customer',
    'RollerDataSync',
    'TourEvalCriterion',
    'TourEvalQuestion',
    'TourEvalSection',
    'TourEvaluation',
    'TourEvaluationCriteriaScore',
    'TourEvaluationItemScore'
]
