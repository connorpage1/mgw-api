"""
Glossary models for terms and categories
"""
from datetime import datetime
from sqlalchemy import func
from . import db

class Category(db.Model):
    """Categories for organizing glossary terms"""
    __tablename__ = 'categories'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    sort_order = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        """Convert category to dictionary for API responses"""
        return {
            'id': self.id,
            'name': self.name,
            'slug': self.slug,
            'description': self.description,
            'sort_order': self.sort_order,
            'is_active': self.is_active,
            'term_count': len([term for term in self.terms if term.is_active])
        }

class Term(db.Model):
    """Glossary terms with definitions and metadata"""
    __tablename__ = 'terms'
    
    id = db.Column(db.Integer, primary_key=True)
    term = db.Column(db.String(200), unique=True, nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False)
    pronunciation = db.Column(db.String(200), nullable=False)
    definition = db.Column(db.Text, nullable=False)
    etymology = db.Column(db.Text)
    example = db.Column(db.Text)
    difficulty = db.Column(db.String(20), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    view_count = db.Column(db.Integer, default=0)
    is_featured = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    category_rel = db.relationship('Category', backref='terms')
    
    def to_dict(self, include_related=False):
        """Convert term to dictionary for API responses"""
        data = {
            'id': self.id,
            'term': self.term,
            'slug': self.slug,
            'pronunciation': self.pronunciation,
            'definition': self.definition,
            'etymology': self.etymology,
            'example': self.example,
            'difficulty': self.difficulty,
            'category': self.category_rel.name if self.category_rel else 'Unknown',
            'category_slug': self.category_rel.slug if self.category_rel else '',
            'category_id': self.category_id,
            'view_count': self.view_count,
            'is_featured': self.is_featured,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
        
        if include_related:
            data['related_terms'] = [rt.to_dict() for rt in self.get_related_terms()]
        
        return data
    
    def get_related_terms(self, limit=5):
        """Get related terms based on category"""
        return Term.query.filter(
            Term.category_id == self.category_id,
            Term.id != self.id,
            Term.is_active == True
        ).order_by(func.random()).limit(limit).all()