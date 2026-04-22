"""
Tour evaluation models - placeholder implementation
"""
from datetime import datetime
from models import db

class TourEvalCriterion(db.Model):
    """Tour evaluation criterion"""
    __tablename__ = 'tour_eval_criteria'
    
    id = db.Column(db.Integer, primary_key=True)
    external_id = db.Column(db.String(50), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class TourEvalQuestion(db.Model):
    """Tour evaluation question"""
    __tablename__ = 'tour_eval_questions'
    
    id = db.Column(db.Integer, primary_key=True)
    external_id = db.Column(db.String(50), nullable=False, unique=True)
    question = db.Column(db.Text, nullable=False)
    criterion_id = db.Column(db.Integer, db.ForeignKey('tour_eval_criteria.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class TourEvalSection(db.Model):
    """Tour evaluation section"""
    __tablename__ = 'tour_eval_sections'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    sort_order = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)

class TourEvaluation(db.Model):
    """Tour evaluation"""
    __tablename__ = 'tour_evaluations'
    
    id = db.Column(db.Integer, primary_key=True)
    external_id = db.Column(db.String(50), nullable=False, unique=True)
    tour_date = db.Column(db.DateTime, nullable=False)
    guide_name = db.Column(db.String(200))
    evaluator_name = db.Column(db.String(200))
    overall_score = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class TourEvaluationCriteriaScore(db.Model):
    """Tour evaluation criteria score"""
    __tablename__ = 'tour_evaluation_criteria_scores'
    
    id = db.Column(db.Integer, primary_key=True)
    evaluation_id = db.Column(db.Integer, db.ForeignKey('tour_evaluations.id'))
    criterion_id = db.Column(db.Integer, db.ForeignKey('tour_eval_criteria.id'))
    score = db.Column(db.Float)
    comments = db.Column(db.Text)

class TourEvaluationItemScore(db.Model):
    """Tour evaluation item score"""
    __tablename__ = 'tour_evaluation_item_scores'
    
    id = db.Column(db.Integer, primary_key=True)
    evaluation_id = db.Column(db.Integer, db.ForeignKey('tour_evaluations.id'))
    question_id = db.Column(db.Integer, db.ForeignKey('tour_eval_questions.id'))
    score = db.Column(db.Float)
    comments = db.Column(db.Text)