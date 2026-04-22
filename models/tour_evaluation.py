"""
Tour evaluation models.
"""
import uuid
from datetime import datetime

from . import db

class TourEvalCriterion(db.Model):
    """Performance criteria shown in the coaching dashboard."""

    __tablename__ = "tour_eval_criteria"

    id = db.Column(db.Integer, primary_key=True)
    external_id = db.Column(db.String(64), nullable=False, unique=True)
    text = db.Column(db.Text, nullable=False)
    sort_order = db.Column(db.Integer, default=0, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    scores = db.relationship(
        "TourEvaluationCriteriaScore",
        back_populates="criterion",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

class TourEvalQuestion(db.Model):
    """Prompt/question inside a tour evaluation section."""

    __tablename__ = "tour_eval_questions"

    id = db.Column(db.Integer, primary_key=True)
    external_id = db.Column(db.String(64), nullable=False, unique=True)
    section_id = db.Column(db.Integer, db.ForeignKey("tour_eval_sections.id"), nullable=False)
    text = db.Column(db.Text, nullable=False)
    sort_order = db.Column(db.Integer, default=0, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    section = db.relationship("TourEvalSection", back_populates="questions")

class TourEvalSection(db.Model):
    """High-level grouping for evaluation talking points."""

    __tablename__ = "tour_eval_sections"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), nullable=False, unique=True)
    title = db.Column(db.String(200), nullable=False)
    sort_order = db.Column(db.Integer, default=0, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    questions = db.relationship(
        "TourEvalQuestion",
        back_populates="section",
        cascade="all, delete-orphan",
        order_by="TourEvalQuestion.sort_order, TourEvalQuestion.id",
        lazy="selectin",
    )

class TourEvaluation(db.Model):
    """Submitted guide evaluation."""

    __tablename__ = "tour_evaluations"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tour_date = db.Column(db.DateTime, nullable=False)
    guide_name = db.Column(db.String(200), nullable=False)
    evaluator_name = db.Column(db.String(200), nullable=False)
    tour_number = db.Column(db.String(64))
    tour_time = db.Column(db.String(64))
    group_size = db.Column(db.Integer)
    strengths = db.Column(db.Text, default="", nullable=False)
    deviations = db.Column(db.Text, default="", nullable=False)
    coaching_notes = db.Column(db.Text, default="", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    item_scores = db.relationship(
        "TourEvaluationItemScore",
        back_populates="evaluation",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    criteria_scores = db.relationship(
        "TourEvaluationCriteriaScore",
        back_populates="evaluation",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

class TourEvaluationCriteriaScore(db.Model):
    """Criterion score snapshot stored with an evaluation."""

    __tablename__ = "tour_evaluation_criteria_scores"

    id = db.Column(db.Integer, primary_key=True)
    evaluation_id = db.Column(db.String(36), db.ForeignKey("tour_evaluations.id"), nullable=False)
    criterion_id = db.Column(db.String(64), nullable=False)
    criteria_text = db.Column(db.Text, nullable=False)
    score = db.Column(db.String(32), nullable=False)

    evaluation = db.relationship("TourEvaluation", back_populates="criteria_scores")
    criterion_fk = db.Column(db.Integer, db.ForeignKey("tour_eval_criteria.id"))
    criterion = db.relationship("TourEvalCriterion", back_populates="scores")

class TourEvaluationItemScore(db.Model):
    """Per-question score snapshot stored with an evaluation."""

    __tablename__ = "tour_evaluation_item_scores"

    id = db.Column(db.Integer, primary_key=True)
    evaluation_id = db.Column(db.String(36), db.ForeignKey("tour_evaluations.id"), nullable=False)
    item_id = db.Column(db.String(64), nullable=False)
    section_key = db.Column(db.String(64), nullable=False)
    section_title = db.Column(db.String(200), nullable=False)
    item_text = db.Column(db.Text, nullable=False)
    score = db.Column(db.String(32), nullable=False)
    section_notes = db.Column(db.Text, default="", nullable=False)

    evaluation = db.relationship("TourEvaluation", back_populates="item_scores")
