"""
Tour evaluation service stub - placeholder implementation
"""
from typing import Dict, List, Any

# Constants
SCORE_VALUES = {
    'excellent': 5,
    'good': 4,
    'average': 3,
    'poor': 2,
    'unacceptable': 1
}

def seed_default_tour_eval_catalog():
    """Seed default tour evaluation catalog"""
    # Placeholder - implement tour eval seeding logic if needed
    pass

def apply_tour_eval_filters(*args, **kwargs):
    """Apply filters to tour evaluations"""
    return []

def build_export_csv(*args, **kwargs):
    """Build CSV export"""
    return ""

def create_pdf_report(*args, **kwargs):
    """Create PDF report"""
    return None

def default_report_recipients():
    """Get default report recipients"""
    return []

def get_catalog_lookup():
    """Get catalog lookup"""
    return {}

def get_coaching_threshold():
    """Get coaching threshold"""
    return 1.3

def normalize_recipients(*args):
    """Normalize recipients"""
    return []

def next_criteria_external_id():
    """Get next criteria external ID"""
    return "C001"

def next_question_external_id():
    """Get next question external ID"""
    return "Q001"

def parse_tour_date(*args):
    """Parse tour date"""
    return None

def recent_evaluation_cutoff():
    """Get recent evaluation cutoff"""
    from datetime import datetime, timedelta
    return datetime.utcnow() - timedelta(days=30)

def report_filename(*args):
    """Generate report filename"""
    return "report.pdf"

def serialize_evaluation_detail(*args):
    """Serialize evaluation detail"""
    return {}

def serialize_evaluation_row(*args):
    """Serialize evaluation row"""
    return {}

def serialize_tour_eval_catalog(*args):
    """Serialize tour eval catalog"""
    return []