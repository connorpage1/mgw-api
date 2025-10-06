"""
Admin interface routes for managing the application
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_required, current_user
from functools import wraps
from models import db, User, Category, Term, STLFile
from utils.logger import logger

admin_bp = Blueprint('admin', __name__)

def admin_required(f):
    """Decorator for admin-only routes"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.has_role('admin') and not current_user.has_role('superadmin'):
            flash('Admin access required.', 'error')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function

def superadmin_required(f):
    """Decorator for superadmin-only routes"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.has_role('superadmin'):
            flash('Super admin access required.', 'error')
            return redirect(url_for('admin.dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/')
@admin_required
def dashboard():
    """Main admin dashboard"""
    try:
        # Get basic statistics
        stats = {
            'total_terms': Term.query.filter_by(is_active=True).count(),
            'total_categories': Category.query.filter_by(is_active=True).count(),
            'total_users': User.query.filter_by(active=True).count(),
            'total_files': STLFile.query.count()
        }
        
        return render_template('admin/main_dashboard.html', stats=stats)
        
    except Exception as e:
        logger.error(f"Error loading admin dashboard: {e}")
        flash('Error loading dashboard', 'error')
        return render_template('admin/main_dashboard.html', stats={})

# Additional admin routes would be implemented here
# For brevity, including just the main dashboard
# The full implementation would include all CRUD operations for:
# - Users
# - Terms  
# - Categories
# - Files
# - Bulk uploads
# - etc.