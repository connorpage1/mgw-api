"""
Admin interface routes for managing the application
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_required, current_user, logout_user
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
            return redirect(url_for('auth.login'))
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
        logger.info("Loading admin dashboard...")
        
        # Get basic statistics - test each query individually
        stats = {}
        
        try:
            stats['total_terms'] = Term.query.filter_by(is_active=True).count()
            logger.info(f"Total terms: {stats['total_terms']}")
        except Exception as e:
            logger.error(f"Error querying terms: {e}")
            stats['total_terms'] = 0
            
        try:
            stats['total_categories'] = Category.query.filter_by(is_active=True).count()
            logger.info(f"Total categories: {stats['total_categories']}")
        except Exception as e:
            logger.error(f"Error querying categories: {e}")
            stats['total_categories'] = 0
            
        try:
            stats['total_users'] = User.query.filter_by(active=True).count()
            logger.info(f"Total users: {stats['total_users']}")
        except Exception as e:
            logger.error(f"Error querying users: {e}")
            stats['total_users'] = 0
            
        try:
            stats['total_files'] = STLFile.query.count()
            logger.info(f"Total files: {stats['total_files']}")
        except Exception as e:
            logger.error(f"Error querying files: {e}")
            stats['total_files'] = 0
        
        logger.info(f"Dashboard stats: {stats}")
        logger.info("Rendering admin dashboard template...")
        
        return render_template('admin/main_dashboard.html', stats=stats)
        
    except Exception as e:
        logger.error(f"Error loading admin dashboard: {e}")
        import traceback
        logger.error(f"Dashboard error traceback: {traceback.format_exc()}")
        flash('Error loading dashboard', 'error')
        return render_template('admin/main_dashboard.html', stats={})

# === USER MANAGEMENT ROUTES ===

@admin_bp.route('/users')
@admin_required
def users_list():
    """List all users (placeholder)"""
    try:
        users = User.query.all()
        return render_template('admin/users_list.html', users=users)
    except Exception as e:
        logger.error(f"Error loading users list: {e}")
        flash('Error loading users', 'error')
        return redirect(url_for('admin.dashboard'))

@admin_bp.route('/tokens')
@superadmin_required  
def tokens():
    """API Token management (placeholder)"""
    try:
        users_with_tokens = User.query.filter(User.api_key.isnot(None)).all()
        return render_template('admin/tokens.html', users=users_with_tokens)
    except Exception as e:
        logger.error(f"Error loading tokens: {e}")
        flash('Error loading tokens', 'error')
        return redirect(url_for('admin.dashboard'))

@admin_bp.route('/logout')
@login_required
def logout():
    """Admin logout"""
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('auth.login'))

@admin_bp.route('/account', methods=['GET', 'POST'])
@admin_required
def account():
    """Admin account settings (placeholder)"""
    if request.method == 'POST':
        flash('Account updated successfully', 'success')
        return redirect(url_for('admin.account'))
    return render_template('admin/account.html', user=current_user)