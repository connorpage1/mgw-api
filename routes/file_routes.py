"""
File management routes for STL and video uploads
"""
from flask import Blueprint, request, jsonify, send_file, render_template, redirect, url_for, flash
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_login import login_required, current_user
from functools import wraps
from models import db, STLFile, VideoFile, User
from utils.logger import logger

file_bp = Blueprint('files', __name__)

@file_bp.route('/stl/<file_id>')
def serve_stl_file(file_id):
    """Serve STL file for download"""
    try:
        stl_file = STLFile.query.get_or_404(file_id)
        
        if not stl_file.local_path:
            return jsonify({'error': 'File not available'}), 404
        
        return send_file(
            stl_file.local_path,
            as_attachment=True,
            download_name=stl_file.original_filename
        )
        
    except Exception as e:
        logger.error(f"Error serving STL file: {e}")
        return jsonify({'error': 'File not found'}), 404

# === ADMIN FILE ROUTES ===

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

@file_bp.route('/dashboard')
@superadmin_required
def dashboard():
    """Files admin dashboard (placeholder)"""
    try:
        stats = {
            'total_stl_files': STLFile.query.count(),
            'total_video_files': VideoFile.query.count(),
            'featured_files': STLFile.query.filter_by(is_featured=True).count()
        }
        return render_template('admin/files_dashboard.html', stats=stats)
    except Exception as e:
        logger.error(f"Error loading files dashboard: {e}")
        flash('Error loading files dashboard', 'error')
        return redirect(url_for('admin.dashboard'))

@file_bp.route('/list')
@superadmin_required
def files_list():
    """Admin files list (placeholder)"""
    try:
        stl_files = STLFile.query.order_by(STLFile.created_at.desc()).limit(50).all()
        video_files = VideoFile.query.order_by(VideoFile.created_at.desc()).limit(50).all()
        return render_template('admin/files_list.html', stl_files=stl_files, video_files=video_files)
    except Exception as e:
        logger.error(f"Error loading files list: {e}")
        flash('Error loading files', 'error')
        return redirect(url_for('files.dashboard'))