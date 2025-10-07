"""
File management routes for STL and video uploads
"""
from flask import Blueprint, request, jsonify, send_file, render_template, redirect, url_for, flash
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_login import login_required, current_user
from functools import wraps
from datetime import datetime
import os
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
    """Files admin dashboard"""
    try:
        stats = {
            'stl_files': STLFile.query.count(),
            'video_files': VideoFile.query.count(),
            'total_file_uploads': STLFile.query.count() + VideoFile.query.count(),
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
    """Admin files list"""
    try:
        stl_files = STLFile.query.order_by(STLFile.created_at.desc()).limit(50).all()
        video_files = VideoFile.query.order_by(VideoFile.created_at.desc()).limit(50).all()
        return render_template('admin/files_list.html', stl_files=stl_files, video_files=video_files)
    except Exception as e:
        logger.error(f"Error loading files list: {e}")
        flash('Error loading files', 'error')
        return redirect(url_for('files.dashboard'))

# === FILE UPLOAD ROUTES ===

@file_bp.route('/upload/stl', methods=['POST'])
@superadmin_required
def upload_stl():
    """Upload STL file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.lower().endswith('.stl'):
            return jsonify({'error': 'Only STL files are allowed'}), 400
        
        # Generate unique filename
        import uuid
        from werkzeug.utils import secure_filename
        
        filename = secure_filename(file.filename)
        unique_id = str(uuid.uuid4())
        
        # Create upload directory
        upload_dir = os.path.join('uploads', 'stl', unique_id)
        os.makedirs(upload_dir, exist_ok=True)
        
        # Save file
        file_path = os.path.join(upload_dir, filename)
        file.save(file_path)
        
        # Create database record
        stl_file = STLFile(
            original_filename=filename,
            file_path=file_path,
            local_path=file_path,
            file_size=os.path.getsize(file_path),
            uploaded_by=current_user.id,
            upload_timestamp=datetime.utcnow()
        )
        
        db.session.add(stl_file)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'File uploaded successfully',
            'file_id': stl_file.id
        })
        
    except Exception as e:
        logger.error(f"Error uploading STL file: {e}")
        db.session.rollback()
        return jsonify({'error': 'Upload failed'}), 500

@file_bp.route('/upload/video', methods=['POST'])
@superadmin_required
def upload_video():
    """Upload video file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Check file extension
        allowed_extensions = ['.mp4', '.avi', '.mov', '.mkv', '.webm']
        if not any(file.filename.lower().endswith(ext) for ext in allowed_extensions):
            return jsonify({'error': 'Invalid video file format'}), 400
        
        # Generate unique filename
        import uuid
        from werkzeug.utils import secure_filename
        
        filename = secure_filename(file.filename)
        unique_id = str(uuid.uuid4())
        
        # Create upload directory
        upload_dir = os.path.join('uploads', 'video', unique_id)
        os.makedirs(upload_dir, exist_ok=True)
        
        # Save file
        file_path = os.path.join(upload_dir, filename)
        file.save(file_path)
        
        # Create database record
        video_file = VideoFile(
            original_filename=filename,
            file_path=file_path,
            local_path=file_path,
            file_size=os.path.getsize(file_path),
            uploaded_by=current_user.id,
            upload_timestamp=datetime.utcnow()
        )
        
        db.session.add(video_file)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Video uploaded successfully',
            'file_id': video_file.id
        })
        
    except Exception as e:
        logger.error(f"Error uploading video file: {e}")
        db.session.rollback()
        return jsonify({'error': 'Upload failed'}), 500

# === FILE DETAIL ROUTES ===

@file_bp.route('/stl/<file_id>/detail')
@superadmin_required
def stl_detail(file_id):
    """STL file detail page"""
    try:
        stl_file = STLFile.query.get_or_404(file_id)
        return render_template('admin/stl_file_detail.html', file=stl_file)
    except Exception as e:
        logger.error(f"Error loading STL file detail: {e}")
        flash('Error loading file details', 'error')
        return redirect(url_for('files.files_list'))

@file_bp.route('/video/<file_id>/detail')
@superadmin_required
def video_detail(file_id):
    """Video file detail page"""
    try:
        video_file = VideoFile.query.get_or_404(file_id)
        return render_template('admin/video_file_detail.html', file=video_file)
    except Exception as e:
        logger.error(f"Error loading video file detail: {e}")
        flash('Error loading file details', 'error')
        return redirect(url_for('files.files_list'))

# === FILE DOWNLOAD ROUTES ===

@file_bp.route('/stl/<file_id>/download')
@superadmin_required
def download_stl(file_id):
    """Download STL file"""
    try:
        stl_file = STLFile.query.get_or_404(file_id)
        
        if not stl_file.local_path or not os.path.exists(stl_file.local_path):
            flash('File not found on disk', 'error')
            return redirect(url_for('files.files_list'))
        
        return send_file(
            stl_file.local_path,
            as_attachment=True,
            download_name=stl_file.original_filename
        )
        
    except Exception as e:
        logger.error(f"Error downloading STL file: {e}")
        flash('Error downloading file', 'error')
        return redirect(url_for('files.files_list'))

@file_bp.route('/video/<file_id>/download')
@superadmin_required
def download_video(file_id):
    """Download video file"""
    try:
        video_file = VideoFile.query.get_or_404(file_id)
        
        if not video_file.local_path or not os.path.exists(video_file.local_path):
            flash('File not found on disk', 'error')
            return redirect(url_for('files.files_list'))
        
        return send_file(
            video_file.local_path,
            as_attachment=True,
            download_name=video_file.original_filename
        )
        
    except Exception as e:
        logger.error(f"Error downloading video file: {e}")
        flash('Error downloading file', 'error')
        return redirect(url_for('files.files_list'))

# === FILE MANAGEMENT ROUTES ===

@file_bp.route('/stl/<file_id>/delete', methods=['POST'])
@superadmin_required
def delete_stl(file_id):
    """Delete STL file"""
    try:
        stl_file = STLFile.query.get_or_404(file_id)
        
        # Delete file from disk
        if stl_file.local_path and os.path.exists(stl_file.local_path):
            os.remove(stl_file.local_path)
            # Try to remove the directory if empty
            try:
                os.rmdir(os.path.dirname(stl_file.local_path))
            except OSError:
                pass  # Directory not empty
        
        # Delete from database
        db.session.delete(stl_file)
        db.session.commit()
        
        flash(f'STL file "{stl_file.original_filename}" deleted successfully', 'success')
        return redirect(url_for('files.files_list'))
        
    except Exception as e:
        logger.error(f"Error deleting STL file: {e}")
        db.session.rollback()
        flash('Error deleting file', 'error')
        return redirect(url_for('files.files_list'))

@file_bp.route('/video/<file_id>/delete', methods=['POST'])
@superadmin_required
def delete_video(file_id):
    """Delete video file"""
    try:
        video_file = VideoFile.query.get_or_404(file_id)
        
        # Delete file from disk
        if video_file.local_path and os.path.exists(video_file.local_path):
            os.remove(video_file.local_path)
            # Try to remove the directory if empty
            try:
                os.rmdir(os.path.dirname(video_file.local_path))
            except OSError:
                pass  # Directory not empty
        
        # Delete from database
        db.session.delete(video_file)
        db.session.commit()
        
        flash(f'Video file "{video_file.original_filename}" deleted successfully', 'success')
        return redirect(url_for('files.files_list'))
        
    except Exception as e:
        logger.error(f"Error deleting video file: {e}")
        db.session.rollback()
        flash('Error deleting file', 'error')
        return redirect(url_for('files.files_list'))

@file_bp.route('/stl/<file_id>/feature', methods=['POST'])
@superadmin_required
def feature_stl(file_id):
    """Toggle featured status for STL file"""
    try:
        stl_file = STLFile.query.get_or_404(file_id)
        
        # If setting as featured, remove featured status from other files
        if not stl_file.is_featured:
            STLFile.query.update({'is_featured': False})
            stl_file.is_featured = True
            flash(f'STL file "{stl_file.original_filename}" is now featured', 'success')
        else:
            stl_file.is_featured = False
            flash(f'STL file "{stl_file.original_filename}" is no longer featured', 'success')
        
        db.session.commit()
        return redirect(url_for('files.stl_detail', file_id=file_id))
        
    except Exception as e:
        logger.error(f"Error updating featured status: {e}")
        db.session.rollback()
        flash('Error updating featured status', 'error')
        return redirect(url_for('files.files_list'))