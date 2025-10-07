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
        # Get STL files for video upload dropdown
        stl_files = STLFile.query.order_by(STLFile.upload_timestamp.desc()).all()
        return render_template('admin/files_dashboard.html', stats=stats, stl_files=stl_files)
    except Exception as e:
        logger.error(f"Error loading files dashboard: {e}")
        flash('Error loading files dashboard', 'error')
        return redirect(url_for('admin.dashboard'))

@file_bp.route('/list')
@superadmin_required
def files_list():
    """Admin files list"""
    try:
        stl_files = STLFile.query.order_by(STLFile.upload_timestamp.desc()).limit(50).all()
        video_files = VideoFile.query.order_by(VideoFile.upload_timestamp.desc()).limit(50).all()
        # Get all STL files for video upload dropdown
        all_stl_files = STLFile.query.order_by(STLFile.upload_timestamp.desc()).all()
        return render_template('admin/files_list.html', stl_files=stl_files, video_files=video_files, all_stl_files=all_stl_files)
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
            flash('No file provided', 'error')
            return redirect(request.referrer or url_for('files.dashboard'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.referrer or url_for('files.dashboard'))
        
        if not file.filename.lower().endswith('.stl'):
            flash('Only STL files are allowed', 'error')
            return redirect(request.referrer or url_for('files.dashboard'))
        
        # Generate unique filename
        import uuid
        from werkzeug.utils import secure_filename
        from flask import current_app
        
        filename = secure_filename(file.filename)
        unique_id = str(uuid.uuid4())
        
        # Create upload directory with absolute path
        base_dir = os.path.dirname(os.path.abspath(__file__ + '/../'))
        upload_dir = os.path.join(base_dir, 'uploads', 'stl', unique_id)
        os.makedirs(upload_dir, exist_ok=True)
        
        # Save file
        file_path = os.path.join(upload_dir, filename)
        file.save(file_path)
        
        # Calculate file hash for duplicate detection
        import hashlib
        def calculate_file_hash(file_path):
            """Calculate SHA-256 hash of file content"""
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        
        file_hash = calculate_file_hash(file_path)
        file_size = os.path.getsize(file_path)
        
        # Check for duplicate files
        # Check by content hash (exact duplicate regardless of filename)
        content_duplicate = STLFile.query.filter_by(file_hash=file_hash).first()
        if content_duplicate:
            # Remove the uploaded file since it's a duplicate
            os.remove(file_path)
            try:
                os.rmdir(upload_dir)  # Remove empty directory
            except OSError:
                pass  # Directory might not be empty or might not exist
            flash(f'File "{filename}" is a duplicate of existing file "{content_duplicate.original_filename}" (uploaded {content_duplicate.upload_timestamp.strftime("%Y-%m-%d")})', 'error')
            return redirect(request.referrer or url_for('files.dashboard'))
        
        # Check by filename and size (likely duplicate with same name)
        name_size_duplicate = STLFile.query.filter_by(
            original_filename=filename,
            file_size=file_size
        ).first()
        if name_size_duplicate:
            # Remove the uploaded file since it's likely a duplicate
            os.remove(file_path)
            try:
                os.rmdir(upload_dir)  # Remove empty directory
            except OSError:
                pass  # Directory might not be empty or might not exist
            flash(f'File "{filename}" with the same name and size already exists (uploaded {name_size_duplicate.upload_timestamp.strftime("%Y-%m-%d")})', 'error')
            return redirect(request.referrer or url_for('files.dashboard'))
        
        # Get optional fields from form
        description = request.form.get('description', '').strip()
        tags = request.form.get('tags', '').strip()
        is_partial = request.form.get('is_partial') == 'true'
        parent_file_id = request.form.get('parent_file_id')
        
        # Validate parent file if provided
        if parent_file_id and parent_file_id.strip():
            parent_file = STLFile.query.get(parent_file_id)
            if not parent_file:
                flash('Selected parent file not found', 'error')
                return redirect(request.referrer or url_for('files.dashboard'))
            if parent_file.is_partial:
                flash('Cannot set a partial file as parent', 'error')
                return redirect(request.referrer or url_for('files.dashboard'))
        else:
            parent_file_id = None

        # Create database record
        stl_file = STLFile(
            original_filename=filename,
            local_path=file_path,
            file_size=file_size,
            file_hash=file_hash,
            uploaded_by=current_user.id,
            upload_timestamp=datetime.utcnow(),
            description=description if description else None,
            tags=tags if tags else None,
            is_partial=is_partial,
            parent_file_id=parent_file_id
        )
        
        db.session.add(stl_file)
        db.session.commit()
        
        flash(f'STL file "{filename}" uploaded successfully!', 'success')
        return redirect(url_for('files.stl_detail', file_id=stl_file.id))
        
    except Exception as e:
        logger.error(f"Error uploading STL file: {e}")
        db.session.rollback()
        flash(f'Upload failed: {str(e)}', 'error')
        return redirect(request.referrer or url_for('files.dashboard'))

@file_bp.route('/upload/video', methods=['POST'])
@superadmin_required
def upload_video():
    """Upload video file"""
    try:
        if 'file' not in request.files:
            flash('No file provided', 'error')
            return redirect(request.referrer or url_for('files.dashboard'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.referrer or url_for('files.dashboard'))
        
        # Check file extension
        allowed_extensions = ['.mp4', '.avi', '.mov', '.mkv', '.webm']
        if not any(file.filename.lower().endswith(ext) for ext in allowed_extensions):
            flash('Invalid video file format. Allowed formats: MP4, AVI, MOV, MKV, WEBM', 'error')
            return redirect(request.referrer or url_for('files.dashboard'))
        
        # Generate unique filename
        import uuid
        from werkzeug.utils import secure_filename
        
        filename = secure_filename(file.filename)
        unique_id = str(uuid.uuid4())
        
        # Create upload directory with absolute path
        base_dir = os.path.dirname(os.path.abspath(__file__ + '/../'))
        upload_dir = os.path.join(base_dir, 'uploads', 'video', unique_id)
        os.makedirs(upload_dir, exist_ok=True)
        
        # Save file
        file_path = os.path.join(upload_dir, filename)
        file.save(file_path)
        
        # Get optional fields from form
        description = request.form.get('description', '').strip()
        stl_id = request.form.get('stl_id')
        associated_stl_id = stl_id if stl_id else None

        # Create database record
        video_file = VideoFile(
            original_filename=filename,
            local_path=file_path,
            file_size=os.path.getsize(file_path),
            uploaded_by=current_user.id,
            upload_timestamp=datetime.utcnow(),
            description=description if description else None,
            associated_stl_id=associated_stl_id
        )
        
        db.session.add(video_file)
        db.session.commit()
        
        flash(f'Video file "{filename}" uploaded successfully!', 'success')
        return redirect(url_for('files.video_detail', file_id=video_file.id))
        
    except Exception as e:
        logger.error(f"Error uploading video file: {e}")
        db.session.rollback()
        flash(f'Upload failed: {str(e)}', 'error')
        return redirect(request.referrer or url_for('files.dashboard'))

# === FILE DETAIL ROUTES ===

@file_bp.route('/stl/<file_id>/detail')
@superadmin_required
def stl_detail(file_id):
    """STL file detail page"""
    try:
        stl_file = STLFile.query.get_or_404(file_id)
        
        # Generate download URL
        download_url = None
        if stl_file.s3_key:
            # For S3 files, generate presigned URL
            from services.s3_service import s3_service
            download_url = s3_service.generate_presigned_url(stl_file.s3_key)
        elif stl_file.local_path and os.path.exists(stl_file.local_path):
            # For local files, use download route
            download_url = url_for('files.download_stl', file_id=file_id)
        
        return render_template('admin/stl_file_detail.html', stl_file=stl_file, download_url=download_url)
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
        
        # Generate download URL
        download_url = None
        if video_file.s3_key:
            # For S3 files, generate presigned URL
            from services.s3_service import s3_service
            download_url = s3_service.generate_presigned_url(video_file.s3_key)
        elif video_file.local_path and os.path.exists(video_file.local_path):
            # For local files, use download route
            download_url = url_for('files.download_video', file_id=file_id)
        
        return render_template('admin/video_file_detail.html', video_file=video_file, download_url=download_url)
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

# === PARENT-CHILD RELATIONSHIP ROUTES ===

@file_bp.route('/stl/available-parents/<file_id>')
@superadmin_required
def get_available_parents(file_id):
    """Get available parent files for a given STL file (excludes self and children)"""
    try:
        current_file = STLFile.query.get_or_404(file_id)
        
        # Get all non-partial files except current file and its direct children  
        # We want files that:
        # 1. Are not partial files (is_partial = False) 
        # 2. Are not the current file (id != file_id)
        # 3. Are not direct children of the current file
        available_parents = STLFile.query.filter(
            STLFile.is_partial == False,
            STLFile.id != file_id,
            db.or_(STLFile.parent_file_id.is_(None), STLFile.parent_file_id != file_id)
        ).order_by(STLFile.original_filename).all()
        
        # Convert to JSON
        parents = []
        for file in available_parents:
            parents.append({
                'id': file.id,
                'filename': file.original_filename,
                'upload_date': file.upload_timestamp.strftime('%Y-%m-%d')
            })
        
        return jsonify({'parents': parents})
        
    except Exception as e:
        logger.error(f"Error getting available parents for file {file_id}: {e}")
        return jsonify({'error': 'Failed to get available parents'}), 500

@file_bp.route('/stl/<file_id>/relationships', methods=['POST'])
@superadmin_required
def update_stl_relationships(file_id):
    """Update parent-child relationships for an STL file"""
    try:
        stl_file = STLFile.query.get_or_404(file_id)
        
        # Get form data
        is_partial = request.form.get('is_partial') == 'true'
        parent_file_id = request.form.get('parent_file_id')
        
        # Validate parent file if provided
        parent_file = None
        if parent_file_id:
            parent_file = STLFile.query.get(parent_file_id)
            if not parent_file:
                return jsonify({'error': 'Parent file not found'}), 400
            
            # Prevent circular relationships
            if parent_file_id == file_id:
                return jsonify({'error': 'A file cannot be its own parent'}), 400
            
            # Check if proposed parent is actually a child of this file
            if stl_file.id == parent_file.parent_file_id:
                return jsonify({'error': 'Cannot create circular relationship: proposed parent is a child of this file'}), 400
            
            # Check deeper circular relationships
            def check_circular_relationship(potential_parent, target_file_id, depth=0):
                if depth > 10:  # Prevent infinite recursion
                    return False
                if potential_parent.parent_file_id == target_file_id:
                    return True
                if potential_parent.parent_file and potential_parent.parent_file_id:
                    return check_circular_relationship(potential_parent.parent_file, target_file_id, depth + 1)
                return False
            
            if check_circular_relationship(parent_file, file_id):
                return jsonify({'error': 'Cannot create circular relationship in the file hierarchy'}), 400
        
        # Update the file
        stl_file.is_partial = is_partial
        stl_file.parent_file_id = parent_file_id if parent_file_id else None
        
        db.session.commit()
        
        # Return updated file data
        return jsonify({
            'success': True,
            'message': 'Relationships updated successfully',
            'file': {
                'id': stl_file.id,
                'is_partial': stl_file.is_partial,
                'parent_file_id': stl_file.parent_file_id,
                'parent_file_name': stl_file.parent_file.original_filename if stl_file.parent_file else None
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating relationships for file {file_id}: {e}")
        return jsonify({'error': 'Failed to update relationships'}), 500

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