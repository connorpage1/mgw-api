"""
Pixie viewer API routes for file access (OAuth2 delegated authentication)
"""
from flask import Blueprint, request, jsonify, send_file, current_app
from datetime import datetime
import os
from models import db, STLFile
from services.oauth2_service import require_oauth2
from utils.logger import logger

pixie_bp = Blueprint('pixie', __name__)

@pixie_bp.route('/api/featured', methods=['GET'])
def pixie_api_featured():
    """Public API: Get featured STL file for Pixie tourist viewer"""
    try:
        # Get the featured STL file
        featured_file = STLFile.query.filter_by(is_featured=True).first()
        
        if not featured_file:
            return jsonify({
                'message': 'No featured project available',
                'featured': None
            })
        
        # Update view count
        featured_file.view_count = (featured_file.view_count or 0) + 1
        featured_file.last_viewed = datetime.utcnow()
        db.session.commit()
        
        # Generate download URL
        download_url = f"/pixie/api/download/stl/{featured_file.id}"
        
        return jsonify({
            'featured': {
                'id': featured_file.id,
                'filename': featured_file.original_filename,
                'description': featured_file.description or "Featured CNC Creation",
                'size': featured_file.file_size,
                'upload_date': featured_file.upload_timestamp.isoformat(),
                'download_url': download_url,
                'screenshot_url': featured_file.get_screenshot_url(),
                'tags': featured_file.tags.split(',') if featured_file.tags else [],
                'view_count': featured_file.view_count
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting featured file: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@pixie_bp.route('/api/past-projects', methods=['GET'])
def pixie_api_past_projects():
    """Public API: Get recent STL files for browsing past projects"""
    try:
        # Get recent STL files (last 10)
        past_files = STLFile.query.order_by(STLFile.upload_timestamp.desc()).limit(10).all()
        
        projects = []
        for file in past_files:
            # Generate download URL
            download_url = f"/pixie/api/download/stl/{file.id}"
            
            projects.append({
                'id': file.id,
                'filename': file.original_filename,
                'description': file.description or "Custom CNC Creation",
                'size': file.file_size,
                'upload_date': file.upload_timestamp.isoformat(),
                'download_url': download_url,
                'screenshot_url': file.get_screenshot_url(),
                'tags': file.tags.split(',') if file.tags else [],
                'view_count': file.view_count,
                'is_featured': file.is_featured,
                'is_partial': file.is_partial,
                'parent_file_id': file.parent_file_id
            })
        
        return jsonify({'projects': projects})
        
    except Exception as e:
        logger.error(f"Error getting past projects: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@pixie_bp.route('/api/download/stl/<file_id>', methods=['GET'])
def pixie_api_download_stl(file_id):
    """Public API: Download STL file for Pixie viewer"""
    try:
        stl_file = STLFile.query.get_or_404(file_id)
        
        if not stl_file.local_path or not os.path.exists(stl_file.local_path):
            return jsonify({'error': 'File not found'}), 404
        
        return send_file(
            stl_file.local_path,
            as_attachment=False,  # Allow inline viewing for STL viewer
            download_name=stl_file.original_filename,
            mimetype='application/octet-stream'
        )
        
    except Exception as e:
        logger.error(f"Error downloading STL file: {e}")
        return jsonify({'error': 'File not found'}), 404

@pixie_bp.route('/api/admin/files', methods=['GET'])
@require_oauth2()
def pixie_api_admin_files():
    """OAuth2 Protected: Get all files for admin management"""
    try:
        files = STLFile.query.order_by(STLFile.upload_timestamp.desc()).all()
        
        file_list = []
        for file in files:
            file_list.append({
                'id': file.id,
                'filename': file.original_filename,
                'type': 'stl',  # All files in STLFile table are STL files
                'description': file.description,
                'size': file.file_size,
                'uploadedAt': file.upload_timestamp.isoformat(),
                'uploadedBy': file.uploaded_by or 'Unknown',
                'downloadCount': file.view_count or 0,
                'tags': file.tags.split(',') if file.tags else [],
                'is_featured': file.is_featured,
                'is_partial': file.is_partial,
                'parent_file_id': file.parent_file_id
            })
        
        return jsonify({'files': file_list})
        
    except Exception as e:
        logger.error(f"Error getting admin files: {e}")
        return jsonify({'error': 'Internal server error'}), 500