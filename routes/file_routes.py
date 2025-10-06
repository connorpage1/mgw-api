"""
File management routes for STL and video uploads
"""
from flask import Blueprint, request, jsonify, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity
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

# Additional file routes would be implemented here
# For brevity, including just basic file serving
# The full implementation would include:
# - File upload handling
# - File deletion
# - Bulk operations
# - S3 integration
# - etc.