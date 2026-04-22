"""
Main API routes for CRUD operations
"""
from flask import Blueprint, request, jsonify, g, send_file
from datetime import datetime
import re
import os
from models import db, Term, Category, STLFile, VideoFile
from services.oauth2_service import require_oauth2
from utils.logger import logger

api_bp = Blueprint('api', __name__)

@api_bp.route('/health')
def health_check():
    """API health check endpoint"""
    return jsonify({
        'status': 'ok',
        'service': 'mardi-gras-api',
        'version': '2.0.0'
    })

# === TERMS API ENDPOINTS ===

@api_bp.route('/terms', methods=['GET'])
@require_oauth2()
def get_terms():
    """Get all terms with filtering"""
    try:
        # Parse query parameters
        search = request.args.get('search', '')
        category_id = request.args.get('category_id', type=int)
        difficulty = request.args.get('difficulty', '')
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        
        # Build query
        query = Term.query.filter_by(is_active=True)
        
        if search:
            query = query.filter(
                (Term.term.ilike(f'%{search}%')) | 
                (Term.definition.ilike(f'%{search}%'))
            )
        
        if category_id:
            query = query.filter_by(category_id=category_id)
        
        if difficulty and difficulty in ['tourist', 'local', 'expert']:
            query = query.filter_by(difficulty=difficulty)
        
        # Paginate results
        terms = query.order_by(Term.term).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'terms': [term.to_dict() for term in terms.items],
            'pagination': {
                'page': page,
                'pages': terms.pages,
                'per_page': per_page,
                'total': terms.total
            }
        })
        
    except Exception as e:
        logger.error(f"Error fetching terms: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/terms/<int:term_id>', methods=['GET'])
@require_oauth2()
def get_term(term_id):
    """Get a specific term"""
    try:
        term = Term.query.filter_by(id=term_id, is_active=True).first()
        if not term:
            return jsonify({'error': 'Term not found'}), 404
        
        return jsonify({'term': term.to_dict(include_related=True)})
        
    except Exception as e:
        logger.error(f"Error fetching term {term_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/terms', methods=['POST'])
@require_oauth2()
def create_term():
    """Create a new term"""
    try:
        # API tokens have full access - no additional permission check needed
        # In the future, you could add app-level permissions here
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate required fields
        required_fields = ['term', 'definition', 'category_id']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Create slug
        import re
        slug = re.sub(r'[^\\w\\s-]', '', data['term'].lower())
        slug = re.sub(r'[-\\s]+', '-', slug)
        
        # Check if term already exists
        existing = Term.query.filter(
            (Term.term.ilike(data['term'])) | (Term.slug == slug)
        ).first()
        
        if existing:
            return jsonify({'error': 'Term already exists'}), 409
        
        # Create new term
        term = Term(
            term=data['term'],
            slug=slug,
            pronunciation=data.get('pronunciation', ''),  # Required field
            definition=data['definition'],
            category_id=data['category_id'],
            difficulty=data.get('difficulty', 'tourist'),
            etymology=data.get('etymology')
        )
        
        db.session.add(term)
        db.session.commit()
        
        return jsonify({
            'message': 'Term created successfully',
            'term': term.to_dict()
        }), 201
        
    except Exception as e:
        logger.error(f"Error creating term: {e}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/terms/<int:term_id>', methods=['PUT'])
@require_oauth2()
def update_term(term_id):
    """Update an existing term"""
    try:
        
        term = Term.query.get_or_404(term_id)
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Update fields if provided
        if 'term' in data:
            # Create new slug if term name changed
            import re
            slug = re.sub(r'[^\\w\\s-]', '', data['term'].lower())
            slug = re.sub(r'[-\\s]+', '-', slug)
            
            # Check if new term name conflicts
            existing = Term.query.filter(
                Term.id != term_id,
                (Term.term.ilike(data['term'])) | (Term.slug == slug)
            ).first()
            
            if existing:
                return jsonify({'error': 'Term name already exists'}), 409
            
            term.term = data['term']
            term.slug = slug
        
        if 'definition' in data:
            term.definition = data['definition']
        
        if 'category_id' in data:
            term.category_id = data['category_id']
        
        if 'difficulty' in data:
            term.difficulty = data['difficulty']
        
        if 'etymology' in data:
            term.etymology = data['etymology']
        
        if 'pronunciation' in data:
            term.pronunciation = data['pronunciation']
        
        term.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'message': 'Term updated successfully',
            'term': term.to_dict()
        })
        
    except Exception as e:
        logger.error(f"Error updating term {term_id}: {e}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/terms/<int:term_id>', methods=['DELETE'])
@require_oauth2()
def delete_term(term_id):
    """Delete (deactivate) a term"""
    try:
        
        term = Term.query.get_or_404(term_id)
        
        # Soft delete
        term.is_active = False
        term.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({'message': 'Term deleted successfully'})
        
    except Exception as e:
        logger.error(f"Error deleting term {term_id}: {e}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

# === CATEGORIES API ENDPOINTS ===

@api_bp.route('/categories', methods=['GET'])
@require_oauth2()
def get_categories():
    """Get all categories"""
    try:
        categories = Category.query.filter_by(is_active=True).order_by(
            Category.sort_order, Category.name
        ).all()
        
        return jsonify({
            'categories': [category.to_dict() for category in categories]
        })
        
    except Exception as e:
        logger.error(f"Error fetching categories: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/categories', methods=['POST'])
@require_oauth2()
def create_category():
    """Create a new category"""
    try:
        
        data = request.get_json()
        if not data or not data.get('name'):
            return jsonify({'error': 'Category name is required'}), 400
        
        # Create slug
        import re
        slug = re.sub(r'[^\\w\\s-]', '', data['name'].lower())
        slug = re.sub(r'[-\\s]+', '-', slug)
        
        # Check if category already exists
        existing = Category.query.filter(
            (Category.name.ilike(data['name'])) | (Category.slug == slug)
        ).first()
        
        if existing:
            return jsonify({'error': 'Category already exists'}), 409
        
        # Create new category
        category = Category(
            name=data['name'],
            slug=slug,
            description=data.get('description'),
            sort_order=data.get('sort_order', 0)
        )
        
        db.session.add(category)
        db.session.commit()
        
        return jsonify({
            'message': 'Category created successfully',
            'category': category.to_dict()
        }), 201
        
    except Exception as e:
        logger.error(f"Error creating category: {e}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

# === FILE UPLOAD API ENDPOINTS ===

@api_bp.route('/files/upload', methods=['POST'])
@require_oauth2()
def upload_file():
    """Upload a file (STL or video) via JSON API"""
    try:
        # Check if a file was uploaded
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Get file metadata
        description = request.form.get('description', '').strip()
        tags_json = request.form.get('tags', '[]')
        
        # Parse tags from JSON string
        import json
        try:
            tags_list = json.loads(tags_json) if tags_json else []
        except json.JSONDecodeError:
            tags_list = []
        
        # Convert tags list to comma-separated string for database
        tags = ','.join(tags_list) if tags_list else None
        
        # Determine file type based on extension
        filename_lower = file.filename.lower()
        
        if filename_lower.endswith('.stl'):
            # Handle STL file upload
            try:
                return _upload_stl_file(file, description, tags)
            except ValueError as e:
                logger.warning(f"File upload validation failed: {e}")
                return jsonify({'error': 'Invalid file upload request'}), 400
        elif any(filename_lower.endswith(ext) for ext in ['.mp4', '.mov', '.avi', '.mkv', '.webm']):
            # Handle video file upload  
            try:
                return _upload_video_file(file, description, tags)
            except ValueError as e:
                logger.warning(f"File upload validation failed: {e}")
                return jsonify({'error': 'Invalid file upload request'}), 400
        else:
            return jsonify({'error': 'Unsupported file type. Only STL and video files are allowed.'}), 400
            
    except Exception as e:
        logger.error(f"Error in file upload: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': 'Upload failed due to server error'}), 500

def _upload_stl_file(file, description, tags):
    """Helper function to upload STL file"""
    import uuid
    import hashlib
    import re
    from werkzeug.utils import secure_filename
    from models import STLFile
    
    filename = secure_filename(file.filename)
    if not filename:
        raise ValueError("Invalid filename")
        
    unique_id = str(uuid.uuid4())
    # Validate UUID format to prevent path traversal
    if not re.match(r'^[a-f0-9-]{36}$', unique_id):
        raise ValueError("Invalid UUID generated")
    
    # Create upload directory with absolute path and validation
    base_dir = os.path.dirname(os.path.abspath(__file__ + '/../'))
    upload_dir = os.path.join(base_dir, 'uploads', 'stl', unique_id)
    upload_dir = os.path.realpath(upload_dir)
    
    # Ensure the upload directory is within the expected base path
    expected_base = os.path.realpath(os.path.join(base_dir, 'uploads', 'stl'))
    if not upload_dir.startswith(expected_base):
        raise ValueError("Path traversal attempt detected")
        
    os.makedirs(upload_dir, exist_ok=True)
    
    # Save file with additional path validation
    file_path = os.path.join(upload_dir, filename)
    file_path = os.path.realpath(file_path)
    if not file_path.startswith(upload_dir):
        raise ValueError("Invalid file path")
        
    file.save(file_path)
    
    # Validate file type and size
    from utils.file_validation import FileValidator
    
    # Size validation (max 50MB for STL files)
    size_validation = FileValidator.validate_file_size(file_path, max_size_mb=50)
    if not size_validation['valid']:
        os.remove(file_path)
        os.rmdir(upload_dir)
        raise ValueError(size_validation['error'])
    
    # File type validation
    type_validation = FileValidator.validate_file_type(file_path, 'stl', filename)
    if not type_validation['valid']:
        os.remove(file_path)
        os.rmdir(upload_dir)
        raise ValueError(f"Invalid STL file: {type_validation['error']}")
    
    # Calculate file hash for duplicate detection
    def calculate_file_hash(file_path):
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    file_hash = calculate_file_hash(file_path)
    file_size = os.path.getsize(file_path)
    
    # Check for duplicate files
    content_duplicate = STLFile.query.filter_by(file_hash=file_hash).first()
    if content_duplicate:
        # Remove the uploaded file since it's a duplicate
        os.remove(file_path)
        try:
            os.rmdir(upload_dir)
        except OSError:
            pass
        return jsonify({
            'error': f'File "{filename}" is a duplicate of existing file "{content_duplicate.original_filename}" (uploaded {content_duplicate.upload_timestamp.strftime("%Y-%m-%d")})'
        }), 409
    
    # Create database record
    stl_file = STLFile(
        original_filename=filename,
        local_path=file_path,
        file_size=file_size,
        file_hash=file_hash,
        uploaded_by=request.oauth2_user.get('email', 'unknown@admin.com'),
        upload_timestamp=datetime.utcnow(),
        description=description if description else None,
        tags=tags,
        is_partial=False,
        parent_file_id=None
    )
    
    db.session.add(stl_file)
    db.session.commit()
    
    return jsonify({
        'message': f'STL file "{filename}" uploaded successfully',
        'file': {
            'id': stl_file.id,
            'filename': stl_file.original_filename,
            'type': 'stl',
            'size': stl_file.file_size,
            'uploadedAt': stl_file.upload_timestamp.isoformat(),
            'uploadedBy': request.oauth2_user.get('email', 'unknown@admin.com'),
            'downloadCount': 0,
            'description': stl_file.description,
            'tags': stl_file.tags.split(',') if stl_file.tags else []
        }
    }), 201

def _upload_video_file(file, description, tags):
    """Helper function to upload video file"""
    import uuid
    import re
    from werkzeug.utils import secure_filename
    from models import VideoFile
    
    filename = secure_filename(file.filename)
    if not filename:
        raise ValueError("Invalid filename")
        
    unique_id = str(uuid.uuid4())
    # Validate UUID format to prevent path traversal
    if not re.match(r'^[a-f0-9-]{36}$', unique_id):
        raise ValueError("Invalid UUID generated")
    
    # Create upload directory with absolute path and validation
    base_dir = os.path.dirname(os.path.abspath(__file__ + '/../'))
    upload_dir = os.path.join(base_dir, 'uploads', 'video', unique_id)
    upload_dir = os.path.realpath(upload_dir)
    
    # Ensure the upload directory is within the expected base path
    expected_base = os.path.realpath(os.path.join(base_dir, 'uploads', 'video'))
    if not upload_dir.startswith(expected_base):
        raise ValueError("Path traversal attempt detected")
        
    os.makedirs(upload_dir, exist_ok=True)
    
    # Save file with additional path validation
    file_path = os.path.join(upload_dir, filename)
    file_path = os.path.realpath(file_path)
    if not file_path.startswith(upload_dir):
        raise ValueError("Invalid file path")
        
    file.save(file_path)
    
    # Validate file type and size
    from utils.file_validation import FileValidator
    
    # Size validation (max 200MB for video files)
    size_validation = FileValidator.validate_file_size(file_path, max_size_mb=200)
    if not size_validation['valid']:
        os.remove(file_path)
        os.rmdir(upload_dir)
        raise ValueError(size_validation['error'])
    
    # File type validation
    type_validation = FileValidator.validate_file_type(file_path, 'video', filename)
    if not type_validation['valid']:
        os.remove(file_path)
        os.rmdir(upload_dir)
        raise ValueError(f"Invalid video file: {type_validation['error']}")
    
    # Create database record
    video_file = VideoFile(
        original_filename=filename,
        local_path=file_path,
        file_size=os.path.getsize(file_path),
        uploaded_by=request.oauth2_user.get('email', 'unknown@admin.com'),
        upload_timestamp=datetime.utcnow(),
        description=description if description else None,
        associated_stl_id=None  # Could be enhanced later to link to STL files
    )
    
    db.session.add(video_file)
    db.session.commit()
    
    return jsonify({
        'message': f'Video file "{filename}" uploaded successfully',
        'file': {
            'id': video_file.id,
            'filename': video_file.original_filename,
            'type': 'video',
            'size': video_file.file_size,
            'uploadedAt': video_file.upload_timestamp.isoformat(),
            'uploadedBy': request.oauth2_user.get('email', 'unknown@admin.com'), 
            'downloadCount': 0,
            'description': video_file.description,
            'tags': tags.split(',') if tags else []
        }
    }), 201

@api_bp.route('/files/<file_id>/download', methods=['GET'])
@require_oauth2()
def download_file(file_id):
    """Download a file (STL or video) via unified endpoint"""
    try:
        # Get the file type from query parameter (if provided)
        file_type = request.args.get('type', '').lower()
        
        # If type is specified, query the appropriate table directly
        if file_type == 'stl':
            stl_file = STLFile.query.get(file_id)
            if stl_file:
                if not stl_file.local_path or not os.path.exists(stl_file.local_path):
                    return jsonify({'error': 'File not found on disk'}), 404
                
                # Update download count for STL files
                stl_file.view_count = (stl_file.view_count or 0) + 1
                db.session.commit()
                
                return send_file(
                    stl_file.local_path,
                    as_attachment=True,
                    download_name=stl_file.original_filename,
                    mimetype='application/octet-stream'
                )
            else:
                return jsonify({'error': 'STL file not found'}), 404
                
        elif file_type == 'video':
            video_file = VideoFile.query.get(file_id)
            if video_file:
                if not video_file.local_path or not os.path.exists(video_file.local_path):
                    return jsonify({'error': 'File not found on disk'}), 404
                
                return send_file(
                    video_file.local_path,
                    as_attachment=True,
                    download_name=video_file.original_filename,
                    mimetype='application/octet-stream'
                )
            else:
                return jsonify({'error': 'Video file not found'}), 404
        
        else:
            # No type specified or invalid type - fallback to old behavior (STL first, then video)
            # This maintains backward compatibility
            stl_file = STLFile.query.get(file_id)
            if stl_file:
                if not stl_file.local_path or not os.path.exists(stl_file.local_path):
                    return jsonify({'error': 'File not found on disk'}), 404
                
                # Update download count for STL files
                stl_file.view_count = (stl_file.view_count or 0) + 1
                db.session.commit()
                
                return send_file(
                    stl_file.local_path,
                    as_attachment=True,
                    download_name=stl_file.original_filename,
                    mimetype='application/octet-stream'
                )
            
            # If not found as STL, try as video file
            video_file = VideoFile.query.get(file_id)
            if video_file:
                if not video_file.local_path or not os.path.exists(video_file.local_path):
                    return jsonify({'error': 'File not found on disk'}), 404
                
                return send_file(
                    video_file.local_path,
                    as_attachment=True,
                    download_name=video_file.original_filename,
                    mimetype='application/octet-stream'
                )
            
            # File not found in either table
            return jsonify({'error': 'File not found'}), 404
        
    except Exception as e:
        logger.error(f"Error downloading file {file_id}: {e}")
        return jsonify({'error': 'Download failed'}), 500

@api_bp.route('/files/stats', methods=['GET'])
@require_oauth2()
def get_file_stats():
    """Get file statistics"""
    try:
        stl_files_count = STLFile.query.count()
        video_files_count = VideoFile.query.count()
        featured_files_count = STLFile.query.filter_by(is_featured=True).count()
        total_files = stl_files_count + video_files_count
        
        return jsonify({
            'stl_files': stl_files_count,
            'video_files': video_files_count,
            'total_files': total_files,
            'total_file_uploads': total_files,
            'featured_files': featured_files_count
        })
        
    except Exception as e:
        logger.error(f"Error getting file stats: {e}")
        return jsonify({'error': 'Internal server error'}), 500