"""
Main API routes for CRUD operations
"""
from flask import Blueprint, request, jsonify, g
from datetime import datetime
import re
from models import db, Term, Category, STLFile
from services.api_auth_service import api_token_required
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
@api_token_required
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
@api_token_required
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
@api_token_required
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
@api_token_required
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
@api_token_required
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
@api_token_required
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
@api_token_required
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