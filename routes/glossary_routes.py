"""
Public glossary API routes for terms and categories
"""
from flask import Blueprint, request, jsonify
from services.oauth2_service import require_oauth2
from sqlalchemy import or_, desc, asc, func
from functools import wraps
from models import db, Term, Category
from utils.logger import logger

glossary_bp = Blueprint('glossary', __name__)

@glossary_bp.route('/terms')
def api_terms():
    """Get terms with filtering and search"""
    try:
        query = request.args.get('search', '').strip()
        category_slug = request.args.get('category', '').strip()
        difficulty = request.args.get('difficulty', '').strip()
        
        # Remove limit entirely - get all terms
        limit_param = request.args.get('limit', type=int)
        if limit_param and limit_param > 0:
            limit = min(limit_param, 2000)  # Cap at 2000 for safety
        else:
            limit = None  # No limit
        
        # Build query
        terms_query = Term.query.join(Category).filter(
            Term.is_active == True,
            Category.is_active == True
        )
        
        if query:
            search_filter = or_(
                Term.term.ilike(f'%{query}%'),
                Term.definition.ilike(f'%{query}%')
            )
            terms_query = terms_query.filter(search_filter)
        
        if category_slug:
            terms_query = terms_query.filter(Category.slug == category_slug)
        
        if difficulty and difficulty in ['tourist', 'local', 'expert']:
            terms_query = terms_query.filter(Term.difficulty == difficulty)
        
        # Determine sort order
        sort_param = request.args.get('sort', 'term')
        order_param = request.args.get('order', 'asc')
        
        if sort_param == 'term':
            sort_column = Term.term
        elif sort_param == 'category':
            sort_column = Category.name
        elif sort_param == 'difficulty':
            sort_column = Term.difficulty
        elif sort_param == 'view_count':
            sort_column = Term.view_count
        elif sort_param == 'created_at':
            sort_column = Term.created_at
        else:
            sort_column = Term.term
        
        if order_param == 'desc':
            sort_column = desc(sort_column)
        else:
            sort_column = asc(sort_column)
        
        terms_query = terms_query.order_by(sort_column)
        
        # Apply limit if specified
        if limit:
            terms = terms_query.limit(limit).all()
        else:
            terms = terms_query.all()
        
        # Convert to dictionaries
        terms_data = [term.to_dict() for term in terms]
        
        return jsonify({
            'terms': terms_data,
            'count': len(terms_data),
            'search': query,
            'category': category_slug,
            'difficulty': difficulty
        })
        
    except Exception as e:
        logger.error(f"Error fetching terms: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@glossary_bp.route('/categories')
def api_categories():
    """Get all active categories"""
    try:
        categories = Category.query.filter_by(is_active=True).order_by(Category.sort_order, Category.name).all()
        categories_data = [category.to_dict() for category in categories]
        
        return jsonify({
            'categories': categories_data,
            'count': len(categories_data)
        })
        
    except Exception as e:
        logger.error(f"Error fetching categories: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@glossary_bp.route('/terms/<slug>')
def api_term_detail(slug):
    """Get a specific term by slug"""
    try:
        term = Term.query.filter_by(slug=slug, is_active=True).first()
        
        if not term:
            return jsonify({'error': 'Term not found'}), 404
        
        # Increment view count
        term.view_count = (term.view_count or 0) + 1
        db.session.commit()
        
        # Get term data with related terms
        term_data = term.to_dict(include_related=True)
        
        return jsonify({'term': term_data})
        
    except Exception as e:
        logger.error(f"Error fetching term {slug}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@glossary_bp.route('/search')
def api_search():
    """Enhanced search endpoint with suggestions"""
    try:
        query = request.args.get('q', '').strip()
        
        if not query:
            return jsonify({'results': [], 'suggestions': []})
        
        # Search terms
        terms = Term.query.join(Category).filter(
            Term.is_active == True,
            Category.is_active == True,
            or_(
                Term.term.ilike(f'%{query}%'),
                Term.definition.ilike(f'%{query}%'),
                Term.etymology.ilike(f'%{query}%')
            )
        ).order_by(
            # Prioritize exact matches in term name
            func.case((Term.term.ilike(query), 1), else_=2),
            Term.view_count.desc()
        ).limit(20).all()
        
        results = [term.to_dict() for term in terms]
        
        # Generate search suggestions
        suggestions = []
        if len(results) < 5:
            suggestion_terms = Term.query.filter(
                Term.is_active == True,
                Term.term.ilike(f'{query}%')
            ).order_by(Term.view_count.desc()).limit(5).all()
            
            suggestions = [term.term for term in suggestion_terms if term.term.lower() != query.lower()]
        
        return jsonify({
            'results': results,
            'suggestions': suggestions[:5],
            'query': query,
            'total': len(results)
        })
        
    except Exception as e:
        logger.error(f"Error in search: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# === ADMIN GLOSSARY ROUTES ===

def admin_required(f):
    """Decorator for admin-only routes"""
    @wraps(f)
    @require_oauth2
    def decorated_function(*args, **kwargs):
        # OAuth2 user has admin access - no additional checks needed
        return f(*args, **kwargs)
    return decorated_function

@glossary_bp.route('/dashboard')
@admin_required
def dashboard():
    """Glossary admin dashboard (placeholder)"""
    try:
        stats = {
            'total_terms': Term.query.filter_by(is_active=True).count(),
            'total_categories': Category.query.filter_by(is_active=True).count(),
            'inactive_terms': Term.query.filter_by(is_active=False).count(),
            'inactive_categories': Category.query.filter_by(is_active=False).count()
        }
        return render_template('admin/glossary_dashboard.html', stats=stats)
    except Exception as e:
        logger.error(f"Error loading glossary dashboard: {e}")
        flash('Error loading glossary dashboard', 'error')
        return redirect(url_for('admin.dashboard'))

@glossary_bp.route('/terms-list')
@admin_required  
def terms_list():
    """Admin terms list (placeholder)"""
    try:
        terms = Term.query.join(Category).order_by(Term.term).all()
        return render_template('admin/terms_list.html', terms=terms)
    except Exception as e:
        logger.error(f"Error loading terms list: {e}")
        flash('Error loading terms', 'error')
        return redirect(url_for('glossary.dashboard'))

@glossary_bp.route('/categories-list')
@admin_required  
def categories_list():
    """Admin categories list"""
    try:
        categories = Category.query.order_by(Category.sort_order, Category.name).all()
        return render_template('admin/categories_list.html', categories=categories)
    except Exception as e:
        logger.error(f"Error loading categories list: {e}")
        flash('Error loading categories', 'error')
        return redirect(url_for('glossary.dashboard'))