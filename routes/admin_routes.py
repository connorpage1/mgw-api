"""
Admin interface routes for managing the application
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_required, current_user, logout_user
from functools import wraps
from datetime import datetime
import re
import json
from models import db, User, Category, Term, STLFile, VideoFile, Role, App, AppToken
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
            logger.info(f"Total STL files: {stats['total_files']}")
        except Exception as e:
            logger.error(f"Error querying STL files: {e}")
            stats['total_files'] = 0
            
        try:
            stats['total_video_files'] = VideoFile.query.count()
            logger.info(f"Total video files: {stats['total_video_files']}")
        except Exception as e:
            logger.error(f"Error querying video files: {e}")
            stats['total_video_files'] = 0
            
        try:
            stats['total_apps'] = App.query.filter_by(active=True).count()
            logger.info(f"Total apps: {stats['total_apps']}")
        except Exception as e:
            logger.error(f"Error querying apps: {e}")
            stats['total_apps'] = 0
            
        try:
            stats['total_tokens'] = AppToken.query.filter_by(active=True).count()
            logger.info(f"Total active tokens: {stats['total_tokens']}")
        except Exception as e:
            logger.error(f"Error querying tokens: {e}")
            stats['total_tokens'] = 0
        
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
        users = User.query.filter_by(active=True).all()
        return render_template('admin/users_list.html', users=users)
    except Exception as e:
        logger.error(f"Error loading users list: {e}")
        flash('Error loading users', 'error')
        return redirect(url_for('admin.dashboard'))

@admin_bp.route('/apps')
@superadmin_required  
def apps_list():
    """App management"""
    try:
        apps = App.query.order_by(App.created_at.desc()).all()
        return render_template('admin/apps_list.html', apps=apps)
    except Exception as e:
        logger.error(f"Error loading apps: {e}")
        flash('Error loading apps', 'error')
        return redirect(url_for('admin.dashboard'))

@admin_bp.route('/tokens')
@superadmin_required  
def tokens():
    """API Token management"""
    try:
        tokens = AppToken.query.join(App).order_by(AppToken.created_at.desc()).all()
        return render_template('admin/tokens.html', tokens=tokens)
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

# === GLOSSARY MANAGEMENT ROUTES ===

@admin_bp.route('/glossary/dashboard')
@admin_required
def glossary_dashboard():
    """Glossary admin dashboard"""
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

@admin_bp.route('/glossary/terms')
@admin_required
def glossary_terms():
    """Admin terms list"""
    try:
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        search = request.args.get('search', '')
        category_id = request.args.get('category', type=int)
        show_inactive = request.args.get('show_inactive', 0, type=int)
        sort = request.args.get('sort', 'term')
        order = request.args.get('order', 'asc')
        
        # Build query
        query = Term.query.join(Category)
        
        # Filter by search
        if search:
            query = query.filter(Term.term.ilike(f'%{search}%'))
        
        # Filter by category
        if category_id:
            query = query.filter(Term.category_id == category_id)
        
        # Filter by active status
        if not show_inactive:
            query = query.filter(Term.is_active == True)
        
        # Apply sorting
        if sort == 'term':
            query = query.order_by(Term.term.desc() if order == 'desc' else Term.term.asc())
        elif sort == 'category':
            query = query.order_by(Category.name.desc() if order == 'desc' else Category.name.asc())
        elif sort == 'difficulty':
            query = query.order_by(Term.difficulty.desc() if order == 'desc' else Term.difficulty.asc())
        elif sort == 'views':
            query = query.order_by(Term.view_count.desc() if order == 'desc' else Term.view_count.asc())
        elif sort == 'status':
            query = query.order_by(Term.is_active.desc() if order == 'desc' else Term.is_active.asc())
        else:
            query = query.order_by(Term.term.asc())
        
        # Paginate
        terms = query.paginate(page=page, per_page=20, error_out=False)
        
        # Get categories for filter dropdown
        categories = Category.query.filter_by(is_active=True).order_by(Category.name).all()
        
        return render_template('admin/terms_list.html', 
                             terms=terms, 
                             categories=categories,
                             search=search,
                             category_id=category_id,
                             show_inactive=show_inactive,
                             sort=sort,
                             order=order)
    except Exception as e:
        logger.error(f"Error loading terms list: {e}")
        flash('Error loading terms', 'error')
        return redirect(url_for('admin.glossary_dashboard'))

@admin_bp.route('/glossary/terms/new', methods=['GET', 'POST'])
@admin_required
def new_term():
    """Create new term"""
    if request.method == 'GET':
        categories = Category.query.filter_by(is_active=True).order_by(Category.name).all()
        return render_template('admin/term_form.html', categories=categories, term=None)
    
    try:
        # Handle POST request - create new term
        term_text = request.form.get('term', '').strip()
        pronunciation = request.form.get('pronunciation', '').strip()
        definition = request.form.get('definition', '').strip()
        category_id = request.form.get('category_id')
        difficulty = request.form.get('difficulty', 'tourist')
        etymology = request.form.get('etymology', '').strip()
        example = request.form.get('example', '').strip()
        is_featured = request.form.get('is_featured') == 'on'
        
        if not term_text or not pronunciation or not definition or not category_id:
            flash('Term, pronunciation, definition, and category are required', 'error')
            categories = Category.query.filter_by(is_active=True).order_by(Category.name).all()
            return render_template('admin/term_form.html', categories=categories, term=None)
        
        # Create slug from term
        slug = re.sub(r'[^\w\s-]', '', term_text.lower())
        slug = re.sub(r'[-\s]+', '-', slug)
        
        # Check if term or slug already exists
        existing = Term.query.filter(
            (Term.term.ilike(term_text)) | (Term.slug == slug)
        ).first()
        
        if existing:
            flash('A term with this name already exists', 'error')
            categories = Category.query.filter_by(is_active=True).order_by(Category.name).all()
            return render_template('admin/term_form.html', categories=categories, term=None)
        
        # Create new term
        new_term = Term(
            term=term_text,
            slug=slug,
            pronunciation=pronunciation,
            definition=definition,
            category_id=int(category_id),
            difficulty=difficulty,
            etymology=etymology if etymology else None,
            example=example if example else None,
            is_featured=is_featured
        )
        
        db.session.add(new_term)
        db.session.commit()
        
        flash(f'Term "{term_text}" created successfully', 'success')
        return redirect(url_for('admin.glossary_terms'))
        
    except Exception as e:
        logger.error(f"Error creating term: {e}")
        db.session.rollback()
        flash('Error creating term', 'error')
        categories = Category.query.filter_by(is_active=True).order_by(Category.name).all()
        return render_template('admin/term_form.html', categories=categories, term=None)

@admin_bp.route('/glossary/terms/<int:term_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_term(term_id):
    """Edit existing term"""
    term = Term.query.get_or_404(term_id)
    
    if request.method == 'GET':
        categories = Category.query.filter_by(is_active=True).order_by(Category.name).all()
        return render_template('admin/term_form.html', categories=categories, term=term)
    
    try:
        # Handle POST request - update term
        term_text = request.form.get('term', '').strip()
        definition = request.form.get('definition', '').strip()
        category_id = request.form.get('category_id')
        difficulty = request.form.get('difficulty', 'tourist')
        etymology = request.form.get('etymology', '').strip()
        
        if not term_text or not definition or not category_id:
            flash('Term, definition, and category are required', 'error')
            categories = Category.query.filter_by(is_active=True).order_by(Category.name).all()
            return render_template('admin/term_form.html', categories=categories, term=term)
        
        # Create slug from term
        slug = re.sub(r'[^\w\s-]', '', term_text.lower())
        slug = re.sub(r'[-\s]+', '-', slug)
        
        # Check if term or slug already exists (excluding current term)
        existing = Term.query.filter(
            Term.id != term_id,
            (Term.term.ilike(term_text)) | (Term.slug == slug)
        ).first()
        
        if existing:
            flash('A term with this name already exists', 'error')
            categories = Category.query.filter_by(is_active=True).order_by(Category.name).all()
            return render_template('admin/term_form.html', categories=categories, term=term)
        
        # Update term
        term.term = term_text
        term.slug = slug
        term.definition = definition
        term.category_id = int(category_id)
        term.difficulty = difficulty
        term.etymology = etymology if etymology else None
        term.updated_by = current_user.id
        term.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        flash(f'Term "{term_text}" updated successfully', 'success')
        return redirect(url_for('admin.glossary_terms'))
        
    except Exception as e:
        logger.error(f"Error updating term: {e}")
        db.session.rollback()
        flash('Error updating term', 'error')
        categories = Category.query.filter_by(is_active=True).order_by(Category.name).all()
        return render_template('admin/term_form.html', categories=categories, term=term)

@admin_bp.route('/glossary/terms/<int:term_id>/delete', methods=['POST'])
@admin_required
def delete_term(term_id):
    """Delete (deactivate) term"""
    try:
        term = Term.query.get_or_404(term_id)
        term.is_active = False
        term.updated_by = current_user.id
        term.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        flash(f'Term "{term.term}" deleted successfully', 'success')
        return redirect(url_for('admin.glossary_terms'))
        
    except Exception as e:
        logger.error(f"Error deleting term: {e}")
        db.session.rollback()
        flash('Error deleting term', 'error')
        return redirect(url_for('admin.glossary_terms'))

@admin_bp.route('/glossary/categories')
@admin_required
def glossary_categories():
    """Admin categories list"""
    try:
        categories = Category.query.order_by(Category.sort_order, Category.name).all()
        return render_template('admin/categories_list.html', categories=categories)
    except Exception as e:
        logger.error(f"Error loading categories list: {e}")
        flash('Error loading categories', 'error')
        return redirect(url_for('admin.glossary_dashboard'))

@admin_bp.route('/glossary/categories/new', methods=['GET', 'POST'])
@admin_required
def new_category():
    """Create new category"""
    if request.method == 'GET':
        return render_template('admin/category_form.html', category=None)
    
    try:
        # Handle POST request - create new category
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        sort_order = request.form.get('sort_order', 0, type=int)
        is_active = '1' in request.form.getlist('is_active')
        
        if not name:
            flash('Category name is required', 'error')
            return render_template('admin/category_form.html', category=None)
        
        # Create slug from name
        slug = re.sub(r'[^\w\s-]', '', name.lower())
        slug = re.sub(r'[-\s]+', '-', slug)
        
        # Check if category or slug already exists
        existing = Category.query.filter(
            (Category.name.ilike(name)) | (Category.slug == slug)
        ).first()
        
        if existing:
            flash('A category with this name already exists', 'error')
            return render_template('admin/category_form.html', category=None)
        
        # Create new category
        new_category = Category(
            name=name,
            slug=slug,
            description=description if description else None,
            sort_order=sort_order,
            is_active=is_active
        )
        
        db.session.add(new_category)
        db.session.commit()
        
        flash(f'Category "{name}" created successfully', 'success')
        return redirect(url_for('admin.glossary_categories'))
        
    except Exception as e:
        logger.error(f"Error creating category: {e}")
        db.session.rollback()
        flash('Error creating category', 'error')
        return render_template('admin/category_form.html', category=None)

@admin_bp.route('/glossary/categories/<int:category_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_category(category_id):
    """Edit existing category"""
    category = Category.query.get_or_404(category_id)
    
    if request.method == 'GET':
        return render_template('admin/category_form.html', category=category)
    
    try:
        # Handle POST request - update category
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        sort_order = request.form.get('sort_order', 0, type=int)
        is_active = '1' in request.form.getlist('is_active')
        
        if not name:
            flash('Category name is required', 'error')
            return render_template('admin/category_form.html', category=category)
        
        # Create slug from name
        slug = re.sub(r'[^\w\s-]', '', name.lower())
        slug = re.sub(r'[-\s]+', '-', slug)
        
        # Check if category or slug already exists (excluding current category)
        existing = Category.query.filter(
            Category.id != category_id,
            (Category.name.ilike(name)) | (Category.slug == slug)
        ).first()
        
        if existing:
            flash('A category with this name already exists', 'error')
            return render_template('admin/category_form.html', category=category)
        
        # Update category
        category.name = name
        category.slug = slug
        category.description = description if description else None
        category.sort_order = sort_order
        category.is_active = is_active
        
        db.session.commit()
        
        flash(f'Category "{name}" updated successfully', 'success')
        return redirect(url_for('admin.glossary_categories'))
        
    except Exception as e:
        logger.error(f"Error updating category: {e}")
        db.session.rollback()
        flash('Error updating category', 'error')
        return render_template('admin/category_form.html', category=category)

@admin_bp.route('/glossary/categories/<int:category_id>/delete', methods=['POST'])
@admin_required
def delete_category(category_id):
    """Delete (deactivate) category"""
    try:
        category = Category.query.get_or_404(category_id)
        
        # Check if category has active terms
        active_terms = Term.query.filter_by(category_id=category_id, is_active=True).count()
        if active_terms > 0:
            flash(f'Cannot delete category "{category.name}" - it has {active_terms} active terms', 'error')
            return redirect(url_for('admin.glossary_categories'))
        
        category.is_active = False
        
        db.session.commit()
        
        flash(f'Category "{category.name}" deleted successfully', 'success')
        return redirect(url_for('admin.glossary_categories'))
        
    except Exception as e:
        logger.error(f"Error deleting category: {e}")
        db.session.rollback()
        flash('Error deleting category', 'error')
        return redirect(url_for('admin.glossary_categories'))

@admin_bp.route('/glossary/categories/<int:category_id>/restore', methods=['POST'])
@admin_required
def restore_category(category_id):
    """Restore (reactivate) category"""
    try:
        category = Category.query.get_or_404(category_id)
        category.is_active = True
        
        db.session.commit()
        
        flash(f'Category "{category.name}" restored successfully', 'success')
        return redirect(url_for('admin.glossary_categories'))
        
    except Exception as e:
        logger.error(f"Error restoring category: {e}")
        db.session.rollback()
        flash('Error restoring category', 'error')
        return redirect(url_for('admin.glossary_categories'))

@admin_bp.route('/glossary/bulk-upload', methods=['GET', 'POST'])
@admin_required
def bulk_upload():
    """Bulk upload terms from JSON"""
    if request.method == 'GET':
        return render_template('admin/bulk_upload.html')
    
    try:
        # Handle JSON upload
        json_data = request.form.get('json_data', '').strip()
        
        if not json_data:
            flash('JSON data is required', 'error')
            return render_template('admin/bulk_upload.html')
        
        # Parse JSON
        terms_data = json.loads(json_data)
        
        if not isinstance(terms_data, list):
            flash('JSON data must be an array of term objects', 'error')
            return render_template('admin/bulk_upload.html')
        
        created_count = 0
        skipped_count = 0
        
        for term_data in terms_data:
            try:
                # Validate required fields
                if not all(key in term_data for key in ['term', 'definition', 'category']):
                    skipped_count += 1
                    continue
                
                # Find or create category
                category = Category.query.filter_by(name=term_data['category']).first()
                if not category:
                    # Create new category
                    category_slug = re.sub(r'[^\w\s-]', '', term_data['category'].lower())
                    category_slug = re.sub(r'[-\s]+', '-', category_slug)
                    
                    category = Category(
                        name=term_data['category'],
                        slug=category_slug
                    )
                    db.session.add(category)
                    db.session.flush()  # Get category ID
                
                # Create term slug
                term_slug = re.sub(r'[^\w\s-]', '', term_data['term'].lower())
                term_slug = re.sub(r'[-\s]+', '-', term_slug)
                
                # Check if term already exists
                existing = Term.query.filter(
                    (Term.term.ilike(term_data['term'])) | (Term.slug == term_slug)
                ).first()
                
                if existing:
                    skipped_count += 1
                    continue
                
                # Create new term
                new_term = Term(
                    term=term_data['term'],
                    slug=term_slug,
                    pronunciation=term_data.get('pronunciation', term_data['term']),
                    definition=term_data['definition'],
                    category_id=category.id,
                    difficulty=term_data.get('difficulty', 'tourist'),
                    etymology=term_data.get('etymology')
                )
                
                db.session.add(new_term)
                created_count += 1
                
            except Exception as e:
                logger.error(f"Error processing term {term_data}: {e}")
                skipped_count += 1
                continue
        
        db.session.commit()
        
        flash(f'Bulk upload completed: {created_count} terms created, {skipped_count} skipped', 'success')
        return redirect(url_for('admin.glossary_terms'))
        
    except json.JSONDecodeError:
        flash('Invalid JSON format', 'error')
        return render_template('admin/bulk_upload.html')
    except Exception as e:
        logger.error(f"Error in bulk upload: {e}")
        db.session.rollback()
        flash('Error processing bulk upload', 'error')
        return render_template('admin/bulk_upload.html')

# === USER MANAGEMENT ROUTES ===

@admin_bp.route('/users/new', methods=['GET', 'POST'])
@superadmin_required
def new_user():
    """Create new user"""
    from services.auth_service import secure_hasher
    
    if request.method == 'GET':
        all_roles = Role.query.all()
        return render_template('admin/user_form.html', user=None, all_roles=all_roles)
    
    try:
        # Handle POST request - create new user
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip()
        role_id = request.form.get('role', '')
        password = request.form.get('password', '').strip()
        
        if not all([email, password]):
            flash('Email and password are required', 'error')
            all_roles = Role.query.all()
            return render_template('admin/user_form.html', user=None, all_roles=all_roles)
        
        if not role_id:
            flash('Please select a role', 'error')
            all_roles = Role.query.all()
            return render_template('admin/user_form.html', user=None, all_roles=all_roles)
        
        # Check if user already exists
        existing = User.query.filter_by(email=email).first()
        if existing:
            flash('A user with this email already exists', 'error')
            all_roles = Role.query.all()
            return render_template('admin/user_form.html', user=None, all_roles=all_roles)
        
        # Find the role
        role = Role.query.get(int(role_id))
        if not role:
            flash('Invalid role selected', 'error')
            all_roles = Role.query.all()
            return render_template('admin/user_form.html', user=None, all_roles=all_roles)
        
        # Create new user
        hashed_password = secure_hasher.hash_password(password)
        new_user = User(
            first_name=first_name if first_name else None,
            last_name=last_name if last_name else None,
            email=email,
            password=hashed_password,
            active=True,
            created_at=datetime.utcnow()
        )
        
        # Assign role
        new_user.roles.append(role)
        
        db.session.add(new_user)
        db.session.commit()
        
        user_name = new_user.name or email
        flash(f'User "{user_name}" created successfully', 'success')
        return redirect(url_for('admin.users_list'))
        
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        db.session.rollback()
        flash('Error creating user', 'error')
        all_roles = Role.query.all()
        return render_template('admin/user_form.html', user=None, all_roles=all_roles)

@admin_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@superadmin_required
def edit_user(user_id):
    """Edit existing user"""
    user = User.query.get_or_404(user_id)
    
    if request.method == 'GET':
        all_roles = Role.query.all()
        return render_template('admin/user_form.html', user=user, all_roles=all_roles)
    
    try:
        # Handle POST request - update user
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip()
        role_id = request.form.get('role', '')
        active = request.form.get('active') == 'on'
        
        if not email:
            flash('Email is required', 'error')
            all_roles = Role.query.all()
            return render_template('admin/user_form.html', user=user, all_roles=all_roles)
        
        if not role_id:
            flash('Please select a role', 'error')
            all_roles = Role.query.all()
            return render_template('admin/user_form.html', user=user, all_roles=all_roles)
        
        # Check if email is already taken by another user
        existing = User.query.filter(User.id != user_id, User.email == email).first()
        if existing:
            flash('A user with this email already exists', 'error')
            all_roles = Role.query.all()
            return render_template('admin/user_form.html', user=user, all_roles=all_roles)
        
        # Find the role
        role = Role.query.get(int(role_id))
        if not role:
            flash('Invalid role selected', 'error')
            all_roles = Role.query.all()
            return render_template('admin/user_form.html', user=user, all_roles=all_roles)
        
        # Update user
        user.first_name = first_name if first_name else None
        user.last_name = last_name if last_name else None
        user.email = email
        user.active = active
        
        # Update roles (clear existing and add new)
        user.roles.clear()
        user.roles.append(role)
        
        db.session.commit()
        
        user_name = user.name or email
        flash(f'User "{user_name}" updated successfully', 'success')
        return redirect(url_for('admin.users_list'))
        
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        db.session.rollback()
        flash('Error updating user', 'error')
        all_roles = Role.query.all()
        return render_template('admin/user_form.html', user=user, all_roles=all_roles)

@admin_bp.route('/users/<int:user_id>/delete-confirm', methods=['GET'])
@superadmin_required
def confirm_delete_user(user_id):
    """Confirm user deletion"""
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting yourself
    if user.id == current_user.id:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('admin.users_list'))
    
    return render_template('admin/confirm_delete_user.html', user=user)

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@superadmin_required
def delete_user(user_id):
    """Delete (deactivate) user"""
    try:
        user = User.query.get_or_404(user_id)
        
        # Prevent deleting yourself
        if user.id == current_user.id:
            flash('Cannot delete your own account', 'error')
            return redirect(url_for('admin.users_list'))
        
        user.active = False
        user.updated_by = current_user.id
        user.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        flash(f'User "{user.name}" deleted successfully', 'success')
        return redirect(url_for('admin.users_list'))
        
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        db.session.rollback()
        flash('Error deleting user', 'error')
        return redirect(url_for('admin.users_list'))

@admin_bp.route('/users/<int:user_id>/reset-password', methods=['GET', 'POST'])
@superadmin_required
def reset_user_password(user_id):
    """Reset user password"""
    from services.auth_service import secure_hasher
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'GET':
        return render_template('admin/user_form.html', user=user, password_reset=True)
    
    try:
        password = request.form.get('password', '').strip()
        
        if not password:
            flash('Password is required', 'error')
            return render_template('admin/user_form.html', user=user, password_reset=True)
        
        # Update password
        user.password = secure_hasher.hash_password(password)
        user.updated_by = current_user.id
        user.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        flash(f'Password reset for user "{user.name}"', 'success')
        return redirect(url_for('admin.users_list'))
        
    except Exception as e:
        logger.error(f"Error resetting password: {e}")
        db.session.rollback()
        flash('Error resetting password', 'error')
        return render_template('admin/user_form.html', user=user, password_reset=True)

# === APP MANAGEMENT ===

@admin_bp.route('/apps/new', methods=['GET', 'POST'])
@superadmin_required
def new_app():
    """Create new app"""
    if request.method == 'GET':
        return render_template('admin/app_form.html', app=None)
    
    try:
        # Handle POST request - create new app
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        
        if not name:
            flash('App name is required', 'error')
            return render_template('admin/app_form.html', app=None)
        
        # Check if app already exists
        existing = App.query.filter_by(name=name).first()
        if existing:
            flash('An app with this name already exists', 'error')
            return render_template('admin/app_form.html', app=None)
        
        # Create new app
        new_app = App(
            name=name,
            description=description if description else None,
            created_by=current_user.id,
            updated_by=current_user.id
        )
        
        db.session.add(new_app)
        db.session.commit()
        
        flash(f'App "{name}" created successfully', 'success')
        return redirect(url_for('admin.apps_list'))
        
    except Exception as e:
        logger.error(f"Error creating app: {e}")
        db.session.rollback()
        flash('Error creating app', 'error')
        return render_template('admin/app_form.html', app=None)

@admin_bp.route('/apps/<int:app_id>/edit', methods=['GET', 'POST'])
@superadmin_required
def edit_app(app_id):
    """Edit existing app"""
    app = App.query.get_or_404(app_id)
    
    if request.method == 'GET':
        return render_template('admin/app_form.html', app=app)
    
    try:
        # Handle POST request - update app
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        active = request.form.get('active') == 'on'
        
        if not name:
            flash('App name is required', 'error')
            return render_template('admin/app_form.html', app=app)
        
        # Check if name is already taken by another app
        existing = App.query.filter(App.id != app_id, App.name == name).first()
        if existing:
            flash('An app with this name already exists', 'error')
            return render_template('admin/app_form.html', app=app)
        
        # Update app
        app.name = name
        app.description = description if description else None
        app.active = active
        app.updated_by = current_user.id
        app.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        flash(f'App "{name}" updated successfully', 'success')
        return redirect(url_for('admin.apps_list'))
        
    except Exception as e:
        logger.error(f"Error updating app: {e}")
        db.session.rollback()
        flash('Error updating app', 'error')
        return render_template('admin/app_form.html', app=app)

@admin_bp.route('/apps/<int:app_id>/delete', methods=['POST'])
@superadmin_required
def delete_app(app_id):
    """Delete (deactivate) app"""
    try:
        app = App.query.get_or_404(app_id)
        
        # Check if app has active tokens
        active_tokens = AppToken.query.filter_by(app_id=app_id, active=True).count()
        if active_tokens > 0:
            flash(f'Cannot delete app "{app.name}" - it has {active_tokens} active tokens. Revoke tokens first.', 'error')
            return redirect(url_for('admin.apps_list'))
        
        app.active = False
        app.updated_by = current_user.id
        app.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        flash(f'App "{app.name}" deleted successfully', 'success')
        return redirect(url_for('admin.apps_list'))
        
    except Exception as e:
        logger.error(f"Error deleting app: {e}")
        db.session.rollback()
        flash('Error deleting app', 'error')
        return redirect(url_for('admin.apps_list'))

# === API TOKEN MANAGEMENT ===

@admin_bp.route('/apps/<int:app_id>/tokens/new', methods=['GET', 'POST'])
@superadmin_required
def new_token(app_id):
    """Create new API token for app"""
    app = App.query.get_or_404(app_id)
    
    if not app.active:
        flash('Cannot create tokens for inactive apps', 'error')
        return redirect(url_for('admin.apps_list'))
    
    if request.method == 'GET':
        return render_template('admin/token_form.html', app=app, token=None)
    
    try:
        # Handle POST request - create new token
        name = request.form.get('name', '').strip()
        
        if not name:
            flash('Token name is required', 'error')
            return render_template('admin/token_form.html', app=app, token=None)
        
        # Check if token name already exists for this app
        existing = AppToken.query.filter_by(app_id=app_id, name=name).first()
        if existing:
            flash('A token with this name already exists for this app', 'error')
            return render_template('admin/token_form.html', app=app, token=None)
        
        # Generate new API token
        import secrets
        import hashlib
        
        # Generate raw token
        raw_token = f"mg_{''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(32))}"
        
        # Hash the token for storage
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        
        # Create new token
        new_token = AppToken(
            app_id=app_id,
            name=name,
            token_hash=token_hash,
            prefix="mg_",
            created_by=current_user.id,
            updated_by=current_user.id
        )
        
        db.session.add(new_token)
        db.session.commit()
        
        flash(f'Token "{name}" created successfully. Token: {raw_token}', 'success')
        session['new_token'] = raw_token  # Store in session to display once
        return redirect(url_for('admin.tokens'))
        
    except Exception as e:
        logger.error(f"Error creating token: {e}")
        db.session.rollback()
        flash('Error creating token', 'error')
        return render_template('admin/token_form.html', app=app, token=None)

@admin_bp.route('/tokens/<int:token_id>/revoke', methods=['POST'])
@superadmin_required
def revoke_token(token_id):
    """Revoke API token"""
    try:
        token = AppToken.query.get_or_404(token_id)
        
        token.active = False
        token.updated_by = current_user.id
        token.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        flash(f'Token "{token.name}" revoked successfully', 'success')
        return redirect(url_for('admin.tokens'))
        
    except Exception as e:
        logger.error(f"Error revoking token: {e}")
        db.session.rollback()
        flash('Error revoking token', 'error')
        return redirect(url_for('admin.tokens'))

@admin_bp.route('/tokens/<int:token_id>/delete', methods=['POST'])
@superadmin_required
def delete_token(token_id):
    """Permanently delete API token"""
    try:
        token = AppToken.query.get_or_404(token_id)
        token_name = token.name
        
        db.session.delete(token)
        db.session.commit()
        
        flash(f'Token "{token_name}" deleted permanently', 'success')
        return redirect(url_for('admin.tokens'))
        
    except Exception as e:
        logger.error(f"Error deleting token: {e}")
        db.session.rollback()
        flash('Error deleting token', 'error')
        return redirect(url_for('admin.tokens'))