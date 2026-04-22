"""
Customer Data Routes
API endpoints for customer zipcode data from Roller integration
"""
from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, date, timedelta
from utils.logger import logger
from models.customer_data import Customer, RollerDataSync, db
from services.roller_service import create_roller_service
from services.oauth2_service import require_oauth2_if_enabled
import os

customer_bp = Blueprint('customer', __name__)
customer_data_required = require_oauth2_if_enabled(
    'CUSTOMER_DATA_AUTH_REQUIRED', ['admin', 'admin_read']
)

@customer_bp.route('/sync-customers', methods=['POST'])
@customer_data_required
def sync_customers():
    """
    Sync customer data from Roller API
    Admin endpoint to fetch and store customer data
    """
    try:
        # Check if Roller credentials are configured
        if not os.environ.get('ROLLER_CLIENT_ID') or not os.environ.get('ROLLER_CLIENT_SECRET'):
            return jsonify({
                'error': 'Roller API credentials not configured. Set ROLLER_CLIENT_ID and ROLLER_CLIENT_SECRET environment variables.'
            }), 500

        # Get optional date parameters
        data = request.get_json() or {}
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        
        # Create sync record
        sync_record = RollerDataSync(
            sync_date=date.today(),
            start_time=datetime.utcnow(),
            status='running',
            api_start_date=datetime.strptime(start_date, '%Y-%m-%d').date() if start_date else None,
            api_end_date=datetime.strptime(end_date, '%Y-%m-%d').date() if end_date else None
        )
        db.session.add(sync_record)
        db.session.commit()

        try:
            # Initialize Roller service
            roller_service = create_roller_service()
            
            # Fetch customers from Roller API
            logger.info(f"Starting customer sync from Roller API (sync_id: {sync_record.id})")
            
            if start_date and end_date:
                # Use date range method if both dates provided
                customers = roller_service.fetch_customers_date_range(start_date, end_date)
            else:
                # Use single-day method (default behavior)
                customers = roller_service.fetch_customers(start_date, end_date)
            
            sync_record.customers_fetched = len(customers)
            
            # Process and store customers
            processed_count = 0
            updated_count = 0
            created_count = 0
            
            for roller_customer in customers:
                customer_data = roller_service.extract_customer_data(roller_customer)
                
                if not customer_data or not customer_data.get('roller_customer_id'):
                    continue
                
                # Find or create customer
                existing_customer = Customer.get_by_roller_id(customer_data['roller_customer_id'])
                
                if existing_customer:
                    # Update existing customer
                    existing_customer.postcode = customer_data.get('postcode')
                    existing_customer.country = customer_data.get('country')
                    existing_customer.marketing_acceptance = customer_data.get('marketing_acceptance')
                    existing_customer.last_sync_date = date.today()
                    updated_count += 1
                else:
                    # Create new customer
                    new_customer = Customer(
                        roller_customer_id=customer_data['roller_customer_id'],
                        postcode=customer_data.get('postcode'),
                        country=customer_data.get('country'),
                        marketing_acceptance=customer_data.get('marketing_acceptance'),
                        last_sync_date=date.today()
                    )
                    db.session.add(new_customer)
                    created_count += 1
                
                processed_count += 1
                
                # Commit in batches for better performance
                if processed_count % 100 == 0:
                    db.session.commit()
                    logger.info(f"Processed {processed_count} customers...")
            
            # Final commit
            db.session.commit()
            
            # Get statistics
            stats = Customer.get_stats()
            
            # Update sync record
            sync_record.status = 'completed'
            sync_record.end_time = datetime.utcnow()
            sync_record.customers_with_zipcode = stats['customers_with_postcode']
            sync_record.customers_without_zipcode = stats['customers_without_postcode']
            sync_record.unique_zipcodes = len(set(c.postcode for c in Customer.query.filter(Customer.postcode.isnot(None)).all()))
            
            db.session.commit()
            
            logger.info(f"Customer sync completed successfully. Created: {created_count}, Updated: {updated_count}")
            
            return jsonify({
                'success': True,
                'sync_id': sync_record.id,
                'customers_fetched': len(customers),
                'customers_processed': processed_count,
                'customers_created': created_count,
                'customers_updated': updated_count,
                'statistics': stats,
                'duration_seconds': (sync_record.end_time - sync_record.start_time).total_seconds()
            })

        except Exception as e:
            logger.error(f"Error during customer sync: {str(e)}", exc_info=True)
            
            # Update sync record with error
            sync_record.status = 'failed'
            sync_record.end_time = datetime.utcnow()
            sync_record.error_message = str(e)
            db.session.commit()
            
            return jsonify({
                'error': f'Customer sync failed: {str(e)}',
                'sync_id': sync_record.id
            }), 500

    except Exception as e:
        logger.error(f"Error setting up customer sync: {str(e)}", exc_info=True)
        return jsonify({'error': f'Sync setup failed: {str(e)}'}), 500

@customer_bp.route('/zipcode-data', methods=['GET'])
@customer_data_required
def get_zipcode_data():
    """
    Get zipcode distribution data for heatmap visualization
    Public endpoint (with appropriate filtering)
    """
    try:
        # Get query parameters
        country = request.args.get('country', 'USA')
        limit = request.args.get('limit', 1000, type=int)
        min_count = request.args.get('min_count', 1, type=int)
        
        # Validate limit
        limit = min(limit, 5000)  # Maximum 5000 records
        
        # Get zipcode distribution
        zipcode_data = Customer.get_zipcode_distribution(country=country, limit=limit)
        
        # Filter by minimum count and format for frontend
        formatted_data = []
        for postcode, count in zipcode_data:
            if count >= min_count:
                formatted_data.append({
                    'zipcode': postcode,
                    'count': count
                })
        
        # Get overall statistics
        stats = Customer.get_stats(country=country)
        
        # Get latest sync info
        latest_sync = RollerDataSync.get_latest_successful_sync()
        
        return jsonify({
            'zipcode_data': formatted_data,
            'statistics': stats,
            'country': country,
            'last_updated': latest_sync.end_time.isoformat() if latest_sync else None,
            'filters': {
                'country': country,
                'limit': limit,
                'min_count': min_count
            }
        })

    except Exception as e:
        logger.error(f"Error getting zipcode data: {str(e)}", exc_info=True)
        return jsonify({'error': f'Failed to get zipcode data: {str(e)}'}), 500

@customer_bp.route('/stats', methods=['GET'])
@customer_data_required
def get_customer_stats():
    """
    Get customer statistics
    """
    try:
        country = request.args.get('country')
        
        # Get customer statistics
        stats = Customer.get_stats(country=country)
        
        # Get sync history
        recent_syncs = RollerDataSync.get_recent_syncs(limit=5)
        
        return jsonify({
            'statistics': stats,
            'country': country,
            'recent_syncs': [sync.to_dict() for sync in recent_syncs]
        })

    except Exception as e:
        logger.error(f"Error getting customer stats: {str(e)}", exc_info=True)
        return jsonify({'error': f'Failed to get customer stats: {str(e)}'}), 500

@customer_bp.route('/sync-status/<int:sync_id>', methods=['GET'])
@customer_data_required
def get_sync_status(sync_id):
    """
    Get status of a specific sync operation
    """
    try:
        sync_record = RollerDataSync.query.get_or_404(sync_id)
        return jsonify(sync_record.to_dict())

    except Exception as e:
        logger.error(f"Error getting sync status: {str(e)}", exc_info=True)
        return jsonify({'error': f'Failed to get sync status: {str(e)}'}), 500

@customer_bp.route('/load-demo-data', methods=['POST'])
@customer_data_required
def load_demo_data():
    """
    Load demo zipcode data for testing the heatmap functionality
    """
    try:
        from models.customer_data import Customer, db
        from datetime import date
        import random
        
        # Demo zipcode data with realistic customer counts
        demo_data = [
            {'postcode': '10001', 'country': 'USA', 'count': 45},  # NYC
            {'postcode': '90210', 'country': 'USA', 'count': 32},  # Beverly Hills
            {'postcode': '60601', 'country': 'USA', 'count': 38},  # Chicago
            {'postcode': '02101', 'country': 'USA', 'count': 28},  # Boston
            {'postcode': '33101', 'country': 'USA', 'count': 41},  # Miami
            {'postcode': '75201', 'country': 'USA', 'count': 35},  # Dallas
            {'postcode': '98101', 'country': 'USA', 'count': 29},  # Seattle
            {'postcode': '94102', 'country': 'USA', 'count': 52},  # San Francisco
            {'postcode': '30301', 'country': 'USA', 'count': 31},  # Atlanta
            {'postcode': '80201', 'country': 'USA', 'count': 26},  # Denver
            {'postcode': '19101', 'country': 'USA', 'count': 33},  # Philadelphia
            {'postcode': '20001', 'country': 'USA', 'count': 37},  # Washington DC
            {'postcode': '85001', 'country': 'USA', 'count': 24},  # Phoenix
            {'postcode': '89101', 'country': 'USA', 'count': 48},  # Las Vegas
            {'postcode': '32801', 'country': 'USA', 'count': 67},  # Orlando (higher for theme parks)
            {'postcode': '70112', 'country': 'USA', 'count': 89},  # New Orleans (Mardi Gras!)
            {'postcode': '77002', 'country': 'USA', 'count': 31},  # Houston
            {'postcode': '55401', 'country': 'USA', 'count': 22},  # Minneapolis
            {'postcode': '63101', 'country': 'USA', 'count': 18},  # St. Louis
            {'postcode': '37201', 'country': 'USA', 'count': 27},  # Nashville
        ]
        
        # Clear existing demo data (customers with demo_ prefix are considered demo data)
        existing_demo = Customer.query.filter(Customer.roller_customer_id.like('demo_%')).all()
        for customer in existing_demo:
            db.session.delete(customer)
        
        # Insert demo customers
        demo_customers_created = 0
        for item in demo_data:
            for i in range(item['count']):
                demo_customer = Customer(
                    roller_customer_id=f"demo_{item['postcode']}_{i}",  # Unique demo ID
                    postcode=item['postcode'],
                    country=item['country'],
                    marketing_acceptance=random.choice([True, False, None]),
                    last_sync_date=date.today()
                )
                db.session.add(demo_customer)
                demo_customers_created += 1
        
        db.session.commit()
        
        # Get updated statistics
        stats = Customer.get_stats()
        
        return jsonify({
            'success': True,
            'message': 'Demo data loaded successfully',
            'demo_customers_created': demo_customers_created,
            'unique_zipcodes': len(demo_data),
            'statistics': stats
        })

    except Exception as e:
        logger.error(f"Error loading demo data: {str(e)}", exc_info=True)
        return jsonify({'error': f'Failed to load demo data: {str(e)}'}), 500

@customer_bp.route('/test-roller-connection', methods=['GET'])
@customer_data_required
def test_roller_connection():
    """
    Test connection to Roller API without syncing data
    """
    try:
        if not os.environ.get('ROLLER_CLIENT_ID') or not os.environ.get('ROLLER_CLIENT_SECRET'):
            return jsonify({
                'success': False,
                'error': 'Roller API credentials not configured'
            }), 500

        roller_service = create_roller_service()
        
        # Test authentication
        token = roller_service._get_access_token()
        
        return jsonify({
            'success': True,
            'message': 'Successfully connected to Roller API',
            'token_expires_at': roller_service.token_expires_at.isoformat() if roller_service.token_expires_at else None
        })

    except Exception as e:
        logger.error(f"Error testing Roller connection: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Failed to connect to Roller API: {str(e)}'
        }), 500
