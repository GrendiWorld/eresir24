# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone
# Flask-Limiter and Flask-Talisman are optional - removed to prevent errors
import os
import re
import hashlib
import logging
from functools import wraps

def get_utc_now():
    """Get timezone-aware UTC datetime"""
    return datetime.now(timezone.utc)

# For SQLAlchemy default values, we need a callable that returns the datetime
def utc_now():
    """Callable for SQLAlchemy default"""
    return datetime.now(timezone.utc)

def ensure_timezone_aware(dt):
    """Ensure datetime is timezone-aware, convert if needed"""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

# Configure logging for security events
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
security_logger = logging.getLogger('security')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production-' + hashlib.sha256(str(datetime.now(timezone.utc)).encode()).hexdigest()[:32])
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max request size
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Security headers - set manually (Talisman removed to prevent errors)
@app.after_request
def set_security_headers(response):
    """Set security headers manually"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

db = SQLAlchemy(app)

# Database models
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now, index=True)

class CloudConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True, index=True)
    config_data = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now, index=True)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now)

class ActiveMedia(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discord_account_id = db.Column(db.String(200), nullable=False, index=True)
    weekly_quota = db.Column(db.Integer, default=2, nullable=False)  # Weekly video quota
    videos_completed = db.Column(db.Integer, default=0, nullable=False)  # Videos completed this week
    week_start_date = db.Column(db.DateTime, default=utc_now, nullable=False)  # Week start date
    start_date = db.Column(db.DateTime, default=utc_now, index=True)
    end_date = db.Column(db.DateTime, nullable=False, index=True)
    notified = db.Column(db.Boolean, default=False, index=True)
    bonus_days = db.Column(db.Integer, default=0, nullable=False)  # Bonus days for overperformance
    quota_notified = db.Column(db.Boolean, default=False, index=True)  # Notified about quota issues

class ActiveUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discord_account_id = db.Column(db.String(200), nullable=False, unique=True, index=True)
    days = db.Column(db.Integer, nullable=False)
    start_date = db.Column(db.DateTime, default=utc_now, index=True)
    end_date = db.Column(db.DateTime, nullable=False, index=True)
    notified = db.Column(db.Boolean, default=False, index=True)

# Database initialization
with app.app_context():
    # Migrate ActiveMedia table if needed (before create_all)
    try:
        from sqlalchemy import inspect, text
        inspector = inspect(db.engine)
        if 'active_media' in inspector.get_table_names():
            columns = [col['name'] for col in inspector.get_columns('active_media')]
            # Check if old structure exists (has 'user' or 'discord_server' column without new fields)
            if 'user' in columns or ('discord_server' in columns and 'weekly_quota' not in columns):
                # Drop old table and recreate with new structure
                db.session.execute(text("DROP TABLE IF EXISTS active_media"))
                db.session.commit()
                print("ActiveMedia table recreated with new structure")
    except Exception as e:
        print(f"Migration: {e}")
        try:
            db.session.rollback()
            # If migration fails, drop and recreate
            db.session.execute(text("DROP TABLE IF EXISTS active_media"))
            db.session.commit()
        except:
            pass
    
    db.create_all()
    
    # Create default admin if doesn't exist
    default_admin = Admin.query.filter_by(login='admenchek').first()
    if not default_admin:
        default_admin = Admin(
            login='admenchek',
            password_hash=generate_password_hash('afkjajdfhoik4')
        )
        db.session.add(default_admin)
        db.session.commit()

# Middleware for authorization check with security logging
def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            if client_ip:
                client_ip = client_ip.split(',')[0].strip()
            security_logger.warning(f"Unauthorized access attempt to {request.path} from IP: {client_ip}")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Routes
@app.route('/')
def index():
    if 'admin_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form.get('login')
        password = request.form.get('password')
        
        if not login_input or not password:
            return render_template('login.html', error='Login and password are required')
        
        admin = Admin.query.filter_by(login=login_input).first()
        
        if admin and check_password_hash(admin.password_hash, password):
            session['admin_id'] = admin.id
            session['admin_login'] = admin.login
            session.permanent = True
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid login or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@require_admin
def dashboard():
    # Check expiring subscriptions
    now = datetime.now(timezone.utc)
    
    # Active Media expiring/expired
    expiring_soon_media = ActiveMedia.query.filter(
        ActiveMedia.end_date <= now + timedelta(days=1),
        ActiveMedia.end_date > now,
        ActiveMedia.notified == False
    ).all()
    
    expired_media = ActiveMedia.query.filter(
        ActiveMedia.end_date <= now,
        ActiveMedia.notified == False
    ).all()
    
    # Active Users expiring/expired
    expiring_soon_users = ActiveUser.query.filter(
        ActiveUser.end_date <= now + timedelta(days=1),
        ActiveUser.end_date > now,
        ActiveUser.notified == False
    ).all()
    
    expired_users = ActiveUser.query.filter(
        ActiveUser.end_date <= now,
        ActiveUser.notified == False
    ).all()
    
    # Check quota issues
    quota_issues = []
    for media in ActiveMedia.query.all():
        try:
            # Ensure week_start_date is timezone-aware (fix for old records)
            week_start = media.week_start_date
            if week_start and week_start.tzinfo is None:
                week_start = week_start.replace(tzinfo=timezone.utc)
            if week_start:
                days_since_week_start = (now - week_start).days
                if days_since_week_start >= 6 and media.videos_completed < media.weekly_quota and not media.quota_notified:
                    quota_issues.append(media)
        except Exception as e:
            security_logger.error(f"Error checking quota for media {media.id}: {str(e)}")
            continue
    
    admin_count = Admin.query.count()
    config_count = CloudConfig.query.count()
    media_count = ActiveMedia.query.count()
    users_count = ActiveUser.query.count()
    
    # Get admin info for welcome message
    admin = db.session.get(Admin, session['admin_id'])
    admin_username = admin.login if admin else 'Admin'
    
    return render_template('dashboard.html', 
                         expiring_soon_media=expiring_soon_media,
                         expired_media=expired_media,
                         expiring_soon_users=expiring_soon_users,
                         expired_users=expired_users,
                         quota_issues=quota_issues,
                         admin_count=admin_count,
                         config_count=config_count,
                         media_count=media_count,
                         users_count=users_count,
                         admin_username=admin_username)

# Admin management
@app.route('/admins')
@require_admin
def admins():
    admin_list = Admin.query.all()
    return render_template('admins.html', admins=admin_list)

@app.route('/api/admins/add', methods=['POST'])
@require_admin
def add_admin():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')
    
    if not login or not password:
        return jsonify({'error': 'Login and password are required'}), 400
    
    existing = Admin.query.filter_by(login=login).first()
    if existing:
        return jsonify({'error': 'Admin with this login already exists'}), 400
    
    new_admin = Admin(
        login=login,
        password_hash=generate_password_hash(password)
    )
    db.session.add(new_admin)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Admin successfully added'})

@app.route('/api/admins/delete/<int:admin_id>', methods=['DELETE'])
@require_admin
def delete_admin(admin_id):
    if admin_id == session.get('admin_id'):
        return jsonify({'error': 'Cannot delete yourself'}), 400
    
    admin = Admin.query.get_or_404(admin_id)
    db.session.delete(admin)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Admin deleted'})

# Cloud Config
@app.route('/cloud-config')
@require_admin
def cloud_config():
    configs = CloudConfig.query.order_by(CloudConfig.updated_at.desc()).all()
    return render_template('cloud_config.html', configs=configs)

@app.route('/api/cloud-config/add', methods=['POST'])
@require_admin
def add_cloud_config():
    try:
        data = request.get_json(force=False)
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
        
        name = data.get('name')
        config_data = data.get('config_data')
        
        if not name or not config_data:
            return jsonify({'error': 'Config name and data are required'}), 400
        
        if len(str(config_data)) > 1024 * 1024:  # 1MB limit
            return jsonify({'error': 'Config data too large'}), 400
        
        # Use parameterized query
        new_config = CloudConfig(name=name, config_data=config_data)
        db.session.add(new_config)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Config added', 'id': new_config.id})
        
    except Exception as e:
        security_logger.error(f"Error in add_cloud_config: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/cloud-config/update/<int:config_id>', methods=['PUT'])
@require_admin
def update_cloud_config(config_id):
    config = CloudConfig.query.get_or_404(config_id)
    data = request.get_json()
    
    config.name = data.get('name', config.name)
    config.config_data = data.get('config_data', config.config_data)
    config.updated_at = datetime.now(timezone.utc)
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Config updated'})

@app.route('/api/cloud-config/delete/<int:config_id>', methods=['DELETE'])
@require_admin
def delete_cloud_config(config_id):
    config = CloudConfig.query.get_or_404(config_id)
    db.session.delete(config)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Config deleted'})

@app.route('/api/cloud-config/<int:config_id>', methods=['GET'])
@require_admin
def get_cloud_config(config_id):
    config = CloudConfig.query.get_or_404(config_id)
    return jsonify({
        'id': config.id,
        'name': config.name,
        'config_data': config.config_data,
        'created_at': config.created_at.isoformat(),
        'updated_at': config.updated_at.isoformat()
    })

@app.route('/api/cloud-configs', methods=['GET'])
@require_admin
def get_all_cloud_configs():
    configs = CloudConfig.query.all()
    return jsonify([{
        'id': c.id,
        'name': c.name,
        'config_data': c.config_data,
        'created_at': c.created_at.isoformat(),
        'updated_at': c.updated_at.isoformat()
    } for c in configs])

# Active Media
@app.route('/active-media')
@require_admin
def active_media():
    try:
        media_list = ActiveMedia.query.order_by(ActiveMedia.end_date.asc()).all()
        now = datetime.now(timezone.utc)
        
        # First, ensure ALL datetime fields are timezone-aware in DB (fix for old records)
        needs_commit = False
        for media in media_list:
            if media.week_start_date and media.week_start_date.tzinfo is None:
                media.week_start_date = ensure_timezone_aware(media.week_start_date)
                needs_commit = True
            if media.start_date and media.start_date.tzinfo is None:
                media.start_date = ensure_timezone_aware(media.start_date)
                needs_commit = True
            if media.end_date and media.end_date.tzinfo is None:
                media.end_date = ensure_timezone_aware(media.end_date)
                needs_commit = True
        
        if needs_commit:
            db.session.commit()
            # Reload after commit to get fresh objects
            media_list = ActiveMedia.query.order_by(ActiveMedia.end_date.asc()).all()
        
        # Now process quota logic
        for media in media_list:
            try:
                # Ensure timezone-aware for calculations
                week_start = ensure_timezone_aware(media.week_start_date) if media.week_start_date else None
                if week_start:
                    days_since_week_start = (now - week_start).days
                    if days_since_week_start >= 7:
                        # Check if quota was exceeded (bonus) or not met (warning)
                        if media.videos_completed > media.weekly_quota:
                            # Overperformance - add bonus days
                            bonus = 2
                            media.bonus_days += bonus
                            end_date = ensure_timezone_aware(media.end_date)
                            media.end_date = end_date + timedelta(days=bonus)
                        elif media.videos_completed < media.weekly_quota:
                            # Underperformance - mark for notification
                            media.quota_notified = False
                        
                        # Reset for new week
                        media.videos_completed = 0
                        media.week_start_date = now
                        db.session.commit()
            except Exception as e:
                security_logger.error(f"Error processing media {media.id}: {str(e)}")
                continue
        
        # FINAL: Ensure ALL datetime fields are timezone-aware before template rendering
        # This is critical - do this AFTER all commits
        for media in media_list:
            media.week_start_date = ensure_timezone_aware(media.week_start_date) if media.week_start_date else None
            media.start_date = ensure_timezone_aware(media.start_date) if media.start_date else None
            media.end_date = ensure_timezone_aware(media.end_date) if media.end_date else None
        
        return render_template('active_media.html', media_list=media_list, now=now)
    except Exception as e:
        import traceback
        security_logger.error(f"Error in active_media: {str(e)}\n{traceback.format_exc()}")
        return render_template('active_media.html', media_list=[], now=datetime.now(timezone.utc))

@app.route('/active-users')
@require_admin
def active_users():
    users_list = ActiveUser.query.order_by(ActiveUser.end_date.asc()).all()
    now = datetime.now(timezone.utc)
    
    # Ensure all datetime fields are timezone-aware in DB (fix for old records)
    needs_commit = False
    for user in users_list:
        if user.start_date and user.start_date.tzinfo is None:
            user.start_date = ensure_timezone_aware(user.start_date)
            needs_commit = True
        if user.end_date and user.end_date.tzinfo is None:
            user.end_date = ensure_timezone_aware(user.end_date)
            needs_commit = True
    
    if needs_commit:
        db.session.commit()
        # Reload after commit to get fresh objects
        users_list = ActiveUser.query.order_by(ActiveUser.end_date.asc()).all()
    
    # FINAL: Ensure ALL datetime fields are timezone-aware before template rendering
    # This is critical - do this AFTER all commits
    for user in users_list:
        user.start_date = ensure_timezone_aware(user.start_date) if user.start_date else None
        user.end_date = ensure_timezone_aware(user.end_date) if user.end_date else None
    
    return render_template('active_users.html', users_list=users_list, now=now)

@app.route('/api-docs')
@require_admin
def api_docs():
    return render_template('api_docs.html')

@app.route('/api/active-media/add', methods=['POST'])
@require_admin
def add_active_media():
    data = request.get_json()
    discord_account_id = data.get('discord_account_id')
    weekly_quota = data.get('weekly_quota', 2)  # Default 2 videos per week
    days = data.get('days', 30)  # Default 30 days subscription
    
    if not discord_account_id:
        return jsonify({'error': 'Discord account ID is required'}), 400
    
    end_date = datetime.now(timezone.utc) + timedelta(days=days)
    
    new_media = ActiveMedia(
        discord_account_id=discord_account_id,
        weekly_quota=int(weekly_quota),
        end_date=end_date
    )
    db.session.add(new_media)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Media added', 'id': new_media.id})

@app.route('/api/active-media/add-video/<int:media_id>', methods=['POST'])
@require_admin
def add_video_to_media(media_id):
    """Add a completed video to media account"""
    try:
        media = ActiveMedia.query.get_or_404(media_id)
        now = datetime.now(timezone.utc)
        
        # Ensure ALL datetime fields are timezone-aware (fix for old records)
        needs_commit = False
        if media.week_start_date and media.week_start_date.tzinfo is None:
            media.week_start_date = ensure_timezone_aware(media.week_start_date)
            needs_commit = True
        if media.start_date and media.start_date.tzinfo is None:
            media.start_date = ensure_timezone_aware(media.start_date)
            needs_commit = True
        if media.end_date and media.end_date.tzinfo is None:
            media.end_date = ensure_timezone_aware(media.end_date)
            needs_commit = True
        
        if needs_commit:
            db.session.commit()
            # Reload after commit to get fresh object
            media = ActiveMedia.query.get_or_404(media_id)
        
        # Ensure timezone-aware for calculations (use local variables to avoid issues after commit)
        week_start = ensure_timezone_aware(media.week_start_date) if media.week_start_date else None
        end_date = ensure_timezone_aware(media.end_date) if media.end_date else None
        
        # Check if new week started
        if week_start:
            days_since_week_start = (now - week_start).days
            if days_since_week_start >= 7:
                # Check previous week performance
                if media.videos_completed > media.weekly_quota:
                    # Overperformance - add bonus days
                    bonus = 2
                    media.bonus_days += bonus
                    if end_date:
                        media.end_date = end_date + timedelta(days=bonus)
                elif media.videos_completed < media.weekly_quota:
                    # Underperformance - reset notification flag
                    media.quota_notified = False
                
                # Reset for new week
                media.videos_completed = 0
                media.week_start_date = now
        
        # Add video
        media.videos_completed += 1
        
        # Check if quota exceeded (overperformance)
        if media.videos_completed > media.weekly_quota:
            # Already exceeded - could add immediate bonus, but we'll do it at week end
            pass
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': 'Video added',
            'videos_completed': media.videos_completed,
            'weekly_quota': media.weekly_quota
        })
    except Exception as e:
        import traceback
        security_logger.error(f"Error in add_video_to_media: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/active-media/delete/<int:media_id>', methods=['DELETE'])
@require_admin
def delete_active_media(media_id):
    media = ActiveMedia.query.get_or_404(media_id)
    db.session.delete(media)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Media deleted'})

@app.route('/api/active-media/mark-notified/<int:media_id>', methods=['POST'])
@require_admin
def mark_notified(media_id):
    media = ActiveMedia.query.get_or_404(media_id)
    media.notified = True
    media.quota_notified = True
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Marked as notified'})

# Active Users API
@app.route('/api/active-users/add', methods=['POST'])
@require_admin
def add_active_user():
    data = request.get_json()
    discord_account_id = data.get('discord_account_id')
    days = data.get('days', 30)
    
    if not discord_account_id:
        return jsonify({'error': 'Discord account ID is required'}), 400
    
    # Check if user already exists
    existing = ActiveUser.query.filter_by(discord_account_id=discord_account_id).first()
    if existing:
        # Extend subscription
        existing.days += int(days)
        existing.end_date += timedelta(days=int(days))
        existing.notified = False
        db.session.commit()
        return jsonify({'success': True, 'message': 'Subscription extended', 'id': existing.id})
    
    # Create new user
    end_date = datetime.now(timezone.utc) + timedelta(days=int(days))
    new_user = ActiveUser(
        discord_account_id=discord_account_id,
        days=int(days),
        end_date=end_date
    )
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'User added', 'id': new_user.id})

@app.route('/api/active-users/add-days/<int:user_id>', methods=['POST'])
@require_admin
def add_days_to_user(user_id):
    """Add days to existing user subscription"""
    data = request.get_json()
    additional_days = data.get('days', 0)
    
    if not additional_days or additional_days <= 0:
        return jsonify({'error': 'Days must be greater than 0'}), 400
    
    user = ActiveUser.query.get_or_404(user_id)
    user.days += int(additional_days)
    user.end_date += timedelta(days=int(additional_days))
    user.notified = False
    db.session.commit()
    
    return jsonify({
        'success': True, 
        'message': f'{additional_days} days added',
        'total_days': user.days,
        'new_end_date': user.end_date.isoformat()
    })

@app.route('/api/active-users/delete/<int:user_id>', methods=['DELETE'])
@require_admin
def delete_active_user(user_id):
    user = ActiveUser.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'User deleted'})

@app.route('/api/active-users/mark-notified/<int:user_id>', methods=['POST'])
@require_admin
def mark_user_notified(user_id):
    user = ActiveUser.query.get_or_404(user_id)
    user.notified = True
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Marked as notified'})

# Public API for cloud configs
@app.route('/api/config/add', methods=['POST'])
def add_config_public():
    """Public API to add cloud config. Send: {"name": "config_name", "config_data": "content"}"""
    try:
        data = request.get_json(force=False)
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
        
        name = data.get('name')
        config_data = data.get('config_data')
        
        if not name or not config_data:
            return jsonify({'error': 'Name and config_data are required'}), 400
        
        # Limit config_data size (1MB)
        if len(str(config_data)) > 1024 * 1024:
            return jsonify({'error': 'Config data too large. Maximum 1MB.'}), 400
        
        # Use parameterized query (SQLAlchemy does this automatically)
        existing = CloudConfig.query.filter_by(name=name).first()
        if existing:
            # Update existing config
            existing.config_data = config_data
            existing.updated_at = datetime.now(timezone.utc)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Config successfully updated'})
        
        # Create new config
        new_config = CloudConfig(name=name, config_data=config_data)
        db.session.add(new_config)
        db.session.commit()
        
        response = jsonify({'success': True, 'message': 'Config successfully added'})
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response
        
    except Exception as e:
        security_logger.error(f"Error in add_config_public: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# Public API to get all configs (list with content)
@app.route('/api/configs', methods=['GET'])
def get_all_configs_public():
    """Get all configs with their content. Returns JSON array."""
    try:
        # Use parameterized query
        configs = CloudConfig.query.order_by(CloudConfig.updated_at.desc()).limit(100).all()  # Limit to 100 configs
        
        result = [{
            'name': c.name,
            'content': c.config_data,
            'created_at': c.created_at.isoformat(),
            'updated_at': c.updated_at.isoformat()
        } for c in configs]
        
        response = jsonify(result)
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response
        
    except Exception as e:
        security_logger.error(f"Error in get_all_configs_public: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# Public API to get config by name (returns only content)
@app.route('/api/config/<config_name>', methods=['GET'])
def get_config_by_name(config_name):
    """Get config by name. Returns only config content. Example: /api/config/myconfig"""
    try:
        # Check that this is not a system path
        reserved_paths = ['cloud-config', 'cloud-configs', 'active-media', 'admins', 'add', 'configs']
        if config_name.lower() in reserved_paths:
            return jsonify({'error': 'Config not found'}), 404
        
        # Use parameterized query
        config = CloudConfig.query.filter_by(name=config_name).first()
        if not config:
            return jsonify({'error': 'Config not found'}), 404
        
        # Return only config data
        from flask import Response
        response = Response(
            config.config_data,
            mimetype='text/plain; charset=utf-8',
            headers={
                'Access-Control-Allow-Origin': '*',
                'X-Content-Type-Options': 'nosniff'
            }
        )
        return response
        
    except Exception as e:
        security_logger.error(f"Error in get_config_by_name: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Forbidden'}), 403


@app.errorhandler(500)
def internal_error(error):
    import traceback
    error_traceback = traceback.format_exc()
    security_logger.error(f"Internal server error: {str(error)}\n{error_traceback}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Never run in debug mode in production!
    app.run(debug=False, host='0.0.0.0', port=5000)
