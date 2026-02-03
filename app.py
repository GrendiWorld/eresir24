# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database models
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class CloudConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True, index=True)
    config_data = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ActiveMedia(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discord_account_id = db.Column(db.String(200), nullable=False, index=True)
    weekly_quota = db.Column(db.Integer, default=2, nullable=False)  # Weekly video quota
    videos_completed = db.Column(db.Integer, default=0, nullable=False)  # Videos completed this week
    week_start_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  # Week start date
    start_date = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    end_date = db.Column(db.DateTime, nullable=False, index=True)
    notified = db.Column(db.Boolean, default=False, index=True)
    bonus_days = db.Column(db.Integer, default=0, nullable=False)  # Bonus days for overperformance
    quota_notified = db.Column(db.Boolean, default=False, index=True)  # Notified about quota issues

class ActiveUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discord_account_id = db.Column(db.String(200), nullable=False, unique=True, index=True)
    days = db.Column(db.Integer, nullable=False)
    start_date = db.Column(db.DateTime, default=datetime.utcnow, index=True)
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

# Rate limiting storage (in-memory, simple implementation)
rate_limit_storage = {}

# Rate limiting decorator (10 seconds between requests)
def rate_limit(seconds=10):
    from functools import wraps
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client IP address
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            if client_ip:
                client_ip = client_ip.split(',')[0].strip()
            else:
                client_ip = 'unknown'
            
            # Check rate limit
            current_time = datetime.utcnow()
            last_request_time = rate_limit_storage.get(client_ip)
            
            if last_request_time:
                time_diff = (current_time - last_request_time).total_seconds()
                if time_diff < seconds:
                    remaining = seconds - time_diff
                    return jsonify({
                        'error': 'Rate limit exceeded',
                        'message': f'Please wait {remaining:.1f} seconds before making another request',
                        'retry_after': int(remaining) + 1
                    }), 429
            
            # Update last request time
            rate_limit_storage[client_ip] = current_time
            
            # Clean old entries (older than 1 minute)
            to_remove = [ip for ip, time in rate_limit_storage.items() 
                        if (current_time - time).total_seconds() > 60]
            for ip in to_remove:
                del rate_limit_storage[ip]
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Middleware for authorization check
def require_admin(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
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
        login = request.form.get('login')
        password = request.form.get('password')
        
        admin = Admin.query.filter_by(login=login).first()
        if admin and check_password_hash(admin.password_hash, password):
            session['admin_id'] = admin.id
            session['admin_login'] = admin.login
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
    now = datetime.utcnow()
    
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
        days_since_week_start = (now - media.week_start_date).days
        if days_since_week_start >= 6 and media.videos_completed < media.weekly_quota and not media.quota_notified:
            quota_issues.append(media)
    
    admin_count = Admin.query.count()
    config_count = CloudConfig.query.count()
    media_count = ActiveMedia.query.count()
    users_count = ActiveUser.query.count()
    
    # Get admin info for welcome message
    admin = Admin.query.get(session['admin_id'])
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
    data = request.get_json()
    name = data.get('name')
    config_data = data.get('config_data')
    
    if not name or not config_data:
        return jsonify({'error': 'Config name and data are required'}), 400
    
    new_config = CloudConfig(name=name, config_data=config_data)
    db.session.add(new_config)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Config added', 'id': new_config.id})

@app.route('/api/cloud-config/update/<int:config_id>', methods=['PUT'])
@require_admin
def update_cloud_config(config_id):
    config = CloudConfig.query.get_or_404(config_id)
    data = request.get_json()
    
    config.name = data.get('name', config.name)
    config.config_data = data.get('config_data', config.config_data)
    config.updated_at = datetime.utcnow()
    
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
    media_list = ActiveMedia.query.order_by(ActiveMedia.end_date.asc()).all()
    now = datetime.utcnow()
    
    # Check quota status for each media
    for media in media_list:
        # Reset week if new week started
        days_since_week_start = (now - media.week_start_date).days
        if days_since_week_start >= 7:
            # Check if quota was exceeded (bonus) or not met (warning)
            if media.videos_completed > media.weekly_quota:
                # Overperformance - add bonus days
                bonus = 2
                media.bonus_days += bonus
                media.end_date += timedelta(days=bonus)
            elif media.videos_completed < media.weekly_quota:
                # Underperformance - mark for notification
                media.quota_notified = False
            
            # Reset for new week
            media.videos_completed = 0
            media.week_start_date = now
            db.session.commit()
    
    return render_template('active_media.html', media_list=media_list, now=now)

@app.route('/active-users')
@require_admin
def active_users():
    users_list = ActiveUser.query.order_by(ActiveUser.end_date.asc()).all()
    now = datetime.utcnow()
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
    
    end_date = datetime.utcnow() + timedelta(days=days)
    
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
    media = ActiveMedia.query.get_or_404(media_id)
    now = datetime.utcnow()
    
    # Check if new week started
    days_since_week_start = (now - media.week_start_date).days
    if days_since_week_start >= 7:
        # Check previous week performance
        if media.videos_completed > media.weekly_quota:
            # Overperformance - add bonus days
            bonus = 2
            media.bonus_days += bonus
            media.end_date += timedelta(days=bonus)
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
    end_date = datetime.utcnow() + timedelta(days=int(days))
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
@rate_limit(seconds=10)
def add_config_public():
    """Public API to add cloud config. Send: {"name": "config_name", "config_data": "content"}"""
    data = request.get_json()
    name = data.get('name')
    config_data = data.get('config_data')
    
    if not name or not config_data:
        return jsonify({'error': 'Name and config_data are required'}), 400
    
    # Check if config already exists
    existing = CloudConfig.query.filter_by(name=name).first()
    if existing:
        # Update existing config
        existing.config_data = config_data
        existing.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True, 'message': 'Config successfully updated'})
    
    # Create new config
    new_config = CloudConfig(name=name, config_data=config_data)
    db.session.add(new_config)
    db.session.commit()
    
    response = jsonify({'success': True, 'message': 'Config successfully added'})
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

# Public API to get config by name (returns only content)
@app.route('/api/config/<config_name>', methods=['GET'])
@rate_limit(seconds=10)
def get_config_by_name(config_name):
    """Get config by name. Returns only config content. Example: /api/config/myconfig"""
    # Check that this is not a system path
    reserved_paths = ['cloud-config', 'cloud-configs', 'active-media', 'admins', 'add']
    if config_name in reserved_paths:
        return jsonify({'error': 'Config not found'}), 404
    
    config = CloudConfig.query.filter_by(name=config_name).first()
    if not config:
        return jsonify({'error': 'Config not found'}), 404
    
    # Return only config data
    from flask import Response
    response = Response(
        config.config_data,
        mimetype='text/plain; charset=utf-8',
        headers={'Access-Control-Allow-Origin': '*'}
    )
    return response

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
