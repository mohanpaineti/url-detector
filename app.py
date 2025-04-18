from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import secrets
from dotenv import load_dotenv
import json
# Import models module to ensure it's loaded
import models

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///url_detector.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Mail configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() in ['true', '1', 't']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@urldetector.com')
mail = Mail(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'

# Available models
models = [
    {
        "id": 1, 
        "name": "DeepSeek", 
        "description": "Fast URL detection using few-shot prompting technique", 
        "icon": "bolt",
        "type": "deepseek",
        "technique": "few-shot"
    },
    {
        "id": 4, 
        "name": "ChatGPT", 
        "description": "Advanced detection using few-shot prompting for complex threats", 
        "icon": "microscope",
        "type": "chatgpt",
        "technique": "few-shot"
    },
    {
        "id": 5, 
        "name": "Gemini", 
        "description": "High performance detection using Google's Gemini model", 
        "icon": "star",
        "type": "gemini",
        "technique": "few-shot"
    },
    {
        "id": 6, 
        "name": "Llama", 
        "description": "Advanced URL detection powered by Meta's Llama model", 
        "icon": "robot",
        "type": "llama",
        "technique": "few-shot"
    }
]

# Create the database tables
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            user = User.query.filter_by(username=username).first()
            
            if user and check_password_hash(user.password, password):
                session['user_id'] = user.id
                session['username'] = user.username
                
                # Set is_admin in session, defaulting to False if the attribute doesn't exist
                session['is_admin'] = getattr(user, 'is_admin', False)
                
                # Update last_login time if the attribute exists
                try:
                    if hasattr(user, 'last_login'):
                        user.last_login = datetime.utcnow()
                        db.session.commit()
                except Exception as e:
                    app.logger.error(f"Error updating last login time: {str(e)}")
                    # Don't let last_login errors prevent login
                    db.session.rollback()
                
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            
            flash('Invalid username or password', 'error')
        except Exception as e:
            app.logger.error(f"Error during login: {str(e)}")
            flash('An error occurred during login. Please try again later.', 'error')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        role = request.form.get('role', 'user')  # Default to 'user' if not specified
        
        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        
        if existing_user:
            flash('Username already exists', 'error')
        elif existing_email:
            flash('Email already in use', 'error')
        else:
            hashed_password = generate_password_hash(password)
            
            # Set admin status based on role selection
            is_admin = (role == 'admin')
            
            # Check if this is the first user (make them admin regardless)
            is_first_user = User.query.count() == 0
            if is_first_user:
                is_admin = True
                
            new_user = User(
                username=username, 
                password=hashed_password, 
                email=email,
                is_admin=is_admin
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            # Set flash message based on role
            if is_admin:
                flash('Admin account created successfully! Please login.', 'success')
            else:
                flash('Account created successfully! Please login.', 'success')
                
            return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', models=models)

@app.route('/chat/<int:model_id>')
def chat(model_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    selected_model = next((model for model in models if model['id'] == model_id), None)
    
    if selected_model is None:
        flash('Model not found', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('chat.html', model=selected_model)

@app.route('/detect_url', methods=['POST'])
def detect_url():
    if 'user_id' not in session:
        return {'error': 'Unauthorized'}, 401
    
    data = request.get_json()
    
    if not data:
        return {'error': 'No data provided', 'details': 'Request body is empty or invalid'}, 400
    
    url = data.get('url', '').strip()
    model_id = data.get('model_id')
    
    if not url:
        return {'error': 'Invalid URL', 'details': 'URL cannot be empty'}, 400
    
    if not model_id:
        return {'error': 'Invalid model ID', 'details': 'Model ID must be provided'}, 400
    
    try:
        # Convert model_id to integer
        model_id = int(model_id)
    except (ValueError, TypeError):
        return {'error': 'Invalid model ID', 'details': 'Model ID must be a number'}, 400
    
    # Get the model configuration based on model ID
    selected_model = next((model for model in models if model['id'] == model_id), None)
    
    if not selected_model:
        return {'error': 'Invalid model ID', 'details': 'The requested model does not exist'}, 400
    
    try:
        # Import the get_model function for model selection
        from models import get_model
        
        # Get the appropriate model based on type and technique
        model = get_model(selected_model['type'], selected_model['technique'])
        
        # Classify the URL
        result, confidence, details = model.classify_url(url)
        
        # If the result is "error", return a 400 status code
        if result == "error":
            return {
                'error': 'Invalid input',
                'details': details
            }, 400
        
        # Return successful response
        return {
            'result': result,
            'confidence': confidence,
            'url': url,
            'details': details
        }
    except Exception as e:
        app.logger.error(f"Error during URL detection: {str(e)}")
        return {
            'error': 'Processing error',
            'details': f"An error occurred during processing: {str(e)}"
        }, 500

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            return redirect(url_for('login'))
        
        # Create a dict with user data, safely handling attributes that might not exist
        user_data = {
            'email': user.email,
            'created_at': user.created_at
        }
        
        # Only add last_login if the attribute exists
        if hasattr(user, 'last_login'):
            user_data['last_login'] = user.last_login
        
        return render_template('profile.html', user_data=user_data, username=user.username)
        
    except Exception as e:
        app.logger.error(f"Error in profile route: {str(e)}")
        flash('An error occurred while loading your profile. Please try again later.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Password reset request route
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate a token
            token = secrets.token_urlsafe(32)
            expiry = datetime.utcnow() + timedelta(hours=1)
            
            # Save token to user
            user.reset_token = token
            user.reset_token_expiry = expiry
            db.session.commit()
            
            # Send email
            reset_url = url_for('reset_password', token=token, _external=True)
            
            # Check if mail configuration is available
            if app.config['MAIL_USERNAME'] and app.config['MAIL_PASSWORD']:
                try:
                    msg = Message('Password Reset Request', recipients=[email])
                    msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, simply ignore this email and no changes will be made.

This link will expire in 1 hour.
'''
                    mail.send(msg)
                    flash('Password reset instructions have been sent to your email.', 'info')
                except Exception as e:
                    app.logger.error(f"Error sending email: {e}")
                    flash('Email could not be sent. Please contact support.', 'error')
            else:
                # For development without email configuration
                flash(f'For development: Reset link is {reset_url}', 'info')
                
        else:
            # Don't reveal that the user doesn't exist
            flash('If an account with that email exists, we have sent password reset instructions.', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

# Password reset route
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    
    # Verify token is valid and not expired
    if not user or not user.reset_token_expiry or user.reset_token_expiry < datetime.utcnow():
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)
        
        # Update password and clear token
        user.password = generate_password_hash(password)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        
        flash('Your password has been updated! You can now log in with your new password.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

# Admin Dashboard routes
@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        # Check if user is admin
        current_user = User.query.get(session['user_id'])
        if not current_user or not getattr(current_user, 'is_admin', False):
            flash('You need admin privileges to access this page', 'error')
            return redirect(url_for('dashboard'))
        
        # Get all users for the admin dashboard
        users = User.query.all()
        
        # Convert datetime objects to readable format for display
        for user in users:
            # Handle last_login safely
            if hasattr(user, 'last_login') and user.last_login:
                user.last_login_formatted = user.last_login.strftime('%Y-%m-%d %H:%M:%S')
            else:
                user.last_login_formatted = 'Never'
                
            user.created_at_formatted = user.created_at.strftime('%Y-%m-%d %H:%M:%S')
            
            # Ensure is_admin attribute exists
            if not hasattr(user, 'is_admin'):
                user.is_admin = False
        
        return render_template('admin/dashboard.html', users=users)
        
    except Exception as e:
        app.logger.error(f"Error in admin dashboard: {str(e)}")
        flash('An error occurred while loading the admin dashboard. Please try again later.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/users/<int:user_id>')
def admin_user_detail(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        # Check if user is admin
        current_user = User.query.get(session['user_id'])
        if not current_user or not getattr(current_user, 'is_admin', False):
            flash('You need admin privileges to access this page', 'error')
            return redirect(url_for('dashboard'))
        
        user = User.query.get_or_404(user_id)
        
        # Format datetime fields
        if hasattr(user, 'last_login') and user.last_login:
            user.last_login_formatted = user.last_login.strftime('%Y-%m-%d %H:%M:%S')
        else:
            user.last_login_formatted = 'Never'
        
        user.created_at_formatted = user.created_at.strftime('%Y-%m-%d %H:%M:%S')
        
        # Ensure is_admin attribute exists
        if not hasattr(user, 'is_admin'):
            user.is_admin = False
        
        return render_template('admin/user_detail.html', user=user)
        
    except Exception as e:
        app.logger.error(f"Error in user detail: {str(e)}")
        flash('An error occurred while loading user details. Please try again later.', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/toggle_admin/<int:user_id>', methods=['POST'])
def toggle_admin(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        # Check if user is admin
        current_user = User.query.get(session['user_id'])
        if not current_user or not getattr(current_user, 'is_admin', False):
            flash('You need admin privileges to access this page', 'error')
            return redirect(url_for('dashboard'))
        
        user = User.query.get_or_404(user_id)
        
        # Don't allow removing admin from yourself
        if user.id == session['user_id']:
            flash('You cannot change your own admin status', 'error')
        else:
            # Ensure is_admin attribute exists
            if not hasattr(user, 'is_admin'):
                user.is_admin = False
                
            user.is_admin = not user.is_admin
            db.session.commit()
            flash(f'Admin status changed for {user.username}', 'success')
        
        return redirect(url_for('admin_dashboard'))
        
    except Exception as e:
        app.logger.error(f"Error toggling admin status: {str(e)}")
        flash('An error occurred while changing admin status. Please try again later.', 'error')
        return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True) 