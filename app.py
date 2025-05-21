from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response, send_file, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
import os
import secrets
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
import pyotp
import qrcode
import io
import base64
import hashlib
import hmac
from io import BytesIO
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from sqlalchemy import LargeBinary
from sqlalchemy.exc import OperationalError, SQLAlchemyError, IntegrityError, DatabaseError
import time
import zlib
from waitress import serve
from werkzeug.serving import make_server
from werkzeug.utils import secure_filename
from sqlalchemy import func

# Load environment variables
load_dotenv()
print(f"Loaded AES_KEY from environment: {os.environ.get('AES_KEY')}")

# Initialize Flask
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes in seconds

# MySQL Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+pymysql://{os.environ['DB_USER']}:{os.environ['DB_PASSWORD']}"
    f"@{os.environ['DB_HOST']}/{os.environ['DB_NAME']}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 5,
    'max_overflow': 10,
    'pool_timeout': 30,
    'pool_recycle': 1800,
    'pool_pre_ping': True
}
db = SQLAlchemy(app)

# OAuth Configuration
oauth = OAuth(app)
github = oauth.register(
    name='github',
    client_id=os.environ.get('GITHUB_CLIENT_ID'),
    client_secret=os.environ.get('GITHUB_CLIENT_SECRET'),
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile', 'prompt': 'select_account'}
)

auth0 = oauth.register(
    name='auth0',
    client_id=os.environ.get('AUTH0_CLIENT_ID'),
    client_secret=os.environ.get('AUTH0_CLIENT_SECRET'),
    server_metadata_url=f"{os.environ.get('AUTH0_DOMAIN')}/.well-known/openid-configuration",
    client_kwargs={'scope': 'openid profile email'}
)

# Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    auth_method = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    twofa_secret = db.Column(db.String(32))
    role = db.Column(db.String(10), nullable=False, default='user')
    parent_admin_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    parent_admin = db.relationship('User', remote_side=[id], backref='child_admins', lazy='joined')

    manual_auth = db.relationship('ManualAuth', backref='user', lazy='dynamic', cascade="all, delete-orphan", passive_deletes=True)
    github_auth = db.relationship('GitHubAuth', backref='user', lazy='dynamic', cascade="all, delete-orphan", passive_deletes=True)
    google_auth = db.relationship('GoogleAuth', backref='user', lazy='dynamic', cascade="all, delete-orphan", passive_deletes=True)
    okta_auth = db.relationship('OktaAuth', backref='user', lazy='dynamic', cascade="all, delete-orphan", passive_deletes=True)
    documents = db.relationship('Document', backref='user', lazy='joined')

    @property
    def is_admin(self):
        return self.role == 'admin'

    def has_role(self, role):
        return self.role == role

    @property
    def requires_2fa(self):
        return self.twofa_secret is not None

class ManualAuth(db.Model):
    __tablename__ = 'manual_auth'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

class GitHubAuth(db.Model):
    __tablename__ = 'github_auth'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    github_id = db.Column(db.String(50), unique=True, nullable=False)
    github_username = db.Column(db.String(50))
    github_email = db.Column(db.String(255))

class GoogleAuth(db.Model):
    __tablename__ = 'google_auth'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    google_id = db.Column(db.String(50), unique=True, nullable=False)
    google_username = db.Column(db.String(50))
    google_email = db.Column(db.String(255))

class OktaAuth(db.Model):
    __tablename__ = 'okta_auth'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    okta_id = db.Column(db.String(50), unique=True, nullable=False)
    okta_email = db.Column(db.String(255), nullable=False)
    okta_name = db.Column(db.String(100))

class LoginLog(db.Model):
    __tablename__ = 'login_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    login_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.Text)
    auth_method = db.Column(db.String(10), nullable=False)

class FailedLoginAttempt(db.Model):
    __tablename__ = 'failed_login_attempts'
    id = db.Column(db.Integer, primary_key=True)
    identifier = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    attempt_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class PendingUser(db.Model):
    __tablename__ = 'pending_users'
    id = db.Column(db.Integer, primary_key=True)
    auth_method = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    twofa_secret = db.Column(db.String(32), nullable=False)
    status = db.Column(db.String(20), default='pending')

class PendingManualAuth(db.Model):
    __tablename__ = 'pending_manual_auth'
    user_id = db.Column(db.Integer, db.ForeignKey('pending_users.id'), primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

class PendingGitHubAuth(db.Model):
    __tablename__ = 'pending_github_auth'
    user_id = db.Column(db.Integer, db.ForeignKey('pending_users.id'), primary_key=True)
    github_id = db.Column(db.String(50), unique=True, nullable=False)
    github_username = db.Column(db.String(50))
    github_email = db.Column(db.String(255))

class PendingGoogleAuth(db.Model):
    __tablename__ = 'pending_google_auth'
    user_id = db.Column(db.Integer, db.ForeignKey('pending_users.id'), primary_key=True)
    google_id = db.Column(db.String(50), unique=True, nullable=False)
    google_username = db.Column(db.String(50))
    google_email = db.Column(db.String(255))

class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    content_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(1000), nullable=True)
    sha256_hash = db.Column(db.String(64), nullable=False)
    hmac_signature = db.Column(db.String(128), nullable=False)
    digital_signature = db.Column(LargeBinary)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    chunks = db.relationship(
        'DocumentChunk',
        backref='document',
        lazy='dynamic',
        cascade="all, delete-orphan",
        passive_deletes=True
    )

class DocumentChunk(db.Model):
    __tablename__ = 'document_chunks'
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=False)
    chunk_index = db.Column(db.Integer, nullable=False)
    chunk_data = db.Column(LargeBinary, nullable=False)  # Stores Base64-encoded bytes
    checksum = db.Column(db.String(64), nullable=False, default='')

class SharedDocument(db.Model):
    __tablename__ = 'shared_documents'
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=False)
    shared_with_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    shared_at = db.Column(db.DateTime, default=datetime.utcnow)

    document = db.relationship('Document', backref='shared_with', lazy='joined')
    shared_with_user = db.relationship('User', backref='shared_documents', lazy='joined')

# --- AES and HMAC Keys from environment variables ---
AES_KEY = os.environ.get('AES_KEY')
if not AES_KEY:
    raise ValueError("AES_KEY environment variable is not set")
print(f"AES_KEY before encoding: {AES_KEY} (type: {type(AES_KEY)})")
AES_KEY = AES_KEY.encode('utf-8')[:32].ljust(32, b'\0')
print(f"AES_KEY after encoding: {AES_KEY} (type: {type(AES_KEY)})")

HMAC_KEY = os.environ.get('HMAC_KEY')
if not HMAC_KEY:
    raise ValueError("HMAC_KEY environment variable is not set")
HMAC_KEY = HMAC_KEY.encode('utf-8')
print(f"HMAC_KEY after encoding: {HMAC_KEY} (type: {type(HMAC_KEY)})")

# Load private/public keys for signing (PEM format)
try:
    with open('private_key.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    print("Private key loaded successfully")
except FileNotFoundError:
    raise FileNotFoundError("private_key.pem file not found")
except Exception as e:
    raise Exception(f"Error loading private_key.pem: {str(e)}")

try:
    with open('public_key.pem', 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    print("Public key loaded successfully")
except FileNotFoundError:
    raise FileNotFoundError("public_key.pem file not found")
except Exception as e:
    raise Exception(f"Error loading public_key.pem: {str(e)}")

# Password policy validation
def validate_password(password):
    if (len(password) < 8 or 
        not any(c.isupper() for c in password) or
        not any(c.islower() for c in password) or
        not any(c.isdigit() for c in password) or
        not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?~' for c in password)):
        return False
    return True
def is_root_id(user_id):
    return user_id == 1

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(f"Session state before route {f.__name__}: {dict(session)}")
        if 'user_id' not in session:
            flash('Please log in first', 'error')
            print(f"Redirecting to /login: User not logged in (session['user_id'] missing)")
            return redirect(url_for('login'))
        
        try:
            print("Attempting to access session['user_id']")
            user_id = session['user_id']
            print(f"Successfully accessed session['user_id']: {user_id}")
            print(f"Attempting to fetch user with ID {user_id}")
            user = db.session.get(User, user_id)
            print(f"Successfully fetched user: {user}")

            # Add a check to ensure the fetched object is a User instance
            print("Checking if fetched object is a User instance")
            if not isinstance(user, User):
                session.clear()
                flash('Invalid user session data', 'error')
                print(f"Redirecting to /login: Fetched object is not a User instance (Type: {type(user).__name__})")
                return redirect(url_for('login'))
            print("Fetched object is a User instance.")

            if not user:
                session.clear()
                flash('User not found', 'error')
                print(f"Redirecting to /login: User not found (ID: {user_id})")
                return redirect(url_for('login'))

            print("Checking if user requires 2FA")
            if user.requires_2fa and 'twofa_verified' not in session:
                flash('Please complete authentication', 'error')
                print("Redirecting to /login: 2FA verification required")
                return redirect(url_for('login'))
            print("User does not require 2FA or is verified.")

            # If successful, call the decorated function
            print(f"Calling decorated function: {f.__name__}")
            response = f(*args, **kwargs)
            print(f"Return value from decorated function {f.__name__}: Type - {type(response).__name__}, Value - {response}")
            return response

        except Exception as e:
            # Catch any unexpected errors during the decorator's execution
            session.clear()
            print(f"Unexpected error in login_required (type: {type(e).__name__}): {str(e)}")
            # Optional: log traceback for detailed debugging
            # import traceback
            # traceback.print_exc()
            flash('An unexpected error occurred. Please log in again.', 'error')
            return make_response(redirect(url_for('login')))

        except OperationalError as e:
            session.clear()
            print(f"Database connection error in login_required: {str(e)}")
            flash('Database connection error. Please try again.', 'error')
            return make_response(redirect(url_for('login')))

    return decorated_function

def no_cache(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = make_response(f(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return decorated_function

def is_account_locked(identifier):
    one_minute_ago = datetime.utcnow() - timedelta(minutes=5)
    recent_attempts = FailedLoginAttempt.query.filter(
        FailedLoginAttempt.identifier == identifier,
        FailedLoginAttempt.attempt_time >= one_minute_ago
    ).count()
    
    if recent_attempts >= 3:
        first_failed_attempt = FailedLoginAttempt.query.filter(
            FailedLoginAttempt.identifier == identifier
        ).order_by(FailedLoginAttempt.attempt_time.desc()).first()
        
        if first_failed_attempt and (datetime.utcnow() - first_failed_attempt.attempt_time) < timedelta(minutes=15):
            return True
    return False

def record_failed_attempt(identifier, ip_address):
    attempt = FailedLoginAttempt(
        identifier=identifier,
        ip_address=ip_address
    )
    db.session.add(attempt)
    db.session.commit()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(f"Session state before route {f.__name__}: {dict(session)}")
        if 'user_id' not in session:
            flash('Please log in first', 'error')
            print(f"Redirecting to /login: User not logged in (session['user_id'] missing)")
            return redirect(url_for('login'))
        
        try:
            user = db.session.get(User, session['user_id'])
            if not user or not user.is_admin:
                flash('Admin access required', 'error')
                print("Redirecting to /home: Admin access required")
                return redirect(url_for('home'))
            
            return f(*args, **kwargs)
        except Exception as e:
            session.clear()
            flash('Database error during admin validation. Please log in again.', 'error')
            print(f"Database error in admin_required: {str(e)}")
            return redirect(url_for('login'))
    return decorated_function

# --- AES Encryption/Decryption ---
def encrypt_data(data: bytes) -> bytes:
    try:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt_data(encrypted_data: bytes) -> bytes:
    try:
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        if len(iv) != 16:
            raise ValueError("Invalid IV length")
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be a multiple of 16")
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

# --- SHA-256 Hash ---
def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# --- HMAC generation & verification ---
def generate_hmac(data: bytes) -> str:
    return hmac.new(HMAC_KEY, data, hashlib.sha256).hexdigest()

def verify_hmac(data: bytes, hmac_to_verify: str) -> bool:
    expected_hmac = generate_hmac(data)
    return hmac.compare_digest(expected_hmac, hmac_to_verify)

# --- Digital signature & verification ---
def sign_document(data: bytes) -> bytes:
    signature = private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Routes
@app.route('/debug/session')
def debug_session():
    return jsonify(dict(session))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
@login_required
@no_cache
def home():
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        flash('User not found', 'error')
        print(f"Redirecting to /login: User not found (ID: {session.get('user_id', 'unknown')})")
        return redirect(url_for('login'))

    username = None
    if user.auth_method == 'manual':
        manual_auth = db.session.get(ManualAuth, user.id)
        if manual_auth:
            username = manual_auth.username
    elif user.auth_method == 'github':
        github_auth = db.session.get(GitHubAuth, user.id)
        if github_auth:
            username = github_auth.github_username
    elif user.auth_method == 'google':
        google_auth = db.session.get(GoogleAuth, user.id)
        if google_auth:
            username = google_auth.google_username
    elif user.auth_method == 'auth0':
        auth0_auth = db.session.get(OktaAuth, user.id)
        if auth0_auth:
            username = auth0_auth.okta_name or auth0_auth.okta_email

    if not username:
        session.clear()
        flash('User data incomplete', 'error')
        print("Redirecting to /login: User data incomplete")
        return redirect(url_for('login'))

    recent_logs = db.session.query(LoginLog)\
                    .filter_by(user_id=user.id)\
                    .order_by(LoginLog.login_timestamp.desc())\
                    .limit(5)\
                    .all()
    
    return render_template('home.html',
                           username=username,
                           auth_method=user.auth_method,
                           created_at=user.created_at,
                           recent_logs=recent_logs,
                           role=user.role,
                           is_admin=user.is_admin)

@app.route('/signup', methods=['GET', 'POST'])
@no_cache
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if not all([username, email, password]):
            flash('All fields are required!', 'error')
            return redirect(url_for('signup'))
        if not validate_password(password):
            flash('Password must be 8+ chars with uppercase, lowercase, number, and special char', 'error')
            return redirect(url_for('signup'))
        if ManualAuth.query.filter((ManualAuth.username == username) | (ManualAuth.email == email)).first() or \
           PendingManualAuth.query.filter((PendingManualAuth.username == username) | (PendingManualAuth.email == email)).first():
            flash('Username or email already exists', 'error')
            return redirect(url_for('signup'))
        twofa_secret = pyotp.random_base32()
        try:
            pending_user = PendingUser(
                auth_method='manual',
                twofa_secret=twofa_secret
            )
            db.session.add(pending_user)
            db.session.flush()
            pending_manual_auth = PendingManualAuth(
                user_id=pending_user.id,
                username=username,
                email=email,
                password_hash=generate_password_hash(password)
            )
            db.session.add(pending_manual_auth)
            db.session.commit()
            flash('Registration submitted! Please wait for admin approval.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Error creating account', 'error')
            return redirect(url_for('signup'))
    return render_template('signup.html')

@app.route('/setup-2fa', methods=['GET', 'POST'])
def setup_2fa():
    if 'setup_2fa_user_id' in session and 'setup_2fa_secret' in session:
        user = db.session.get(User, session['setup_2fa_user_id'])
        username = session.get('setup_2fa_username', None)
        twofa_secret = session.get('setup_2fa_secret', None)
        if not user or not username or not twofa_secret:
            session.pop('setup_2fa_user_id', None)
            session.pop('setup_2fa_username', None)
            session.pop('setup_2fa_secret', None)
            flash('Invalid 2FA setup session', 'error')
            return redirect(url_for('login'))
        if request.method == 'POST':
            otp = request.form.get('otp')
            if not otp or len(otp) != 6 or not otp.isdigit():
                flash('Invalid OTP format - must be 6 digits', 'error')
                return render_template('setup_2fa.html')
            totp = pyotp.TOTP(twofa_secret)
            if not totp.verify(otp, valid_window=1):
                flash('Invalid OTP code', 'error')
                return render_template('setup_2fa.html')
            try:
                user.twofa_secret = twofa_secret
                db.session.commit()
                session['user_id'] = user.id
                session['auth_method'] = 'manual'
                session['twofa_verified'] = True
                session.permanent = True  # Always set permanent session
                session.pop('setup_2fa_user_id', None)
                session.pop('setup_2fa_username', None)
                session.pop('setup_2fa_secret', None)
                flash('2FA setup complete! You are now logged in.', 'success')
                print(f"2FA setup: Set session['user_id'] = {user.id}")
                return redirect(url_for('home'))
            except Exception as e:
                flash('Error completing 2FA setup', 'error')
                return redirect(url_for('login'))
        otp_uri = pyotp.totp.TOTP(twofa_secret).provisioning_uri(
            name=username,
            issuer_name="Flask Auth App"
        )
        img = qrcode.make(otp_uri)
        img_io = io.BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)
        qr_code = base64.b64encode(img_io.getvalue()).decode('ascii')
        return render_template('setup_2fa.html', qr_code=qr_code, secret=twofa_secret)
    if 'signup_data' not in session:
        return redirect(url_for('signup'))
@app.route('/profile', methods=['GET', 'POST'])
@login_required
@no_cache
def profile():
    user = db.session.get(User, session['user_id'])
    if not user:
        flash('User not found', 'error')
        print(f"User not found for user_id={session['user_id']}")
        return redirect(url_for('login'))

    # Fetch current profile data based on auth method
    auth_data = None
    current_username = None
    current_email = None
    if user.auth_method == 'manual':
        auth_data = ManualAuth.query.filter_by(user_id=user.id).first()
        if auth_data:
            current_username = auth_data.username
            current_email = auth_data.email
    elif user.auth_method == 'github':
        auth_data = GitHubAuth.query.filter_by(user_id=user.id).first()
        if auth_data:
            current_username = auth_data.github_username
            current_email = auth_data.github_email
    elif user.auth_method == 'google':
        auth_data = GoogleAuth.query.filter_by(user_id=user.id).first()
        if auth_data:
            current_username = auth_data.google_username
            current_email = auth_data.google_email
    elif user.auth_method == 'auth0':
        auth_data = OktaAuth.query.filter_by(user_id=user.id).first()
        if auth_data:
            current_username = auth_data.okta_name or auth_data.okta_email
            current_email = auth_data.okta_email

    if not auth_data:
        flash('Authentication data not found', 'error')
        print(f"Auth data not found for user_id={user.id}, auth_method={user.auth_method}")
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_username = request.form.get('username', '').strip()
        new_email = request.form.get('email', '').strip()
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validate inputs
        if not new_username or not new_email:
            flash('Username and email cannot be empty', 'error')
            return redirect(url_for('profile'))

        # Check for unique username and email across all auth methods
        if user.auth_method != 'manual':
            if (ManualAuth.query.filter_by(username=new_username).first() or
                GitHubAuth.query.filter(GitHubAuth.github_username == new_username, GitHubAuth.user_id != user.id).first() or
                GoogleAuth.query.filter(GoogleAuth.google_username == new_username, GoogleAuth.user_id != user.id).first() or
                OktaAuth.query.filter(OktaAuth.okta_name == new_username, OktaAuth.user_id != user.id).first()):
                flash('Username already taken', 'error')
                return redirect(url_for('profile'))
            if (ManualAuth.query.filter_by(email=new_email).first() or
                GitHubAuth.query.filter(GitHubAuth.github_email == new_email, GitHubAuth.user_id != user.id).first() or
                GoogleAuth.query.filter(GoogleAuth.google_email == new_email, GoogleAuth.user_id != user.id).first() or
                OktaAuth.query.filter(OktaAuth.okta_email == new_email, OktaAuth.user_id != user.id).first()):
                flash('Email already in use', 'error')
                return redirect(url_for('profile'))
        else:
            if ManualAuth.query.filter(ManualAuth.username == new_username, ManualAuth.user_id != user.id).first():
                flash('Username already taken', 'error')
                return redirect(url_for('profile'))
            if ManualAuth.query.filter(ManualAuth.email == new_email, ManualAuth.user_id != user.id).first():
                flash('Email already in use', 'error')
                return redirect(url_for('profile'))

        # Handle password update (only for manual auth)
        if user.auth_method == 'manual' and new_password:
            if new_password != confirm_password:
                flash('New password and confirmation do not match', 'error')
                return redirect(url_for('profile'))
            if not validate_password(new_password):
                flash('Password must be 8+ chars with uppercase, lowercase, number, and special char', 'error')
                return redirect(url_for('profile'))
            if not check_password_hash(auth_data.password_hash, current_password):
                flash('Current password is incorrect', 'error')
                return redirect(url_for('profile'))
            auth_data.password_hash = generate_password_hash(new_password)

        # Update username and email based on auth method
        try:
            if user.auth_method == 'manual':
                auth_data.username = new_username
                auth_data.email = new_email
            elif user.auth_method == 'github':
                auth_data.github_username = new_username
                auth_data.github_email = new_email or auth_data.github_email  # Email can be nullable
            elif user.auth_method == 'google':
                auth_data.google_username = new_username
                auth_data.google_email = new_email or auth_data.google_email  # Email can be nullable
            elif user.auth_method == 'auth0':
                auth_data.okta_name = new_username
                auth_data.okta_email = new_email

            db.session.commit()
            flash('Profile updated successfully', 'success')
            print(f"Profile updated for user_id={user.id}, auth_method={user.auth_method}")
            return redirect(url_for('profile'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating profile', 'error')
            print(f"Error updating profile for user_id={user.id}: {str(e)}")
            return redirect(url_for('profile'))

    return render_template('profile.html', 
                          user=user, 
                          auth_data=auth_data, 
                          username=current_username, 
                          email=current_email)
@app.route('/login', methods=['GET', 'POST'])
@no_cache
def login():
    if request.method == 'POST':
        identifier = request.form.get('identifier')
        password = request.form.get('password')
        remember = 'remember' in request.form
        if is_account_locked(identifier):
            flash('Account temporarily locked due to too many failed attempts. Please try again in 15 minutes.', 'error')
            return redirect(url_for('login'))
        try:
            manual_auth = ManualAuth.query.filter(
                (ManualAuth.username == identifier) | 
                (ManualAuth.email == identifier)
            ).first()
            if not manual_auth:
                flash('Account not found. Please sign up first.', 'error')
                return redirect(url_for('signup'))
            if check_password_hash(manual_auth.password_hash, password):
                user = db.session.get(User, manual_auth.user_id)
                if not user:
                    flash('User not found in database', 'error')
                    print(f"User not found for manual_auth.user_id={manual_auth.user_id}")
                    return redirect(url_for('login'))

                # Check if user account is active
                if not user.is_active:
                    flash('Your account has been deactivated. Please contact an administrator.', 'error')
                    return redirect(url_for('login'))

                # Record successful manual login attempt immediately after password verification
                login_log = LoginLog(
                    user_id=user.id,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    auth_method='manual'
                )
                db.session.add(login_log)
                db.session.commit() # Commit the login log immediately

                if user.is_admin:
                    session['user_id'] = user.id
                    session['auth_method'] = 'manual'
                    session['twofa_verified'] = True
                    session.permanent = True  # Always set permanent session
                    # Login log already committed above
                    flash('Login successful!', 'success')
                    print(f"Login successful: Set session['user_id'] = {user.id}")
                    return redirect(url_for('home'))
                else:
                    # Check if user has 2FA enabled and if this is their first login
                    # We can determine first login by checking if they have *any* login logs
                    # We already added the current login log, so checking count > 1 or checking existence
                    # for previous logs will work. Let's check for logs *before* this one.
                    previous_login_logs = LoginLog.query.filter(
                        LoginLog.user_id == user.id,
                        LoginLog.id != login_log.id # Exclude the log we just added
                    ).first()

                    if user.twofa_secret and not previous_login_logs:
                        # If 2FA is enabled and no *previous* login logs exist, redirect to setup
                        # Note: The current login log HAS been recorded at this point
                        session['setup_2fa_user_id'] = user.id
                        # Need username for setup_2fa template, get it from manual_auth
                        session['setup_2fa_username'] = manual_auth.username
                        session['setup_2fa_secret'] = user.twofa_secret
                        flash('Please setup your 2FA', 'info') # Add a flash message
                        return redirect(url_for('setup_2fa'))
                    elif user.twofa_secret:
                        # If 2FA is enabled and previous login logs exist, redirect to verification
                        # The current login log has been recorded
                        session['login_data'] = {
                            'user_id': user.id,
                            'auth_method': 'manual',
                            'remember': remember
                        }
                        return redirect(url_for('verify_2fa'))
                    else:
                        # If 2FA is not enabled (should not happen for new approved users, but as a fallback)
                        session['user_id'] = user.id
                        session['auth_method'] = 'manual'
                        session['twofa_verified'] = False # 2FA not enabled
                        session.permanent = True
                        # Log the login even if no 2FA
                        login_log = LoginLog(
                            user_id=user.id,
                            ip_address=request.remote_addr,
                            user_agent=request.headers.get('User-Agent'),
                            auth_method='manual'
                        )
                        db.session.add(login_log)
                        db.session.commit()
                        flash('Login successful (2FA not enabled).', 'success')
                        print(f"Login successful (2FA not enabled): Set session['user_id'] = {user.id}")
                        return redirect(url_for('home'))
            else:
                record_failed_attempt(identifier, request.remote_addr)
                flash('Incorrect password.', 'error')
        except Exception as e:
            flash('Database error during login. Please try again.', 'error')
            print(f"Database error during login: {str(e)}")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
@no_cache
def verify_2fa():
    if 'login_data' not in session and 'github_login' not in session and 'google_login' not in session and 'okta_login' not in session:
        flash('No pending authentication', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp = request.form.get('otp')
        if not otp or len(otp) != 6 or not otp.isdigit():
            flash('Invalid OTP format - must be 6 digits', 'error')
            return redirect(request.url)
        
        try:
            if 'login_data' in session:
                user = db.session.get(User, session['login_data']['user_id'])
                if not user:
                    flash('User not found', 'error')
                    print(f"User not found for login_data.user_id={session['login_data']['user_id']}")
                    return redirect(url_for('login'))
                
                totp = pyotp.TOTP(user.twofa_secret)
                if not totp.verify(otp, valid_window=1):
                    flash('Invalid OTP code', 'error')
                    return redirect(request.url)
                
                session['user_id'] = user.id
                session['auth_method'] = session['login_data']['auth_method']
                session['twofa_verified'] = True
                session.permanent = True  # Always set permanent session
                login_log = LoginLog(
                    user_id=user.id,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    auth_method=session['login_data']['auth_method']
                )
                db.session.add(login_log)
                db.session.commit()
                
                session.pop('login_data', None)
                flash('Login successful!', 'success')
                print(f"2FA verified: Set session['user_id'] = {user.id}")
                return redirect(url_for('home'))
            
            elif 'github_login' in session:
                user = db.session.get(User, session['github_login']['user_id'])
                if not user:
                    flash('User not found', 'error')
                    print(f"User not found for github_login.user_id={session['github_login']['user_id']}")
                    return redirect(url_for('login'))
                
                totp = pyotp.TOTP(user.twofa_secret)
                if not totp.verify(otp, valid_window=1):
                    flash('Invalid OTP code', 'error')
                    return redirect(request.url)
                
                session['user_id'] = user.id
                session['auth_method'] = 'github'
                session['twofa_verified'] = True
                session.permanent = True  # Always set permanent session
                login_log = LoginLog(
                    user_id=user.id,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    auth_method='github'
                )
                db.session.add(login_log)
                db.session.commit()
                
                session.pop('github_login', None)
                flash('GitHub login successful!', 'success')
                print(f"GitHub 2FA verified: Set session['user_id'] = {user.id}")
                return redirect(url_for('home'))

            elif 'google_login' in session:
                user = db.session.get(User, session['google_login']['user_id'])
                if not user:
                    flash('User not found', 'error')
                    print(f"User not found for google_login.user_id={session['google_login']['user_id']}")
                    return redirect(url_for('login'))
                
                totp = pyotp.TOTP(user.twofa_secret)
                if not totp.verify(otp, valid_window=1):
                    flash('Invalid OTP code', 'error')
                    return redirect(request.url)
                
                session['user_id'] = user.id
                session['auth_method'] = 'google'
                session['twofa_verified'] = True
                session.permanent = True  # Always set permanent session
                login_log = LoginLog(
                    user_id=user.id,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    auth_method='google'
                )
                db.session.add(login_log)
                db.session.commit()
                
                session.pop('google_login', None)
                flash('Google login successful!', 'success')
                print(f"Google 2FA verified: Set session['user_id'] = {user.id}")
                return redirect(url_for('home'))

            elif 'auth0_login' in session:
                user = db.session.get(User, session['auth0_login']['user_id'])
                if not user:
                    flash('User not found', 'error')
                    print(f"User not found for auth0_login.user_id={session['auth0_login']['user_id']}")
                    return redirect(url_for('login'))
                
                totp = pyotp.TOTP(user.twofa_secret)
                if not totp.verify(otp, valid_window=1):
                    flash('Invalid OTP code', 'error')
                    return redirect(request.url)
                
                session['user_id'] = user.id
                session['auth_method'] = 'auth0'
                session['twofa_verified'] = True
                session.permanent = True  # Always set permanent session
                login_log = LoginLog(
                    user_id=user.id,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    auth_method='auth0'
                )
                db.session.add(login_log)
                db.session.commit()
                
                session.pop('auth0_login', None)
                flash('Auth0 login successful!', 'success')
                print(f"Auth0 2FA verified: Set session['user_id'] = {user.id}")
                return redirect(url_for('home'))
        except Exception as e:
            flash('Database error during 2FA verification. Please try again.', 'error')
            print(f"Database error during 2FA verification: {str(e)}")
            return redirect(url_for('login'))
    
    return render_template('verify_2fa.html')

@app.route('/login/github')
@no_cache
def login_github():
    redirect_uri = url_for('authorize_github', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/login/github/callback')
@no_cache
def authorize_github():
    try:
        token = github.authorize_access_token()
        resp = github.get('user', token=token)
        profile = resp.json()
        
        github_auth = GitHubAuth.query.filter_by(github_id=str(profile['id'])).first()
        
        if github_auth:
            user = db.session.get(User, github_auth.user_id)
            if not user.is_active:
                flash('Your account has been deactivated. Please contact an administrator.', 'error')
                return redirect(url_for('login'))
            session['github_login'] = {
                'user_id': github_auth.user_id,
                'auth_method': 'github'
            }
            return redirect(url_for('verify_2fa'))
        else:
            twofa_secret = pyotp.random_base32()
            session['github_signup'] = {
                'github_id': str(profile['id']),
                'github_username': profile['login'],
                'github_email': profile.get('email'),
                'twofa_secret': twofa_secret
            }
            return redirect(url_for('setup_github_2fa'))
    
    except Exception as e:
        flash('GitHub login failed', 'error')
        return redirect(url_for('login'))

@app.route('/setup-github-2fa', methods=['GET', 'POST'])
def setup_github_2fa():
    if 'github_signup' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp = request.form.get('otp')
        if not otp or len(otp) != 6 or not otp.isdigit():
            flash('Invalid OTP format - must be 6 digits', 'error')
            return render_template('setup_2fa.html')
        
        totp = pyotp.TOTP(session['github_signup']['twofa_secret'])
        if not totp.verify(otp, valid_window=1):
            flash('Invalid OTP code', 'error')
            return render_template('setup_2fa.html')
        
        try:
            user = User(
                auth_method='github',
                twofa_secret=session['github_signup']['twofa_secret']
            )
            db.session.add(user)
            db.session.flush()
            
            github_auth = GitHubAuth(
                user_id=user.id,
                github_id=session['github_signup']['github_id'],
                github_username=session['github_signup']['github_username'],
                github_email=session['github_signup']['github_email']
            )
            db.session.add(github_auth)
            
            login_log = LoginLog(
                user_id=user.id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                auth_method='github'
            )
            db.session.add(login_log)
            
            db.session.commit()
            
            session['user_id'] = user.id
            session['auth_method'] = 'github'
            session['twofa_verified'] = True
            session.permanent = True  # Always set permanent session
            session.pop('github_signup', None)
            
            flash('GitHub account linked successfully!', 'success')
            print(f"GitHub signup: Set session['user_id'] = {user.id}")
            return redirect(url_for('home'))
            
        except Exception as e:
            db.session.rollback()
            flash('Error creating GitHub account', 'error')
            return redirect(url_for('login'))
    
    otp_uri = pyotp.totp.TOTP(session['github_signup']['twofa_secret']).provisioning_uri(
        name=session['github_signup']['github_username'],
        issuer_name="Flask Auth App"
    )
    img = qrcode.make(otp_uri)
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    qr_code = base64.b64encode(img_io.getvalue()).decode('ascii')
    
    return render_template('setup_2fa.html', 
                           qr_code=qr_code, 
                           secret=session['github_signup']['twofa_secret'])

@app.route('/login/google')
@no_cache
def login_google():
    if not os.environ.get('GOOGLE_CLIENT_ID') or not os.environ.get('GOOGLE_CLIENT_SECRET'):
        print("Google OAuth credentials not found in environment variables")
        flash('Google login is not configured properly', 'error')
        return redirect(url_for('login'))
    try:
        redirect_uri = url_for('authorize_google', _external=True)
        return google.authorize_redirect(redirect_uri)
    except Exception as e:
        print(f"Error in Google login redirect: {str(e)}")
        flash('Error during Google login', 'error')
        return redirect(url_for('login'))

@app.route('/login/google/callback')
@no_cache
def authorize_google():
    try:
        token = google.authorize_access_token()
        if not token:
            print("No token received from Google")
            flash('Failed to get authentication token from Google', 'error')
            return redirect(url_for('login'))
        resp = google.get(google.server_metadata['userinfo_endpoint'], token=token)
        if not resp:
            print("Failed to get user info from Google")
            flash('Failed to get user information from Google', 'error')
            return redirect(url_for('login'))
        user_info = resp.json()
        print(f"Google user info received: {user_info}")
        google_auth = GoogleAuth.query.filter_by(google_id=user_info['sub']).first()
        if google_auth:
            user = db.session.get(User, google_auth.user_id)
            if not user.is_active:
                flash('Your account has been deactivated. Please contact an administrator.', 'error')
                return redirect(url_for('login'))
            session['google_login'] = {
                'user_id': google_auth.user_id,
                'auth_method': 'google'
            }
            return redirect(url_for('verify_2fa'))
        else:
            twofa_secret = pyotp.random_base32()
            session['google_signup'] = {
                'google_id': user_info['sub'],
                'google_username': user_info.get('name'),
                'google_email': user_info.get('email'),
                'twofa_secret': twofa_secret
            }
            return redirect(url_for('setup_google_2fa'))
    except Exception as e:
        print(f"Detailed Google login error: {str(e)}")
        flash('Google login failed. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/setup-google-2fa', methods=['GET', 'POST'])
def setup_google_2fa():
    if 'google_signup' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp = request.form.get('otp')
        if not otp or len(otp) != 6 or not otp.isdigit():
            flash('Invalid OTP format - must be 6 digits', 'error')
            return render_template('setup_2fa.html')
        
        totp = pyotp.TOTP(session['google_signup']['twofa_secret'])
        if not totp.verify(otp, valid_window=1):
            flash('Invalid OTP code', 'error')
            return render_template('setup_2fa.html')
        
        try:
            user = User(
                auth_method='google',
                twofa_secret=session['google_signup']['twofa_secret']
            )
            db.session.add(user)
            db.session.flush()
            
            google_auth = GoogleAuth(
                user_id=user.id,
                google_id=session['google_signup']['google_id'],
                google_username=session['google_signup']['google_username'],
                google_email=session['google_signup']['google_email']
            )
            db.session.add(google_auth)
            
            login_log = LoginLog(
                user_id=user.id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                auth_method='google'
            )
            db.session.add(login_log)
            
            db.session.commit()
            
            session['user_id'] = user.id
            session['auth_method'] = 'google'
            session['twofa_verified'] = True
            session.permanent = True  # Always set permanent session
            session.pop('google_signup', None)
            
            flash('Google account linked successfully!', 'success')
            print(f"Google signup: Set session['user_id'] = {user.id}")
            return redirect(url_for('home'))
            
        except Exception as e:
            db.session.rollback()
            flash('Error creating Google account', 'error')
            return redirect(url_for('login'))
    
    otp_uri = pyotp.totp.TOTP(session['google_signup']['twofa_secret']).provisioning_uri(
        name=session['google_signup']['google_email'],
        issuer_name="Flask Auth App"
    )
    img = qrcode.make(otp_uri)
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    qr_code = base64.b64encode(img_io.getvalue()).decode('ascii')
    
    return render_template('setup_2fa.html', 
                           qr_code=qr_code, 
                           secret=session['google_signup']['twofa_secret'])

@app.route('/login/auth0')
@no_cache
def login_auth0():
    redirect_uri = url_for('authorize_auth0', _external=True)
    print("Redirect URI for Auth0:", redirect_uri)
    return auth0.authorize_redirect(redirect_uri)

@app.route('/login/auth0/callback')
@no_cache
def authorize_auth0():
    try:
        token = auth0.authorize_access_token()
        resp = auth0.get(auth0.server_metadata['userinfo_endpoint'])
        userinfo = resp.json()
        print("Auth0 userinfo:", userinfo)
        from sqlalchemy.orm.exc import NoResultFound
        auth0_auth = None
        try:
            auth0_auth = db.session.query(OktaAuth).filter_by(okta_id=userinfo['sub']).one()
        except NoResultFound:
            auth0_auth = None
        if auth0_auth:
            user = db.session.get(User, auth0_auth.user_id)
            if not user.is_active:
                flash('Your account has been deactivated. Please contact an administrator.', 'error')
                return redirect(url_for('login'))
            session['auth0_login'] = {
                'user_id': auth0_auth.user_id,
                'auth_method': 'auth0'
            }
            return redirect(url_for('verify_2fa'))
        else:
            twofa_secret = pyotp.random_base32()
            session['auth0_signup'] = {
                'auth0_id': userinfo['sub'],
                'auth0_email': userinfo.get('email'),
                'auth0_name': userinfo.get('name'),
                'twofa_secret': twofa_secret
            }
            return redirect(url_for('setup_auth0_2fa'))
    except Exception as e:
        import traceback
        print("Auth0 login error:", str(e))
        traceback.print_exc()
        flash('Auth0 login failed. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/setup-auth0-2fa', methods=['GET', 'POST'])
def setup_auth0_2fa():
    if 'auth0_signup' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        otp = request.form.get('otp')
        if not otp or len(otp) != 6 or not otp.isdigit():
            flash('Invalid OTP format - must be 6 digits', 'error')
            return render_template('setup_2fa.html')
        totp = pyotp.TOTP(session['auth0_signup']['twofa_secret'])
        if not totp.verify(otp, valid_window=1):
            flash('Invalid OTP code', 'error')
            return render_template('setup_2fa.html')
        try:
            user = User(
                auth_method='auth0',
                twofa_secret=session['auth0_signup']['twofa_secret']
            )
            db.session.add(user)
            db.session.flush()
            okta_auth = OktaAuth(
                user_id=user.id,
                okta_id=session['auth0_signup']['auth0_id'],
                okta_email=session['auth0_signup']['auth0_email'],
                okta_name=session['auth0_signup']['auth0_name']
            )
            db.session.add(okta_auth)
            login_log = LoginLog(
                user_id=user.id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                auth_method='auth0'
            )
            db.session.add(login_log)
            db.session.commit()
            session['user_id'] = user.id
            session['auth_method'] = 'auth0'
            session['twofa_verified'] = True
            session.permanent = True  # Always set permanent session
            session.pop('auth0_signup', None)
            flash('Auth0 account linked successfully!', 'success')
            print(f"Auth0 signup: Set session['user_id'] = {user.id}")
            return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            import traceback
            traceback.print_exc()
            flash('Error creating Auth0 account', 'error')
            return redirect(url_for('login'))
    otp_uri = pyotp.totp.TOTP(session['auth0_signup']['twofa_secret']).provisioning_uri(
        name=session['auth0_signup']['auth0_email'],
        issuer_name="Flask Auth App"
    )
    img = qrcode.make(otp_uri)
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    qr_code = base64.b64encode(img_io.getvalue()).decode('ascii')
    return render_template('setup_2fa.html', 
                          qr_code=qr_code, 
                          secret=session['auth0_signup']['twofa_secret'])

@app.route('/logout')
@no_cache
def logout():
    print(f"Session state before logout: {dict(session)}")
    session.clear()
    print(f"Session state after logout: {dict(session)}")
    flash('You have been logged out', 'info')
    response = make_response(redirect(url_for('login')))
    response.set_cookie('session', '', expires=0)  # Invalidate session cookie
    return response

@app.route('/api/check_username/<username>')
def check_username(username):
    exists = ManualAuth.query.filter_by(username=username).first() is not None
    return jsonify({'available': not exists})

@app.route('/api/search_users', methods=['GET'])
@login_required
@no_cache
def search_users():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])

    # Search for users by username or email across different auth methods
    # Limit the number of results to avoid large responses
    limit = 10

    manual_users = ManualAuth.query.filter(
        (ManualAuth.username.ilike(f'%{query}%')) | 
        (ManualAuth.email.ilike(f'%{query}%'))
    ).limit(limit).all()

    github_users = GitHubAuth.query.filter(
        (GitHubAuth.github_username.ilike(f'%{query}%')) | 
        (GitHubAuth.github_email.ilike(f'%{query}%'))
    ).limit(limit).all()

    google_users = GoogleAuth.query.filter(
        (GoogleAuth.google_username.ilike(f'%{query}%')) | 
        (GoogleAuth.google_email.ilike(f'%{query}%'))
    ).limit(limit).all()

    okta_users = OktaAuth.query.filter(
         (OktaAuth.okta_name.ilike(f'%{query}%')) | 
         (OktaAuth.okta_email.ilike(f'%{query}%'))
     ).limit(limit).all()

    results = []
    current_user_id = session.get('user_id')

    for user_auth in manual_users + github_users + google_users + okta_users:
        # Avoid including the current user in search results
        user = None
        if isinstance(user_auth, ManualAuth):
            user = db.session.get(User, user_auth.user_id)
        elif isinstance(user_auth, GitHubAuth):
             user = db.session.get(User, user_auth.user_id)
        elif isinstance(user_auth, GoogleAuth):
             user = db.session.get(User, user_auth.user_id)
        elif isinstance(user_auth, OktaAuth):
             user = db.session.get(User, user_auth.user_id)
             
        if user and user.id != current_user_id:
             identifier = None
             if isinstance(user_auth, ManualAuth):
                  identifier = user_auth.username  # Or email, depending on preference
             elif isinstance(user_auth, GitHubAuth):
                  identifier = user_auth.github_username or user_auth.github_email
             elif isinstance(user_auth, GoogleAuth):
                  identifier = user_auth.google_username or user_auth.google_email
             elif isinstance(user_auth, OktaAuth):
                  identifier = user_auth.okta_name or user_auth.okta_email

             if identifier:
                  results.append({'id': user.id, 'identifier': identifier})

    # Remove duplicates if any (e.g., same user with different auth methods matching query)
    # Convert to list of tuples for uniqueness check, then back to list of dicts
    unique_results = list(dict(t) for t in {tuple(d.items()) for d in results})

    return jsonify(unique_results)

@app.route('/admin/dashboard')
@login_required
@admin_required
@no_cache
def admin_dashboard():
    total_users = User.query.count()
    twofa_users = User.query.filter(User.twofa_secret.isnot(None)).count()
    pending_count = PendingUser.query.filter_by(status='pending').count()
    today = datetime.utcnow().date()
    todays_logins = LoginLog.query.filter(
        db.func.date(LoginLog.login_timestamp) == today
    ).count()
    recent_logs = LoginLog.query.order_by(
        LoginLog.login_timestamp.desc()
    ).limit(10).all()
    auth_stats = {
        'manual': User.query.filter_by(auth_method='manual').count(),
        'github': User.query.filter_by(auth_method='github').count(),
        'google': User.query.filter_by(auth_method='google').count()
    }
    # Document stats
    total_documents = Document.query.count()
    documents_today = Document.query.filter(func.date(Document.upload_date) == today).count()
    documents_this_month = Document.query.filter(func.extract('year', Document.upload_date) == today.year, func.extract('month', Document.upload_date) == today.month).count()
    # Uploads per day (last 30 days)
    last_30_days = [today - timedelta(days=i) for i in range(29, -1, -1)]
    uploads_per_day = []
    for day in last_30_days:
        count = Document.query.filter(func.date(Document.upload_date) == day).count()
        uploads_per_day.append({'date': day.strftime('%Y-%m-%d'), 'count': count})
    # File type distribution
    file_types = ['pdf', 'docx', 'txt']
    file_type_counts = {}
    for ext in file_types:
        file_type_counts[ext] = Document.query.filter(Document.filename.ilike(f'%.{ext}')).count()
    return render_template('admin/dashboard.html',
                           total_users=total_users,
                           twofa_users=twofa_users,
                           pending_count=pending_count,
                           todays_logins=todays_logins,
                           recent_logs=recent_logs,
                           auth_stats=auth_stats,
                           total_documents=total_documents,
                           documents_today=documents_today,
                           documents_this_month=documents_this_month,
                           uploads_per_day=uploads_per_day,
                           file_type_counts=file_type_counts
    )
@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = db.session.get(User, user_id)
    current_user = db.session.get(User, session['user_id'])
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('manage_users'))
    # If editing an admin, only parent or root can edit
    if user.role == 'admin' and not (current_user.id == 1 or user.parent_admin_id == current_user.id):
        flash("You do not have permission to edit this admin.", "error")
        return redirect(url_for('manage_users'))
    if user.id == 1:
        flash("Cannot edit root admin.", "error")
        return redirect(url_for('manage_users'))
    if request.method == 'POST':
        new_role = request.form.get('role')
        promote_to_admin = request.form.get('promote_to_admin') == 'true'
        if user.role == 'user' and promote_to_admin:
            user.role = 'admin'
            user.parent_admin_id = current_user.id
        elif new_role in ['admin', 'user']:
            # Only parent or root can change role of an admin
            if user.role == 'admin' and not (current_user.id == 1 or user.parent_admin_id == current_user.id):
                flash("You do not have permission to change this admin's role.", "error")
                return redirect(url_for('manage_users'))
            user.role = new_role
            if new_role == 'user':
                user.parent_admin_id = None
        db.session.commit()
        flash("User role updated successfully.", "success")
        return redirect(url_for('manage_users'))
    manual_auth = ManualAuth.query.filter_by(user_id=user.id).first() if user.auth_method == 'manual' else None
    return render_template('admin/edit_user.html', user=user, manual_auth=manual_auth)

@app.route('/admin/user/<int:user_id>/delete', methods=['GET'])
@login_required
@admin_required
def delete_user(user_id):
    user = db.session.get(User, user_id)
    current_user = db.session.get(User, session['user_id'])
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('manage_users'))
    if user.id == 1:
        flash("Cannot delete root admin.", "error")
        return redirect(url_for('manage_users'))
    if user.role == 'admin' and not (current_user.id == 1 or user.parent_admin_id == current_user.id):
        flash("You do not have permission to delete this admin.", "error")
        return redirect(url_for('manage_users'))
    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully.", "success")
    return redirect(url_for('manage_users'))


@app.route('/admin/users')
@login_required
@admin_required
@no_cache
def manage_users():
    users = db.session.query(User).all()
    return render_template('admin/manage_users.html', users=users)

@app.route('/admin/logs')
@login_required
@admin_required
@no_cache
def view_logs():
    logs = db.session.query(LoginLog)\
            .order_by(LoginLog.login_timestamp.desc())\
            .all()
    return render_template('admin/view_logs.html', logs=logs)
@app.route('/admin/security')
@login_required
@admin_required
@no_cache
def security_settings():
    settings = {
        'min_password_length': 8,
        'require_uppercase': True,
        'require_numbers': True,
        'require_special': True,
        'max_login_attempts': 3,
        'lockout_duration': 15,
        'session_timeout': 30,
        'enforce_2fa': False,
        'github_enabled': bool(os.environ.get('GITHUB_CLIENT_ID')),
        'github_client_id': os.environ.get('GITHUB_CLIENT_ID', ''),
        'github_client_secret': os.environ.get('GITHUB_CLIENT_SECRET', ''),
        'google_enabled': bool(os.environ.get('GOOGLE_CLIENT_ID')),
        'google_client_id': os.environ.get('GOOGLE_CLIENT_ID', ''),
        'google_client_secret': os.environ.get('GOOGLE_CLIENT_SECRET', ''),
        'auth0_enabled': bool(os.environ.get('AUTH0_CLIENT_ID')),
        'auth0_domain': os.environ.get('AUTH0_DOMAIN', ''),
        'auth0_client_id': os.environ.get('AUTH0_CLIENT_ID', ''),
        'auth0_client_secret': os.environ.get('AUTH0_CLIENT_SECRET', '')
    }
    return render_template('admin/security_settings.html', settings=settings)

@app.route('/admin/security/password-policy', methods=['POST'])
@login_required
@admin_required
@no_cache
def update_password_policy():
    flash('Password policy updated successfully', 'success')
    return redirect(url_for('security_settings'))

@app.route('/admin/security/login-security', methods=['POST'])
@login_required
@admin_required
@no_cache
def update_login_security():
    flash('Login security settings updated successfully', 'success')
    return redirect(url_for('security_settings'))

@app.route('/admin/security/github-oauth', methods=['POST'])
@login_required
@admin_required
@no_cache
def update_github_oauth():
    flash('GitHub OAuth settings updated successfully', 'success')
    return redirect(url_for('security_settings'))

@app.route('/admin/security/google-oauth', methods=['POST'])
@login_required
@admin_required
@no_cache
def update_google_oauth():
    flash('Google OAuth settings updated successfully', 'success')
    return redirect(url_for('security_settings'))

@app.route('/admin/security/auth0-oauth', methods=['POST'])
@login_required
@admin_required
@no_cache
def update_auth0_oauth():
    flash('Auth0 OAuth settings updated successfully', 'success')
    return redirect(url_for('security_settings'))

@app.route('/admin/pending-registrations')
@login_required
@admin_required
@no_cache
def pending_registrations():
    pending_users = db.session.query(PendingUser).filter_by(status='pending').all()
    pending_details = []
    
    for pending_user in pending_users:
        details = {'user': pending_user, 'auth_details': None}
        if pending_user.auth_method == 'manual':
            details['auth_details'] = PendingManualAuth.query.get(pending_user.id)
        elif pending_user.auth_method == 'github':
            details['auth_details'] = PendingGitHubAuth.query.get(pending_user.id)
        elif pending_user.auth_method == 'google':
            details['auth_details'] = PendingGoogleAuth.query.get(pending_user.id)
        pending_details.append(details)
    
    return render_template('admin/pending_registrations.html', pending_details=pending_details)

@app.route('/admin/process-registration/<int:user_id>/<action>')
@login_required
@admin_required
@no_cache
def process_registration(user_id, action):
    if action not in ['approve', 'decline']:
        flash('Invalid action', 'error')
        return redirect(url_for('pending_registrations'))
    pending_user = PendingUser.query.get_or_404(user_id)
    make_admin = request.args.get('make_admin', 'false') == 'true'
    try:
        if action == 'approve':
            user = User(
                auth_method=pending_user.auth_method,
                twofa_secret=pending_user.twofa_secret,  # Use the secret from pending_users
                role='admin' if make_admin else 'user',
                parent_admin_id=session['user_id'] if make_admin else None
            )
            db.session.add(user)
            db.session.flush()
            
            if pending_user.auth_method == 'manual':
                pending_auth = PendingManualAuth.query.get(pending_user.id)
                manual_auth = ManualAuth(
                    user_id=user.id,
                    username=pending_auth.username,
                    email=pending_auth.email,
                    password_hash=pending_auth.password_hash
                )
                db.session.add(manual_auth)
                # DELETE the pending record after moving
                db.session.delete(pending_auth)
            
            elif pending_user.auth_method == 'github':
                pending_auth = PendingGitHubAuth.query.get(pending_user.id)
                github_auth = GitHubAuth(
                    user_id=user.id,
                    github_id=pending_auth.github_id,
                    github_username=pending_auth.github_username,
                    github_email=pending_auth.github_email
                )
                db.session.add(github_auth)
            
            elif pending_user.auth_method == 'google':
                pending_auth = PendingGoogleAuth.query.get(pending_user.id)
                google_auth = GoogleAuth(
                    user_id=user.id,
                    google_id=pending_auth.google_id,
                    google_username=pending_auth.google_username,
                    google_email=pending_auth.google_email
                )
                db.session.add(google_auth)
            
            pending_user.status = 'approved'
            flash('Registration approved successfully', 'success')
            
        else:
            # On decline, also delete the pending auth record
            if pending_user.auth_method == 'manual':
                pending_auth = PendingManualAuth.query.get(pending_user.id)
                if pending_auth:
                    db.session.delete(pending_auth)
            # ... (similar for github/google if needed) ...
            pending_user.status = 'declined'
            flash('Registration declined', 'success')
        
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        flash('Error processing registration', 'error')
    
    return redirect(url_for('pending_registrations'))

@app.route('/documents')
@login_required
@no_cache
def list_documents():
    user_id = session['user_id']
    user = db.session.get(User, user_id)

    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))

    if user.is_admin:
        # Advanced search filters
        filename = request.args.get('filename', '').strip()
        owner = request.args.get('owner', '').strip()
        filetype = request.args.get('filetype', '').strip()
        date = request.args.get('date', '').strip()

        # Start query
        query = Document.query
        # Join with User for owner search
        query = query.join(User)
        # Apply filters
        if filename:
            query = query.filter(Document.filename.ilike(f'%{filename}%'))
        if filetype:
            query = query.filter(Document.filename.ilike(f'%.{filetype}'))
        if date:
            query = query.filter(db.func.date(Document.upload_date) == date)
        if owner:
            # Search in all auth tables
            user_ids = set()
            # Manual
            manual_users = ManualAuth.query.filter(ManualAuth.username.ilike(f'%{owner}%')).all()
            user_ids.update([u.user_id for u in manual_users])
            # GitHub
            github_users = GitHubAuth.query.filter(GitHubAuth.github_username.ilike(f'%{owner}%')).all()
            user_ids.update([u.user_id for u in github_users])
            # Google
            google_users = GoogleAuth.query.filter(GoogleAuth.google_username.ilike(f'%{owner}%')).all()
            user_ids.update([u.user_id for u in google_users])
            # Okta/Auth0
            okta_users = OktaAuth.query.filter(OktaAuth.okta_name.ilike(f'%{owner}%')).all()
            user_ids.update([u.user_id for u in okta_users])
            if user_ids:
                query = query.filter(Document.user_id.in_(user_ids))
            else:
                # No match, return empty
                return render_template('documents_list.html', documents=[], shared_documents=[], is_admin=True)
        documents = query.all()
        # Get usernames for each document
        document_details = []
        for doc in documents:
            username = None
            if doc.user:
                if doc.user.auth_method == 'manual':
                    manual_auth = ManualAuth.query.filter_by(user_id=doc.user_id).first()
                    if manual_auth:
                        username = manual_auth.username
                elif doc.user.auth_method == 'github':
                    github_auth = GitHubAuth.query.filter_by(user_id=doc.user_id).first()
                    if github_auth:
                        username = github_auth.github_username
                elif doc.user.auth_method == 'google':
                    google_auth = GoogleAuth.query.filter_by(user_id=doc.user_id).first()
                    if google_auth:
                        username = google_auth.google_username
                elif doc.user.auth_method == 'auth0':
                    okta_auth = OktaAuth.query.filter_by(user_id=doc.user_id).first()
                    if okta_auth:
                        username = okta_auth.okta_name or okta_auth.okta_email
            document_details.append({
                'document': doc,
                'username': username or 'Unknown'
            })
        shared_documents_details = []
        return render_template('documents_list.html', 
                               documents=document_details, 
                               shared_documents=shared_documents_details, 
                               is_admin=True)
    else:
        # Regular users can only see their own documents
        owned_documents = Document.query.filter_by(user_id=user_id).all()
        shared_documents = SharedDocument.query.filter_by(shared_with_user_id=user_id).all()
        return render_template('documents_list.html', 
                               documents=owned_documents, 
                               shared_documents=shared_documents, 
                               is_admin=False)

@app.route('/documents/upload', methods=['GET', 'POST'])
@login_required
@no_cache
def upload_document():
    if request.method == 'POST':
        file = request.files.get('document')
        custom_filename = request.form.get('filename', '').strip()
        description = request.form.get('description', '').strip()

        if not file or file.filename == '':
            flash('No file selected', 'error')
            print("Redirecting to /documents/upload: No file selected")
            return redirect(request.url)

        # Validate file type (PDF, DOCX, TXT)
        allowed_extensions = {'.pdf', '.docx', '.txt'}
        file_ext = os.path.splitext(file.filename)[1].lower()
        if file_ext not in allowed_extensions:
            flash('Invalid file type. Only PDF, DOCX, and TXT are allowed.', 'error')
            print(f"Redirecting to /documents/upload: Invalid file type ({file_ext})")
            return redirect(request.url)

        # Determine the filename to use
        if custom_filename:
            # Ensure the custom filename has the correct extension
            custom_ext = os.path.splitext(custom_filename)[1].lower()
            if custom_ext and custom_ext != file_ext:
                flash('Custom filename extension must match file type.', 'error')
                print(f"Redirecting to /documents/upload: Custom filename extension mismatch ({custom_ext} vs {file_ext})")
                return redirect(request.url)
            if not custom_ext:
                custom_filename = custom_filename + file_ext
            # Sanitize custom filename
            custom_filename = secure_filename(custom_filename)
            if not custom_filename:
                flash('Invalid custom filename.', 'error')
                print("Redirecting to /documents/upload: Invalid custom filename")
                return redirect(request.url)
            final_filename = custom_filename
        else:
            final_filename = secure_filename(file.filename)

        # Validate description length (e.g., max 1000 characters)
        if len(description) > 1000:
            flash('Description too long. Maximum 1000 characters allowed.', 'error')
            print(f"Redirecting to /documents/upload: Description too long ({len(description)} characters)")
            return redirect(request.url)

        # Set a file size limit (e.g., 20MB)
        MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        if file_size > MAX_FILE_SIZE:
            flash(f'File too large. Maximum size is {MAX_FILE_SIZE / (1024 * 1024)}MB.', 'error')
            print(f"Redirecting to /documents/upload: File too large ({file_size} bytes)")
            return redirect(request.url)
        file.seek(0)

        # Stream the file data in chunks
        CHUNK_SIZE = 8192
        data_chunks = []
        total_size = 0
        while True:
            chunk = file.read(CHUNK_SIZE)
            if not chunk:
                break
            data_chunks.append(chunk)
            total_size += len(chunk)
        if total_size == 0:
            flash('File is empty', 'error')
            print("Redirecting to /documents/upload: File is empty")
            return redirect(request.url)

        data = b''.join(data_chunks)

        # Compress the data (skip for .pdf files)
        if file_ext == '.pdf':
            print(f"Skipping compression for PDF file: {final_filename}")
            compressed_data = data  # Skip compression
        else:
            compressed_data = zlib.compress(data, level=9)
            print(f"Original size: {len(data)} bytes, Compressed size: {len(compressed_data)} bytes")

        # Split the data into smaller chunks (e.g., 256KB each) before encryption
        CHUNK_SIZE = 256 * 1024  # 256KB
        data_chunks = [compressed_data[i:i + CHUNK_SIZE] for i in range(0, len(compressed_data), CHUNK_SIZE)]
        print(f"Split data into {len(data_chunks)} chunks before encryption")

        # Encrypt each chunk individually
        encrypted_chunks = []
        for chunk in data_chunks:
            try:
                encrypted_chunk = encrypt_data(chunk)
                encrypted_chunks.append(encrypted_chunk)
            except ValueError as e:
                flash(f'Error encrypting chunk: {str(e)}', 'error')
                print(f"Redirecting to /documents/upload: Encryption error - {str(e)}")
                return redirect(request.url)

        # Compute SHA-256 and HMAC on the compressed data (before splitting)
        sha256 = sha256_hash(compressed_data)
        # Compute HMAC on the concatenated encrypted chunks
        encrypted_data = b''.join(encrypted_chunks)
        hmac_signature = generate_hmac(encrypted_data)
        digital_signature = sign_document(encrypted_data)
        print(f"Generated HMAC during upload: {hmac_signature}")

        # Save the document and chunks
        document_id = None
        retries = 3
        for attempt in range(retries):
            try:
                document = Document(
                    user_id=session['user_id'],
                    filename=final_filename,
                    description=description if description else None,
                    content_type=file.content_type,
                    sha256_hash=sha256,
                    hmac_signature=hmac_signature,
                    digital_signature=digital_signature
                )
                db.session.add(document)
                db.session.flush()
                document_id = document.id

                # Save chunks with checksums
                for index, chunk in enumerate(encrypted_chunks):
                    chunk_checksum = hashlib.sha256(chunk).hexdigest()
                    chunk_encoded = base64.b64encode(chunk)
                    print(f"Chunk {index}: Base64-encoded data (before storage): {chunk_encoded[:50]}... (length: {len(chunk_encoded)} bytes)")
                    document_chunk = DocumentChunk(
                        document_id=document_id,
                        chunk_index=index,
                        chunk_data=chunk_encoded,
                        checksum=chunk_checksum
                    )
                    db.session.add(document_chunk)
                    db.session.flush()
                    # Verify the stored chunk
                    saved_chunk = DocumentChunk.query.filter_by(document_id=document_id, chunk_index=index).first()
                    print(f"Chunk {index}: Base64-encoded data (after storage): {saved_chunk.chunk_data[:50]}... (length: {len(saved_chunk.chunk_data)} bytes)")
                    try:
                        saved_chunk_decoded = base64.b64decode(saved_chunk.chunk_data)
                        saved_checksum = hashlib.sha256(saved_chunk_decoded).hexdigest()
                        print(f"Chunk {index}: Original checksum: {chunk_checksum}, Stored checksum: {saved_chunk.checksum}, Recomputed checksum: {saved_checksum}")
                        if saved_checksum != chunk_checksum:
                            raise Exception(f"Chunk {index} integrity check failed after saving")
                    except base64.binascii.Error as e:
                        db.session.rollback()
                        raise Exception(f"Chunk {index} stored data is corrupted, cannot decode as Base64: {str(e)}")

                db.session.commit()
                saved_document = Document.query.filter_by(id=document_id).first()
                if not saved_document:
                    raise Exception("Document was not persisted to the database after commit")
                saved_chunks = DocumentChunk.query.filter_by(document_id=document_id).count()
                if saved_chunks != len(encrypted_chunks):
                    raise Exception(f"Expected {len(encrypted_chunks)} chunks, but found {saved_chunks}")
                flash('Document uploaded and secured successfully', 'success')
                print(f"Redirecting to /documents: Upload successful (Document ID: {document_id}, Chunks: {len(encrypted_chunks)}, Filename: {final_filename}, Description: {description[:50] + '...' if description else 'None'})")
                return redirect(url_for('list_documents'))
            except OperationalError as e:
                if ("MySQL server has gone away" in str(e) or "Lost connection to MySQL server during query" in str(e)) and attempt < retries - 1:
                    print(f"Connection error on attempt {attempt + 1}: {str(e)}. Retrying...")
                    db.session.rollback()
                    time.sleep(1)
                    continue
                db.session.rollback()
                flash(f'Error uploading document: Database connection error - {str(e)}', 'error')
                print(f"Redirecting to /documents/upload: Upload error - {str(e)}")
                return redirect(request.url)
            except Exception as e:
                db.session.rollback()
                flash(f'Error uploading document: {str(e)}', 'error')
                print(f"Redirecting to /documents/upload: Upload error - {str(e)}")
                return redirect(request.url)

        # If all retries fail
        flash('Error uploading document: Maximum retries exceeded', 'error')
        print("Redirecting to /documents/upload: Maximum retries exceeded")
        return redirect(request.url)

    # For GET requests or if POST processing doesn't result in a redirect
    return render_template('upload_document.html')

@app.route('/documents/download/<int:doc_id>')
@login_required
@no_cache
def download_document(doc_id):
    print(f"Starting download for document ID {doc_id}")
    document = Document.query.get_or_404(doc_id)
    user = db.session.get(User, session['user_id'])
    
    # Allow access if user owns the document or is an admin
    is_shared_with_user = SharedDocument.query.filter_by(document_id=doc_id, shared_with_user_id=session['user_id']).first() is not None
    if document.user_id != session['user_id'] and not user.is_admin and not is_shared_with_user:
        flash('Access denied', 'error')
        print(f"Access denied: Document user_id {document.user_id} does not match session user_id {session['user_id']}")
        return redirect(url_for('list_documents'))

    # Retrieve chunks in batches
    try:
        chunk_count = DocumentChunk.query.filter_by(document_id=doc_id).count()
        if chunk_count == 0:
            flash('Document data not found', 'error')
            print(f"No chunks found for document ID {doc_id}")
            return redirect(url_for('list_documents'))

        print(f"Total chunks to retrieve: {chunk_count}")
        BATCH_SIZE = 5  # Reduced to 5 chunks per batch
        chunk_data_list = []
        for offset in range(0, chunk_count, BATCH_SIZE):
            try:
                batch_chunks = DocumentChunk.query.filter_by(document_id=doc_id)\
                    .order_by(DocumentChunk.chunk_index)\
                    .offset(offset)\
                    .limit(BATCH_SIZE)\
                    .all()
                print(f"Retrieved batch of {len(batch_chunks)} chunks starting at offset {offset}")
                for chunk in batch_chunks:
                    try:
                        chunk_data_decoded = base64.b64decode(chunk.chunk_data)
                        chunk_checksum = hashlib.sha256(chunk_data_decoded).hexdigest()
                        print(f"Chunk index: {chunk.chunk_index}, Size: {len(chunk_data_decoded)} bytes, Stored checksum: {chunk.checksum}, Computed checksum: {chunk_checksum}")
                        if chunk_checksum != chunk.checksum:
                            flash(f'Chunk integrity check failed for chunk {chunk.chunk_index}', 'error')
                            print(f"Chunk integrity check failed for chunk {chunk.chunk_index}")
                            return redirect(url_for('list_documents'))
                        chunk_data_list.append(chunk_data_decoded)
                    except base64.binascii.Error as e:
                        flash('Error decoding chunk data. Data may be corrupted.', 'error')
                        print(f"Base64 decoding error for chunk index {chunk.chunk_index} of document ID {doc_id}: {str(e)}")
                        return redirect(url_for('list_documents'))
            except OperationalError as e:
                flash('Database connection error while retrieving chunks. Please try again.', 'error')
                print(f"OperationalError retrieving chunks for document ID {doc_id} at offset {offset}: {str(e)}")
                return redirect(url_for('list_documents'))
            except SQLAlchemyError as e:
                flash('Database error while retrieving chunks. Please try again.', 'error')
                print(f"SQLAlchemyError retrieving chunks for document ID {doc_id} at offset {offset}: {str(e)}")
                return redirect(url_for('list_documents'))
            except Exception as e:
                flash('Unexpected error retrieving document chunks. Please try again.', 'error')
                print(f"Unexpected error retrieving chunks for document ID {doc_id} at offset {offset}: {str(e)}")
                return redirect(url_for('list_documents'))

        # Compute HMAC incrementally
        hmac_obj = hmac.new(HMAC_KEY, digestmod=hashlib.sha256)
        encrypted_data_size = 0
        for chunk in chunk_data_list:
            hmac_obj.update(chunk)
            encrypted_data_size += len(chunk)
        expected_hmac = hmac_obj.hexdigest()
        print(f"Reassembled encrypted_data size: {encrypted_data_size} bytes")
        print(f"Stored HMAC: {document.hmac_signature}")
        print(f"Computed HMAC: {expected_hmac}")

        if not hmac.compare_digest(expected_hmac, document.hmac_signature):
            flash('Document integrity check failed (HMAC)', 'error')
            print(f"HMAC verification failed for document ID {doc_id}")
            return redirect(url_for('list_documents'))

        # Verify digital signature incrementally
        signature_data = b''.join(chunk_data_list[:10])  # Use first 10 chunks for signature
        if not verify_signature(signature_data, document.digital_signature):
            flash('Document signature verification failed', 'error')
            print(f"Signature verification failed for document ID {doc_id}")
            return redirect(url_for('list_documents'))

        # Decrypt and decompress incrementally
        def generate_decrypted_stream():
            CHUNK_SIZE = 8192
            compressed_buffer = BytesIO()
            
            # Decrypt each chunk individually
            for chunk in chunk_data_list:
                try:
                    decrypted_chunk = decrypt_data(chunk)
                    compressed_buffer.write(decrypted_chunk)
                except ValueError as e:
                    print(f"Error decrypting chunk for document ID {doc_id}: {str(e)}")
                    return
            
            compressed_buffer.seek(0)
            # Skip decompression for .pdf files
            if document.filename.lower().endswith('.pdf'):
                print(f"Skipping decompression for PDF file: {document.filename}")
                while True:
                    chunk = compressed_buffer.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    yield chunk
            else:
                decompressor = zlib.decompressobj()
                print(f"Starting decompression for document ID {doc_id}")
                while True:
                    compressed_chunk = compressed_buffer.read(CHUNK_SIZE)
                    if not compressed_chunk:
                        break
                    try:
                        decompressed_chunk = decompressor.decompress(compressed_chunk)
                        yield decompressed_chunk
                    except zlib.error as e:
                        print(f"Error decompressing document ID {doc_id}: {str(e)}")
                        return
                
                # Flush any remaining decompressed data
                decompressed_chunk = decompressor.flush()
                if decompressed_chunk:
                    yield decompressed_chunk
            
            compressed_buffer.close()

        # Stream the file to the client
        response = Response(
            generate_decrypted_stream(),
            mimetype=document.content_type,
            headers={
                "Content-Disposition": f"attachment; filename={document.filename}"
            }
        )
        print(f"Streaming file {document.filename} to client")
        return response

    except Exception as e:
        flash('Unexpected error during download. Please try again.', 'error')
        print(f"Unexpected error in download for document ID {doc_id}: {str(e)}")
        return redirect(url_for('list_documents'))

@app.route('/documents/delete/<int:doc_id>', methods=['POST'])
@login_required
@no_cache
def delete_document(doc_id):
    print(f"Attempting to delete document ID {doc_id} for user_id {session['user_id']}")
    document = Document.query.get_or_404(doc_id)
    user = db.session.get(User, session['user_id'])
    
    # Allow deletion if user owns the document or is an admin
    if document.user_id != session['user_id'] and not user.is_admin:
        flash('Access denied', 'error')
        print(f"Access denied: Document user_id {document.user_id} does not match session user_id {session['user_id']}")
        return redirect(url_for('list_documents'))

    try:
        # Explicitly delete shared document entries first due to foreign key constraint
        SharedDocument.query.filter_by(document_id=doc_id).delete()
        db.session.commit() # Commit the deletion of shared documents
        db.session.delete(document)  # Chunks are automatically deleted due to ON DELETE CASCADE
        db.session.commit() # Commit the deletion of the document
        flash('Document deleted successfully', 'success')
        print(f"Deleted document ID {doc_id} for user_id {session['user_id']}")
    except OperationalError as e:
        db.session.rollback()
        flash('Database connection error while deleting document. Please try again.', 'error')
        print(f"Database OperationalError while deleting document ID {doc_id}: {str(e)}")
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting document: {str(e)}', 'error')
        print(f"Unexpected error while deleting document ID {doc_id}: {str(e)}")

    return redirect(url_for('list_documents'))

@app.route('/documents/share/<int:doc_id>', methods=['POST'])
@login_required
@no_cache
def share_document(doc_id):
    print(f"Attempting to share document ID {doc_id} for user_id {session['user_id']}")
    document = Document.query.get(doc_id)
    sharer_user = db.session.get(User, session['user_id'])

    if not document:
        flash('Document not found.', 'error')
        print(f"Share failed: Document ID {doc_id} not found.")
        return redirect(url_for('list_documents'))

    # Check if the current user owns the document
    if document.user_id != session['user_id']:
        flash('You can only share documents you own.', 'error')
        print(f"Share failed: User {session['user_id']} does not own document {doc_id}.")
        return redirect(url_for('list_documents'))

    recipient_identifier = request.form.get('recipient_identifier', '').strip()
    if not recipient_identifier:
        flash('Please provide a recipient username or email.', 'error')
        print("Share failed: Recipient identifier is missing.")
        return redirect(url_for('list_documents'))

    # Find the recipient user by username or email across different auth methods
    recipient_user = None
    # Check ManualAuth
    manual_auth_user = ManualAuth.query.filter((ManualAuth.username == recipient_identifier) | (ManualAuth.email == recipient_identifier)).first()
    if manual_auth_user:
        recipient_user = db.session.get(User, manual_auth_user.user_id)
    # Check GitHubAuth (by username or email)
    if not recipient_user:
        github_auth_user = GitHubAuth.query.filter((GitHubAuth.github_username == recipient_identifier) | (GitHubAuth.github_email == recipient_identifier)).first()
        if github_auth_user:
            recipient_user = db.session.get(User, github_auth_user.user_id)
    # Check GoogleAuth (by username or email)
    if not recipient_user:
        google_auth_user = GoogleAuth.query.filter((GoogleAuth.google_username == recipient_identifier) | (GoogleAuth.google_email == recipient_identifier)).first()
        if google_auth_user:
            recipient_user = db.session.get(User, google_auth_user.user_id)
    # Check Auth0 (by name or email)
    if not recipient_user:
         okta_auth_user = OktaAuth.query.filter((OktaAuth.okta_name == recipient_identifier) | (OktaAuth.okta_email == recipient_identifier)).first()
         if okta_auth_user:
            recipient_user = db.session.get(User, okta_auth_user.user_id)

    if not recipient_user:
        flash(f'User "{recipient_identifier}" not found.', 'error')
        print(f"Share failed: Recipient user '{recipient_identifier}' not found.")
        return redirect(url_for('list_documents'))

    # Prevent sharing with self
    if recipient_user.id == session['user_id']:
        flash('You cannot share a document with yourself.', 'error')
        print(f"Share failed: User {session['user_id']} attempted to share document {doc_id} with themselves.")
        return redirect(url_for('list_documents'))
    
    # Check if already shared with this user
    existing_share = SharedDocument.query.filter_by(
        document_id=doc_id,
        shared_with_user_id=recipient_user.id
    ).first()

    if existing_share:
        flash(f'Document already shared with "{recipient_identifier}".', 'info')
        print(f"Share failed: Document {doc_id} already shared with user {recipient_user.id}.")
        return redirect(url_for('list_documents'))


    try:
        shared_doc = SharedDocument(
            document_id=doc_id,
            shared_with_user_id=recipient_user.id
        )
        db.session.add(shared_doc)
        db.session.commit()
        flash(f'Document "{document.filename}" shared successfully with "{recipient_identifier}".', 'success')
        print(f"Document {doc_id} shared successfully with user {recipient_user.id}.")
    except Exception as e:
        db.session.rollback()
        flash('Error sharing document.', 'error')
        print(f"Error sharing document {doc_id} with user {recipient_user.id}: {str(e)}")

    return redirect(url_for('list_documents'))

@app.route('/documents/unshare/<int:shared_doc_id>', methods=['POST'])
@login_required
@no_cache
def unshare_document(shared_doc_id):
    print(f"Attempting to unshare shared document ID {shared_doc_id} for user_id {session['user_id']}")
    
    shared_doc = SharedDocument.query.get(shared_doc_id)

    if not shared_doc:
        flash('Shared document entry not found.', 'error')
        print(f"Unshare failed: Shared document entry {shared_doc_id} not found.")
        return redirect(url_for('list_documents'))

    # Verify that the current user is the owner of the original document
    # This prevents a recipient from unsharing a document shared by someone else
    if shared_doc.document.user_id != session['user_id']:
         flash('You can only unshare documents you have shared.', 'error')
         print(f"Unshare failed: User {session['user_id']} does not own the original document for shared entry {shared_doc_id}.")
         return redirect(url_for('list_documents'))

    try:
        db.session.delete(shared_doc)
        db.session.commit()
        flash(f'Document "{shared_doc.document.filename}" successfully unshared.', 'success')
        print(f"Shared document entry {shared_doc_id} successfully unshared by user {session['user_id']}.")
    except Exception as e:
        db.session.rollback()
        flash('Error unsharing document.', 'error')
        print(f"Error unsharing shared document entry {shared_doc_id}: {str(e)}")

    return redirect(url_for('list_documents'))

# Initialize the database
def create_app():
    with app.app_context():
        try:
            print(f"Attempting to connect to database: {app.config['SQLALCHEMY_DATABASE_URI']}")
            db.create_all()
            print("Database tables created successfully")
        except Exception as e:
            print(f"Failed to connect to database: {str(e)}")
            raise
    return app

# Add a new route for editing documents (Admin only)
@app.route('/documents/edit/<int:doc_id>', methods=['GET', 'POST'])
@login_required
@admin_required
@no_cache
def edit_document(doc_id):
    document = db.session.get(Document, doc_id)
    if not document:
        flash('Document not found.', 'error')
        return redirect(url_for('list_documents'))

    if request.method == 'POST':
        new_filename = request.form.get('filename', '').strip()
        new_description = request.form.get('description', '').strip()

        if not new_filename:
            flash('Filename cannot be empty.', 'error')
            # Render the form again with the current document data and error message
            return render_template('edit_document.html', document=document)

        # Optional: Add more validation for filename if needed (e.g., allowed characters)
        # Sanitize the filename before saving
        sanitized_filename = secure_filename(new_filename)
        if not sanitized_filename:
             flash('Invalid filename.', 'error')
             return render_template('edit_document.html', document=document)

        # Validate description length (e.g., max 1000 characters)
        if len(new_description) > 1000:
            flash('Description too long. Maximum 1000 characters allowed.', 'error')
            return render_template('edit_document.html', document=document)


        try:
            document.filename = sanitized_filename
            document.description = new_description if new_description else None
            db.session.commit()
            flash('Document updated successfully.', 'success')
            return redirect(url_for('list_documents'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating document: {str(e)}', 'error')
            # Render the form again with the current document data and error message
            return render_template('edit_document.html', document=document)

    # GET request: Display the edit form
    return render_template('edit_document.html', document=document)

@app.route('/admin/user/<int:user_id>/activate', methods=['GET'])
@login_required
@admin_required
def activate_user(user_id):
    user = db.session.get(User, user_id)
    current_user = db.session.get(User, session['user_id'])
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('manage_users'))
    if user.id == 1:
        flash("Cannot modify root admin.", "error")
        return redirect(url_for('manage_users'))
    if user.role == 'admin' and not (current_user.id == 1 or user.parent_admin_id == current_user.id):
        flash("You do not have permission to modify this admin.", "error")
        return redirect(url_for('manage_users'))
    
    user.is_active = True
    db.session.commit()
    flash("User activated successfully.", "success")
    return redirect(url_for('manage_users'))

@app.route('/admin/user/<int:user_id>/deactivate', methods=['GET'])
@login_required
@admin_required
def deactivate_user(user_id):
    user = db.session.get(User, user_id)
    current_user = db.session.get(User, session['user_id'])
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('manage_users'))
    if user.id == 1:
        flash("Cannot modify root admin.", "error")
        return redirect(url_for('manage_users'))
    if user.role == 'admin' and not (current_user.id == 1 or user.parent_admin_id == current_user.id):
        flash("You do not have permission to modify this admin.", "error")
        return redirect(url_for('manage_users'))
    
    user.is_active = False
    db.session.commit()
    flash("User deactivated successfully.", "success")
    return redirect(url_for('manage_users'))

if __name__ == '__main__':
    app = create_app()
    app.run(port=443, ssl_context=('cert_files/cert.crt', 'cert_files/sk.key'),debug=True)
