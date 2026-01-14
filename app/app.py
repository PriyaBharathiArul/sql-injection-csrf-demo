"""
Main Flask Application
Combines vulnerable and patched endpoints based on MODE environment variable
MODE=vulnerable - Uses vulnerable SQL and CSRF endpoints
MODE=patched - Uses patched/secure endpoints
"""

from flask import Flask, render_template, session, redirect, url_for, jsonify
import sqlite3
import os
import secrets

# Import blueprints
from vuln_sql import vuln_sql_bp
from vuln_csrf import vuln_csrf_bp
from patched_sql import patched_sql_bp
from patched_csrf import patched_csrf_bp

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Determine mode from environment variable
MODE = os.environ.get('MODE', 'vulnerable').lower()
IS_VULNERABLE = MODE == 'vulnerable'

DATABASE = '/app/data/users.db'

def init_db():
    """Initialize database with schema and seed data"""
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row

    # Create tables
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            bio TEXT
        )
    ''')

    db.execute('''
        CREATE TABLE IF NOT EXISTS friends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            friend_id INTEGER,
            UNIQUE(user_id, friend_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (friend_id) REFERENCES users(id)
        )
    ''')

    # Table for second-order SQL injection demonstration
    db.execute('''
        CREATE TABLE IF NOT EXISTS user_preferences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            display_name TEXT,
            theme TEXT DEFAULT 'light',
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # Seed data
    users = [
        ('alice', 'password123', 'alice@example.com', 'Hi, I am Alice!'),
        ('bob', 'secret456', 'bob@example.com', 'Bob here!'),
        ('charlie', 'pass789', 'charlie@example.com', 'Charlie at your service'),
        ('admin', 'admin_secret', 'admin@example.com', 'System administrator'),
    ]

    try:
        for username, password, email, bio in users:
            db.execute(
                "INSERT INTO users (username, password, email, bio) VALUES (?, ?, ?, ?)",
                (username, password, email, bio)
            )
        db.commit()
        print("✓ Database initialized with seed data")
    except sqlite3.IntegrityError:
        print("✓ Database already initialized")

    db.close()

# Register blueprints based on mode
if IS_VULNERABLE:
    app.register_blueprint(vuln_sql_bp)
    app.register_blueprint(vuln_csrf_bp)
    print(f"⚠️  Running in VULNERABLE mode")
else:
    app.register_blueprint(patched_sql_bp)
    app.register_blueprint(patched_csrf_bp)
    print(f"✓ Running in PATCHED mode")

# Configure session cookies
@app.after_request
def set_cookie_policy(response):
    """Set cookie security policies"""
    if not IS_VULNERABLE:
        # DEFENSE: SameSite cookies for CSRF protection
        for cookie in response.headers.getlist('Set-Cookie'):
            if 'session=' in cookie:
                # Add SameSite=Lax and HttpOnly flags
                response.headers.add('Set-Cookie',
                    cookie + '; SameSite=Lax; HttpOnly')

        # DEFENSE: Content Security Policy
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'"
        )

    return response

# Main routes
@app.route('/')
def index():
    """Home page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html', mode=MODE)

@app.route('/login')
def login_page():
    """Login page"""
    return render_template('login.html', mode=MODE)

@app.route('/dashboard')
def dashboard():
    """User dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))

    return render_template('dashboard.html',
                         username=session.get('username'),
                         mode=MODE,
                         is_vulnerable=IS_VULNERABLE)

@app.route('/logout')
def logout():
    """Logout endpoint"""
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'mode': MODE,
        'is_vulnerable': IS_VULNERABLE
    })

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
