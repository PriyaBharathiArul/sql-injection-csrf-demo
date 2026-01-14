"""
Patched SQL Endpoints with Security Mitigations
Demonstrates proper defenses against SQL Injection
"""

from flask import Blueprint, request, jsonify, session
import sqlite3
import re

patched_sql_bp = Blueprint('patched_sql', __name__)

def get_db():
    """Get database connection"""
    db = sqlite3.connect('/app/data/users.db')
    db.row_factory = sqlite3.Row
    return db

def validate_input(input_str, max_length=100, allow_special=False):
    """
    Input validation helper
    Returns (is_valid, sanitized_input)
    """
    if not input_str or len(input_str) > max_length:
        return False, None

    # Remove potentially dangerous characters if not allowed
    if not allow_special:
        # Allow only alphanumeric, spaces, @, ., -, _
        if not re.match(r'^[a-zA-Z0-9@.\-_ ]+$', input_str):
            return False, None

    return True, input_str.strip()

@patched_sql_bp.route('/api/login', methods=['POST'])
def secure_login():
    """
    SECURE: Uses parameterized queries to prevent SQL injection
    Defense: Prepared statements, input validation, generic error messages
    """
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # DEFENSE 1: Input validation
    valid_username, username = validate_input(username, max_length=50)
    valid_password, password = validate_input(password, max_length=100, allow_special=True)

    if not valid_username or not valid_password:
        # DEFENSE 2: Generic error message (don't reveal validation details)
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    # DEFENSE 3: Parameterized query prevents SQL injection
    query = "SELECT * FROM users WHERE username = ? AND password = ?"

    db = get_db()
    try:
        cursor = db.execute(query, (username, password))
        user = cursor.fetchone()

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email']
                    # Note: Not exposing password in response
                }
            })
        else:
            # DEFENSE 4: Generic error message
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    except sqlite3.Error:
        # DEFENSE 5: Don't expose database errors
        return jsonify({
            'success': False,
            'message': 'An error occurred. Please try again.'
        }), 500
    finally:
        db.close()

@patched_sql_bp.route('/api/search', methods=['GET'])
def secure_search():
    """
    SECURE: Uses parameterized queries for search
    Defense: Prepared statements, input validation
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    query_param = request.args.get('query', '')

    # DEFENSE 1: Input validation
    valid, query_param = validate_input(query_param, max_length=50)

    if not valid:
        return jsonify({
            'success': False,
            'message': 'Invalid search query'
        }), 400

    # DEFENSE 2: Parameterized query with LIKE
    sql = "SELECT id, username, email, bio FROM users WHERE username LIKE ?"

    db = get_db()
    try:
        # Use parameterized query with wildcard in the parameter
        cursor = db.execute(sql, (f'%{query_param}%',))
        results = cursor.fetchall()

        return jsonify({
            'success': True,
            'results': [dict(row) for row in results]
            # Note: Not exposing the SQL query
        })

    except sqlite3.Error:
        # DEFENSE 3: Generic error message
        return jsonify({
            'success': False,
            'message': 'Search failed. Please try again.'
        }), 500
    finally:
        db.close()

@patched_sql_bp.route('/api/update_profile', methods=['POST'])
def secure_update_profile():
    """
    SECURE: Uses parameterized queries for UPDATE
    Defense: Prepared statements, input validation, type checking
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    email = request.form.get('email', '')
    bio = request.form.get('bio', '')

    # DEFENSE 1: Input validation
    valid_email, email = validate_input(email, max_length=100)
    valid_bio, bio = validate_input(bio, max_length=500, allow_special=True)

    if not valid_email or not valid_bio:
        return jsonify({
            'success': False,
            'message': 'Invalid input data'
        }), 400

    # DEFENSE 2: Email format validation
    if email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return jsonify({
            'success': False,
            'message': 'Invalid email format'
        }), 400

    # DEFENSE 3: Parameterized query
    sql = "UPDATE users SET email = ?, bio = ? WHERE id = ?"

    db = get_db()
    try:
        # DEFENSE 4: Type-safe parameter binding
        db.execute(sql, (email, bio, int(session['user_id'])))
        db.commit()

        return jsonify({
            'success': True,
            'message': 'Profile updated successfully'
        })

    except sqlite3.Error:
        # DEFENSE 5: Generic error message
        return jsonify({
            'success': False,
            'message': 'Update failed. Please try again.'
        }), 500
    except ValueError:
        return jsonify({
            'success': False,
            'message': 'Invalid user session'
        }), 401
    finally:
        db.close()

@patched_sql_bp.route('/api/get_profile', methods=['GET'])
def get_profile():
    """Get current user profile (already secure)"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    db = get_db()
    try:
        user = db.execute(
            "SELECT id, username, email, bio FROM users WHERE id = ?",
            (session['user_id'],)
        ).fetchone()

        return jsonify({
            'success': True,
            'user': dict(user) if user else None
        })
    finally:
        db.close()

@patched_sql_bp.route('/api/get_all_users', methods=['GET'])
def get_all_users():
    """
    Get all users (safe read-only operation)
    Note: In production, implement pagination and access control
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    db = get_db()
    try:
        users = db.execute(
            "SELECT id, username, email, bio FROM users"
        ).fetchall()

        return jsonify({
            'success': True,
            'users': [dict(user) for user in users]
        })
    finally:
        db.close()

# ========== SECURE VERSIONS OF ADVANCED SQL INJECTION DEFENSES ==========

@patched_sql_bp.route('/api/bulk_delete', methods=['POST'])
def secure_bulk_delete():
    """
    SECURE: Prevents stacked statements SQL injection
    Defense: Single statement execution, parameterized queries, input validation
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    username = request.form.get('username', '')

    # DEFENSE 1: Input validation
    valid, username = validate_input(username, max_length=50)
    if not valid:
        return jsonify({
            'success': False,
            'message': 'Invalid username'
        }), 400

    # DEFENSE 2: Parameterized query (prevents injection)
    sql = "DELETE FROM users WHERE username = ?"

    db = get_db()
    try:
        # DEFENSE 3: Use execute() instead of executescript()
        # execute() only allows single statements
        result = db.execute(sql, (username,))
        rows_deleted = result.rowcount
        db.commit()

        return jsonify({
            'success': True,
            'message': f'Deleted {rows_deleted} user(s)',
            'rows_affected': rows_deleted
        })

    except sqlite3.Error:
        # DEFENSE 4: Generic error message
        return jsonify({
            'success': False,
            'message': 'Delete operation failed'
        }), 500
    finally:
        db.close()

@patched_sql_bp.route('/api/save_preference', methods=['POST'])
def secure_save_preference():
    """
    SECURE: First stage of second-order SQL injection defense
    Defense: Parameterized queries for storage (AND retrieval in get_user_stats)
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    display_name = request.form.get('display_name', '')
    theme = request.form.get('theme', 'light')
    user_id = session['user_id']

    # DEFENSE 1: Input validation
    valid_name, display_name = validate_input(display_name, max_length=100, allow_special=True)
    valid_theme, theme = validate_input(theme, max_length=20)

    if not valid_name or not valid_theme:
        return jsonify({
            'success': False,
            'message': 'Invalid input data'
        }), 400

    # DEFENSE 2: Whitelist theme values
    if theme not in ['light', 'dark', 'auto']:
        return jsonify({
            'success': False,
            'message': 'Invalid theme'
        }), 400

    db = get_db()
    try:
        # Check if preference exists
        existing = db.execute(
            "SELECT id FROM user_preferences WHERE user_id = ?",
            (user_id,)
        ).fetchone()

        if existing:
            # DEFENSE 3: Parameterized UPDATE
            db.execute(
                "UPDATE user_preferences SET display_name = ?, theme = ? WHERE user_id = ?",
                (display_name, theme, user_id)
            )
        else:
            # DEFENSE 3: Parameterized INSERT
            db.execute(
                "INSERT INTO user_preferences (user_id, display_name, theme) VALUES (?, ?, ?)",
                (user_id, display_name, theme)
            )

        db.commit()

        return jsonify({
            'success': True,
            'message': 'Preferences saved successfully'
        })

    except sqlite3.Error:
        return jsonify({
            'success': False,
            'message': 'Failed to save preferences'
        }), 500
    finally:
        db.close()

@patched_sql_bp.route('/api/get_user_stats', methods=['GET'])
def secure_get_user_stats():
    """
    SECURE: Second stage of second-order SQL injection defense
    Defense: Parameterized queries even when using stored data
    KEY: Even though display_name is from the database, we still use parameterized queries
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    user_id = session['user_id']

    db = get_db()
    try:
        # Get the user's display name (safely)
        pref = db.execute(
            "SELECT display_name FROM user_preferences WHERE user_id = ?",
            (user_id,)
        ).fetchone()

        if pref and pref['display_name']:
            display_name = pref['display_name']

            # DEFENSE: Still use parameterized query even with database-sourced data!
            # Never trust data, even from your own database
            sql = "SELECT COUNT(*) as count FROM users WHERE username = ?"

            cursor = db.execute(sql, (display_name,))
            result = cursor.fetchone()

            return jsonify({
                'success': True,
                'display_name': display_name,
                'stats': {
                    'user_count': result['count']
                },
                'note': 'Even database-sourced data is safely parameterized!'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'No preferences found'
            }), 404

    except sqlite3.Error:
        return jsonify({
            'success': False,
            'message': 'Failed to retrieve stats'
        }), 500
    finally:
        db.close()

@patched_sql_bp.route('/api/check_username', methods=['GET'])
def secure_check_username():
    """
    SECURE: Prevents boolean-based blind SQL injection
    Defense: Parameterized queries, input validation
    """
    username = request.args.get('username', '')

    # DEFENSE 1: Input validation
    valid, username = validate_input(username, max_length=50)
    if not valid:
        return jsonify({
            'success': False,
            'message': 'Invalid username format'
        }), 400

    # DEFENSE 2: Parameterized query
    sql = "SELECT COUNT(*) as count FROM users WHERE username = ?"

    db = get_db()
    try:
        cursor = db.execute(sql, (username,))
        result = cursor.fetchone()
        count = result['count']

        # Same response structure, but injection is prevented
        if count > 0:
            return jsonify({
                'success': True,
                'available': False,
                'message': 'Username is taken'
            })
        else:
            return jsonify({
                'success': True,
                'available': True,
                'message': 'Username is available'
            })

    except sqlite3.Error:
        # DEFENSE 3: Generic error message
        return jsonify({
            'success': False,
            'message': 'Username check failed'
        }), 500
    finally:
        db.close()

@patched_sql_bp.route('/api/verify_user', methods=['GET'])
def secure_verify_user():
    """
    SECURE: Prevents time-based blind SQL injection
    Defense: Parameterized queries, input validation, rate limiting (recommended)
    """
    username = request.args.get('username', '')

    # DEFENSE 1: Input validation
    valid, username = validate_input(username, max_length=50)
    if not valid:
        return jsonify({
            'success': False,
            'message': 'Invalid username format'
        }), 400

    # DEFENSE 2: Parameterized query
    sql = "SELECT id, username, email FROM users WHERE username = ?"

    db = get_db()
    try:
        cursor = db.execute(sql, (username,))
        user = cursor.fetchone()

        if user:
            return jsonify({
                'success': True,
                'exists': True,
                'message': 'User exists'
            })
        else:
            return jsonify({
                'success': True,
                'exists': False,
                'message': 'User not found'
            })

    except sqlite3.Error:
        # DEFENSE 3: Generic error message
        # NOTE: In production, also implement rate limiting to prevent
        # timing attacks and brute force attempts
        return jsonify({
            'success': False,
            'message': 'Verification failed'
        }), 500
    finally:
        db.close()
