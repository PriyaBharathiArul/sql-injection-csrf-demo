"""
Patched CSRF Endpoints with Security Mitigations
Demonstrates proper defenses against CSRF attacks
"""

from flask import Blueprint, request, jsonify, session
import sqlite3
import secrets

patched_csrf_bp = Blueprint('patched_csrf', __name__)

def get_db():
    """Get database connection"""
    db = sqlite3.connect('/app/data/users.db')
    db.row_factory = sqlite3.Row
    return db

def generate_csrf_token():
    """
    DEFENSE: Generate a cryptographically secure CSRF token
    Store in session for validation
    """
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token(token):
    """
    DEFENSE: Validate CSRF token from request
    Returns True if valid, False otherwise
    """
    if not token:
        return False

    session_token = session.get('csrf_token')
    if not session_token:
        return False

    # Constant-time comparison to prevent timing attacks
    return secrets.compare_digest(token, session_token)

def validate_origin(request):
    """
    DEFENSE: Validate request origin
    Check Origin and Referer headers
    """
    origin = request.headers.get('Origin')
    referer = request.headers.get('Referer')

    # In production, check against whitelist of allowed origins
    # For this demo, we'll check if origin exists and is not from attacker domain
    if origin and 'attacker' in origin.lower():
        return False

    if referer and 'attacker' in referer.lower():
        return False

    return True

@patched_csrf_bp.route('/api/csrf_token', methods=['GET'])
def get_csrf_token():
    """
    Endpoint to get CSRF token
    Client should include this in subsequent POST requests
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    token = generate_csrf_token()
    return jsonify({
        'success': True,
        'csrf_token': token
    })

@patched_csrf_bp.route('/api/add_friend', methods=['POST'])
def secure_add_friend():
    """
    SECURE: CSRF token validation for add friend
    Defense: Token validation, POST-only, origin checking
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    # DEFENSE 1: Only accept POST requests (not GET)
    # This is enforced by the route decorator

    # DEFENSE 2: Validate CSRF token
    csrf_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')

    if not validate_csrf_token(csrf_token):
        return jsonify({
            'success': False,
            'message': 'CSRF token validation failed',
            'error': 'csrf_validation_failed'
        }), 403

    # DEFENSE 3: Validate origin
    if not validate_origin(request):
        return jsonify({
            'success': False,
            'message': 'Request origin not allowed',
            'error': 'origin_validation_failed'
        }), 403

    friend_username = request.form.get('friend_username', '')

    if not friend_username:
        return jsonify({'success': False, 'message': 'No friend username provided'}), 400

    db = get_db()
    try:
        friend = db.execute("SELECT id FROM users WHERE username = ?", (friend_username,)).fetchone()

        if not friend:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        # Check if already friends
        existing = db.execute(
            "SELECT * FROM friends WHERE user_id = ? AND friend_id = ?",
            (session['user_id'], friend['id'])
        ).fetchone()

        if existing:
            return jsonify({'success': False, 'message': 'Already friends'}), 400

        # Add friend
        db.execute(
            "INSERT INTO friends (user_id, friend_id) VALUES (?, ?)",
            (session['user_id'], friend['id'])
        )
        db.commit()

        return jsonify({
            'success': True,
            'message': f'Successfully added {friend_username} as friend',
            'security_note': 'Request validated with CSRF token and origin check'
        })

    except sqlite3.Error as e:
        return jsonify({'success': False, 'message': 'Database error occurred'}), 500
    finally:
        db.close()

@patched_csrf_bp.route('/api/update_profile_csrf', methods=['POST'])
def secure_update_profile_csrf():
    """
    SECURE: CSRF token validation for profile update
    Defense: Token validation, SameSite cookies, origin checking
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    # DEFENSE 1: Validate CSRF token
    csrf_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')

    if not validate_csrf_token(csrf_token):
        return jsonify({
            'success': False,
            'message': 'CSRF token validation failed',
            'error': 'csrf_validation_failed'
        }), 403

    # DEFENSE 2: Validate origin
    if not validate_origin(request):
        return jsonify({
            'success': False,
            'message': 'Request origin not allowed',
            'error': 'origin_validation_failed'
        }), 403

    email = request.form.get('email', '')
    bio = request.form.get('bio', '')

    if not email and not bio:
        return jsonify({'success': False, 'message': 'No data provided'}), 400

    db = get_db()
    try:
        db.execute(
            "UPDATE users SET email = ?, bio = ? WHERE id = ?",
            (email, bio, session['user_id'])
        )
        db.commit()

        return jsonify({
            'success': True,
            'message': 'Profile updated successfully',
            'security_note': 'CSRF protection active - request validated',
            'new_email': email,
            'new_bio': bio
        })

    except sqlite3.Error:
        return jsonify({'success': False, 'message': 'Update failed'}), 500
    finally:
        db.close()

@patched_csrf_bp.route('/api/delete_friend', methods=['POST'])
def secure_delete_friend():
    """
    SECURE: CSRF protection on friend deletion
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    # DEFENSE: Validate CSRF token
    csrf_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')

    if not validate_csrf_token(csrf_token):
        return jsonify({
            'success': False,
            'message': 'CSRF token validation failed',
            'error': 'csrf_validation_failed'
        }), 403

    friend_username = request.form.get('friend_username', '')

    if not friend_username:
        return jsonify({'success': False, 'message': 'No friend username provided'}), 400

    db = get_db()
    try:
        friend = db.execute("SELECT id FROM users WHERE username = ?", (friend_username,)).fetchone()

        if not friend:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        db.execute(
            "DELETE FROM friends WHERE user_id = ? AND friend_id = ?",
            (session['user_id'], friend['id'])
        )
        db.commit()

        return jsonify({
            'success': True,
            'message': f'Removed {friend_username} from friends',
            'security_note': 'CSRF protection active'
        })

    except sqlite3.Error:
        return jsonify({'success': False, 'message': 'Error occurred'}), 500
    finally:
        db.close()

@patched_csrf_bp.route('/api/get_friends', methods=['GET'])
def get_friends():
    """Get user's friends list (safe read operation - no CSRF needed for GET)"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    db = get_db()
    try:
        friends = db.execute("""
            SELECT u.id, u.username, u.email
            FROM friends f
            JOIN users u ON f.friend_id = u.id
            WHERE f.user_id = ?
        """, (session['user_id'],)).fetchall()

        return jsonify({
            'success': True,
            'friends': [dict(friend) for friend in friends]
        })
    finally:
        db.close()

@patched_csrf_bp.route('/api/transfer', methods=['POST'])
def secure_transfer():
    """
    SECURE: Money transfer with full CSRF protection
    Defense: POST-only, CSRF token validation, origin checking
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    # DEFENSE 1: Only accept POST requests (enforced by route decorator)
    # DEFENSE 2: Validate CSRF token
    csrf_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')

    if not validate_csrf_token(csrf_token):
        return jsonify({
            'success': False,
            'message': 'CSRF token validation failed - Transfer blocked!',
            'error': 'csrf_validation_failed'
        }), 403

    # DEFENSE 3: Validate origin
    if not validate_origin(request):
        return jsonify({
            'success': False,
            'message': 'Request origin not allowed - Transfer blocked!',
            'error': 'origin_validation_failed'
        }), 403

    to_account = request.form.get('to', '')
    amount = request.form.get('amount', '')

    if not to_account or not amount:
        return jsonify({'success': False, 'message': 'Missing transfer details'}), 400

    try:
        amount_float = float(amount)
        if amount_float <= 0:
            return jsonify({'success': False, 'message': 'Invalid amount'}), 400
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid amount format'}), 400

    # In a real app, this would actually transfer money
    # For demo purposes, we just log the transaction
    return jsonify({
        'success': True,
        'message': f'SECURE TRANSFER: ${amount} sent to {to_account}',
        'security_note': 'CSRF protection active - request validated with token and origin check',
        'from_user_id': session['user_id'],
        'to_account': to_account,
        'amount': amount_float
    })
