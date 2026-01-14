"""
Vulnerable CSRF Endpoints
Educational demonstration - DO NOT use in production
"""

from flask import Blueprint, request, jsonify, session
import sqlite3

vuln_csrf_bp = Blueprint('vuln_csrf', __name__)

def get_db():
    """Get database connection"""
    db = sqlite3.connect('/app/data/users.db')
    db.row_factory = sqlite3.Row
    return db

@vuln_csrf_bp.route('/api/add_friend', methods=['POST', 'GET'])
def vulnerable_add_friend():
    """
    VULNERABLE: No CSRF token validation
    Accepts both GET and POST requests (GET is even more vulnerable)
    Attack: Malicious site can trigger with <img> tag or hidden form
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    # VULNERABLE: No CSRF token check
    # VULNERABLE: Accepts GET requests for state-changing operation
    friend_username = request.values.get('friend_username', '')  # values gets both GET and POST

    if not friend_username:
        return jsonify({'success': False, 'message': 'No friend username provided'}), 400

    db = get_db()
    try:
        # Find friend user ID
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
            'warning': 'NO CSRF PROTECTION - This request was not validated!'
        })

    except sqlite3.Error as e:
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500
    finally:
        db.close()

@vuln_csrf_bp.route('/api/update_profile_csrf', methods=['POST'])
def vulnerable_update_profile_csrf():
    """
    VULNERABLE: No CSRF token validation on profile update
    Attack: Malicious site can submit hidden form to change victim's profile
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    # VULNERABLE: No CSRF token validation
    email = request.form.get('email', '')
    bio = request.form.get('bio', '')

    if not email and not bio:
        return jsonify({'success': False, 'message': 'No data provided'}), 400

    db = get_db()
    try:
        # Using parameterized query here (SQL is safe, but CSRF is not)
        db.execute(
            "UPDATE users SET email = ?, bio = ? WHERE id = ?",
            (email, bio, session['user_id'])
        )
        db.commit()

        return jsonify({
            'success': True,
            'message': 'Profile updated successfully',
            'warning': 'NO CSRF PROTECTION - This could have been triggered from another site!',
            'new_email': email,
            'new_bio': bio
        })

    except sqlite3.Error as e:
        return jsonify({'success': False, 'message': f'Update failed: {str(e)}'}), 500
    finally:
        db.close()

@vuln_csrf_bp.route('/api/delete_friend', methods=['POST', 'GET'])
def vulnerable_delete_friend():
    """
    VULNERABLE: No CSRF protection on friend deletion
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    # VULNERABLE: No CSRF token check
    friend_username = request.values.get('friend_username', '')

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
            'warning': 'NO CSRF PROTECTION'
        })

    except sqlite3.Error as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500
    finally:
        db.close()

@vuln_csrf_bp.route('/api/get_friends', methods=['GET'])
def get_friends():
    """Get user's friends list (safe read operation)"""
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

@vuln_csrf_bp.route('/api/transfer', methods=['POST', 'GET'])
def vulnerable_transfer():
    """
    VULNERABLE: Money transfer with no CSRF protection
    Accepts both GET and POST requests (extremely vulnerable!)
    Attack: Malicious site can trigger transfer with <img> tag
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    # VULNERABLE: No CSRF token check
    # VULNERABLE: Accepts GET requests for money transfer!
    to_account = request.values.get('to', '')  # values gets both GET and POST
    amount = request.values.get('amount', '')

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
        'message': f'TRANSFER EXECUTED: ${amount} sent to {to_account}',
        'warning': 'CRITICAL: NO CSRF PROTECTION - Attacker could drain your account!',
        'from_user_id': session['user_id'],
        'to_account': to_account,
        'amount': amount_float,
        'method': request.method
    })
