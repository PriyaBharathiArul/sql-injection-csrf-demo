"""
Vulnerable SQL Injection Endpoints
Educational demonstration - DO NOT use in production
"""

from flask import Blueprint, request, jsonify, session
import sqlite3

vuln_sql_bp = Blueprint('vuln_sql', __name__)

def get_db():
    """Get database connection"""
    db = sqlite3.connect('/app/data/users.db')
    db.row_factory = sqlite3.Row
    return db

@vuln_sql_bp.route('/api/login', methods=['POST'])
def vulnerable_login():
    """
    VULNERABLE: SQL Injection in authentication
    Attack: ' OR '1'='1
    """
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # VULNERABLE: String concatenation allows SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

    db = get_db()
    try:
        cursor = db.execute(query)
        user = cursor.fetchone()

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'user': dict(user)
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    except sqlite3.Error as e:
        # VULNERABLE: Exposing detailed database errors
        return jsonify({
            'success': False,
            'message': f'Database error: {str(e)}',
            'query': query  # VULNERABLE: Exposing the query
        }), 500
    finally:
        db.close()

@vuln_sql_bp.route('/api/search', methods=['GET'])
def vulnerable_search():
    """
    VULNERABLE: SQL Injection in search
    Attack: ' UNION SELECT id, username, password, email FROM users --
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    query_param = request.args.get('query', '')

    # VULNERABLE: String concatenation in LIKE clause
    sql = f"SELECT * FROM users WHERE username LIKE '%{query_param}%'"

    db = get_db()
    try:
        cursor = db.execute(sql)
        results = cursor.fetchall()

        return jsonify({
            'success': True,
            'results': [dict(row) for row in results],
            'query': sql  # VULNERABLE: Exposing query
        })

    except sqlite3.Error as e:
        # VULNERABLE: Detailed error messages
        return jsonify({
            'success': False,
            'message': f'SQL Error: {str(e)}',
            'query': sql
        }), 500
    finally:
        db.close()

@vuln_sql_bp.route('/api/update_profile', methods=['POST'])
def vulnerable_update_profile():
    """
    VULNERABLE: SQL Injection in UPDATE statement
    Attack: Could inject malicious SQL in email/bio fields
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    email = request.form.get('email', '')
    bio = request.form.get('bio', '')
    user_id = session['user_id']

    # VULNERABLE: String concatenation in UPDATE
    sql = f"UPDATE users SET email = '{email}', bio = '{bio}' WHERE id = {user_id}"

    db = get_db()
    try:
        db.execute(sql)
        db.commit()

        return jsonify({
            'success': True,
            'message': 'Profile updated',
            'query': sql  # VULNERABLE: Exposing query
        })

    except sqlite3.Error as e:
        return jsonify({
            'success': False,
            'message': f'Update failed: {str(e)}'
        }), 500
    finally:
        db.close()

@vuln_sql_bp.route('/api/get_profile', methods=['GET'])
def get_profile():
    """Get current user profile (safe endpoint for comparison)"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    db = get_db()
    try:
        # This one is safe - used for retrieving current state
        user = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        return jsonify({
            'success': True,
            'user': dict(user) if user else None
        })
    finally:
        db.close()

# ========== ADVANCED SQL INJECTION TECHNIQUES ==========

@vuln_sql_bp.route('/api/bulk_delete', methods=['POST'])
def vulnerable_bulk_delete():
    """
    VULNERABLE: Stacked statements SQL injection
    Allows multiple SQL statements to be executed
    Attack: alice'; DROP TABLE users; --
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    username = request.form.get('username', '')

    # VULNERABLE: Using executescript allows stacked statements
    sql = f"DELETE FROM users WHERE username = '{username}'"

    db = get_db()
    try:
        # VULNERABLE: executescript allows multiple statements separated by semicolons
        db.executescript(sql)
        db.commit()

        return jsonify({
            'success': True,
            'message': f'Deleted user: {username}',
            'query': sql  # VULNERABLE: Exposing query
        })

    except sqlite3.Error as e:
        return jsonify({
            'success': False,
            'message': f'Delete failed: {str(e)}',
            'query': sql
        }), 500
    finally:
        db.close()

@vuln_sql_bp.route('/api/save_preference', methods=['POST'])
def vulnerable_save_preference():
    """
    VULNERABLE: First stage of second-order SQL injection
    Stores malicious input that will be exploited later
    Attack: Saves "admin' OR '1'='1' --" as display_name
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    display_name = request.form.get('display_name', '')
    theme = request.form.get('theme', 'light')
    user_id = session['user_id']

    db = get_db()
    try:
        # First check if preference exists
        existing = db.execute(
            "SELECT id FROM user_preferences WHERE user_id = ?",
            (user_id,)
        ).fetchone()

        if existing:
            # Update existing - THIS IS SAFE (parameterized)
            db.execute(
                "UPDATE user_preferences SET display_name = ?, theme = ? WHERE user_id = ?",
                (display_name, theme, user_id)
            )
        else:
            # Insert new - THIS IS SAFE (parameterized)
            db.execute(
                "INSERT INTO user_preferences (user_id, display_name, theme) VALUES (?, ?, ?)",
                (user_id, display_name, theme)
            )

        db.commit()

        return jsonify({
            'success': True,
            'message': 'Preferences saved',
            'note': 'Malicious input stored safely... but will be exploited on retrieval!'
        })

    except sqlite3.Error as e:
        return jsonify({
            'success': False,
            'message': f'Save failed: {str(e)}'
        }), 500
    finally:
        db.close()

@vuln_sql_bp.route('/api/get_user_stats', methods=['GET'])
def vulnerable_get_user_stats():
    """
    VULNERABLE: Second stage of second-order SQL injection
    Retrieves stored preference and uses it in vulnerable query
    The malicious display_name stored earlier is now executed as SQL
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    user_id = session['user_id']

    db = get_db()
    try:
        # Get the user's display name (which may contain malicious SQL)
        pref = db.execute(
            "SELECT display_name FROM user_preferences WHERE user_id = ?",
            (user_id,)
        ).fetchone()

        if pref and pref['display_name']:
            display_name = pref['display_name']

            # VULNERABLE: Using the stored display_name in a SQL query without sanitization
            # If display_name contains "admin' OR '1'='1' --", this becomes vulnerable
            sql = f"SELECT * FROM users WHERE username = '{display_name}'"

            cursor = db.execute(sql)
            results = cursor.fetchall()

            return jsonify({
                'success': True,
                'display_name': display_name,
                'stats': {
                    'user_count': len(results),
                    'users_found': [dict(row) for row in results]
                },
                'query': sql,  # VULNERABLE: Exposing query
                'note': 'Second-order SQL injection: malicious input stored safely but executed here!'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'No preferences found. Set a display name first.'
            }), 404

    except sqlite3.Error as e:
        return jsonify({
            'success': False,
            'message': f'Query failed: {str(e)}'
        }), 500
    finally:
        db.close()

@vuln_sql_bp.route('/api/check_username', methods=['GET'])
def vulnerable_check_username():
    """
    VULNERABLE: Boolean-based blind SQL injection
    Returns different responses based on true/false SQL conditions
    Attack: admin' AND SUBSTR(password,1,1)='a'--
    This allows extracting passwords character by character
    """
    username = request.args.get('username', '')

    # VULNERABLE: String concatenation allows injection
    sql = f"SELECT COUNT(*) as count FROM users WHERE username = '{username}'"

    db = get_db()
    try:
        cursor = db.execute(sql)
        result = cursor.fetchone()
        count = result['count']

        # Different responses based on SQL result (enables blind SQLi)
        if count > 0:
            return jsonify({
                'success': True,
                'available': False,
                'message': 'Username is taken',
                'query': sql  # VULNERABLE: Exposing query
            })
        else:
            return jsonify({
                'success': True,
                'available': True,
                'message': 'Username is available',
                'query': sql
            })

    except sqlite3.Error as e:
        return jsonify({
            'success': False,
            'message': f'Check failed: {str(e)}',
            'query': sql
        }), 500
    finally:
        db.close()

@vuln_sql_bp.route('/api/verify_user', methods=['GET'])
def vulnerable_verify_user():
    """
    VULNERABLE: Time-based blind SQL injection
    Uses SQLite functions to create time delays based on conditions
    Attack: ' OR (SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 1 END)--
    Response time indicates whether condition is true or false
    """
    username = request.args.get('username', '')

    # VULNERABLE: String concatenation allows time-based injection
    sql = f"SELECT * FROM users WHERE username = '{username}'"

    db = get_db()
    try:
        cursor = db.execute(sql)
        user = cursor.fetchone()

        if user:
            return jsonify({
                'success': True,
                'exists': True,
                'message': 'User exists',
                'query': sql  # VULNERABLE: Exposing query
            })
        else:
            return jsonify({
                'success': True,
                'exists': False,
                'message': 'User not found',
                'query': sql
            })

    except sqlite3.Error as e:
        # Time delay will occur during query execution if injection successful
        return jsonify({
            'success': False,
            'message': f'Verification failed: {str(e)}',
            'query': sql
        }), 500
    finally:
        db.close()
