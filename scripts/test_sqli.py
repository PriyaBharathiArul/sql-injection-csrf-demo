#!/usr/bin/env python3
"""
SQL Injection Attack Tester
Tests various SQLi payloads against vulnerable and patched applications
"""

import requests
import sys
from urllib.parse import urljoin

def load_payloads(filename='sqli_payloads.txt'):
    """Load SQL injection payloads from file"""
    payloads = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    payloads.append(line)
    except FileNotFoundError:
        print(f"Error: {filename} not found")
        sys.exit(1)
    return payloads

def test_login_bypass(base_url, payload):
    """Test SQL injection in login form"""
    login_url = urljoin(base_url, '/login')

    data = {
        'username': payload,
        'password': 'anything'
    }

    try:
        response = requests.post(login_url, data=data, allow_redirects=False, timeout=5)

        # Check if login was successful (redirect to dashboard)
        if response.status_code == 302 and '/dashboard' in response.headers.get('Location', ''):
            return True, "Login bypass successful!"
        elif response.status_code == 200 and 'Invalid credentials' in response.text:
            return False, "Login blocked (invalid credentials)"
        elif 'error' in response.text.lower() or 'sqlite' in response.text.lower():
            return False, f"SQL Error (potential vulnerability detected)"
        else:
            return False, "Login blocked"

    except requests.RequestException as e:
        return False, f"Request failed: {str(e)}"

def test_search_sqli(base_url, payload):
    """Test SQL injection in search functionality"""
    # First login as alice
    session = requests.Session()
    login_url = urljoin(base_url, '/login')
    session.post(login_url, data={'username': 'alice', 'password': 'password123'})

    search_url = urljoin(base_url, '/search')

    try:
        response = session.get(search_url, params={'query': payload}, timeout=5)

        if response.status_code == 200:
            # Check for signs of successful SQLi
            if 'admin_secret' in response.text or 'password' in response.text.lower():
                return True, "Data exfiltration possible!"
            elif 'sqlite' in response.text.lower() or 'syntax error' in response.text.lower():
                return False, "SQL Error (vulnerability exists but data not extracted)"
            else:
                return False, "Search returned results safely"
        else:
            return False, f"Unexpected status code: {response.status_code}"

    except requests.RequestException as e:
        return False, f"Request failed: {str(e)}"

def run_tests(target_url, app_name):
    """Run all SQL injection tests"""
    print(f"\n{'='*70}")
    print(f"Testing {app_name}: {target_url}")
    print(f"{'='*70}\n")

    payloads = load_payloads()

    print(f"Loaded {len(payloads)} payloads\n")

    # Test login bypass
    print("=" * 70)
    print("TEST 1: Login Bypass (Authentication SQLi)")
    print("=" * 70)

    success_count = 0
    for i, payload in enumerate(payloads[:10], 1):  # Test first 10 payloads
        success, message = test_login_bypass(target_url, payload)
        status = "✓ SUCCESS" if success else "✗ BLOCKED"
        print(f"{i}. Payload: {payload[:50]:<50} | {status}")
        if success:
            success_count += 1
            print(f"   → {message}")

    print(f"\nLogin Bypass Results: {success_count}/{10} payloads succeeded")

    # Test search SQLi
    print("\n" + "=" * 70)
    print("TEST 2: Search Field (Data Exfiltration)")
    print("=" * 70)

    union_payloads = [p for p in payloads if 'UNION' in p][:5]
    success_count = 0

    for i, payload in enumerate(union_payloads, 1):
        success, message = test_search_sqli(target_url, payload)
        status = "✓ SUCCESS" if success else "✗ BLOCKED"
        print(f"{i}. Payload: {payload[:50]:<50} | {status}")
        if success:
            success_count += 1
            print(f"   → {message}")

    print(f"\nSearch SQLi Results: {success_count}/{len(union_payloads)} payloads succeeded")

    print(f"\n{'='*70}\n")

def main():
    """Main function"""
    print("\n" + "="*70)
    print("SQL Injection Attack Tester")
    print("="*70)

    vulnerable_url = input("Enter vulnerable app URL (default: http://localhost:5000): ").strip()
    if not vulnerable_url:
        vulnerable_url = "http://localhost:5000"

    patched_url = input("Enter patched app URL (default: http://localhost:5001): ").strip()
    if not patched_url:
        patched_url = "http://localhost:5001"

    # Test vulnerable app
    run_tests(vulnerable_url, "VULNERABLE APP")

    # Test patched app
    run_tests(patched_url, "PATCHED APP")

    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print("The vulnerable app should show multiple successful SQLi attacks.")
    print("The patched app should block all SQLi attempts.")
    print("="*70 + "\n")

if __name__ == '__main__':
    main()
