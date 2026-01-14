#!/usr/bin/env python3
"""
CSRF Attack Tester
Tests CSRF vulnerabilities against vulnerable and patched applications
"""

import requests
import sys
import time

def test_csrf_update_profile(base_url, attacker_origin="http://attacker.com"):
    """Test CSRF in profile update"""
    print(f"\nTesting CSRF on profile update at {base_url}")

    # Step 1: Login as alice to establish a session
    session = requests.Session()
    login_url = f"{base_url}/login"

    login_data = {
        'username': 'alice',
        'password': 'password123'
    }

    response = session.post(login_url, data=login_data)

    if response.status_code != 200 and response.status_code != 302:
        return False, "Failed to login"

    print("  ✓ Logged in as alice")

    # Step 2: Get current profile to verify
    dashboard_response = session.get(f"{base_url}/dashboard")
    original_email = "alice@example.com"

    # Step 3: Simulate CSRF attack (POST without CSRF token, simulating cross-origin request)
    csrf_data = {
        'email': 'hacked@attacker.com',
        'bio': 'I was hacked via CSRF!'
    }

    # Remove referer and set origin to simulate cross-origin attack
    headers = {
        'Origin': attacker_origin,
        'Referer': f'{attacker_origin}/attacker.html'
    }

    attack_response = session.post(
        f"{base_url}/update_profile",
        data=csrf_data,
        headers=headers,
        allow_redirects=False
    )

    # Step 4: Check if the attack succeeded
    if attack_response.status_code == 403:
        return False, "CSRF attack blocked (403 Forbidden)"

    # Check the profile to see if it was updated
    check_response = session.get(f"{base_url}/dashboard")

    if 'hacked@attacker.com' in check_response.text:
        return True, "CSRF attack successful! Profile was updated without CSRF token"
    else:
        return False, "CSRF attack blocked (profile not updated)"

def test_csrf_add_friend(base_url):
    """Test CSRF in add friend functionality"""
    print(f"\nTesting CSRF on add friend at {base_url}")

    # Step 1: Login as alice
    session = requests.Session()
    login_url = f"{base_url}/login"

    login_data = {
        'username': 'alice',
        'password': 'password123'
    }

    response = session.post(login_url, data=login_data)

    if response.status_code != 200 and response.status_code != 302:
        return False, "Failed to login"

    print("  ✓ Logged in as alice")

    # Step 2: Simulate CSRF attack to add 'attacker' as friend
    csrf_data = {
        'friend_username': 'bob'
    }

    headers = {
        'Origin': 'http://attacker.com',
        'Referer': 'http://attacker.com/attacker.html'
    }

    attack_response = session.post(
        f"{base_url}/add_friend",
        data=csrf_data,
        headers=headers,
        allow_redirects=False
    )

    if attack_response.status_code == 403:
        return False, "CSRF attack blocked (403 Forbidden)"

    # For this demo, we'll consider it successful if we didn't get a 403
    # In a real app, you'd check the friends list
    if attack_response.status_code in [200, 302]:
        return True, "CSRF attack successful! Friend was added without CSRF token"
    else:
        return False, "CSRF attack blocked"

def run_tests(app_name, base_url):
    """Run all CSRF tests"""
    print(f"\n{'='*70}")
    print(f"Testing {app_name}: {base_url}")
    print(f"{'='*70}")

    # Test 1: Profile Update CSRF
    print("\n" + "="*70)
    print("TEST 1: Profile Update CSRF")
    print("="*70)

    success, message = test_csrf_update_profile(base_url)
    status = "✓ VULNERABLE" if success else "✓ SECURE"
    print(f"\nResult: {status}")
    print(f"Message: {message}")

    # Test 2: Add Friend CSRF
    print("\n" + "="*70)
    print("TEST 2: Add Friend CSRF")
    print("="*70)

    success, message = test_csrf_add_friend(base_url)
    status = "✓ VULNERABLE" if success else "✓ SECURE"
    print(f"\nResult: {status}")
    print(f"Message: {message}")

    print(f"\n{'='*70}\n")

def main():
    """Main function"""
    print("\n" + "="*70)
    print("CSRF Attack Tester")
    print("="*70)

    vulnerable_url = input("Enter vulnerable app URL (default: http://localhost:5000): ").strip()
    if not vulnerable_url:
        vulnerable_url = "http://localhost:5000"

    patched_url = input("Enter patched app URL (default: http://localhost:5001): ").strip()
    if not patched_url:
        patched_url = "http://localhost:5001"

    # Test vulnerable app
    run_tests("VULNERABLE APP", vulnerable_url)

    # Test patched app
    run_tests("PATCHED APP", patched_url)

    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print("Expected Results:")
    print("- Vulnerable app: Should be vulnerable to CSRF attacks")
    print("- Patched app: Should block CSRF attacks with tokens")
    print("="*70 + "\n")

if __name__ == '__main__':
    main()
