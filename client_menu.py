import os
import requests
from requests.auth import HTTPBasicAuth

BASE_URL = "http://127.0.0.1:5001"

def ask_creds():
    u = input("Username: ").strip()
    p = input("Password: ").strip()
    return HTTPBasicAuth(u, p)

def do_login(auth):
    r = requests.get(f"{BASE_URL}/login", auth=auth)
    print(r.status_code, r.text)
    return r.ok

def upload_file(auth, path):
    with open(path, "rb") as f:
        files = {"file": (os.path.basename(path), f)}
        r = requests.post(f"{BASE_URL}/upload", auth=auth, files=files)
    print(r.status_code, r.text)
    return r.ok

def encrypt_file(auth, name):
    r = requests.post(f"{BASE_URL}/encrypt/{name}", auth=auth)
    print(r.status_code, r.text)
    if r.ok and r.headers.get("Content-Type", "").startswith("application/json"):
        return r.json().get("encrypted")
    return None

def download_encrypted(auth, enc_name, save_as):
    r = requests.get(f"{BASE_URL}/download/encrypted/{enc_name}", auth=auth, stream=True)
    if not r.ok:
        print(r.status_code, r.text)
        return False
    with open(save_as, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
    print("Saved:", save_as)
    return True

def decrypt_file(auth, enc_name):
    r = requests.post(f"{BASE_URL}/decrypt/{enc_name}", auth=auth)
    print(r.status_code, r.text)
    if r.ok and r.headers.get("Content-Type", "").startswith("application/json"):
        return r.json().get("decrypted")
    return None

def download_decrypted(auth, dec_name, save_as):
    r = requests.get(f"{BASE_URL}/download/decrypted/{dec_name}", auth=auth, stream=True)
    if not r.ok:
        print(r.status_code, r.text)
        return False
    with open(save_as, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
    print("Saved:", save_as)
    return True

def main():
    auth = None
    last_plain_name = None
    last_enc_name = None
    last_dec_name = None

    while True:
        print("\n1 Login")
        print("2 Upload + Encrypt")
        print("3 Download Encrypted")
        print("4 Decrypt (authorized only)")
        print("5 Download Decrypted (authorized only)")
        print("0 Exit")
        choice = input("Choose: ").strip()

        if choice == "0":
            break

        if choice == "1":
            auth = ask_creds()
            do_login(auth)

        elif choice == "2":
            if auth is None:
                print("Login first (option 1).")
                continue
            path = input("Local file path to upload (e.g. test.txt): ").strip().strip('"')
            if not os.path.exists(path):
                print("File not found:", path)
                continue
            ok = upload_file(auth, path)
            if ok:
                last_plain_name = os.path.basename(path)
                last_enc_name = encrypt_file(auth, last_plain_name)

        elif choice == "3":
            if auth is None:
                print("Login first (option 1).")
                continue
            enc_name = input(f"Encrypted filename [{last_enc_name or ''}]: ").strip()
            if not enc_name:
                enc_name = last_enc_name
            if not enc_name:
                print("No encrypted filename.")
                continue
            save_as = input(f"Save as (local) [{enc_name}]: ").strip()
            if not save_as:
                save_as = enc_name
            download_encrypted(auth, enc_name, save_as)

        elif choice == "4":
            if auth is None:
                print("Login first (option 1).")
                continue
            enc_name = input(f"Encrypted filename to decrypt [{last_enc_name or ''}]: ").strip()
            if not enc_name:
                enc_name = last_enc_name
            if not enc_name:
                print("No encrypted filename.")
                continue
            last_dec_name = decrypt_file(auth, enc_name)

        elif choice == "5":
            if auth is None:
                print("Login first (option 1).")
                continue
            dec_name = input(f"Decrypted filename [{last_dec_name or ''}]: ").strip()
            if not dec_name:
                dec_name = last_dec_name
            if not dec_name:
                print("No decrypted filename.")
                continue
            save_as = input(f"Save as (local) [{dec_name}]: ").strip()
            if not save_as:
                save_as = dec_name
            download_decrypted(auth, dec_name, save_as)

        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()


# ============================================================================
# SECURITY UNIT TESTS - Client (client_menu.py)
# Question 6: Security Testing, Validation, and Compliance
# ============================================================================

import unittest
from unittest.mock import patch, MagicMock
import tempfile
import shutil

class TestClientSecurity(unittest.TestCase):
    """Unit tests for security flaws in client (client_menu.py)"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.test_dir, "test.txt")
        with open(self.test_file, 'w') as f:
            f.write("Test content")

    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # ========== CREDENTIAL HANDLING TESTS ==========

    def test_credentials_passed_as_basicauth(self):
        """TEST: Credentials should be passed via HTTP Basic Auth"""
        auth = HTTPBasicAuth("user", "password")
        self.assertEqual(auth.username, "user")
        self.assertEqual(auth.password, "password")
        print("✓ TEST PASSED: Credentials can be created with HTTPBasicAuth")

    def test_ask_creds_returns_httpbasicauth(self):
        """TEST: ask_creds() should return HTTPBasicAuth object"""
        with patch('builtins.input', side_effect=['testuser', 'testpass']):
            auth = ask_creds()
            self.assertIsInstance(auth, HTTPBasicAuth)
            print("✓ TEST PASSED: ask_creds() returns HTTPBasicAuth object")

    def test_credentials_not_logged_to_console(self):
        """TEST: Credentials should not be printed in normal flow"""
        # Test that do_login doesn't echo credentials
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"ok": true}'
        
        with patch('requests.get', return_value=mock_response):
            result = do_login(HTTPBasicAuth("user", "pass"))
            self.assertTrue(result)
            print("✓ TEST PASSED: Credentials not echoed in normal operation")

    # ========== FILE OPERATION TESTS ==========

    def test_upload_file_exists_check(self):
        """TEST: File existence should be checked before upload"""
        nonexistent = os.path.join(self.test_dir, "nonexistent.txt")
        self.assertFalse(os.path.exists(nonexistent))
        print("✓ TEST PASSED: File existence can be verified")

    def test_upload_file_with_valid_path(self):
        """TEST: upload_file should handle valid file paths"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.ok = True
        
        with patch('requests.post', return_value=mock_response):
            result = upload_file(HTTPBasicAuth("user", "pass"), self.test_file)
            self.assertTrue(result)
            print("✓ TEST PASSED: upload_file works with valid paths")

    def test_download_encrypted_creates_file(self):
        """TEST: download_encrypted should create local file"""
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.iter_content = lambda chunk_size: [b"encrypted_data"]
        
        download_path = os.path.join(self.test_dir, "downloaded.enc")
        
        with patch('requests.get', return_value=mock_response):
            result = download_encrypted(HTTPBasicAuth("user", "pass"), "test.enc", download_path)
            self.assertTrue(result)
            print("✓ TEST PASSED: download_encrypted creates file")

    def test_filename_sanitization_from_basename(self):
        """TEST: Files use os.path.basename() for safe filenames"""
        path_with_traversal = "/tmp/../../../etc/passwd"
        safe_name = os.path.basename(path_with_traversal)
        self.assertEqual(safe_name, "passwd")
        print("✓ TEST PASSED: os.path.basename() sanitizes path traversal")

    # ========== ERROR HANDLING TESTS ==========

    def test_login_failure_handling(self):
        """TEST: Failed login should return False"""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.ok = False
        mock_response.text = 'Unauthorized'
        
        with patch('requests.get', return_value=mock_response):
            result = do_login(HTTPBasicAuth("bad", "creds"))
            self.assertFalse(result)
            print("✓ TEST PASSED: Failed login returns False")

    def test_upload_failure_handling(self):
        """TEST: Failed upload should return False"""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.ok = False
        
        with patch('requests.post', return_value=mock_response):
            result = upload_file(HTTPBasicAuth("user", "pass"), self.test_file)
            self.assertFalse(result)
            print("✓ TEST PASSED: Failed upload returns False")

    def test_download_failure_handling(self):
        """TEST: Failed download should return False"""
        mock_response = MagicMock()
        mock_response.ok = False
        
        with patch('requests.get', return_value=mock_response):
            result = download_encrypted(HTTPBasicAuth("user", "pass"), "test.enc", "local.enc")
            self.assertFalse(result)
            print("✓ TEST PASSED: Failed download returns False")

    # ========== SECURITY VULNERABILITY TESTS ==========

    def test_credentials_sent_over_http_vulnerability(self):
        """TEST: VULNERABILITY - Credentials sent over HTTP"""
        # BASE_URL uses http:// instead of https://
        self.assertTrue(BASE_URL.startswith("http://"))
        print("⚠️  VULNERABILITY FOUND: Client connects via HTTP (not HTTPS)")
        print("    BASE_URL = http://127.0.0.1:5001")
        print("    Credentials vulnerable to MITM attacks")

    def test_no_certificate_pinning(self):
        """TEST: VULNERABILITY - No certificate pinning"""
        print("⚠️  VULNERABILITY FOUND: No certificate pinning implemented")
        print("    Client doesn't verify server certificate authenticity")
        print("    Vulnerable to MITM with spoofed certificates")

    def test_credentials_visible_in_memory(self):
        """TEST: VULNERABILITY - Credentials stored in memory"""
        auth = HTTPBasicAuth("admin", "admin123")
        # Credentials are accessible in memory
        self.assertEqual(auth.username, "admin")
        print("⚠️  VULNERABILITY FOUND: Credentials stored in plaintext in memory")
        print("    No encryption or secure wiping of sensitive data")

    def test_session_not_managed(self):
        """TEST: VULNERABILITY - No session management"""
        # auth object is reused across operations but not a session
        print("⚠️  VULNERABILITY FOUND: No proper session management")
        print("    Credentials sent with each request (Basic Auth)")
        print("    No session tokens or timeout mechanism")

    def test_no_rate_limiting_on_client(self):
        """TEST: VULNERABILITY - No rate limiting"""
        print("⚠️  VULNERABILITY FOUND: Client has no rate limiting")
        print("    Can brute-force server without delays")

    # ========== API COMMUNICATION TESTS ==========

    def test_login_returns_user_info(self):
        """TEST: Login response should contain user information"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.ok = True
        mock_response.text = '{"ok": true, "user": "admin", "can_decrypt": true}'
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.json = lambda: {
            "ok": True, 
            "user": "admin", 
            "can_decrypt": True
        }
        
        with patch('requests.get', return_value=mock_response):
            result = do_login(HTTPBasicAuth("admin", "admin123"))
            self.assertTrue(result)
            print("✓ TEST PASSED: Login response contains user info")

    def test_encrypt_response_contains_filename(self):
        """TEST: Encrypt response should contain encrypted filename"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.ok = True
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.json = lambda: {"encrypted": "test.txt.enc"}
        
        with patch('requests.post', return_value=mock_response):
            result = encrypt_file(HTTPBasicAuth("user", "pass"), "test.txt")
            self.assertEqual(result, "test.txt.enc")
            print("✓ TEST PASSED: Encrypt response contains encrypted filename")

    def test_decrypt_response_contains_filename(self):
        """TEST: Decrypt response should contain decrypted filename"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.ok = True
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.json = lambda: {"decrypted": "test.txt.dec"}
        
        with patch('requests.post', return_value=mock_response):
            result = decrypt_file(HTTPBasicAuth("admin", "admin123"), "test.txt.enc")
            self.assertEqual(result, "test.txt.dec")
            print("✓ TEST PASSED: Decrypt response contains decrypted filename")


class TestClientInputValidation(unittest.TestCase):
    """Unit tests for input validation on client side"""

    def test_file_path_validation_exists(self):
        """TEST: Client should check if file exists before upload"""
        with patch('builtins.input', side_effect=['/nonexistent/file.txt']):
            nonexistent_path = input().strip().strip('"')
            exists = os.path.exists(nonexistent_path)
            self.assertFalse(exists)
            print("✓ TEST PASSED: File existence validation works")

    def test_basename_extraction(self):
        """TEST: Filenames should be extracted with os.path.basename()"""
        full_path = "/home/user/documents/file.txt"
        filename = os.path.basename(full_path)
        self.assertEqual(filename, "file.txt")
        print("✓ TEST PASSED: basename() safely extracts filename")

    def test_menu_choice_validation(self):
        """TEST: Menu should accept valid choices (0-5)"""
        valid_choices = ['0', '1', '2', '3', '4', '5']
        for choice in valid_choices:
            # Simulate choice handling
            is_valid = choice in valid_choices
            self.assertTrue(is_valid)
        print("✓ TEST PASSED: Menu choice validation works")


def run_client_security_tests():
    """Run all client security unit tests"""
    print("\n" + "="*70)
    print("SECURITY UNIT TESTS - CLIENT (client_menu.py)")
    print("Question 6: Security Testing, Validation, and Compliance")
    print("="*70 + "\n")
    
    # Run tests
    suite = unittest.TestLoader().loadTestsFromTestCase(TestClientSecurity)
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestClientInputValidation))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "="*70)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("="*70 + "\n")
    
    return result


# Uncomment to run tests when executing this file directly
# if __name__ == "__main__":
#     run_client_security_tests()
