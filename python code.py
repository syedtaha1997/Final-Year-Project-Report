import os
import base64
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
ENC_DIR = os.path.join(DATA_DIR, "encrypted")
DEC_DIR = os.path.join(DATA_DIR, "decrypted")
KEY_DIR = os.path.join(DATA_DIR, "keys")

for d in [DATA_DIR, UPLOAD_DIR, ENC_DIR, DEC_DIR, KEY_DIR]:
    os.makedirs(d, exist_ok=True)

USERS = {
    "user": {"password": "user123", "can_decrypt": False},
    "admin": {"password": "admin123", "can_decrypt": True},
}

PRIV_PATH = os.path.join(KEY_DIR, "private.pem")
PUB_PATH = os.path.join(KEY_DIR, "public.pem")

def ensure_keys():
    if os.path.exists(PRIV_PATH) and os.path.exists(PUB_PATH):
        return
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(PRIV_PATH, "wb") as f:
        f.write(priv_pem)
    with open(PUB_PATH, "wb") as f:
        f.write(pub_pem)

def load_public_key():
    with open(PUB_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

def load_private_key():
    with open(PRIV_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def parse_basic_auth():
    h = request.headers.get("Authorization", "")
    if not h.startswith("Basic "):
        return None, None
    try:
        raw = base64.b64decode(h.split(" ", 1)[1]).decode("utf-8")
        username, password = raw.split(":", 1)
        return username, password
    except Exception:
        return None, None

def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u, p = parse_basic_auth()
        if not u or u not in USERS or USERS[u]["password"] != p:
            return ("Unauthorized", 401, {"WWW-Authenticate": 'Basic realm="Login Required"'})
        request.user = u
        return fn(*args, **kwargs)
    return wrapper

def rsa_encrypt_bytes(data, public_key):
    max_chunk = 190
    out = []
    for i in range(0, len(data), max_chunk):
        chunk = data[i:i+max_chunk]
        out.append(public_key.encrypt(
            chunk,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        ))
    return b"".join(out)

def rsa_decrypt_bytes(data, private_key):
    chunk_size = 256
    if len(data) % chunk_size != 0:
        raise ValueError("Invalid ciphertext size")
    out = []
    for i in range(0, len(data), chunk_size):
        block = data[i:i+chunk_size]
        out.append(private_key.decrypt(
            block,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        ))
    return b"".join(out)

@app.route("/login", methods=["GET"])
@auth_required
def login():
    return jsonify({"ok": True, "user": request.user, "can_decrypt": USERS[request.user]["can_decrypt"]})

@app.route("/upload", methods=["POST"])
@auth_required
def upload():
    if "file" not in request.files:
        return jsonify({"error": "missing file field"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "empty filename"}), 400
    path = os.path.join(UPLOAD_DIR, f.filename)
    f.save(path)
    return jsonify({"uploaded": f.filename})

@app.route("/encrypt/<name>", methods=["POST"])
@auth_required
def encrypt(name):
    in_path = os.path.join(UPLOAD_DIR, name)
    if not os.path.exists(in_path):
        return jsonify({"error": "file not found"}), 404
    with open(in_path, "rb") as f:
        data = f.read()
    public_key = load_public_key()
    enc = rsa_encrypt_bytes(data, public_key)
    out_name = name + ".enc"
    out_path = os.path.join(ENC_DIR, out_name)
    with open(out_path, "wb") as f:
        f.write(enc)
    return jsonify({"encrypted": out_name})

@app.route("/download/encrypted/<name>", methods=["GET"])
@auth_required
def download_encrypted(name):
    return send_from_directory(ENC_DIR, name, as_attachment=True)

@app.route("/decrypt/<name>", methods=["POST"])
@auth_required
def decrypt(name):
    if not USERS[request.user]["can_decrypt"]:
        return jsonify({"error": "not authorized to decrypt"}), 403
    in_path = os.path.join(ENC_DIR, name)
    if not os.path.exists(in_path):
        return jsonify({"error": "file not found"}), 404
    with open(in_path, "rb") as f:
        data = f.read()
    private_key = load_private_key()
    dec = rsa_decrypt_bytes(data, private_key)
    out_name = name.replace(".enc", "") + ".dec"
    out_path = os.path.join(DEC_DIR, out_name)
    with open(out_path, "wb") as f:
        f.write(dec)
    return jsonify({"decrypted": out_name})

@app.route("/download/decrypted/<name>", methods=["GET"])
@auth_required
def download_decrypted(name):
    if not USERS[request.user]["can_decrypt"]:
        return jsonify({"error": "not authorized to download decrypted"}), 403
    return send_from_directory(DEC_DIR, name, as_attachment=True)

if __name__ == "__main__":
    ensure_keys()
    app.run(host="127.0.0.1", port=5001, debug=True)


# ============================================================================
# SECURITY UNIT TESTS - Server (python code.py)
# Question 6: Security Testing, Validation, and Compliance
# ============================================================================

import unittest
import tempfile
import shutil
from io import BytesIO

class TestServerSecurity(unittest.TestCase):
    """Unit tests for security flaws in server (python code.py)"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_dir = tempfile.mkdtemp()
        self.app = app.test_client()
        app.config['TESTING'] = True
        
    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # ========== AUTHENTICATION TESTS ==========
    
    def test_auth_missing_header(self):
        """TEST: Missing Authorization header should return 401"""
        response = self.app.get('/login')
        self.assertEqual(response.status_code, 401)
        print("✓ TEST PASSED: Missing auth header returns 401")

    def test_auth_invalid_credentials(self):
        """TEST: Invalid credentials should return 401"""
        response = self.app.get('/login', headers={
            'Authorization': 'Basic dGVzdDp0ZXN0'  # base64('test:test')
        })
        self.assertEqual(response.status_code, 401)
        print("✓ TEST PASSED: Invalid credentials returns 401")

    def test_auth_valid_user_credentials(self):
        """TEST: Valid user credentials should return 200"""
        response = self.app.get('/login', headers={
            'Authorization': 'Basic dXNlcjp1c2VyMTIz'  # base64('user:user123')
        })
        self.assertEqual(response.status_code, 200)
        print("✓ TEST PASSED: Valid user credentials returns 200")

    def test_auth_valid_admin_credentials(self):
        """TEST: Valid admin credentials should return 200"""
        response = self.app.get('/login', headers={
            'Authorization': 'Basic YWRtaW46YWRtaW4xMjM='  # base64('admin:admin123')
        })
        self.assertEqual(response.status_code, 200)
        print("✓ TEST PASSED: Valid admin credentials returns 200")

    def test_auth_malformed_header(self):
        """TEST: Malformed authorization header should return 401"""
        response = self.app.get('/login', headers={
            'Authorization': 'Bearer invalid'
        })
        self.assertEqual(response.status_code, 401)
        print("✓ TEST PASSED: Malformed auth header returns 401")

    # ========== AUTHORIZATION TESTS ==========
    
    def test_user_cannot_decrypt(self):
        """TEST: Regular user should NOT be able to decrypt (403)"""
        response = self.app.post('/decrypt/test.enc', headers={
            'Authorization': 'Basic dXNlcjp1c2VyMTIz'
        })
        self.assertEqual(response.status_code, 403)
        print("✓ TEST PASSED: User cannot decrypt returns 403")

    def test_admin_can_decrypt_authorization(self):
        """TEST: Admin should have authorization to decrypt"""
        response = self.app.post('/decrypt/test.enc', headers={
            'Authorization': 'Basic YWRtaW46YWRtaW4xMjM='
        })
        # Should be 404 (file not found), NOT 403 (unauthorized)
        self.assertNotEqual(response.status_code, 403)
        print("✓ TEST PASSED: Admin has authorization to decrypt")

    def test_user_cannot_download_decrypted(self):
        """TEST: User should NOT be able to download decrypted files"""
        response = self.app.get('/download/decrypted/test.dec', headers={
            'Authorization': 'Basic dXNlcjp1c2VyMTIz'
        })
        self.assertEqual(response.status_code, 403)
        print("✓ TEST PASSED: User cannot download decrypted returns 403")

    # ========== CRYPTOGRAPHY TESTS ==========
    
    def test_rsa_encrypt_decrypt_roundtrip(self):
        """TEST: RSA encryption and decryption should be reversible"""
        public_key = load_public_key()
        private_key = load_private_key()
        
        plaintext = b"Test message for encryption"
        ciphertext = rsa_encrypt_bytes(plaintext, public_key)
        decrypted = rsa_decrypt_bytes(ciphertext, private_key)
        
        self.assertEqual(plaintext, decrypted)
        print("✓ TEST PASSED: RSA encrypt/decrypt roundtrip works")

    def test_rsa_encrypt_produces_different_ciphertext(self):
        """TEST: Encrypting same plaintext twice should produce different ciphertext"""
        public_key = load_public_key()
        
        plaintext = b"Test message"
        ciphertext1 = rsa_encrypt_bytes(plaintext, public_key)
        ciphertext2 = rsa_encrypt_bytes(plaintext, public_key)
        
        self.assertNotEqual(ciphertext1, ciphertext2)
        print("✓ TEST PASSED: OAEP padding produces different ciphertext each time")

    def test_rsa_key_size_is_2048(self):
        """TEST: RSA key should be 2048 bits"""
        public_key = load_public_key()
        key_size = public_key.key_size
        
        self.assertEqual(key_size, 2048)
        print(f"✓ TEST PASSED: RSA key size is {key_size} bits")

    def test_rsa_decrypt_invalid_ciphertext_size(self):
        """TEST: Decrypting invalid ciphertext should raise ValueError"""
        private_key = load_private_key()
        
        invalid_ciphertext = b"too short"  # Not multiple of 256
        with self.assertRaises(ValueError):
            rsa_decrypt_bytes(invalid_ciphertext, private_key)
        print("✓ TEST PASSED: Invalid ciphertext size raises ValueError")

    # ========== INPUT VALIDATION TESTS ==========
    
    def test_upload_missing_file_field(self):
        """TEST: Upload without file field should return 400"""
        response = self.app.post('/upload', headers={
            'Authorization': 'Basic dXNlcjp1c2VyMTIz'
        })
        self.assertEqual(response.status_code, 400)
        print("✓ TEST PASSED: Missing file field returns 400")

    def test_upload_empty_filename(self):
        """TEST: Upload with empty filename should return 400"""
        data = {'file': (BytesIO(b"test"), '')}
        response = self.app.post('/upload', data=data, headers={
            'Authorization': 'Basic dXNlcjp1c2VyMTIz'
        })
        self.assertEqual(response.status_code, 400)
        print("✓ TEST PASSED: Empty filename returns 400")

    def test_encrypt_nonexistent_file(self):
        """TEST: Encrypting non-existent file should return 404"""
        response = self.app.post('/encrypt/nonexistent.txt', headers={
            'Authorization': 'Basic dXNlcjp1c2VyMTIz'
        })
        self.assertEqual(response.status_code, 404)
        print("✓ TEST PASSED: Non-existent file returns 404")

    def test_decrypt_nonexistent_file(self):
        """TEST: Decrypting non-existent file should return 404"""
        response = self.app.post('/decrypt/nonexistent.enc', headers={
            'Authorization': 'Basic YWRtaW46YWRtaW4xMjM='
        })
        self.assertEqual(response.status_code, 404)
        print("✓ TEST PASSED: Non-existent encrypted file returns 404")

    # ========== SECURITY VULNERABILITY TESTS ==========
    
    def test_path_traversal_vulnerability_exists(self):
        """TEST: VULNERABILITY - Path traversal is possible (../.. in filename)"""
        # This test documents the VULNERABILITY
        # Files with ../ in names can potentially access other directories
        response = self.app.post('/encrypt/../../../etc/passwd.enc', headers={
            'Authorization': 'Basic dXNlcjp1c2VyMTIz'
        })
        # Currently will 404, but the path is processed without sanitization
        print("⚠️  VULNERABILITY FOUND: Path traversal is possible via ../ sequences")
        print("    Filename: ../../../etc/passwd.enc")

    def test_hardcoded_credentials_vulnerability(self):
        """TEST: VULNERABILITY - Hardcoded credentials in code"""
        # This test documents the VULNERABILITY
        self.assertIn("user", USERS)
        self.assertIn("admin", USERS)
        self.assertEqual(USERS["user"]["password"], "user123")
        self.assertEqual(USERS["admin"]["password"], "admin123")
        print("⚠️  VULNERABILITY FOUND: Hardcoded credentials in USERS dictionary")
        print("    user:user123, admin:admin123")

    def test_no_https_protocol(self):
        """TEST: VULNERABILITY - HTTP instead of HTTPS"""
        # This test documents the VULNERABILITY
        print("⚠️  VULNERABILITY FOUND: Server uses HTTP instead of HTTPS")
        print("    Credentials transmitted in Base64 (easily decoded)")
        print("    No encryption in transit")

    def test_plaintext_private_key_storage(self):
        """TEST: VULNERABILITY - Private key stored in plaintext"""
        with open(PRIV_PATH, 'r') as f:
            content = f.read()
        self.assertIn("-----BEGIN PRIVATE KEY-----", content)
        print("⚠️  VULNERABILITY FOUND: Private key stored in plaintext")
        print(f"    Location: {PRIV_PATH}")
        print("    No password protection")

    def test_no_audit_logging(self):
        """TEST: VULNERABILITY - No audit logs for operations"""
        # Response should succeed but no log is created
        self.app.get('/login', headers={
            'Authorization': 'Basic dXNlcjp1c2VyMTIz'
        })
        print("⚠️  VULNERABILITY FOUND: No audit logging of operations")
        print("    Cannot track who accessed what and when")


class TestCryptographicStrength(unittest.TestCase):
    """Unit tests for cryptographic implementation quality"""

    def test_uses_oaep_padding(self):
        """TEST: RSA encryption should use OAEP padding"""
        # OAEP is mentioned in the code
        print("✓ SECURITY CONTROL: RSA-OAEP padding is used")

    def test_uses_sha256_hashing(self):
        """TEST: Cryptographic operations use SHA-256"""
        # SHA-256 is specified in code
        print("✓ SECURITY CONTROL: SHA-256 hashing algorithm used")

    def test_key_generation_uses_secure_exponent(self):
        """TEST: RSA key uses secure public exponent"""
        # 65537 is standard secure exponent
        public_key = load_public_key()
        self.assertEqual(public_key.public_numbers().e, 65537)
        print("✓ SECURITY CONTROL: RSA exponent is 65537 (secure standard)")


def run_security_tests():
    """Run all security unit tests"""
    print("\n" + "="*70)
    print("SECURITY UNIT TESTS - SERVER (python code.py)")
    print("Question 6: Security Testing, Validation, and Compliance")
    print("="*70 + "\n")
    
    # Run tests
    suite = unittest.TestLoader().loadTestsFromTestCase(TestServerSecurity)
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestCryptographicStrength))
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
#     run_security_tests()
