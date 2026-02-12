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
