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
