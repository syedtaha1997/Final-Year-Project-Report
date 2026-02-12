# Software Security Assignment

## One-Time Setup (Run Once)

1. Open Command Prompt and navigate to the project directory:
   ```bash
   cd "C:\Users\alimo\Desktop\Software Security Assignment"
   ```

2. Create a Python virtual environment:
   ```bash
   python -m venv venv
   ```

3. Activate the virtual environment:
   ```bash
   venv\Scripts\activate.bat
   ```

4. Install required dependencies:
   ```bash
   python -m pip install flask cryptography requests
   ```

---

## How to Run the Program

### Window 1: Start the Server

1. Open a new Command Prompt window and navigate to the project directory:
   ```bash
   cd "C:\Users\alimo\Desktop\Software Security Assignment"
   ```

2. Activate the virtual environment:
   ```bash
   venv\Scripts\activate.bat
   ```

3. Run the Python server:
   ```bash
   python python_code.py
   ```

### Window 2: Start the Client Menu

1. Open another Command Prompt window and navigate to the project directory:
   ```bash
   cd "C:\Users\alimo\Desktop\Software Security Assignment"
   ```

2. Activate the virtual environment:
   ```bash
   venv\Scripts\activate.bat
   ```

3. Run the client menu:
   ```bash
   python client_menu.py
   ```

---

## Credentials for Testing

Use the following credentials in the menu:

| Operation | Username | Password |
|-----------|----------|----------|
| Encrypt/Download Encrypted | `user` | `user123` |
| Decrypt/Download Decrypted | `admin` | `admin123` |

---

## Notes

- Make sure to run **Window 1 (Server)** before **Window 2 (Client Menu)**
- Keep both windows open while using the program
- The virtual environment must be activated in each new Command Prompt window