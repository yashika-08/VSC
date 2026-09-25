# test/samples/vulnerable-api.py
# Sample file with intentional Python vulnerabilities for testing Sentinel-VSC

import sqlite3
import pickle
import hashlib
import os
import subprocess

# ❌ VULNERABLE: SQL Injection — f-string in cursor.execute() (sqli-003)
def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return cursor.fetchone()

# ❌ VULNERABLE: Insecure Deserialization — pickle.loads() (deser-002)
def load_session(data):
    session = pickle.loads(data)
    return session

# ❌ VULNERABLE: Weak Hash — MD5 password hashing (auth-004)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# ❌ VULNERABLE: Hardcoded Credentials (auth-003)
DATABASE_CONFIG = {
    "host": "prod-db.internal.example.com",
    "password": "SuperSecret123!",
    "api_key": "sk-live-4eC39HqLyjWDarjtT1zdp7dc",
}

# ❌ VULNERABLE: Debug Mode Enabled (misconfig-001)
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)

# ❌ VULNERABLE: Disabled SSL Verification (misconfig-003)
import requests

def fetch_internal_api(url):
    response = requests.get(url, verify=False)
    return response.json()

# ❌ VULNERABLE: Command Injection — os.system with user input (cmdi-001)
def convert_image(filename):
    os.system(f"convert {filename} -resize 200x200 output.jpg")
