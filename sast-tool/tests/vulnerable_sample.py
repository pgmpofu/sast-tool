"""
⚠️  INTENTIONALLY VULNERABLE CODE — FOR TESTING ONLY ⚠️

This file exists solely to demonstrate SAST detections.
DO NOT use any of these patterns in real code.
"""

import subprocess
import pickle
import hashlib
import yaml
import sqlite3

# ── Secrets ───────────────────────────────────────────────────────────────────

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"           # SEC-001
API_KEY = "apikey = 'super_secret_hardcoded_key'"    # SEC-002
DB_URL = "postgresql://admin:password123@localhost/prod"  # SEC-006
JWT_SECRET = "jwt_secret = 'my_hardcoded_secret'"   # SEC-004


# ── SQL Injection ─────────────────────────────────────────────────────────────

def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # INJ-001: direct string concatenation in SQL
    cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")
    return cursor.fetchone()


# ── Command Injection ─────────────────────────────────────────────────────────

def run_ping(host):
    # INJ-002: shell=True with user input
    subprocess.call("ping -c 1 " + host, shell=True)


# ── Cryptography ──────────────────────────────────────────────────────────────

def hash_password(password):
    # CRYPTO-001: MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()


def hash_token(token):
    # CRYPTO-002: SHA-1 for security token
    return hashlib.sha1(token.encode()).hexdigest()


# ── Deserialization ───────────────────────────────────────────────────────────

def load_user_data(data_bytes):
    # MISC-006: unsafe pickle deserialization
    return pickle.loads(data_bytes)


def load_config(yaml_string):
    # MISC-006: unsafe yaml.load
    return yaml.load(yaml_string)


# ── SSL Verification ──────────────────────────────────────────────────────────

import requests

def fetch_data(url):
    # CRYPTO-006: SSL verification disabled
    return requests.get(url, verify=False)


# ── Path Traversal ────────────────────────────────────────────────────────────

def read_file(filename):
    # MISC-001: unsanitized user-supplied filename
    with open("/var/app/uploads/" + filename) as f:
        return f.read()


# ── Debug Mode ────────────────────────────────────────────────────────────────

from flask import Flask
app = Flask(__name__)

# MISC-002: debug=True hardcoded
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
