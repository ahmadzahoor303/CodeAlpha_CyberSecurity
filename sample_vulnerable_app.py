"""
sample_vulnerable_app.py
────────────────────────
This file is INTENTIONALLY written with security flaws
for demonstration purposes with the Task 3 scanner.
DO NOT use any pattern here in real code.
"""
import sqlite3
import os
import subprocess
import random
import hashlib
import pickle

# ── BAD: Hardcoded credentials ─────────────────────────
db_password = "supersecret123"
api_key     = "sk-live-abcdef1234567890"

def get_user(user_id):
    # ── BAD: SQL injection via string formatting ──────
    conn   = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = '%s'" % user_id)
    return cursor.fetchone()

def run_backup(folder):
    # ── BAD: Shell injection ──────────────────────────
    subprocess.run("tar -czf backup.tar.gz " + folder, shell=True)

def generate_token():
    # ── BAD: Insecure random ──────────────────────────
    return str(random.randint(100000, 999999))

def hash_password(pwd):
    # ── BAD: Weak hashing ────────────────────────────
    return hashlib.md5(pwd.encode()).hexdigest()

def load_session(data):
    # ── BAD: Unsafe pickle ────────────────────────────
    return pickle.loads(data)

def evaluate_formula(user_input):
    # ── BAD: eval() on user input ─────────────────────
    return eval(user_input)

# ── BAD: Debug mode on ─────────────────────────────────
DEBUG = True

def main():
    try:
        result = get_user("1 OR 1=1")
        print(result)
    except Exception:      # BAD: bare exception
        pass

if __name__ == "__main__":
    main()
