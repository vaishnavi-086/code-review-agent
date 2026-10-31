"""
sample_code.py - Target code containing intentional security vulnerabilities and logic bugs
for testing the Multi-Agent Code Review & Security Scanner Pipeline.
"""

import os
import sqlite3
import hashlib
import subprocess

# 1. CRITICAL: Hardcoded Sensitive Credentials & Secrets
DATABASE_URL = "sqlite:///production.db"
DATABASE_PASSWORD = "SuperSecretDbPassword_2024!"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
JWT_SECRET_KEY = "insecure_static_jwt_signing_key_do_not_leak"


def get_user_by_username(username: str):
    """
    2. CRITICAL: SQL Injection vulnerability via direct f-string formatting.
    """
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Insecure query concatenation
    query = f"SELECT id, username, email, is_admin FROM users WHERE username = '{username}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user


def authenticate_user(username: str, password_attempt: str):
    """
    3. HIGH: Weak Cryptography (MD5) and timing-attack-vulnerable plain comparison.
    """
    user = get_user_by_username(username)
    if not user:
        return False

    # Insecure hashing algorithm: MD5 is cryptographically broken
    hashed_attempt = hashlib.md5(password_attempt.encode()).hexdigest()
    
    # Insecure comparison: Should use hmac.compare_digest to mitigate timing attacks
    stored_hash = user[3]
    return hashed_attempt == stored_hash


def execute_diagnostic_ping(host_address: str):
    """
    4. CRITICAL: Remote Command Injection via shell=True with unvalidated user input.
    """
    # Allows command chaining like '127.0.0.1; cat /etc/passwd' or '127.0.0.1 & whoami'
    command = f"ping -c 1 {host_address}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


def delete_user_account(user_id: int, current_user_role: str):
    """
    5. CRITICAL: Logic Bug / Broken Access Control (Inverted Authorization Check).
    """
    # Flawed authorization logic: Non-admins are allowed through!
    if current_user_role != "admin":
        print(f"Warning: Non-admin {current_user_role} attempting delete.")
        # Logic error: continues execution instead of raising PermissionError or returning!
    
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()
    conn.close()
    return {"status": "success", "deleted_user_id": user_id}


def calculate_user_discount(purchase_history: list):
    """
    6. MEDIUM: ZeroDivisionError and Logic Flaw.
    """
    total_spend = sum(purchase_history)
    order_count = len(purchase_history)
    
    # Unhandled division by zero when purchase_history is empty
    average_order_value = total_spend / order_count
    
    # Flawed discount formula
    discount = 0.15 if average_order_value > 100 else 0.05
    return discount


def log_debug_info(message: str, log_file: str = "debug.log"):
    """
    7. LOW: Resource Leak - Unclosed file descriptor without context manager.
    """
    f = open(log_file, "a")
    f.write(message + "\n")
    # Missing f.close() or with open(...) as f
