"""
reuse_tracker.py
-----------------
Optional feature: warns if a password has been used before,
WITHOUT ever storing the password itself.

CONCEPTS YOU'LL LEARN HERE:
1. Hashing: a one-way function. You can turn "mypassword123"
   into a fixed-length string, but you CANNOT turn that string
   back into the original password. This is why hashing is used
   instead of encryption for passwords — even the app itself
   should never be able to recover your real password.
2. Salting: a random value added to the password before hashing.
   Without a salt, two identical passwords produce the identical
   hash, letting an attacker who steals the database spot repeated
   passwords across users, or use a precomputed "rainbow table" to
   crack them fast. A unique salt defeats both.
3. Why SHA-256 alone isn't used for real production password
   storage: it's too FAST. Attackers can compute billions of
   SHA-256 hashes per second on a GPU. Real systems use slow,
   purpose-built algorithms like bcrypt, scrypt, or Argon2, which
   are deliberately expensive to compute. We use hashlib's
   built-in `pbkdf2_hmac`, which applies SHA-256 thousands of
   times in a loop for the same reason — to slow attackers down.
"""

import sqlite3
import hashlib
import os

DB_PATH = "password_history.db"


def init_db(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS password_hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            salt BLOB NOT NULL,
            hash BLOB NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def hash_password(password, salt=None):
    """PBKDF2-HMAC-SHA256 with 100,000 iterations — a deliberately
    slow hash, unlike a single raw SHA-256 pass."""
    if salt is None:
        salt = os.urandom(16)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 100_000
    )
    return salt, pw_hash


def has_been_used_before(password, db_path=DB_PATH):
    """Checks the new password's hash (with each stored salt)
    against every stored hash. Returns True if it matches a
    previously used password."""
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT salt, hash FROM password_hashes").fetchall()
    conn.close()

    for salt, stored_hash in rows:
        _, computed_hash = hash_password(password, salt)
        if computed_hash == stored_hash:
            return True
    return False


def record_password(password, db_path=DB_PATH):
    """Stores only the salt + hash — never the plaintext password."""
    init_db(db_path)
    salt, pw_hash = hash_password(password)
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO password_hashes (salt, hash) VALUES (?, ?)",
        (salt, pw_hash),
    )
    conn.commit()
    conn.close()
