# Password Strength Analyzer

A Python + Streamlit tool that evaluates password strength based on length,
character complexity, common-password patterns, and Shannon entropy. It also
includes an optional salted-hash reuse tracker and a secure password generator.

## Features
- Length and character-class (upper/lower/digit/symbol) complexity checks
- Shannon entropy calculation to estimate brute-force resistance
- Common/leaked password pattern detection
- Salted PBKDF2-HMAC-SHA256 password reuse tracking (no plaintext ever stored)
- Secure random password suggestions using Python's `secrets` module

## How to run
1. `pip install -r requirements.txt`
2. `streamlit run app.py`
3. Open the local URL shown in the terminal

## What I learned
Building this project taught me how entropy is used to estimate password
guessability, why hashing is one-way and different from encryption, why
salting prevents rainbow-table attacks, and why slow hash functions (like
PBKDF2) are used for password storage instead of fast general-purpose
hashes like raw SHA-256.