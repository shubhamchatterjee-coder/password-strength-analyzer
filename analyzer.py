"""
analyzer.py
------------
Core password-strength logic. No UI code here on purpose —
keeping logic separate from the interface is good software
design (and makes this easy to test or reuse later, e.g. in a CLI).

CONCEPTS YOU'LL LEARN HERE:
1. Character-class complexity checks
2. Shannon entropy (a real cryptography concept — measures
   "how many guesses would a brute-force attacker need")
3. Dictionary attacks (checking against known-common passwords)
4. Secure random generation (secrets vs random)
"""

import re
import math
import secrets
import string


# ---------------------------------------------------------------
# 1. LOAD A COMMON-PASSWORD LIST
# ---------------------------------------------------------------
# Real-world tools (like "Have I Been Pwned") check submitted
# passwords against huge leaked-password databases. We use a
# small local sample file to demonstrate the same idea.
def load_common_passwords(filepath="common_passwords.txt"):
    try:
        with open(filepath, "r") as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        return set()


COMMON_PASSWORDS = load_common_passwords()


# ---------------------------------------------------------------
# 2. LENGTH CHECK
# ---------------------------------------------------------------
def check_length(password):
    """Longer passwords are exponentially harder to brute-force.
    Each extra character multiplies the possible combinations."""
    length = len(password)
    if length >= 16:
        return 3, "Excellent length (16+ characters)"
    elif length >= 12:
        return 2, "Good length (12-15 characters)"
    elif length >= 8:
        return 1, "Minimum acceptable length (8-11 characters)"
    else:
        return 0, "Too short (under 8 characters)"


# ---------------------------------------------------------------
# 3. COMPLEXITY CHECK (character variety)
# ---------------------------------------------------------------
def check_complexity(password):
    """Checks how many different character classes are used.
    More classes = bigger 'alphabet' an attacker must search."""
    classes_used = 0
    details = []

    if re.search(r"[a-z]", password):
        classes_used += 1
        details.append("lowercase")
    if re.search(r"[A-Z]", password):
        classes_used += 1
        details.append("uppercase")
    if re.search(r"[0-9]", password):
        classes_used += 1
        details.append("digits")
    if re.search(r"[^a-zA-Z0-9]", password):
        classes_used += 1
        details.append("symbols")

    return classes_used, details


# ---------------------------------------------------------------
# 4. UNIQUENESS / COMMON-PASSWORD CHECK
# ---------------------------------------------------------------
def check_common(password):
    """Flags passwords found in known leaked/common password lists,
    or with obvious repeated/sequential patterns."""
    pw_lower = password.lower()

    if pw_lower in COMMON_PASSWORDS:
        return False, "This password appears in common password lists"

    # Repeated character check, e.g. "aaaaaaaa"
    if re.search(r"(.)\1{3,}", password):
        return False, "Contains a long repeated character sequence"

    # Simple ascending sequence check, e.g. "1234", "abcd"
    sequences = ["0123456789", "abcdefghijklmnopqrstuvwxyz"]
    for seq in sequences:
        for i in range(len(seq) - 3):
            if seq[i:i + 4] in pw_lower:
                return False, "Contains a simple sequential pattern"

    return True, "No common patterns detected"


# ---------------------------------------------------------------
# 5. ENTROPY CALCULATION (the actual cryptography math)
# ---------------------------------------------------------------
def calculate_entropy(password):
    """
    Shannon entropy estimate, in BITS.
    Formula: entropy = length * log2(pool_size)

    'pool_size' = how many possible characters could appear at
    each position (based on which character classes are used).
    This estimates how many guesses (2^entropy) a brute-force
    attacker would need on average.
    """
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool_size += 32  # approx count of common symbols

    if pool_size == 0 or len(password) == 0:
        return 0

    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 1)


# ---------------------------------------------------------------
# 6. OVERALL SCORING
# ---------------------------------------------------------------
def score_password(password):
    """Combines all checks into one final verdict."""
    if not password:
        return {
            "score": 0, "label": "N/A", "entropy": 0,
            "length_msg": "", "complexity_details": [],
            "common_msg": "", "feedback": ["Enter a password to analyze"]
        }

    length_score, length_msg = check_length(password)
    complexity_score, complexity_details = check_complexity(password)
    is_unique, common_msg = check_common(password)
    entropy = calculate_entropy(password)

    total = length_score + complexity_score + (2 if is_unique else 0)

    if not is_unique:
        label = "Weak"
    elif total >= 7:
        label = "Very Strong"
    elif total >= 5:
        label = "Strong"
    elif total >= 3:
        label = "Medium"
    else:
        label = "Weak"

    feedback = []
    if length_score < 2:
        feedback.append("Use at least 12 characters")
    if complexity_score < 3:
        missing = {"lowercase", "uppercase", "digits", "symbols"} - set(complexity_details)
        feedback.append(f"Add {', '.join(missing)} to increase variety")
    if not is_unique:
        feedback.append(common_msg)
    if not feedback:
        feedback.append("Strong password — no immediate improvements needed")

    return {
        "score": total,
        "label": label,
        "entropy": entropy,
        "length_msg": length_msg,
        "complexity_details": complexity_details,
        "common_msg": common_msg,
        "feedback": feedback,
    }


# ---------------------------------------------------------------
# 7. SECURE PASSWORD SUGGESTION
# ---------------------------------------------------------------
def suggest_password(length=16):
    """
    Uses Python's `secrets` module — NOT `random`.
    `random` is predictable (good for games, bad for security).
    `secrets` uses the OS's cryptographically secure random source,
    which is what any real password generator must use.
    """
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))
