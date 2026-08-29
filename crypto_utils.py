"""
crypto_utils.py
----------------
Security Module for MySmartMed (paper Section III-B / III-C-5).

Implements field-level AES-256-GCM authenticated encryption:
  - 256-bit symmetric key derived from the user's login credentials
    via PBKDF2-HMAC-SHA256 (per paper: "keys are derived from user
    credentials using PBKDF2 with HMAC-SHA256").
  - A unique 96-bit (12-byte) nonce is generated per encryption call
    to guarantee semantic security (identical plaintext -> different
    ciphertext) and to avoid nonce reuse under a single key.
  - GCM produces a 128-bit authentication tag which is verified
    BEFORE any plaintext is returned to the caller, giving tamper
    detection (paper Table I: "fails if tampered").

Storage format for an encrypted field (all packed into one text
column, base64-encoded, so the DB schema needs no extra columns):

    base64( salt(16) || nonce(12) || tag(16) || ciphertext )

The salt is stored per-field so that, in principle, per-field key
derivation could be introduced later without a schema change; in the
current prototype the same session-derived key is reused and the
salt is fixed per session (see derive_key below), matching the
paper's statement that "the encryption key is derived during login
and is held in the server-side session memory for the duration of
the session."
"""

import os
import hmac
import base64
import hashlib
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ---------------------------------------------------------------------------
# Key derivation (PBKDF2-HMAC-SHA256)
# ---------------------------------------------------------------------------

PBKDF2_ITERATIONS = 600_000   # conservative local-prototype cost for PBKDF2-SHA256
KEY_LENGTH_BYTES = 32         # 256-bit key for AES-256
NONCE_LENGTH_BYTES = 12       # 96-bit nonce, as specified in the paper
TAG_LENGTH_BYTES = 16         # 128-bit GCM authentication tag
SALT_LENGTH_BYTES = 16


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from a user's password using
    PBKDF2-HMAC-SHA256, as described in Section III-B.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH_BYTES,
        # Domain separation prevents this output from being reused as the
        # password-verification value.
        salt=salt + b"|mysmartmed:aes-v1",
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def generate_login_salt() -> bytes:
    """Generate a fresh random salt (stored per-user in the DB)."""
    return os.urandom(SALT_LENGTH_BYTES)


# ---------------------------------------------------------------------------
# Field-level AES-256-GCM encryption / decryption
# ---------------------------------------------------------------------------

def encrypt_field(plaintext: Optional[str], key: bytes) -> Optional[str]:
    """
    Encrypt a single field value with AES-256-GCM.

    Returns a base64 string encoding: salt || nonce || tag || ciphertext
    (the 'salt' here is a fresh per-field random value that is folded
    into associated data so identical plaintexts across records never
    collide, even though the AES key itself is the same session key).

    Returns None if plaintext is None/empty, so optional fields don't
    get needlessly encrypted-and-stored as ciphertext of an empty string.
    """
    if plaintext is None or plaintext == "":
        return None

    salt = os.urandom(SALT_LENGTH_BYTES)          # per-field randomizer (used as AAD)
    nonce = os.urandom(NONCE_LENGTH_BYTES)         # unique 96-bit nonce per encryption

    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), salt)
    # cryptography's AESGCM.encrypt() appends the 16-byte tag to the ciphertext

    blob = salt + nonce + ciphertext_and_tag
    return base64.b64encode(blob).decode("ascii")


def decrypt_field(stored_value: Optional[str], key: bytes) -> Optional[str]:
    """
    Decrypt a field previously produced by encrypt_field().
    Raises InvalidTag (via cryptography) if the ciphertext was tampered
    with -- this propagates up so callers can treat it as an integrity
    failure rather than silently returning corrupted data.
    """
    if stored_value is None or stored_value == "":
        return None

    try:
        blob = base64.b64decode(stored_value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("Malformed encrypted field encoding") from exc
    if len(blob) < SALT_LENGTH_BYTES + NONCE_LENGTH_BYTES + TAG_LENGTH_BYTES:
        raise ValueError("Malformed encrypted field")
    salt = blob[:SALT_LENGTH_BYTES]
    nonce = blob[SALT_LENGTH_BYTES:SALT_LENGTH_BYTES + NONCE_LENGTH_BYTES]
    ciphertext_and_tag = blob[SALT_LENGTH_BYTES + NONCE_LENGTH_BYTES:]

    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_and_tag, salt)
    return plaintext_bytes.decode("utf-8")


# ---------------------------------------------------------------------------
# Password hashing for login verification (separate from the AES key,
# though both are derived via PBKDF2-HMAC-SHA256 from the same password)
# ---------------------------------------------------------------------------

def hash_password(password: str, salt: bytes) -> str:
    """PBKDF2-based password hash for login verification."""
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"),
        salt + b"|mysmartmed:password-v1", PBKDF2_ITERATIONS,
    )
    return base64.b64encode(dk).decode("ascii")


def verify_password(password: str, salt: bytes, expected_hash: str) -> bool:
    candidate = hash_password(password, salt)
    # constant-time comparison to avoid timing side-channels
    return hmac.compare_digest(candidate, expected_hash)
